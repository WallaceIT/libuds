/* SPDX-License-Identifier: MIT */
/*
 * This file is part of libuds.
 * Copyright (C) 2022 Francesco Valla <francesco@valla.it>
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <linux/can.h>
#include <linux/can/isotp.h>

#include <net/if.h>

#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/un.h>

#include <uds/uds.h>

#define MS_TO_US(ms) (ms * 1000UL)

struct private_data
{
    int fd_can_tp_phys;
    int fd_can_tp_func;

    struct
    {
        uint8_t vin[18];
    } data;
};

static const uint32_t can_tp_phys_rx_id = (0x18DA0102 & CAN_EFF_MASK);
static const uint32_t can_tp_phys_tx_id = (0x18DA0201 & CAN_EFF_MASK);
static const uint32_t can_tp_func_rx_id = (0x18DB0102 & CAN_EFF_MASK);

static int can_tp_init(const char *interface, uint32_t rx_id, uint32_t tx_id, bool id_29bit)
{
    struct sockaddr_can addr;
    struct can_isotp_options opts;
    struct can_isotp_fc_options fcopts;
    int fd;

    fd = socket(PF_CAN, (int)SOCK_DGRAM, CAN_ISOTP);
    if (fd < 0)
    {
        (void)fprintf(stderr, "Failed to create CAN_ISOTP socket: %s\n", strerror(errno));
        return -1;
    }

    memset(&opts, 0, sizeof(opts));
    opts.txpad_content = 0xFF;
    opts.rxpad_content = 0xFF;
    opts.flags |= (CAN_ISOTP_TX_PADDING | CAN_ISOTP_RX_PADDING);
    opts.flags |= CAN_ISOTP_CHK_PAD_LEN;
    setsockopt(fd, SOL_CAN_ISOTP, CAN_ISOTP_OPTS, &opts, sizeof(opts));

    memset(&fcopts, 0, sizeof(fcopts));
    fcopts.bs = 0;
    fcopts.stmin = 20;
    fcopts.wftmax = 10;
    setsockopt(fd, SOL_CAN_ISOTP, CAN_ISOTP_RECV_FC, &fcopts, sizeof(fcopts));

    memset(&addr, 0, sizeof(addr));
    addr.can_family = AF_CAN;
    addr.can_addr.tp.tx_id = (tx_id & CAN_EFF_MASK);
    addr.can_addr.tp.rx_id = (rx_id & CAN_EFF_MASK);
    if (id_29bit)
    {
        addr.can_addr.tp.tx_id |= CAN_EFF_FLAG;
        addr.can_addr.tp.rx_id |= CAN_EFF_FLAG;
    }
    addr.can_ifindex = (int)if_nametoindex(interface);
    if (!addr.can_ifindex)
    {
        (void)fprintf(stderr, "Failed to find CAN interface %s: %s\n", interface, strerror(errno));
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        (void)fprintf(stderr, "Failed to bind to interface %s: %s\n", interface, strerror(errno));
        close(fd);
        return -1;
    }

    return fd;
}

static void can_tp_deinit(int fd)
{
    if (fd >= 0)
    {
        close(fd);
    }
}

static int can_tp_receive(int fd, uint8_t *buffer, size_t *size)
{
    ssize_t ret = 0;

    if (fd < 0)
    {
        return -1;
    }

    ret = read(fd, buffer, *size);
    if (ret >= 0)
    {
        *size = ret;
    }

    return (ret < 0) ? -1 : 0;
}

static int can_tp_send(int fd, const uint8_t *buffer, size_t *size)
{
    ssize_t ret = 0;

    if (fd < 0)
    {
        return -1;
    }

    ret = write(fd, buffer, *size);
    if (ret >= 0)
    {
        *size = ret;
    }

    return (ret < 0) ? -1 : 0;
}

static int timer_init(long microseconds)
{
    const struct itimerspec timer = {
        {.tv_sec = (microseconds / 1000000), .tv_nsec = (microseconds % 1000000) * 1000},
        {.tv_sec = (microseconds / 1000000), .tv_nsec = (microseconds % 1000000) * 1000},
    };
    int fd;

    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0)
    {
        (void)fprintf(stderr, "Failed to create timer: %s\n", strerror(errno));
    }
    else if (timerfd_settime(fd, 0, &timer, NULL))
    {
        (void)fprintf(stderr, "Failed to setup timer: %s\n", strerror(errno));
        close(fd);
        fd = -1;
    }

    return fd;
}

static void timer_deinit(int fd)
{
    if (fd >= 0)
    {
        close(fd);
    }
}

static int timer_reset(int fd)
{
    uint64_t expirations;
    int ret = -1;

    if (read(fd, &expirations, sizeof(expirations)) < (ssize_t)sizeof(expirations))
    {
        (void)fprintf(stderr, "Failed to reset timer: %s\n", strerror(errno));
    }
    else
    {
        ret = 0;
    }

    return ret;
}

static int signal_management_handle(uint32_t signo, bool *terminate)
{
    int ret;

    switch (signo)
    {
    case SIGTERM:
        *terminate = true;
        ret = 0;
        break;

    default:
        (void)fprintf(stderr, "Unhandled signal %u\n", signo);
        ret = -1;
        break;
    }

    return ret;
}

static int signal_management_init(void)
{
    sigset_t sigset;
    int fd = -1;

    if ((sigemptyset(&sigset) < 0) || (sigaddset(&sigset, SIGTERM) < 0) ||
        (sigaddset(&sigset, SIGUSR1) < 0))
    {
        (void)fprintf(stderr, "Failed to fill sigset: %s\n", strerror(errno));
    }
    else
    {
        fd = signalfd(-1, &sigset, O_NONBLOCK | SFD_CLOEXEC);
        if (fd < 0)
        {
            (void)fprintf(stderr, "Failed to create signalfd: %s\n", strerror(errno));
        }
        else if (sigprocmask(SIG_SETMASK, &sigset, NULL) < 0)
        {
            (void)fprintf(stderr, "Failed to set signal mask: %s\n", strerror(errno));
        }
    }

    return fd;
}

static void signal_management_deinit(int fd)
{
    if (fd >= 0)
    {
        close(fd);
    }
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [-h] [-c <interface>]\n", prog);
    printf("    -c <interface>   : CAN interface to use (default: can0)\n");
    printf("    -h               : show this help and exit\n");
}

static const uds_session_cfg_t uds_sessions[] = {
    {
        .session_type = 0x01, // Default Session
        .sa_type_mask = UDS_CFG_SA_TYPE_ALL,
        .p2_timeout_ms = 50,
        .p2star_timeout_ms = 1000,
    },
    {
        .session_type = 0x02, // Programming Session
        .sa_type_mask = UDS_CFG_SA_TYPE_ALL,
        .s3_timeout_ms = 5000,
        .p2_timeout_ms = 65535,
        .p2star_timeout_ms = 65535,
    },
    {
        .session_type = 0x03, // Extended Diagnostic Session
        .sa_type_mask = UDS_CFG_SA_TYPE_ALL,
        .s3_timeout_ms = 5000,
        .p2_timeout_ms = 500,
        .p2star_timeout_ms = 1000,
    },
    {
        .session_type = 0x04, // Safety System Diagnostic Session
        .sa_type_mask = UDS_CFG_SA_TYPE_ALL,
        .p2_timeout_ms = 50,
        .p2star_timeout_ms = 1000,
    },
};

static uds_err_e uds_send_callback(void *priv, const uint8_t data[], size_t len)
{
    struct private_data *private_data = (struct private_data *)priv;
    size_t int_len = len;
    uds_err_e err;

    if ((can_tp_send(private_data->fd_can_tp_phys, data, &int_len) != 0) || (int_len < len))
    {
        err = UDS_ERR_GENERIC;
    }
    else
    {
        err = UDS_NO_ERROR;
    }

    return err;
}

static uds_err_e sa_request_seed(void *priv, const uint8_t sa_index, const uint8_t in_data[],
                                 size_t in_data_len, uint8_t out_seed[], size_t *out_seed_len)
{
    (void)priv;
    (void)sa_index;
    (void)in_data;
    (void)in_data_len;
    (void)sa_index;

    out_seed[0] = 0xAA;
    out_seed[1] = 0xDE;
    *out_seed_len = 2;

    return 0;
}

static uds_err_e sa_validate_key(void *priv, const uint8_t sa_index, const uint8_t key[],
                                 size_t key_len)
{
    (void)priv;
    (void)sa_index;
    (void)key;
    (void)key_len;

    return 0;
}

static const uds_sa_cfg_t sas[] = {
    {
        .sa_index = 0,
        .cb_request_seed = sa_request_seed,
        .cb_validate_key = sa_validate_key,
    }
};

static uds_err_e data_read(void *priv, uint16_t identifier, const uint8_t *in_data,
                           const size_t in_data_len, size_t *in_data_used_len,
                           uint8_t *out_data, size_t *out_data_len)
{
    struct private_data *private_data = (struct private_data *)priv;
    int ret = -1;

    (void)in_data;
    (void)in_data_len;
    (void)in_data_used_len;

    switch (identifier)
    {
    case 0xF190:
        if (*out_data_len >= 17)
        {
            memcpy(out_data, private_data->data.vin, 17);
            ret = 0;
        }
        *out_data_len = 17;
        break;

    default:
        break;
    }

    return ret;
}

static uds_err_e data_write(void *priv, uint16_t identifier, const uint8_t *data, const size_t len)
{
    struct private_data *private_data = (struct private_data *)priv;
    int ret = -1;

    switch (identifier)
    {
    case 0xF190:
        if (len == 17)
        {
            memcpy(private_data->data.vin, data, 17);
            ret = 0;
        }
        break;

    default:
        break;
    }

    return ret;
}

static const uds_config_data_t data_items[] = {
    {
        .identifier = 0xF190,

        .cb_read = data_read,
        .sec_read.sa_type_mask = UDS_CFG_SA_TYPE_NONE,
        .sec_read.standard_session_mask = UDS_CFG_SESSION_MASK_ALL,
        .sec_read.specific_session_mask = UDS_CFG_SESSION_MASK_ALL,

        .cb_write = data_write,
        .sec_write.sa_type_mask = UDS_CFG_SA_TYPE(0),
        .sec_write.standard_session_mask = UDS_CFG_SESSION_MASK(3),
        .sec_write.specific_session_mask = UDS_CFG_SESSION_MASK_NONE,
    }
};

static uds_err_e mem_region_read(void *priv, const uintptr_t address, uint8_t *data,
                                 const size_t data_len)
{
    (void)priv;
    (void)address;
    (void)data;
    (void)data_len;

    return 0;
}

static uds_err_e mem_region_write(void *priv, const uintptr_t address, const uint8_t *data,
                                  const size_t data_len)
{
    (void)priv;
    (void)address;
    (void)data;
    (void)data_len;

    return 0;
}

static uds_err_e mem_region_download_request(void *priv, const uintptr_t address, const size_t data_len,
                                             const uint8_t compression_method,
                                             const uint8_t encrypting_method)
{
    (void)priv;
    (void)address;
    (void)data_len;
    (void)compression_method;
    (void)encrypting_method;

    return 0;
}

static uds_err_e mem_region_download(void *priv, const uintptr_t address, const uint8_t *data,
                                     const size_t data_len)
{
    (void)priv;
    (void)address;
    (void)data;
    (void)data_len;

    return 0;
}

static uds_err_e mem_region_download_exit(void *priv)
{
    (void)priv;

    return 0;
}

static const uds_config_memory_region_t mem_regions[] = {
    {
        .start = 0x00000000U,
        .stop  = 0x00100000U,

        .cb_read = mem_region_read,
        .sec_read.sa_type_mask = UDS_CFG_SA_TYPE_NONE,
        .sec_read.standard_session_mask = UDS_CFG_SESSION_MASK(0x02),

        .cb_write = mem_region_write,
        .sec_write.sa_type_mask = UDS_CFG_SA_TYPE_NONE,
        .sec_write.standard_session_mask = UDS_CFG_SESSION_MASK(0x02),

        .cb_download_request = mem_region_download_request,
        .cb_download         = mem_region_download,
        .cb_download_exit    = mem_region_download_exit,
        .sec_download.sa_type_mask = UDS_CFG_SA_TYPE_NONE,
        .sec_download.standard_session_mask = UDS_CFG_SESSION_MASK(0x02),

        .max_block_len = 512,
    }
};

static char buf_path[4096];
static size_t cur_offset = 0;

static uds_err_e file_transfer_open(void *priv, const char *filepath, size_t filepath_len,
                                    uds_file_mode_e mode, intptr_t *fd, size_t *file_size,
                                    size_t *file_size_compressed, const uint8_t compression_method,
                                    const uint8_t encrypting_method)
{
    int tmp_fd = -1;
    int ret = 0;

    (void)priv;
    (void)compression_method;
    (void)encrypting_method;

    memcpy(buf_path, filepath, filepath_len);
    buf_path[filepath_len] = '\0';

    if (mode == UDS_FILE_MODE_READ)
    {
        tmp_fd = open(buf_path, O_RDONLY);
        if (tmp_fd >= 0)
        {
            struct stat st;
            ret = fstat(tmp_fd, &st);
            if (ret < 0)
            {
                close(tmp_fd);
                tmp_fd = -1;
            }
            else
            {
                *file_size = st.st_size;
                *file_size_compressed = st.st_size;
            }
        }
    }
    else if (mode == UDS_FILE_MODE_WRITE_CREATE)
    {
        tmp_fd = open(buf_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    }
    else if (mode == UDS_FILE_MODE_WRITE_REPLACE)
    {
        tmp_fd = open(buf_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    }
    else if (mode == UDS_FILE_MODE_LIST_DIR)
    {
        tmp_fd = open(buf_path, O_RDONLY);
    }

    if (tmp_fd < 0)
    {
        ret = -1;
    }
    else
    {
        *fd = (intptr_t)tmp_fd;

        cur_offset = 0;
    }

    return ret;
}

static uds_err_e file_transfer_list(void *priv, intptr_t fd, size_t offset, void *buf,
                                    size_t *count)
{
    int ret = 0;

    (void)priv;
    (void)fd;
    (void)offset;
    (void)buf;
    (void)count;

    return ret;
}

static uds_err_e file_transfer_read(void *priv, intptr_t fd, size_t offset, void *buf,
                                    size_t *count)
{
    ssize_t ret = 0;

    (void)priv;

    if (cur_offset != offset)
    {
        ret = lseek((int)fd, (off_t)offset, SEEK_SET);
    }

    if (ret == 0)
    {
        ret = read((int)fd, buf, *count);
        if (ret > 0)
        {
            *count = ret;
            cur_offset = (offset + *count);
            ret = 0;
        }
    }

    return ret;
}

static uds_err_e file_transfer_write(void *priv, intptr_t fd, size_t offset, const void *buf,
                                     size_t count)
{
    ssize_t ret = 0;

    (void)priv;

    if (cur_offset != offset)
    {
        ret = lseek((int)fd, (off_t)offset, SEEK_SET);
    }

    if (ret == 0)
    {
        ret = write((int)fd, buf, count);
        if (ret == (ssize_t)count)
        {
            cur_offset = (offset + count);
            ret = 0;
        }
    }

    return ret;
}

static uds_err_e file_transfer_close(void *priv, uds_file_mode_e mode, intptr_t fd)
{
    int ret = 0;

    (void)priv;

    if (mode == UDS_FILE_MODE_LIST_DIR)
    {
        ret = closedir(fdopendir((int)fd));
    }
    else
    {
        ret = close((int)fd);
    }

    return ret;
}

static uds_err_e file_transfer_delete(void *priv, const char *filepath, size_t filepath_len)
{
    (void)priv;

    memcpy(buf_path, filepath, filepath_len);
    buf_path[filepath_len] = '\0';

    return unlink(buf_path);
}

static uds_loglevel_e current_loglevel = UDS_LOGLVL_WARNING;

static void log_function(void *priv, uds_loglevel_e level, const char *message, const char *arg_name,
                         uint64_t arg)
{
    (void)priv;

    if (level >= current_loglevel)
    {
        static const char * loglevel_names[] = {
            [UDS_LOGLVL_ERR]        = "ERROR",
            [UDS_LOGLVL_WARNING]    = "WARNG",
            [UDS_LOGLVL_INFO]       = "INFO ",
            [UDS_LOGLVL_DEBUG]      = "DEBUG",
            [UDS_LOGLVL_TRACE]      = "TRACE",
        };

        const char * loglevel_name  = "UNKNW";

        if (level <= UDS_LOGLVL_TRACE)
        {
            loglevel_name = loglevel_names[level];
        }

        if (arg_name != NULL)
        {
            printf("uds[%s]: %s (%s = 0x%"PRIX64")\n", loglevel_name, message, arg_name, arg);
        }
        else
        {
            printf("uds[%s]: %s\n", loglevel_name, message);
        }
    }
}

static const uds_config_t uds_config = {
    .log_func = log_function,

    .session_config = uds_sessions,
    .num_session_config = sizeof(uds_sessions) / sizeof(uds_session_cfg_t),

    .sa_config = sas,
    .num_sa_config = sizeof(sas) / sizeof(uds_sa_cfg_t),
    .sa_max_attempts = 5,
    .sa_delay_timer_ms = 3000,

    .cb_send = uds_send_callback,

    .data_items = data_items,
    .num_data_items = sizeof(data_items) / sizeof(uds_config_data_t),

    .mem_regions = mem_regions,
    .num_mem_regions = sizeof(mem_regions) / sizeof(uds_config_memory_region_t),

    .file_transfer = {
        .cb_open = file_transfer_open,
        .cb_list = file_transfer_list,
        .cb_read = file_transfer_read,
        .cb_write = file_transfer_write,
        .cb_close = file_transfer_close,
        .cb_delete = file_transfer_delete,
        .sec.sa_type_mask = UDS_CFG_SA_TYPE_NONE,
        .sec.standard_session_mask = UDS_CFG_SESSION_MASK(0x02),
        .max_block_len = 512,
    },

    .dtc_information = {
        .format_identifier = UDS_DTC_FORMAT_ISO_14229_1,
    },
};

static int gettime_uds(uds_time_t *now)
{
    struct timespec now_ts;
    int ret;

    ret = clock_gettime(CLOCK_MONOTONIC, &now_ts);
    if (ret == 0)
    {
        now->seconds = now_ts.tv_sec;
        now->microseconds = ((now_ts.tv_nsec + 500UL) / 1000UL);
    }

    return ret;
}

int main(int argc, char *argv[])
{
    const char *can_iface = "vcan0";

    uds_context_t uds_ctx;
    uint8_t uds_buffer[4095];

    int fd_timer_uds = -1;
    int fd_signals = -1;

    struct private_data private_data = {
        .data = {
            .vin = "0123456789ABCDEF_"
        }
    };

    struct epoll_event events[6];
    int epollfd = -1;

    unsigned char can_tp_phys_buf[5000];
    unsigned char can_tp_func_buf[5000];

    uds_time_t now;

    bool run = true;
    int i;
    uds_err_e err;

    // Parse command line arguments
    while ((i = getopt(argc, argv, "c:hl:")) >= 0)
    {
        switch (i)
        {
        case 'c':
            can_iface = optarg;
            break;

        case 'h':
            print_usage(argv[0]);
            return 0;

        case 'l':
            current_loglevel = strtoul(optarg, NULL, 10);
            if (current_loglevel > UDS_LOGLVL_TRACE)
            {
                current_loglevel = UDS_LOGLVL_TRACE;
            }
            break;

        default:
            print_usage(argv[0]);
            return -1;
        }
    }

    if (gettime_uds(&now) != 0)
    {
        (void)fprintf(stderr, "gettime failed: %s\n", strerror(errno));
        return -1;
    }

    // Intialize UDS library
    err = uds_init(&uds_ctx, &uds_config, uds_buffer, sizeof(uds_buffer), &private_data, &now);
    if (err != UDS_NO_ERROR)
    {
        (void)fprintf(stderr, "Failed to initialize UDS library\n");
        return -1;
    }

    uds_reset_sa_delay_timer(&uds_ctx);

    // Create poller
    epollfd = epoll_create1(0);
    if (epollfd == -1)
    {
        (void)fprintf(stderr, "Cannot create epoll: %s\n", strerror(errno));
        return -1;
    }

    // Init signal listener fd
    fd_signals = signal_management_init();
    if (fd_signals < 0)
    {
        (void)fprintf(stderr, "Failed to init signal management\n");
    }
    else
    {
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = fd_signals;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd_signals, &ev) == -1)
        {
            (void)fprintf(stderr, "Cannot add signalfd to epoll: %s\n", strerror(errno));
        }
    }

    // Create timer for UDS library
    fd_timer_uds = timer_init(MS_TO_US(50));
    if (fd_timer_uds < 0)
    {
        (void)fprintf(stderr, "Failed to init timer for UDS\n");
    }
    else
    {
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = fd_timer_uds;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd_timer_uds, &ev) == -1)
        {
            (void)fprintf(stderr, "Cannot add UDS timer to epoll: %s\n", strerror(errno));
        }
    }

    // Init ISOTP functional socket and add it to poller
    private_data.fd_can_tp_func = can_tp_init(can_iface, can_tp_func_rx_id, 0, true);
    if (private_data.fd_can_tp_func < 0)
    {
        (void)fprintf(stderr, "Failed to init CAN-ISOTP FUNC\n");
    }
    else
    {
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = private_data.fd_can_tp_func;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, private_data.fd_can_tp_func, &ev) == -1)
        {
            (void)fprintf(stderr, "Cannot add CAN-ISOTP FUNC to epoll: %s\n", strerror(errno));
        }
    }

    // Init ISOTP physical socket and add it to poller
    private_data.fd_can_tp_phys = can_tp_init(can_iface, can_tp_phys_rx_id,
                                              can_tp_phys_tx_id, true);
    if (private_data.fd_can_tp_phys < 0)
    {
        (void)fprintf(stderr, "Failed to init CAN-ISOTP PHYS\n");
    }
    else
    {
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = private_data.fd_can_tp_phys;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, private_data.fd_can_tp_phys, &ev) == -1)
        {
            (void)fprintf(stderr, "Cannot add CAN-ISOTP PHYS to epoll: %s\n", strerror(errno));
        }
    }

    (void)fprintf(stderr, "Start event loop...\n");
    while (run)
    {
        int nfds;

        errno = 0;
        nfds = epoll_wait(epollfd, events, sizeof(events) / sizeof(events[0]), -1);
        if ((nfds == -1) && (errno != EINTR))
        {
            (void)fprintf(stderr, "Error on epoll_wait: %s\n", strerror(errno));
        }
        else if ((nfds == -1) && (errno == EINTR))
        {
            (void)fprintf(stderr, "epoll_wait interrupted by signal\n");
        }
        else if (gettime_uds(&now) != 0)
        {
            (void)fprintf(stderr, "gettime failed: %s\n", strerror(errno));
        }

        // Process events
        for (int n = 0; n < nfds; ++n)
        {
            const int triggered_fd = events[n].data.fd;

            if (triggered_fd < 0)
            {
                (void)fprintf(stderr, "Invalid triggered FD\n");
                continue;
            }
            else if (triggered_fd == fd_signals)
            {
                struct signalfd_siginfo siginfo;
                bool term_req = false;

                if (read(fd_signals, &siginfo, sizeof(siginfo)) < (ssize_t)sizeof(siginfo))
                {
                    (void)fprintf(stderr, "Error reading signalfd: %s\n", strerror(errno));
                }
                else if (signal_management_handle(siginfo.ssi_signo, &term_req) < 0)
                {
                    (void)fprintf(stderr, "Failed to handle signal %u\n", siginfo.ssi_signo);
                }

                if (term_req)
                {
                    (void)fprintf(stderr, "Request to terminate execution\n");
                    run = false;
                    break;
                }
            }
            // Ready to receive CAN frames
            else if (triggered_fd == private_data.fd_can_tp_phys)
            {
                size_t size = sizeof(can_tp_phys_buf);
                if (can_tp_receive(private_data.fd_can_tp_phys, can_tp_phys_buf, &size) == 0)
                {
                    if (uds_receive(&uds_ctx, UDS_ADDRESS_PHYSICAL, can_tp_phys_buf, size,
                                    &now) != UDS_NO_ERROR)
                    {
                        (void)fprintf(stderr, "Failed to send to CAN-ISOTP\n");
                    }
                }
                else
                {
                    (void)fprintf(stderr, "Failed to receive from PHYS CAN-ISOTP: %s\n", strerror(errno));
                }
            }
            else if (triggered_fd == private_data.fd_can_tp_func)
            {
                size_t size = sizeof(can_tp_func_buf);
                if (can_tp_receive(private_data.fd_can_tp_func, can_tp_func_buf, &size) == 0)
                {
                    if (uds_receive(&uds_ctx, UDS_ADDRESS_FUNCTIONAL, can_tp_func_buf, size,
                                    &now) != UDS_NO_ERROR)
                    {
                        (void)fprintf(stderr, "Failed to send to CAN-ISOTP\n");
                    }
                }
                else
                {
                    (void)fprintf(stderr, "Failed to receive from FUNC CAN-ISOTP: %s\n", strerror(errno));
                }
            }
            else if (triggered_fd == fd_timer_uds)
            {
                timer_reset(fd_timer_uds);
                uds_cycle(&uds_ctx, &now);
            }
        }
    }

    (void)fprintf(stderr, "Exiting...\n");

    close(epollfd);

    signal_management_deinit(fd_signals);

    can_tp_deinit(private_data.fd_can_tp_func);
    can_tp_deinit(private_data.fd_can_tp_phys);

    timer_deinit(fd_timer_uds);

    return 0;
}
