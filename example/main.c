
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
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
#include <sys/timerfd.h>
#include <sys/un.h>

#include "uds.h"

#define MS_TO_US(ms) (ms*1000UL)

struct private_data {
    int fd_can_tp_phys;
    int fd_can_tp_func;
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

    fd = socket(PF_CAN, SOCK_DGRAM, CAN_ISOTP);
    if (fd < 0)
    {
        fprintf(stderr, "Failed to create CAN_ISOTP socket: %s\n", strerror(errno));
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
    addr.can_ifindex = if_nametoindex(interface);
    if (!addr.can_ifindex) {
        fprintf(stderr, "Failed to find CAN interface %s: %s\n", interface, strerror(errno));
        close(fd);
        return -1;
    }

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
    {
        fprintf(stderr, "Failed to bind to interface %s: %s\n", interface, strerror(errno));
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

static int can_tp_receive(int fd, void *buffer, size_t *size)
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

static int can_tp_send(int fd, void *buffer, size_t *size)
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
        { .tv_sec = (microseconds / 1000000), .tv_nsec = (microseconds % 1000000) * 1000 },
        { .tv_sec = (microseconds / 1000000), .tv_nsec = (microseconds % 1000000) * 1000 },
    };
    int fd;

    fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    if (fd < 0)
    {
        fprintf(stderr, "Failed to create timer: %s\n", strerror(errno));
    }
    else if (timerfd_settime(fd, 0, &timer, NULL))
    {
        fprintf(stderr, "Failed to setup timer: %s\n", strerror(errno));
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
        fprintf(stderr, "Failed to reset timer: %s\n", strerror(errno));
    }
    else if (expirations > 0x1FFFFFFF)
    {
        ret = 0x1FFFFFFF;
    }
    else
    {
        ret = (expirations & INT32_MAX);
    }

    return ret;
}

static int __attribute__((unused)) timer_reset_modify(int fd, long microseconds)
{
    const struct itimerspec timer = {
        { .tv_sec = (microseconds / 1000000), .tv_nsec = (microseconds % 1000000) * 1000 },
        { .tv_sec = (microseconds / 1000000), .tv_nsec = (microseconds % 1000000) * 1000 },
    };
    int ret;

    timer_reset(fd);

    ret = timerfd_settime(fd, 0, &timer, NULL);
    if (ret != 0)
    {
        fprintf(stderr, "Failed to modify timer: %s\n", strerror(errno));
    }

    return ret;
}

static int signal_management_handle(int signo, bool *terminate)
{
    switch (signo)
    {
    case SIGTERM:
        *terminate = true;
        break;

    default:
        fprintf(stderr, "Unhandled signal %d\n", signo);
        break;
    }

    return 0;
}

static int signal_management_init(void)
{
    sigset_t sigset;
    int fd = -1;

    if ((sigemptyset(&sigset) < 0) ||
        (sigaddset(&sigset, SIGTERM) < 0) ||
        (sigaddset(&sigset, SIGUSR1) < 0))
    {
        fprintf(stderr, "Failed to fill sigset: %s\n", strerror(errno));
    }
    else
    {
        fd = signalfd(-1, &sigset, O_NONBLOCK | SFD_CLOEXEC);
        if (fd < 0)
        {
            fprintf(stderr, "Failed to create signalfd: %s\n", strerror(errno));
        }
        else if (sigprocmask(SIG_SETMASK, &sigset, NULL) < 0)
        {
            fprintf(stderr, "Failed to set signal mask: %s\n", strerror(errno));
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

static const struct option lopts[] =
{
    { "can",            1, 0, 'c' },
    { NULL,             0, 0,  0  },
};

static void print_usage(const char *prog)
{
    printf("Usage: %s [-dh] [-c <interface>] [-m <num>]\n", prog);
    printf("    -c,--can <interface>   : can interface to use (default: can0)\n");
    printf("    -h,--help              : show this help and exit\n");
}

static const uds_session_cfg_t uds_sessions[] =
{
    {
        .session_type = 0x01, // Default Session
        .sa_type_mask = UDS_CFG_SA_TYPE_ALL,
    },
    {
        .session_type = 0x02, // Programming Session
        .sa_type_mask = UDS_CFG_SA_TYPE_ALL,
    },
    {
        .session_type = 0x03, // Extended Diagnostic Session
        .sa_type_mask = UDS_CFG_SA_TYPE_ALL,
    },
    {
        .session_type = 0x04, // Safety System Diagnostic Session
        .sa_type_mask = UDS_CFG_SA_TYPE_ALL,
    },
};

static int uds_send_callback(void *priv, const uint8_t data[], size_t len)
{
    struct private_data * private_data = (struct private_data *)priv;
    size_t int_len = len;
    int ret;

    ret = can_tp_send(private_data->fd_can_tp_phys, (void *)data, &int_len);

    return ret;
}

static int sa_request_seed(void *priv, const uint8_t sa_index,
                           const uint8_t in_data[], size_t in_data_len,
                           uint8_t out_seed[], size_t *out_seed_len)
{
    out_seed[0] = 0xAA;
    out_seed[1] = 0xDE;
    *out_seed_len = 2;
    return 0;
}

static int sa_validate_key(void *priv, const uint8_t sa_index,
                           const uint8_t key[], size_t key_len)
{
    return 0;
}

static const uds_sa_cfg_t sas[] =
{
    {
        .sa_index = 0,
        .request_seed = sa_request_seed,
        .validate_key = sa_validate_key,
    }
};

static const uds_config_t uds_config =
{
    .p2 = 250,
    .p2max = 2000,

    .session_config = uds_sessions,
    .num_session_config = sizeof(uds_sessions) / sizeof(uds_session_cfg_t),

    .sa_config = sas,
    .num_sa_config = sizeof(sas) / sizeof(uds_sa_cfg_t),

    .cb_send = uds_send_callback,
};

int main(int argc, char *argv[])
{
    const char *can_iface = "vcan0";

    uint32_t v_tmp[4];

    uds_context_t uds_ctx;

    int fd_timer_uds = -1;
    int fd_signals = -1;

    struct private_data private_data;

    struct epoll_event events[6];
    int epollfd = -1;

    unsigned char can_tp_phys_buf[5000];
    unsigned char can_tp_func_buf[5000];

    bool run = true;
    int i = 0;
    int ret;

    // Parse command line arguments
    while ((i = getopt_long(argc, argv, "c:h", lopts, NULL)) >= 0)
    {
        switch (i)
        {
        case 'c':
            can_iface = optarg;
            break;

        case 'h':
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;

        default:
            print_usage(argv[0]);
            exit(EXIT_FAILURE);
            break;
        }
    }

    // Intialize UDS library
    uds_init(&uds_ctx, &uds_config, &private_data);

    // Create poller
    epollfd = epoll_create1(0);
    if (epollfd == -1)
    {
        fprintf(stderr, "Cannot create epoll: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Init signal listener fd
    fd_signals = signal_management_init();
    if (fd_signals < 0)
    {
        fprintf(stderr, "Failed to init signal management\n");
    }
    else
    {
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = fd_signals;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd_signals, &ev) == -1)
        {
            fprintf(stderr, "Cannot add signalfd to epoll: %s\n", strerror(errno));
        }
    }

    // Create timer for ISO-TP module
    fd_timer_uds = timer_init(MS_TO_US(50));
    if (fd_timer_uds < 0)
    {
        fprintf(stderr, "Failed to init timer for ISO-TP\n");
    }
    else
    {
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = fd_timer_uds;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, fd_timer_uds, &ev) == -1)
        {
            fprintf(stderr, "Cannot add ISO-TP timer to epoll: %s\n", strerror(errno));
        }
    }

    // Init ISOTP functional socket and add it to poller
    private_data.fd_can_tp_func = can_tp_init(can_iface, can_tp_func_rx_id, 0, true);
    if (private_data.fd_can_tp_func < 0)
    {
        fprintf(stderr, "Failed to init CAN-ISOTP FUNC\n");
    }
    else
    {
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = private_data.fd_can_tp_func;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, private_data.fd_can_tp_func, &ev) == -1)
        {
            fprintf(stderr, "Cannot add CAN-ISOTP FUNC to epoll: %s\n", strerror(errno));
        }
    }

    // Init ISOTP physical socket and add it to poller
    private_data.fd_can_tp_phys = can_tp_init(can_iface, can_tp_phys_rx_id, can_tp_phys_tx_id, true);
    if (private_data.fd_can_tp_phys < 0)
    {
        fprintf(stderr, "Failed to init CAN-ISOTP PHYS\n");
    }
    else
    {
        struct epoll_event ev;
        ev.events = EPOLLIN;
        ev.data.fd = private_data.fd_can_tp_phys;
        if (epoll_ctl(epollfd, EPOLL_CTL_ADD, private_data.fd_can_tp_phys, &ev) == -1)
        {
            fprintf(stderr, "Cannot add CAN-ISOTP PHYS to epoll: %s\n", strerror(errno));
        }
    }

    fprintf(stderr, "Start event loop...\n");
    while (run)
    {
        int nfds;

        nfds = epoll_wait(epollfd, events, sizeof(events) / sizeof(events[0]), -1);
        if ((nfds == -1) && (errno != EINTR))
        {
            fprintf(stderr, "Error on epoll_wait: %s\n", strerror(errno));
        }
        else if ((nfds == -1) && (errno == EINTR))
        {
            fprintf(stderr, "epoll_wait interrupted by signal\n");
        }

        // Process events
        for (int n = 0; n < nfds; ++n)
        {
            const int triggered_fd = events[n].data.fd;

            if (triggered_fd < 0)
            {
                fprintf(stderr, "Invalid triggered FD\n");
                continue;
            }
            else if (triggered_fd == fd_signals)
            {
                struct signalfd_siginfo siginfo;
                bool term_req = false;

                if (read(fd_signals, &siginfo, sizeof(siginfo)) < (ssize_t)sizeof(siginfo))
                {
                    fprintf(stderr, "Error reading signalfd: %s\n", strerror(errno));
                }
                else if (signal_management_handle(siginfo.ssi_signo, &term_req) < 0)
                {
                    fprintf(stderr, "Failed to handle signal %u\n", siginfo.ssi_signo);
                }

                if (term_req)
                {
                    fprintf(stderr, "Request to terminate execution\n");
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
                    if (uds_receive(&uds_ctx, UDS_ADDRESS_PHYSICAL, can_tp_phys_buf, size) != 0)
                    {
                        fprintf(stderr, "Failed to send to CAN-ISOTP\n");
                    }
                }
                else
                {
                    fprintf(stderr, "Failed to receive from PHYS CAN-ISOTP: %s\n", strerror(errno));
                }
            }
            else if (triggered_fd == private_data.fd_can_tp_func)
            {
                size_t size = sizeof(can_tp_func_buf);
                if (can_tp_receive(private_data.fd_can_tp_func, can_tp_func_buf, &size) == 0)
                {
                    if (uds_receive(&uds_ctx, UDS_ADDRESS_FUNCTIONAL, can_tp_func_buf, size) != 0)
                    {
                        fprintf(stderr, "Failed to send to CAN-ISOTP\n");
                    }
                }
                else
                {
                    fprintf(stderr, "Failed to receive from FUNC CAN-ISOTP: %s\n", strerror(errno));
                }
            }
            else if (triggered_fd == fd_timer_uds)
            {
                timer_reset(fd_timer_uds);
                uds_cycle(&uds_ctx);
            }
        }
    }

    fprintf(stderr, "Exiting...\n");

    return 0;
}