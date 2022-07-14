
#ifndef UDS_CONTEXT_H__
#define UDS_CONTEXT_H__

#include <stddef.h>
#include <stdint.h>

#include <uds.h>
#include <uds_config.h>

typedef enum __uds_data_transfer_dir
{
    UDS_DATA_TRANSFER_NONE,
    UDS_DATA_TRANSFER_DOWNLOAD,
    UDS_DATA_TRANSFER_UPLOAD,
    UDS_DATA_TRANSFER_DOWNLOAD_FILE,
    UDS_DATA_TRANSFER_UPLOAD_FILE,
    UDS_DATA_TRANSFER_LIST_DIR,
} uds_data_transfer_dir_e;

typedef struct __uds_context
{
    const uds_config_t *config;
    void *priv;

    struct timespec last_message_timestamp;

    unsigned int loglevel;
    const uds_session_cfg_t *current_session;
    uint8_t current_sa_seed;
    const uds_sa_cfg_t *current_sa;
    unsigned long sa_failed_attempts;
    struct timespec sa_delay_timer_timestamp;

    struct
    {
        struct
        {
            uint8_t pdid;
            uint8_t transmission_mode;
        } data[UDS_CONFIG_NUM_PERIODIC_SLOTS];
        int last_data;
    } periodic;

    struct
    {
        uint8_t mode_verified;
    } link_control;

    struct
    {
        uds_data_transfer_dir_e direction;
        uds_file_mode_e file_mode;
        const uds_config_memory_region_t *mem_region;
        size_t max_block_len;
        uint8_t bsqc;
        uintptr_t prev_address;
        uintptr_t address;
        intptr_t fd;
    } data_transfer;

    uint8_t *response_buffer;
    size_t response_buffer_len;
} uds_context_t;

#endif // UDS_CONTEXT_H__
