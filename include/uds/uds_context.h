/* SPDX-License-Identifier: MIT */
/**
 * \file uds_context.h
 *
 * Type definition for libuds context.
 *
 * This header contains the definition of the context data used by libuds.
 * All types and definitions present in this file shall be treated as opaque.
 *
 * \author Francesco Valla <francesco@valla.it>
 * \copyright (c) 2022-2024 Francesco Valla - License: MIT
 */

#ifndef UDS_CONTEXT_H__
#define UDS_CONTEXT_H__

#include <stddef.h>
#include <stdint.h>

#include <uds/uds_config.h>
#include <uds/uds_types.h>

typedef enum
{
    UDS_DATA_TRANSFER_NONE,
    UDS_DATA_TRANSFER_DOWNLOAD,
    UDS_DATA_TRANSFER_UPLOAD,
    UDS_DATA_TRANSFER_DOWNLOAD_FILE,
    UDS_DATA_TRANSFER_UPLOAD_FILE,
    UDS_DATA_TRANSFER_LIST_DIR,
} uds_data_transfer_dir_e;

typedef struct
{
    const uds_config_t *config;
    void *priv;

    uds_time_t last_message_timestamp;

    const uds_session_cfg_t *current_session;
    uint8_t current_sa_seed;
    const uds_sa_cfg_t *current_sa;
    uint16_t sa_failed_attempts;
    uds_time_t sa_delay_timer_timestamp;

    struct
    {
        struct
        {
            uint8_t pdid;
            uint8_t transmission_mode;
        } data[UDS_CONFIG_NUM_PERIODIC_SLOTS];
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
