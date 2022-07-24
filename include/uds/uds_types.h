/* SPDX-License-Identifier: GPL-3.0-only */
/**
 * \file uds_types.h
 *
 * Custom types defined and used by libuds.
 *
 * This header defines several custom types and enumerations used by libuds.
 *
 * \author Francesco Valla <valla.francesco@gmail.com>
 * \copyright (c) 2022 Francesco Valla - License: GPL-3.0-only
 */

#ifndef UDS_TYPES_H__
#define UDS_TYPES_H__

#include <stddef.h>
#include <stdint.h>

#define UDS_CFG_SA_TYPE_NONE      (0x0000000000000000UL)
#define UDS_CFG_SA_TYPE_ALL       (0xFFFFFFFFFFFFFFFFUL)
#define UDS_CFG_SA_TYPE(x)        (0x0000000000000001UL << (x))

#define UDS_CFG_SESSION_MASK_NONE (0x0000000000000000UL)
#define UDS_CFG_SESSION_MASK_ALL  (0xFFFFFFFFFFFFFFFFUL)
#define UDS_CFG_SESSION_MASK(x)   (0x0000000000000001UL << (x))

typedef enum
{
    UDS_CCACT_EN_RX_EN_TX = 0x00,
    UDS_CCACT_EN_RX_DIS_TX = 0x01,
    UDS_CCACT_DIS_RX_EN_TX = 0x02,
    UDS_CCACT_DIS_RX_DIS_TX = 0x03,
    UDS_CCACT_EN_RX_DIS_TX_EAI = 0x04,
    UDS_CCACT_EN_RX_EN_TX_EAI = 0x05,
} uds_cc_action_e;

typedef enum
{
    UDS_CCMT_NONE = 0x00,
    UDS_CCMT_NORMAL = 0x01,
    UDS_CCMT_NETWORK_MANAGEMENT = 0x02,
    UDS_CCMT_NETWORK_MANAGEMENT_AND_NORMAL = 0x03,
} uds_cc_message_type_e;

typedef enum
{
    UDS_IOCP_RETURN_CONTROL_TO_ECU = 0x00,
    UDS_IOCP_RESET_TO_DEFAULT = 0x01,
    UDS_IOCP_FREEZE_CURRENT_STATE = 0x02,
    UDS_IOCP_SHORT_TERM_ADJUSTMENT = 0x03,
} uds_iocp_e;

typedef enum
{
    UDS_DTC_FORMAT_SAE_J2012_DA_00 = 0x00,
    UDS_DTC_FORMAT_ISO_14229_1 = 0x01,
    UDS_DTC_FORMAT_SAE_J1939_73 = 0x02,
    UDS_DTC_FORMAT_SAE_ISO_11992_4 = 0x03,
    UDS_DTC_FORMAT_SAE_J2012_DA_04 = 0x04,
} uds_dtc_format_identifier_e;

typedef enum
{
    UDS_FILE_MODE_READ = 0,
    UDS_FILE_MODE_WRITE_CREATE = 1,
    UDS_FILE_MODE_WRITE_REPLACE = 2,
    UDS_FILE_MODE_LIST_DIR = 3,
} uds_file_mode_e;

typedef enum
{
    UDS_LOGLVL_ERR = 0,
    UDS_LOGLVL_WARNING = 1,
    UDS_LOGLVL_INFO = 2,
    UDS_LOGLVL_DEBUG = 3,
    UDS_LOGLVL_TRACE = 4,
} uds_loglevel_e;

typedef struct
{
    uint64_t standard_session_mask;
    uint64_t specific_session_mask;
    uint32_t sa_type_mask;
} uds_security_cfg_t;

typedef struct
{
    uint8_t session_type;
    uint64_t sa_type_mask;

    uint16_t p2_timeout_ms;
    uint16_t p2star_timeout_ms;

    unsigned long s3_time;
} uds_session_cfg_t;

typedef struct
{
    uint8_t sa_index;
    int (*cb_request_seed)(void *priv, const uint8_t sa_index, const uint8_t in_data[],
                           size_t in_data_len, uint8_t out_seed[], size_t *out_seed_len);
    int (*cb_validate_key)(void *priv, const uint8_t sa_index, const uint8_t key[], size_t key_len);
} uds_sa_cfg_t;

typedef struct
{
    int (*cb_reset_hard)(void *priv);
    uds_security_cfg_t sec_reset_hard;

    int (*cb_reset_keyoffon)(void *priv);
    uds_security_cfg_t sec_reset_keyoffon;

    int (*cb_reset_soft)(void *priv);
    uds_security_cfg_t sec_reset_soft;

    int (*cb_enable_rps)(void *priv, uint8_t power_down_time);
    int (*cb_disable_rps)(void *priv);
    uds_security_cfg_t sec_rps;

    int (*cb_reset_vms)(void *priv, uint8_t reset_type);
    uds_security_cfg_t sec_reset_vms;

    int (*cb_reset_sss)(void *priv, uint8_t reset_type);
    uds_security_cfg_t sec_reset_sss;
} uds_config_ecureset_t;

typedef struct
{
    int (*cb_control)(void *priv, uds_cc_action_e action, uds_cc_message_type_e message_type,
                      uint8_t subnet_address, uint16_t extended_address);
    uds_security_cfg_t sec;
} uds_config_communication_control_t;

typedef struct
{
    int (*cb_read_available)(void *priv, uint8_t *out_data, size_t *out_data_len);
    int (*cb_read_current)(void *priv, uint8_t *out_data, size_t *out_data_len);
    int (*cb_set_default)(void *priv);
    int (*cb_set_given)(void *priv, const uint8_t *data, size_t data_len);
    uds_security_cfg_t sec;
} uds_config_access_timing_params_t;

typedef struct
{
    int (*cb_dtc_on)(void *priv, const uint8_t *data, size_t data_len);
    uds_security_cfg_t sec_dtc_on;

    int (*cb_dtc_off)(void *priv, const uint8_t *data, size_t data_len);
    uds_security_cfg_t sec_dtc_off;

    int (*cb_dtc_settings_vms)(void *priv, uint8_t dtc_setting_type, const uint8_t *data,
                               size_t data_len);
    uds_security_cfg_t sec_dtc_settings_vms;

    int (*cb_dtc_settings_sss)(void *priv, uint8_t dtc_setting_type, const uint8_t *data,
                               size_t data_len);
    uds_security_cfg_t sec_dtc_settings_sss;
} uds_config_dtc_settings_t;

typedef struct
{
    uint16_t identifier;

    /* Callback shall return -1 on failure; if failure is due to insufficient
     *  space, data_len shall also be set to total required space */
    int (*cb_read)(void *priv, uint16_t identifier, uint8_t *data, size_t *data_len);
    uds_security_cfg_t sec_read;

    int (*cb_write)(void *priv, uint16_t identifier, const uint8_t *data, const size_t data_len);
    uds_security_cfg_t sec_write;

    int (*cb_io)(void *priv, uint16_t identifier, uds_iocp_e iocp, const uint8_t *in_data,
                 const size_t in_data_len, uint8_t *out_data, size_t *out_data_len);
    uds_security_cfg_t sec_io;

    const uint8_t *scaling_data;
    unsigned long scaling_data_size;
} uds_config_data_t;

typedef struct
{
    const uintptr_t start;
    const uintptr_t stop;

    int (*cb_read)(void *priv, const uintptr_t address, uint8_t *data, const size_t data_len);
    uds_security_cfg_t sec_read;

    int (*cb_write)(void *priv, const uintptr_t address, const uint8_t *data,
                    const size_t data_len);
    uds_security_cfg_t sec_write;

    int (*cb_download_request)(void *priv, const uintptr_t address, const size_t data_len,
                               const uint8_t compression_method, const uint8_t encrypting_method);
    int (*cb_download)(void *priv, const uintptr_t address, const uint8_t *data,
                       const size_t data_len);
    int (*cb_download_exit)(void *priv);
    uds_security_cfg_t sec_download;

    int (*cb_upload_request)(void *priv, const uintptr_t address, const size_t data_len,
                             const uint8_t compression_method, const uint8_t encrypting_method);
    int (*cb_upload)(void *priv, const uintptr_t address, uint8_t *data, size_t *data_len);
    int (*cb_upload_exit)(void *priv);
    uds_security_cfg_t sec_upload;
    size_t max_block_len;
} uds_config_memory_region_t;

typedef struct
{
    uint32_t first;
    uint32_t last;
    uds_security_cfg_t sec;
    int (*cb_clear)(void *priv, uint32_t godtc);
} uds_config_group_of_dtc_t;

typedef struct
{
    uint32_t dtc_number;
} uds_config_dtc_t;

typedef struct
{
    uds_dtc_format_identifier_e format_identifier;

    const uds_config_dtc_t *dtcs;
    unsigned long number_of_dtcs;

    int (*cb_get_dtc_status_mask)(void *priv, uint32_t dtc_number, uint8_t *status_mask);

    int (*cb_is_dtc_snapshot_record_available)(void *priv, uint32_t dtc_number,
                                               uint8_t record_number);

    /* Shall return -1 on error, 0 on success; in the latter case, record_data_len shall be set to 0
     * if no data is available, or to the number of bytes copied to *record_data */
    int (*cb_get_dtc_snapshot_record)(void *priv, uint32_t dtc_number, uint8_t record_number,
                                      uint8_t *record_data, size_t *record_data_len);

    /* Shall return -1 on error, 0 on success; in the latter case, record_data_len shall be set to 0
     * if no data is available, or to the number of bytes copied to *record_data */
    int (*cb_get_dtc_extended_data_record)(void *priv, uint32_t dtc_number, uint8_t record_number,
                                           uint8_t *record_data, size_t *record_data_len);

    /* Shall return -1 on error, 0 on success; in the latter case, record_data_len shall be set to 0
     * if no data is available, or to the number of bytes copied to *record_data */
    int (*cb_get_stored_data_record)(void *priv, uint8_t record_number, uint8_t *record_data,
                                     size_t *record_data_len);

} uds_config_dtc_information_t;

typedef struct
{
    int (*cb_verify_mode_fixed)(void *priv, uint8_t link_control_mode);
    int (*cb_verify_mode_specified)(void *priv, const uint8_t *data, const size_t data_len);
    int (*cb_transition_mode)(void *priv);
    int (*cb_specific)(void *priv, uint8_t link_control_type, const uint8_t *data,
                       const size_t data_len);
    uds_security_cfg_t sec;
} uds_config_link_control_t;

typedef struct
{
    int (*cb_open)(void *priv, const char *filepath, size_t filepath_len, uds_file_mode_e mode,
                   intptr_t *fd, size_t *file_size, size_t *file_size_compressed,
                   const uint8_t compression_method, const uint8_t encrypting_method);

    int (*cb_list)(void *priv, intptr_t fd, size_t offset, void *buf, size_t *count);

    int (*cb_read)(void *priv, intptr_t fd, size_t offset, void *buf, size_t *count);

    int (*cb_write)(void *priv, intptr_t fd, size_t offset, const void *buf, size_t count);

    int (*cb_close)(void *priv, uds_file_mode_e mode, intptr_t fd);

    int (*cb_delete)(void *priv, const char *filepath, size_t filepath_len);

    uds_security_cfg_t sec;

    size_t max_block_len;

} uds_config_file_access_t;

typedef struct
{
    uint16_t identifier;

    uds_security_cfg_t sec;

    int (*cb_start)(void *priv, uint16_t identifier, const uint8_t *data, const size_t data_len,
                    uint8_t *res_data, size_t *res_data_len);

    int (*cb_stop)(void *priv, uint16_t identifier, const uint8_t *data, const size_t data_len,
                   uint8_t *res_data, size_t *res_data_len);

    int (*cb_req_results)(void *priv, uint16_t identifier, uint8_t *res_data, size_t *res_data_len);

    int (*cb_is_running)(void *priv, uint16_t identifier);
} uds_config_routine_t;

typedef struct
{
    int (*cb_send)(void *priv, const uint8_t data[], size_t len);
    void (*cb_notify_session_change)(void *priv, const uint8_t session_type);
    void (*cb_notify_sa_change)(void *priv, const uint8_t sa_index);
    void (*log_func)(void *priv, uds_loglevel_e level, const char *message, const char *arg_name,
                     unsigned long long arg);

    const uds_session_cfg_t *session_config;
    unsigned long num_session_config;

    const uds_sa_cfg_t *sa_config;
    unsigned long num_sa_config;

    unsigned long sa_max_attempts;
    unsigned long sa_delay_timer_ms;

    const uds_config_ecureset_t ecureset;
    const uds_config_communication_control_t communication_control;
    const uds_config_access_timing_params_t access_timings_params;
    const uds_config_dtc_settings_t dtc_settings;

    const uds_config_data_t *data_items;
    unsigned long num_data_items;

    const uds_config_memory_region_t *mem_regions;
    unsigned long num_mem_regions;

    const uds_config_group_of_dtc_t *groups_of_dtc;
    unsigned long num_groups_of_dtc;

    const uds_config_dtc_information_t dtc_information;

    const uds_config_link_control_t link_control;

    const uds_config_file_access_t file_transfer;

    const uds_config_routine_t *routines;
    unsigned long num_routines;
} uds_config_t;

typedef struct
{
    int64_t seconds;
    unsigned int microseconds;
} uds_time_t;

typedef enum
{
    UDS_ADDRESS_PHYSICAL,
    UDS_ADDRESS_FUNCTIONAL,
} uds_address_e;

#endif // UDS_TYPES_H__
