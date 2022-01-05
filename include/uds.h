
#ifndef __UDS_H
#define __UDS_H

#include <stdint.h>

#define UDS_CFG_SA_TYPE_NONE        (0x0000000000000000)
#define UDS_CFG_SA_TYPE_ALL         (0xFFFFFFFFFFFFFFFF)
#define UDS_CFG_SA_TYPE(x)          (0x0000000000000001 << x)

#define UDS_CFG_SESSION_MASK_NONE   (0x0000000000000000)
#define UDS_CFG_SESSION_MASK_ALL    (0xFFFFFFFFFFFFFFFF)
#define UDS_CFG_SESSION_MASK(x)     (0x0000000000000001 << x)

typedef enum {
    UDS_IOCP_RETURN_CONTROL_TO_ECU  = 0x00,
    UDS_IOCP_RESET_TO_DEFAULT       = 0x01,
    UDS_IOCP_FREEZE_CURRENT_STATE   = 0x02,
    UDS_IOCP_SHORT_TERM_ADJUSTMENT  = 0x03,
} uds_iocp_e;

typedef enum {
    UDS_DTC_FORMAT_SAE_J2012_DA_00  = 0x00,
    UDS_DTC_FORMAT_ISO_14229_1      = 0x01,
    UDS_DTC_FORMAT_SAE_J1939_73     = 0x02,
    UDS_DTC_FORMAT_SAE_ISO_11992_4  = 0x03,
    UDS_DTC_FORMAT_SAE_J2012_DA_04  = 0x04,
} uds_dtc_format_identifier_e;

typedef struct __uds_security_cfg
{
    uint64_t standard_session_mask;
    uint64_t specific_session_mask;
    uint32_t sa_type_mask;
} uds_security_cfg_t;

typedef struct __uds_session_cfg
{
    uint8_t session_type;
    uint64_t sa_type_mask;
} uds_session_cfg_t;

typedef struct __uds_sa_cfg
{
    uint8_t sa_index;
    int (*cb_request_seed)(void *priv, const uint8_t sa_index,
                           const uint8_t in_data[], size_t in_data_len,
                           uint8_t out_seed[], size_t *out_seed_len);
    int (*cb_validate_key)(void *priv, const uint8_t sa_index,
                           const uint8_t key[], size_t key_len);
} uds_sa_cfg_t;

typedef struct __uds_config_ecureset
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

typedef struct __uds_config_dtc_settings
{
    int (*cb_dtc_on)(void *priv, const uint8_t *data, size_t data_len);
    uds_security_cfg_t sec_dtc_on;

    int (*cb_dtc_off)(void *priv, const uint8_t *data, size_t data_len);
    uds_security_cfg_t sec_dtc_off;

    int (*cb_dtc_settings_vms)(void *priv, uint8_t dtc_setting_type,
                               const uint8_t *data, size_t data_len);
    uds_security_cfg_t sec_dtc_settings_vms;

    int (*cb_dtc_settings_sss)(void *priv, uint8_t dtc_setting_type,
                               const uint8_t *data, size_t data_len);
    uds_security_cfg_t sec_dtc_settings_sss;
} uds_config_dtc_settings_t;

typedef struct __uds_config_data
{
    uint16_t identifier;

    /* Callback shall return -1 on failure; if failure is due to insufficient
     *  space, data_len shall also be set to total required space */
    int (*cb_read)(void *priv, uint16_t identifier,
                   uint8_t *data, size_t *data_len);
    uds_security_cfg_t sec_read;

    int (*cb_write)(void *priv, uint16_t identifier,
                    const uint8_t *data, const size_t data_len);
    uds_security_cfg_t sec_write;

    int (*cb_io)(void *priv, uint16_t identifier, uds_iocp_e iocp,
                 const uint8_t *in_data, const size_t in_data_len,
                 uint8_t *out_data, size_t *out_data_len);
    uds_security_cfg_t sec_io;
} uds_config_data_t;

typedef struct __uds_config_memory_region
{
    const void *start;
    const void *stop;

    int (*cb_read)(void *priv, const void *address,
                   uint8_t *data, const size_t data_len);
    uds_security_cfg_t sec_read;

    int (*cb_write)(void *priv, const void *address,
                    const uint8_t *data, const size_t data_len);
    uds_security_cfg_t sec_write;
} uds_config_memory_region_t;

typedef struct __uds_config_group_of_dtc
{
    uint32_t first;
    uint32_t last;
    uds_security_cfg_t sec;
    int (*cb_clear)(void *priv, uint32_t godtc);
} uds_config_group_of_dtc_t;

typedef struct __uds_config_dtc
{
    uint32_t dtc_number;
} uds_config_dtc_t;

typedef struct __uds_config_dtc_information
{
    uds_dtc_format_identifier_e format_identifier;

    const uds_config_dtc_t *dtcs;
    unsigned long number_of_dtcs;

    int (*cb_get_dtc_status_mask)(void *priv, uint32_t dtc_number, uint8_t *status_mask);

    int (*cb_is_dtc_snapshot_record_available)(void *priv, uint32_t dtc_number, uint8_t record_number);

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
    int (*cb_get_stored_data_record)(void *priv, uint8_t record_number,
                                     uint8_t *record_data, size_t *record_data_len);

} uds_config_dtc_information_t;

typedef struct __uds_config
{
    uint16_t p2;
    uint16_t p2max;

    int (*cb_send)(void *priv, const uint8_t data[], size_t len);

    const uds_session_cfg_t *session_config;
    unsigned long num_session_config;

    const uds_sa_cfg_t *sa_config;
    unsigned long num_sa_config;

    const uds_config_ecureset_t ecureset;
    const uds_config_dtc_settings_t dtc_settings;

    const uds_config_data_t *data_items;
    unsigned long num_data_items;

    const uds_config_memory_region_t *mem_regions;
    unsigned long num_mem_regions;

    const uds_config_group_of_dtc_t *groups_of_dtc;
    unsigned long num_groups_of_dtc;

    const uds_config_dtc_information_t dtc_information;
} uds_config_t;

typedef struct __uds_context
{
    const uds_config_t *config;
    void *priv;

    struct timespec timestamp;

    unsigned int loglevel;
    const uds_session_cfg_t *current_session;
    uint8_t current_sa_seed;
    const uds_sa_cfg_t *current_sa;

    uint8_t *response_buffer;
    size_t response_buffer_len;
} uds_context_t;

typedef enum __uds_address
{
    UDS_ADDRESS_PHYSICAL,
    UDS_ADDRESS_FUNCTIONAL,
} uds_address_e;

int uds_init(uds_context_t *ctx, const uds_config_t *config,
             uint8_t *response_buffer, size_t response_buffer_len, void *priv);
void uds_deinit(uds_context_t *ctx);
int uds_receive(uds_context_t *ctx, const uds_address_e addr_type,
                const uint8_t *data, const size_t len);
int uds_cycle(uds_context_t *ctx);

#endif // __UDS_H
