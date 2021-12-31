
#ifndef __UDS_H
#define __UDS_H

#include <stdint.h>

#define UDS_CFG_SA_TYPE_ALL 0xFFFFFFFFFFFFFFFF
#define UDS_CFG_SA_TYPE(x) (0x01 << x)

typedef struct __uds_security_cfg
{
    uint64_t session_mask[2];
    uint32_t sa_type_mask;
} uds_security_cfg_t;

typedef struct __uds_session_cfg
{
    uint8_t session_type;
    uint64_t sa_type_mask;
} uds_session_cfg_t;

typedef int (*uds_request_seed_cb_t)(void *priv, const uint8_t sa_level,
                                     const uint8_t in_data[], size_t in_data_len,
                                     uint8_t out_seed[], size_t *out_seed_len);
typedef int (*uds_validate_key_cb_t)(void *priv, const uint8_t sa_level,
                                     const uint8_t key[], size_t key_len);

typedef struct __uds_sa_cfg
{
    uint8_t sa_level;
    uds_request_seed_cb_t request_seed;
    uds_validate_key_cb_t validate_key;
} uds_sa_cfg_t;

typedef int (*uds_ecureset_hard_cb_t)(void *priv);
typedef int (*uds_ecureset_keyoffon_cb_t)(void *priv);
typedef int (*uds_ecureset_soft_cb_t)(void *priv);
typedef int (*uds_ecureset_enable_rps_cb_t)(void *priv, uint8_t power_down_time);
typedef int (*uds_ecureset_disable_rps_cb_t)(void *priv);
typedef int (*uds_ecureset_vms_cb_t)(void *priv, uint8_t reset_type);
typedef int (*uds_ecureset_sss_cb_t)(void *priv, uint8_t reset_type);

struct __uds_config_ecureset
{
    uds_ecureset_hard_cb_t cb_reset_hard;
    uds_security_cfg_t sec_reset_hard;

    uds_ecureset_keyoffon_cb_t cb_reset_keyoffon;
    uds_security_cfg_t sec_reset_keyoffon;

    uds_ecureset_soft_cb_t cb_reset_soft;
    uds_security_cfg_t sec_reset_soft;

    uds_ecureset_enable_rps_cb_t cb_enable_rps;
    uds_ecureset_disable_rps_cb_t cb_disable_rps;
    uds_security_cfg_t sec_rps;

    uds_ecureset_vms_cb_t cb_reset_vms;
    uds_security_cfg_t sec_reset_vms;

    uds_ecureset_sss_cb_t cb_reset_sss;
    uds_security_cfg_t sec_reset_sss;
};

typedef int (*uds_send_cb_t)(void *priv, const uint8_t data[], size_t len);

typedef struct __uds_config
{
    uint16_t p2;
    uint16_t p2max;

    uds_send_cb_t cb_send;

    const uds_session_cfg_t *session_config;
    unsigned long num_session_config;

    const uds_sa_cfg_t *sa_config;
    unsigned long num_sa_config;

    struct __uds_config_ecureset ecureset;

} uds_config_t;

typedef struct __uds_context
{
    const uds_config_t *config;
    void *priv;

    struct timespec timestamp;

    unsigned int loglevel;
    const uds_session_cfg_t *current_session;
    uint8_t current_sa_seed;
    const uds_sa_cfg_t *current_sa_level;

    uint8_t response_buffer[4096];
} uds_context_t;

typedef enum __uds_address
{
    UDS_ADDRESS_PHYSICAL,
    UDS_ADDRESS_FUNCTIONAL,
} uds_address_e;

int uds_init(uds_context_t *ctx, const uds_config_t *config, void *priv);
void uds_deinit(uds_context_t *ctx);
int uds_receive(uds_context_t *ctx, const uds_address_e addr_type,
                const uint8_t *data, const size_t len);
int uds_cycle(uds_context_t *ctx);

#endif // __UDS_H
