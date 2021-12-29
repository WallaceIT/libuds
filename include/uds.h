
#ifndef __UDS_H
#define __UDS_H

#include <stdint.h>



typedef struct __uds_session_cfg
{
    uint8_t session_type;
    uint32_t sa_type_mask;
} uds_session_cfg_t;

#define UDS_CFG_SA_TYPE_ALL 0xFFFF
#define UDS_CFG_SA_TYPE(x) ((0x01 << x) & 0xFFFF)

typedef int (*uds_request_seed_cb_t)(const uint8_t sa_level,
                                     const uint8_t in_data[], size_t in_data_len,
                                     uint8_t out_seed[], size_t *out_seed_len);
typedef int (*uds_validate_key_cb_t)(const uint8_t sa_level,
                                     const uint8_t key[], size_t key_len);

typedef struct __uds_sa_cfg
{
    uint8_t sa_level;
    uds_request_seed_cb_t request_seed;
    uds_validate_key_cb_t validate_key;
} uds_sa_cfg_t;

typedef int (*uds_send_cb_t)(const uint8_t data[], size_t len);

typedef struct __uds_config
{
    uint16_t p2;
    uint16_t p2max;

    uds_send_cb_t cb_send;

    const uds_session_cfg_t *session_config;
    unsigned long num_session_config;

    const uds_sa_cfg_t *sa_config;
    unsigned long num_sa_config;

} uds_config_t;

typedef struct __uds_context
{
    struct __uds_config config;

    struct timespec timestamp;

    unsigned int loglevel;
    uint8_t current_session;
    uint8_t current_sa_seed;
    uint8_t current_sa_level;

    uint8_t response_buffer[4096];
} uds_context_t;

typedef enum __uds_address
{
    UDS_ADDRESS_PHYSICAL,
    UDS_ADDRESS_FUNCTIONAL,
} uds_address_e;

int uds_init(uds_context_t *ctx, const uds_config_t *config);
void uds_deinit(uds_context_t *ctx);
int uds_receive(uds_context_t *ctx, const uds_address_e addr_type,
                const uint8_t *data, const size_t len);
int uds_cycle(uds_context_t *ctx);

#endif // __UDS_H
