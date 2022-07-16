
#ifndef UDS_H__
#define UDS_H__

#include <stddef.h>
#include <stdint.h>

#include <uds/uds_types.h>
#include <uds/uds_context.h>

void uds_set_loglevel(uds_context_t *ctx, uds_loglevel_e level);
int uds_init(uds_context_t *ctx, const uds_config_t *config,
             uint8_t *response_buffer, size_t response_buffer_len, void *priv,
             const struct timespec *timestamp);
int uds_receive(uds_context_t *ctx, const uds_address_e addr_type,
                const uint8_t *data, const size_t len,
                const struct timespec *timestamp);
int uds_cycle(uds_context_t *ctx, const struct timespec *timestamp);
void uds_reset_sa_delay_timer(uds_context_t *ctx);

#endif // UDS_H__
