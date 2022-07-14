
#ifndef UDS_LOG_H__
#define UDS_LOG_H__

#include <stdio.h>

#include "uds.h"

#define UDS_LOG_EMERG   0
#define UDS_LOG_ALERT   1
#define UDS_LOG_CRIT    2
#define UDS_LOG_ERR     3
#define UDS_LOG_WARNING 4
#define UDS_LOG_NOTICE  5
#define UDS_LOG_INFO    6
#define UDS_LOG_DEBUG   7

#define uds_log(ctx, level, ...) \
do { \
    const uds_context_t *_ctx = ctx; \
    if (_ctx->loglevel >= level) \
    { \
        (void)fprintf(stderr, "libuds: " __VA_ARGS__); \
    } \
} while (0)

#define uds_emerg(ctx, ...) uds_log(ctx, UDS_LOG_EMERG, __VA_ARGS__)
#define uds_alert(ctx, ...) uds_log(ctx, UDS_LOG_ALERT, __VA_ARGS__)
#define uds_crit(ctx, ...) uds_log(ctx, UDS_LOG_CRIT, __VA_ARGS__)
#define uds_err(ctx, ...) uds_log(ctx, UDS_LOG_ERR, __VA_ARGS__)
#define uds_warning(ctx, ...) uds_log(ctx, UDS_LOG_WARNING, __VA_ARGS__)
#define uds_notice(ctx, ...) uds_log(ctx, UDS_LOG_NOTICE, __VA_ARGS__)
#define uds_notice(ctx, ...) uds_log(ctx, UDS_LOG_NOTICE, __VA_ARGS__)
#define uds_info(ctx, ...) uds_log(ctx, UDS_LOG_INFO, __VA_ARGS__)
#define uds_debug(ctx, ...) uds_log(ctx, UDS_LOG_DEBUG, __VA_ARGS__)

#endif // UDS_LOG_H__
