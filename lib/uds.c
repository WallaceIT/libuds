
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "uds.h"
#include "uds_config.h"
#include "uds_context.h"
#include "uds_log.h"

#include "iso14229_part1.h"

#define UDS_UNUSED(x) ((void)(x))

#define UDS_GET_SUBFUNCTION(x)      ((x) & (~UDS_SPRMINB))
#define UDS_SUPPRESS_PR(x)          (UDS_SPRMINB == ((x) & UDS_SPRMINB))

#define UDS_HIGH_NIBBLE(b)          (((b) >> 4) & 0x0FU)
#define UDS_LOW_NIBBLE(b)           (((b) >> 0) & 0x0FU)
#define UDS_FROM_NIBBLES(low,high)  ((((high) & 0x0FU) << 4) | ((low) % 0x0FU))

#define UDS_INVALID_SA_INDEX 0xFF

#define UDS_FILEPATH_MAX 4096U

#define UDS_LOAD_UINT16_BIG_ENDIAN(d) (((0xFFULL & (d)[0]) << 8U) | (d)[1])

static inline void __uds_store_big_endian(uint8_t *dest, unsigned long long value, size_t num_bytes)
{
    unsigned long p;
    for (p = 0; p < num_bytes; p++)
    {
        dest[p] = (value >> (8U * (num_bytes - p - 1U))) & 0xFFU;
    }
}

static inline unsigned long long __uds_load_big_endian(const uint8_t *src, size_t num_bytes)
{
    unsigned long long val = 0U;
    unsigned long p;
    for (p = 0U; p < num_bytes; p++)
    {
        val |= (0xFFULL & src[p]) << (8U * (num_bytes - p - 1U));
    }
    return val;
}

static inline int __uds_load_big_endian_addr(const uint8_t *src, size_t num_bytes, uintptr_t *addr)
{
    uintptr_t val = 0U;
    int ret = 0;
    unsigned long p;
    for (p = 0U; p < num_bytes; p++)
    {
        if (p <= sizeof(uintptr_t))
        {
            val |= (0xFFULL & src[p]) << (8U * (num_bytes - p - 1U));
        }
        else if (src[p] != 0U)
        {
            ret = -1;
            break;
        }
        else
        {
            // Nothing to do
        }
    }

    if (ret == 0)
    {
        *addr = val;
    }

    return ret;
}

static inline int __uds_load_big_endian_size(const uint8_t *src, size_t num_bytes, size_t *size)
{
    size_t val = 0U;
    int ret = 0;
    unsigned long p;
    for (p = 0U; p < num_bytes; p++)
    {
        if (p <= sizeof(size_t))
        {
            val |= (0xFFULL & src[p]) << (8U * (num_bytes - p - 1U));
        }
        else if (src[p] != 0U)
        {
            ret = -1;
            break;
        }
        else
        {
            // Nothing to do
        }
    }

    if (ret == 0)
    {
        *size = val;
    }

    return ret;
}

static inline uint8_t __uds_sat_to_sa_index(const uint8_t sat)
{
    return ((sat - 1U) / 2U);
}

static inline void __uds_switch_to_session(uds_context_t *ctx,
                                           const uds_session_cfg_t *session)
{
    ctx->current_session = session;
    if (NULL != ctx->config->cb_notify_session_change)
    {
        ctx->config->cb_notify_session_change(ctx->priv, session->session_type);
    }
}

static void __uds_reset_to_default_session(uds_context_t *ctx)
{
    unsigned int s = 0U;
    for (s = 0; s < ctx->config->num_session_config; s++)
    {
        if (ctx->config->session_config[s].session_type == 0x01)
        {
            __uds_switch_to_session(ctx, &ctx->config->session_config[s]);
            break;
        }
    }

    if (s == ctx->config->num_session_config)
    {
        const uds_session_cfg_t default_session =
        {
            .session_type = 0x01,
            .sa_type_mask = 0UL,
        };
        __uds_switch_to_session(ctx, &default_session);
    }
}

static inline void __uds_activate_sa(uds_context_t *ctx, const uds_sa_cfg_t *sa)
{
    ctx->current_sa = sa;
    if (NULL != ctx->config->cb_notify_sa_change)
    {
        if (NULL != sa)
        {
            uds_debug(ctx, "activating SA 0x%02X\n", sa->sa_index);
            ctx->config->cb_notify_sa_change(ctx->priv, sa->sa_index);
        }
        else
        {
            ctx->config->cb_notify_sa_change(ctx->priv, UDS_INVALID_SA_INDEX);
        }
    }
}

static inline void __uds_reset_secure_access(uds_context_t *ctx)
{
    __uds_activate_sa(ctx, NULL);
}

static inline int __uds_sa_vs_session_check(uds_context_t *ctx,
                                            const uds_sa_cfg_t *sa_config,
                                            const uds_session_cfg_t *session_config)
{
    int ret = -1;

    uds_debug(ctx, "sa_vs_session_check with sa = %d and session = 0x%02X\n",
              ((NULL != sa_config) ? sa_config->sa_index : -1),
              ((NULL != session_config) ? session_config->session_type : 0xFF));

    if ((NULL != sa_config) && (NULL != session_config) &&
        ((UDS_CFG_SA_TYPE(sa_config->sa_index) & session_config->sa_type_mask) != 0))
    {
        ret = 0;
    }

    return ret;
}

static int __uds_session_check(uds_context_t *ctx, const uds_security_cfg_t* cfg)
{
    int ret = -1;

    uds_debug(ctx, "session_check with active session = 0x%02X (st = 0x%016lX, sp = 0x%016lX)\n",
              ctx->current_session->session_type,
              cfg->standard_session_mask, cfg->specific_session_mask);

    if (ctx->current_session->session_type >= 128U)
    {
        uds_err(ctx, "invalid current session 0x%02X\n", ctx->current_session->session_type);
        ret = -1;
    }
    else if ((ctx->current_session->session_type < 64U) &&
             ((UDS_CFG_SESSION_MASK(ctx->current_session->session_type) & cfg->standard_session_mask) != 0))
    {
        ret = 0;
    }
    else if ((ctx->current_session->session_type >= 64U) &&
             ((UDS_CFG_SESSION_MASK((ctx->current_session->session_type - 64U)) & cfg->specific_session_mask) != 0))
    {
        ret = 0;
    }
    else
    {
        ret = -1;
    }

    return ret;
}

static int __uds_security_check(uds_context_t *ctx, const uds_security_cfg_t* cfg)
{
    int ret = -1;

    uds_debug(ctx, "security_check with current sa_index = %d\n",
              (NULL != ctx->current_sa) ? ctx->current_sa->sa_index : -1);
    uds_debug(ctx, "sa_tm = 0x%08X\n", cfg->sa_type_mask);

    if (cfg->sa_type_mask == 0U)
    {
        ret = 0;
    }
    else if ((NULL != ctx->current_sa) &&
             ((UDS_CFG_SA_TYPE(ctx->current_sa->sa_index) & cfg->sa_type_mask) != 0))
    {
        ret = 0;
    }
    else
    {
        ret = -1;
    }

    return ret;
}

static inline int __uds_session_and_security_check(uds_context_t *ctx, const uds_security_cfg_t* cfg)
{
    int ret = -1;

    if ((__uds_session_check(ctx, cfg) == 0) &&
        (__uds_security_check(ctx, cfg) == 0))
    {
        ret = 0;
    }

    return ret;
}

static inline int __uds_data_transfer_active(uds_context_t *ctx)
{
    int ret = -1;

    if (UDS_DATA_TRANSFER_NONE != ctx->data_transfer.direction)
    {
        ret = 0;
    }

    return ret;
}

static inline void __uds_data_transfer_reset(uds_context_t *ctx)
{
    uds_info(ctx, "data transfer reset\n");

    ctx->data_transfer.direction = UDS_DATA_TRANSFER_NONE;
    ctx->data_transfer.mem_region = NULL;
    ctx->data_transfer.address = 0;
    ctx->data_transfer.prev_address = 0U;
    ctx->data_transfer.bsqc = 0;
    ctx->data_transfer.fd = -1;
    ctx->data_transfer.max_block_len = 0;
}

static int __uds_send(uds_context_t *ctx, const uint8_t *data, size_t len)
{
    int ret = 0;

    if (NULL == ctx->config->cb_send)
    {
        static int no_cb_err_once = 0;
        if (no_cb_err_once == 0)
        {
            no_cb_err_once = 1;
            uds_alert(ctx, "send callback not installed!\n");
            ret = -1;
        }
    }
    else if ((NULL != data) && (len > 0U))
    {
        ret = ctx->config->cb_send(ctx->priv, data, len);
        if (ret != 0)
        {
            uds_err(ctx, "send callback failed\n");
        }
    }
    else
    {
        uds_err(ctx, "send called with no data\n");
        ret = -1;
    }

    return ret;
}

static uint8_t __uds_svc_session_control(uds_context_t *ctx,
                                         const struct timespec *timestamp,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len != 1U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint8_t requested_session = UDS_GET_SUBFUNCTION(data[0]);
        unsigned int s;

        for (s = 0; s < ctx->config->num_session_config; s++)
        {
            if (ctx->config->session_config[s].session_type == requested_session)
            {
                uds_info(ctx, "entering session 0x%02X\n", requested_session);

                if (__uds_sa_vs_session_check(ctx, ctx->current_sa, &ctx->config->session_config[s]) != 0)
                {
                    uds_info(ctx, "secure access not allowed in new session, reset it\n");
                    __uds_reset_secure_access(ctx);
                }

                __uds_switch_to_session(ctx, &ctx->config->session_config[s]);
                break;
            }
        }

        if (ctx->config->num_session_config == s)
        {
            uds_info(ctx, "requested session 0x%02X not available\n", requested_session);
            nrc = UDS_NRC_SFNS;
        }
        else if (UDS_SUPPRESS_PR(data[0]))
        {
            nrc = UDS_SPRMINB;
        }
        else
        {
            nrc = UDS_NRC_PR;
            res_data[0] = requested_session;
            __uds_store_big_endian(&res_data[1], ctx->config->session_config[s].p2_timeout_ms, 2);
            __uds_store_big_endian(&res_data[3], ctx->config->session_config[s].p2star_timeout_ms, 2);
            *res_data_len = 5;
        }
    }

    return nrc;
}

static uint8_t __uds_svc_ecu_reset(uds_context_t *ctx,
                                   const struct timespec *timestamp,
                                   const uint8_t *data, size_t data_len,
                                   uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint8_t reset_type = 0;

    UDS_UNUSED(timestamp);

    if (data_len < 1U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        reset_type = UDS_GET_SUBFUNCTION(data[0]);

        if ((UDS_LEV_RT_HR == reset_type) &&
            (NULL != ctx->config->ecureset.cb_reset_hard))
        {
            if (__uds_session_check(ctx, &ctx->config->ecureset.sec_reset_hard) != 0)
            {
                nrc = UDS_NRC_SFNSIAS;
            }
            else if (__uds_security_check(ctx, &ctx->config->ecureset.sec_reset_hard) != 0)
            {
                nrc = UDS_NRC_SAD;
            }
            else if (ctx->config->ecureset.cb_reset_hard(ctx->priv) != 0)
            {
                uds_err(ctx, "cb_reset_hard failed\n");
                nrc = UDS_NRC_FPEORA;
            }
            else
            {
                nrc = UDS_NRC_PR;
            }
        }
        else if ((UDS_LEV_RT_KOFFONR == reset_type) &&
                 (NULL != ctx->config->ecureset.cb_reset_keyoffon))
        {
            if (__uds_session_check(ctx, &ctx->config->ecureset.sec_reset_keyoffon) != 0)
            {
                nrc = UDS_NRC_SFNSIAS;
            }
            else if (__uds_security_check(ctx, &ctx->config->ecureset.sec_reset_keyoffon) != 0)
            {
                nrc = UDS_NRC_SAD;
            }
            else if (ctx->config->ecureset.cb_reset_keyoffon(ctx->priv) != 0)
            {
                uds_err(ctx, "cb_reset_keyoffon failed\n");
                nrc = UDS_NRC_FPEORA;
            }
            else
            {
                nrc = UDS_NRC_PR;
            }
        }
        else if ((UDS_LEV_RT_SR == reset_type) &&
                 (NULL != ctx->config->ecureset.cb_reset_soft))
        {
            if (__uds_session_check(ctx, &ctx->config->ecureset.sec_reset_soft) != 0)
            {
                nrc = UDS_NRC_SFNSIAS;
            }
            else if (__uds_security_check(ctx, &ctx->config->ecureset.sec_reset_soft) != 0)
            {
                nrc = UDS_NRC_SAD;
            }
            else if (ctx->config->ecureset.cb_reset_soft(ctx->priv) != 0)
            {
                uds_err(ctx, "cb_reset_soft failed\n");
                nrc = UDS_NRC_FPEORA;
            }
            else
            {
                nrc = UDS_NRC_PR;
            }
        }
        else if ((UDS_LEV_RT_ERPSD == reset_type) &&
                 (NULL != ctx->config->ecureset.cb_enable_rps))
        {
            if (data_len < 2U)
            {
                nrc = UDS_NRC_IMLOIF;
            }
            else if (__uds_session_check(ctx, &ctx->config->ecureset.sec_rps) != 0)
            {
                nrc = UDS_NRC_SFNSIAS;
            }
            else if (__uds_security_check(ctx, &ctx->config->ecureset.sec_rps) != 0)
            {
                nrc = UDS_NRC_SAD;
            }
            else if (ctx->config->ecureset.cb_enable_rps(ctx->priv, data[1]) != 0)
            {
                uds_err(ctx, "cb_enable_rps failed\n");
                nrc = UDS_NRC_FPEORA;
            }
            else
            {
                nrc = UDS_NRC_PR;
            }
        }
        else if ((UDS_LEV_RT_ERPSD == reset_type) &&
                 (NULL != ctx->config->ecureset.cb_disable_rps))
        {
            if (__uds_session_check(ctx, &ctx->config->ecureset.sec_rps) != 0)
            {
                nrc = UDS_NRC_SFNSIAS;
            }
            else if (__uds_security_check(ctx, &ctx->config->ecureset.sec_rps) != 0)
            {
                nrc = UDS_NRC_SAD;
            }
            else if (ctx->config->ecureset.cb_disable_rps(ctx->priv) != 0)
            {
                uds_err(ctx, "cb_enable_rps failed\n");
                nrc = UDS_NRC_FPEORA;
            }
            else
            {
                nrc = UDS_NRC_PR;
            }
        }
        else if ((reset_type >= UDS_LEV_RT_VMS_MIN) &&
                 (reset_type <= UDS_LEV_RT_VMS_MAX) &&
                 (NULL != ctx->config->ecureset.cb_reset_vms))
        {
            if (__uds_session_check(ctx, &ctx->config->ecureset.sec_reset_vms) != 0)
            {
                nrc = UDS_NRC_SFNSIAS;
            }
            else if (__uds_security_check(ctx, &ctx->config->ecureset.sec_reset_vms) != 0)
            {
                nrc = UDS_NRC_SAD;
            }
            else if (ctx->config->ecureset.cb_reset_vms(ctx->priv, reset_type) != 0)
            {
                uds_err(ctx, "cb_reset_vms(0x%02X) failed\n", reset_type);
                nrc = UDS_NRC_FPEORA;
            }
            else
            {
                nrc = UDS_NRC_PR;
            }
        }
        else if ((reset_type >= UDS_LEV_RT_SSS_MIN) &&
                 (reset_type <= UDS_LEV_RT_SSS_MAX) &&
                 (NULL != ctx->config->ecureset.cb_reset_sss))
        {
            if (__uds_session_check(ctx, &ctx->config->ecureset.sec_reset_sss) != 0)
            {
                nrc = UDS_NRC_SFNSIAS;
            }
            else if (__uds_security_check(ctx, &ctx->config->ecureset.sec_reset_sss) != 0)
            {
                nrc = UDS_NRC_SAD;
            }
            else if (ctx->config->ecureset.cb_reset_sss(ctx->priv, reset_type) != 0)
            {
                uds_err(ctx, "cb_reset_sss(0x%02X) failed\n", reset_type);
                nrc = UDS_NRC_FPEORA;
            }
            else
            {
                nrc = UDS_NRC_PR;
            }
        }
        else
        {
            nrc = UDS_NRC_SFNS;
        }
    }

    if (nrc == UDS_NRC_PR)
    {
        if (UDS_SUPPRESS_PR(data[0]))
        {
            nrc = UDS_SPRMINB;
        }
        else
        {
            res_data[0] = reset_type;
            *res_data_len = 1;
        }
    }

    return nrc;
}

static inline int __uds_security_access_max_attempts_exceeded(uds_context_t *ctx)
{
    int exceeded = 0;
    if ((ctx->sa_failed_attempts >= ctx->config->sa_max_attempts) &&
        (ctx->config->sa_max_attempts != 0) &&
        (ctx->config->sa_delay_timer_ms > 0))
    {
        exceeded = 1;
    }
    return exceeded;
}

static inline void __uds_security_access_reset_failed_attempts(uds_context_t *ctx)
{
    ctx->sa_failed_attempts = 0U;
}

static inline void __uds_security_access_start_delay_timer(uds_context_t *ctx,
                                                           const struct timespec *now)
{
    if (NULL != now)
    {
        (void)memcpy(&ctx->sa_delay_timer_timestamp, now,
                     sizeof(ctx->sa_delay_timer_timestamp));
    }
}

static uint8_t __uds_svc_security_access(uds_context_t *ctx,
                                         const struct timespec *timestamp,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    if (data_len < 1U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint8_t sr = UDS_GET_SUBFUNCTION(data[0]);
        uint8_t sa_index = __uds_sat_to_sa_index(sr);

        size_t in_data_len = (data_len - 1U);
        const uint8_t *in_data = NULL;

        if (in_data_len > 0U)
        {
            in_data = &data[1];
        }

        if ((sr == 0x00U) || (sr == 0x7FU))
        {
            nrc = UDS_NRC_SFNS;
        }
        else if ((ctx->current_session->sa_type_mask & UDS_CFG_SA_TYPE(sa_index)) == 0)
        {
            nrc = UDS_NRC_SFNSIAS;
        }
        else if (__uds_security_access_max_attempts_exceeded(ctx) != 0)
        {
            nrc = UDS_NRC_RTDNE;
        }
        else if ((sr % 2U) != 0U)
        {
            unsigned int l;

            uds_debug(ctx, "request_seed for SA 0x%02X\n", sa_index);

            for (l = 0; l < ctx->config->num_sa_config; l++)
            {
                if (ctx->config->sa_config[l].sa_index == sa_index)
                {
                    if (NULL != ctx->config->sa_config[l].cb_request_seed)
                    {
                        int ret;

                        ret = ctx->config->sa_config[l].cb_request_seed(ctx->priv, sa_index,
                                                                        in_data, in_data_len,
                                                                        &res_data[1], res_data_len);
                        if (ret < 0)
                        {
                            uds_info(ctx, "request_seed for SA 0x%02X failed\n", sa_index);
                            nrc = UDS_NRC_ROOR;
                        }
                        else
                        {
                            // If security level is already unlocked, send an all-zero seed
                            if ((NULL != ctx->current_sa) &&
                                (ctx->current_sa->sa_index == sa_index))
                            {
                                for (l = 0; l < *res_data_len; l++)
                                {
                                    res_data[1U + l] = 0x00;
                                }
                            }
                            else
                            {
                                ctx->current_sa_seed = sa_index;
                            }
                            res_data[0] = sr;
                            *res_data_len = (*res_data_len + 1);
                            nrc = UDS_NRC_PR;
                        }
                    }
                    else
                    {
                        uds_err(ctx, "request_seed callback not defined for SA 0x%02X\n", sa_index);
                        nrc = UDS_NRC_SFNS;
                    }
                    break;
                }
            }
        }
        else if (ctx->current_sa_seed != sa_index)
        {
            nrc = UDS_NRC_RSE;
        }
        else
        {
            unsigned int l;

            uds_debug(ctx, "validate_key for SA 0x%02X\n", sa_index);

            for (l = 0; l < ctx->config->num_sa_config; l++)
            {
                if (ctx->config->sa_config[l].sa_index == sa_index)
                {
                    if (NULL != ctx->config->sa_config[l].cb_validate_key)
                    {
                        int ret;

                        ret = ctx->config->sa_config[l].cb_validate_key(ctx->priv, sa_index,
                                                                        in_data, in_data_len);
                        if (ret < 0)
                        {
                            uds_info(ctx, "validate_key for SA 0x%02X failed\n", sa_index);

                            ctx->sa_failed_attempts++;
                            if (__uds_security_access_max_attempts_exceeded(ctx) != 0)
                            {
                                __uds_security_access_start_delay_timer(ctx, timestamp);
                                nrc = UDS_NRC_ENOA;
                            }
                            else
                            {
                                nrc = UDS_NRC_IK;
                            }
                        }
                        else
                        {
                            res_data[0] = sr;
                            *res_data_len = 1;
                            __uds_activate_sa(ctx, &ctx->config->sa_config[l]);
                            ctx->current_sa_seed = UDS_INVALID_SA_INDEX;
                            __uds_security_access_reset_failed_attempts(ctx);
                            nrc = UDS_NRC_PR;
                        }
                    }
                    else
                    {
                        uds_err(ctx, "validate_key callback not defined for SA 0x%02X\n", sa_index);
                    }
                    break;
                }
            }
        }
    }

    return nrc;
}


static uint8_t __uds_svc_communication_control(uds_context_t *ctx,
                                               const struct timespec *timestamp,
                                               const uint8_t *data, size_t data_len,
                                               uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len < 2U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uds_cc_action_e action;
        uds_cc_message_type_e message_type = UDS_CCMT_NONE;
        uint8_t subnet_address = 0x00;
        uint16_t enhanced_address = 0x0000;
        uint8_t ct = UDS_GET_SUBFUNCTION(data[0]);

        /* nrc will be checked after parsing of parameters */
        nrc = UDS_NRC_PR;

        switch (ct)
        {
        case UDS_LEV_CTRLTP_ERXTX:
            action = UDS_CCACT_EN_RX_EN_TX;
            break;
        case UDS_LEV_CTRLTP_ERXDTX:
            action = UDS_CCACT_EN_RX_DIS_TX;
            break;
        case UDS_LEV_CTRLTP_DRXETX:
            action = UDS_CCACT_DIS_RX_EN_TX;
            break;
        case UDS_LEV_CTRLTP_DRXTX:
            action = UDS_CCACT_DIS_RX_DIS_TX;
            break;
        case UDS_LEV_CTRLTP_ERXDTXWEAI:
            if (data_len < 4U)
            {
                nrc = UDS_NRC_IMLOIF;
            }
            else
            {
                action = UDS_CCACT_EN_RX_DIS_TX_EAI;
                enhanced_address = UDS_LOAD_UINT16_BIG_ENDIAN(&data[2]);
            }
            break;
        case UDS_LEV_CTRLTP_ERXTXWEAI:
            if (data_len < 4U)
            {
                nrc = UDS_NRC_IMLOIF;
            }
            else
            {
                action = UDS_CCACT_EN_RX_EN_TX_EAI;
                enhanced_address = UDS_LOAD_UINT16_BIG_ENDIAN(&data[2]);
            }
            break;
        default:
            action = ct;
            break;
        }

        switch (UDS_LOW_NIBBLE(data[1]) & 0x03U)
        {
        case UDS_CTP_NCM:
            message_type = UDS_CCMT_NORMAL;
            break;
        case UDS_CTP_NWMCM:
            message_type = UDS_CCMT_NETWORK_MANAGEMENT;
            break;
        case UDS_CTP_NWMCM_NCM:
            message_type = UDS_CCMT_NETWORK_MANAGEMENT_AND_NORMAL;
            break;
        default:
            nrc = UDS_NRC_ROOR;
            break;
        }

        subnet_address = UDS_HIGH_NIBBLE(data[1]);

        if (nrc != UDS_NRC_PR)
        {
            uds_warning(ctx, "communication control cannot be performed due to bad request");
        }
        else if (__uds_session_check(ctx, &ctx->config->communication_control.sec) != 0)
        {
            nrc = UDS_NRC_SFNSIAS;
        }
        else if (__uds_security_check(ctx, &ctx->config->communication_control.sec) != 0)
        {
            nrc = UDS_NRC_SAD;
        }
        else
        {
            int ret;

            ret = ctx->config->communication_control.cb_control(ctx->priv, action,
                                                                message_type,
                                                                subnet_address,
                                                                enhanced_address);
            if (ret < 0)
            {
                uds_err(ctx, "cb_control failed\n");
                nrc = UDS_NRC_CNC;
            }
            else if (UDS_SUPPRESS_PR(data[0]))
            {
                nrc = UDS_SPRMINB;
            }
            else
            {
                res_data[0] = ct;
                *res_data_len = 1;
                nrc = UDS_NRC_PR;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_tester_present(uds_context_t *ctx,
                                        const struct timespec *timestamp,
                                        const uint8_t *data, size_t data_len,
                                        uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(ctx);
    UDS_UNUSED(timestamp);

    if (data_len != 1U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if (UDS_LEV_ZSUBF != UDS_GET_SUBFUNCTION(data[0]))
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if (UDS_SUPPRESS_PR(data[0]))
    {
        nrc = UDS_SPRMINB;
    }
    else
    {
        res_data[0] = UDS_LEV_ZSUBF;
        *res_data_len = 1U;
        nrc = UDS_NRC_PR;
    }

    return nrc;
}

static uint8_t __uds_svc_access_timing_parameters(uds_context_t *ctx,
                                                  const struct timespec *timestamp,
                                                  const uint8_t *data, size_t data_len,
                                                  uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len < 1U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if (__uds_session_check(ctx, &ctx->config->access_timings_params.sec) != 0)
    {
        nrc = UDS_NRC_SFNSIAS;
    }
    else if (__uds_security_check(ctx, &ctx->config->access_timings_params.sec) != 0)
    {
        nrc = UDS_NRC_SAD;
    }
    else
    {
        uint8_t access_type = UDS_GET_SUBFUNCTION(data[0]);
        size_t out_data_len = (*res_data_len - 1U);
        int ret;

        nrc = UDS_NRC_PR;

        switch (access_type)
        {
        case UDS_LEV_TPAT_RETPS:
            ret = ctx->config->access_timings_params.cb_read_available(ctx->priv,
                                                                       &res_data[1],
                                                                       &out_data_len);
            break;
        case UDS_LEV_TPAT_STPTDV:
            out_data_len = 0U;
            ret = ctx->config->access_timings_params.cb_set_default(ctx->priv);
            break;
        case UDS_LEV_TPAT_RCATP:
            ret = ctx->config->access_timings_params.cb_read_current(ctx->priv,
                                                                     &res_data[1],
                                                                     &out_data_len);
            break;
        case UDS_LEV_TPAT_STPTGV:
            if (data_len < 2U)
            {
                nrc = UDS_NRC_IMLOIF;
            }
            else
            {
                out_data_len = 0U;
                ret = ctx->config->access_timings_params.cb_set_given(ctx->priv,
                                                                      &data[1],
                                                                      (data_len - 1U));
            }
            break;
        default:
            nrc = UDS_NRC_SFNS;
            break;
        }

        if (nrc != UDS_NRC_PR)
        {
            uds_warning(ctx, "access to timings parameters cannot be performed due to bad request");
        }
        else if (ret < 0)
        {
            uds_err(ctx, "cb for access_timings_params failed\n");
            nrc = UDS_NRC_FPEORA;
        }
        else if (UDS_SUPPRESS_PR(data[0]))
        {
            nrc = UDS_SPRMINB;
        }
        else
        {
            res_data[0] = access_type;
            *res_data_len = 1U + out_data_len;
        }
    }

    return nrc;
}

static uint8_t __uds_svc_control_dtc_settings(uds_context_t *ctx,
                                              const struct timespec *timestamp,
                                              const uint8_t *data, size_t data_len,
                                              uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len < 1U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint8_t dtc_setting_type = UDS_GET_SUBFUNCTION(data[0]);
        const uint8_t *extra_data = NULL;
        size_t extra_data_len = 0U;

        if (data_len > 1U)
        {
            extra_data = &data[1];
            extra_data_len = (data_len - 1U);
        }

        if ((UDS_LEV_DTCSTP_ON == dtc_setting_type) &&
            (NULL != ctx->config->dtc_settings.cb_dtc_on))
        {
            if (__uds_session_check(ctx, &ctx->config->dtc_settings.sec_dtc_on) != 0)
            {
                nrc = UDS_NRC_SFNSIAS;
            }
            else if (__uds_security_check(ctx, &ctx->config->dtc_settings.sec_dtc_on) != 0)
            {
                nrc = UDS_NRC_SAD;
            }
            else if (ctx->config->dtc_settings.cb_dtc_on(ctx->priv, extra_data, extra_data_len) != 0)
            {
                uds_err(ctx, "cb_dtc_on failed\n");
                nrc = UDS_NRC_FPEORA;
            }
            else
            {
                nrc = UDS_NRC_PR;
            }
        }
        else if ((UDS_LEV_DTCSTP_OFF == dtc_setting_type) &&
                 (NULL != ctx->config->dtc_settings.cb_dtc_off))
        {
            if (__uds_session_check(ctx, &ctx->config->dtc_settings.sec_dtc_off) != 0)
            {
                nrc = UDS_NRC_SFNSIAS;
            }
            else if (__uds_security_check(ctx, &ctx->config->dtc_settings.sec_dtc_off) != 0)
            {
                nrc = UDS_NRC_SAD;
            }
            else if (ctx->config->dtc_settings.cb_dtc_off(ctx->priv, extra_data, extra_data_len) != 0)
            {
                uds_err(ctx, "cb_dtc_off failed\n");
                nrc = UDS_NRC_FPEORA;
            }
            else
            {
                nrc = UDS_NRC_PR;
            }
        }
        else if ((dtc_setting_type >= UDS_LEV_DTCSTP_VMS_MIN) &&
                 (dtc_setting_type <= UDS_LEV_DTCSTP_VMS_MAX) &&
                 (NULL != ctx->config->dtc_settings.cb_dtc_settings_vms))
        {
            if (__uds_session_check(ctx, &ctx->config->dtc_settings.sec_dtc_settings_vms) != 0)
            {
                nrc = UDS_NRC_SFNSIAS;
            }
            else if (__uds_security_check(ctx, &ctx->config->dtc_settings.sec_dtc_settings_vms) != 0)
            {
                nrc = UDS_NRC_SAD;
            }
            else if (ctx->config->dtc_settings.cb_dtc_settings_vms(ctx->priv, dtc_setting_type,
                                                                   extra_data, extra_data_len) != 0)
            {
                uds_err(ctx, "cb_dtc_settings_vms(0x%02X) failed\n", dtc_setting_type);
                nrc = UDS_NRC_FPEORA;
            }
            else
            {
                nrc = UDS_NRC_PR;
            }
        }
        else if ((dtc_setting_type >= UDS_LEV_DTCSTP_SSS_MIN) &&
                 (dtc_setting_type <= UDS_LEV_DTCSTP_SSS_MAX) &&
                 (NULL != ctx->config->dtc_settings.cb_dtc_settings_sss))
        {
            if (__uds_session_check(ctx, &ctx->config->dtc_settings.sec_dtc_settings_sss) != 0)
            {
                nrc = UDS_NRC_SFNSIAS;
            }
            else if (__uds_security_check(ctx, &ctx->config->dtc_settings.sec_dtc_settings_sss) != 0)
            {
                nrc = UDS_NRC_SAD;
            }
            else if (ctx->config->dtc_settings.cb_dtc_settings_sss(ctx->priv, dtc_setting_type,
                                                                   extra_data, extra_data_len) != 0)
            {
                uds_err(ctx, "cb_dtc_settings_sss(0x%02X) failed\n", dtc_setting_type);
                nrc = UDS_NRC_FPEORA;
            }
            else
            {
                nrc = UDS_NRC_PR;
            }
        }
        else
        {
            nrc = UDS_NRC_SFNS;
        }

        if (nrc == UDS_NRC_PR)
        {
            if (UDS_SUPPRESS_PR(data[0]))
            {
                nrc = UDS_SPRMINB;
            }
            else
            {
                res_data[0] = dtc_setting_type;
                *res_data_len = 1U;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_link_control(uds_context_t *ctx,
                                      const struct timespec *timestamp,
                                      const uint8_t *data, size_t data_len,
                                      uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint8_t link_control_type = 0x00U;
    int ret = -1;

    UDS_UNUSED(timestamp);

    if (data_len < 1U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if (__uds_session_check(ctx, &ctx->config->link_control.sec) != 0)
    {
        nrc = UDS_NRC_SFNSIAS;
    }
    else if (__uds_security_check(ctx, &ctx->config->link_control.sec) != 0)
    {
        nrc = UDS_NRC_SAD;
    }
    else
    {
        link_control_type = UDS_GET_SUBFUNCTION(data[0]);

        switch (link_control_type)
        {
        case UDS_LEV_LCTP_VMTWFP:
            if (ctx->config->link_control.cb_verify_mode_fixed == NULL)
            {
                nrc = UDS_NRC_SFNS;
            }
            else if (data_len < 2U)
            {
                nrc = UDS_NRC_IMLOIF;
            }
            else
            {
                ret = ctx->config->link_control.cb_verify_mode_fixed(ctx->priv, data[1]);
                if (ret < 0)
                {
                    nrc = UDS_NRC_CNC;
                }
                else
                {
                    ctx->link_control.mode_verified = 1;
                    nrc = UDS_NRC_PR;
                }
            }
            break;
        case UDS_LEV_LCTP_VMTWSP:
            if (ctx->config->link_control.cb_verify_mode_specified == NULL)
            {
                nrc = UDS_NRC_SFNS;
            }
            else if (data_len < 2U)
            {
                nrc = UDS_NRC_IMLOIF;
            }
            else
            {
                ret = ctx->config->link_control.cb_verify_mode_specified(ctx->priv,
                                                                         &data[1],
                                                                         (data_len - 1U));
                if (ret < 0)
                {
                    nrc = UDS_NRC_CNC;
                }
                else
                {
                    ctx->link_control.mode_verified = 1;
                    nrc = UDS_NRC_PR;
                }
            }
            break;
        case UDS_LEV_LCTP_TM:
            if (ctx->config->link_control.cb_transition_mode == NULL)
            {
                nrc = UDS_NRC_SFNS;
            }
            else if (ctx->link_control.mode_verified == 0)
            {
                nrc = UDS_NRC_RSE;
            }
            else
            {
                ret = ctx->config->link_control.cb_transition_mode(ctx->priv);
                if (ret < 0)
                {
                    nrc = UDS_NRC_CNC;
                }
                else
                {
                    nrc = UDS_NRC_PR;
                }
            }
            ctx->link_control.mode_verified = 0;
            break;
        default:
            if (ctx->config->link_control.cb_specific == NULL)
            {
                nrc = UDS_NRC_SFNS;
            }
            else
            {
                ret = ctx->config->link_control.cb_specific(ctx->priv,
                                                            link_control_type,
                                                            &data[1],
                                                            (data_len - 1U));
                if (ret < 0)
                {
                    nrc = UDS_NRC_CNC;
                }
                else
                {
                    nrc = UDS_NRC_PR;
                }
            }
            break;
        }
    }

    if (nrc == UDS_NRC_PR)
    {
        if (UDS_SUPPRESS_PR(data[0]))
        {
            nrc = UDS_SPRMINB;
        }
        else
        {
            res_data[0] = link_control_type;
            *res_data_len = 1;
        }
    }


    return nrc;
}

static uint8_t __uds_svc_read_data_by_identifier(uds_context_t *ctx,
                                                 const struct timespec *timestamp,
                                                 const uint8_t *data, size_t data_len,
                                                 uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if ((data_len == 0U) || ((data_len % 2U) != 0U))
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if ((data_len + (data_len / 2U)) > *res_data_len)
    {
        /* Available space for response shall fit at least the requested
         * identifiers and at least one additional byte for each of them */
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        size_t data_start = 0U;
        size_t res_data_used = 0U;

        nrc = UDS_NRC_PR;
        for (data_start = 0U; data_start < data_len; data_start += 2U)
        {
            uint16_t identifier = UDS_LOAD_UINT16_BIG_ENDIAN(&data[data_start]);
            unsigned long d;

            uds_debug(ctx, "requested to read DID 0x%04X\n", identifier);

            for (d = 0; d < ctx->config->num_data_items; d++)
            {
                if (ctx->config->data_items[d].identifier == identifier)
                {
                    if (NULL == ctx->config->data_items[d].cb_read)
                    {
                        uds_info(ctx, "cb_read not defined for ID 0x%04X\n",
                                 identifier);
                    }
                    else if (__uds_session_check(ctx, &ctx->config->data_items[d].sec_read) != 0)
                    {
                        uds_debug(ctx, "DID 0x%04X cannot be read in active session\n",
                                  identifier);
                    }
                    else if (__uds_security_check(ctx, &ctx->config->data_items[d].sec_read) != 0)
                    {
                        uds_debug(ctx, "DID 0x%04X cannot be read with current SA\n",
                                  identifier);
                        nrc = UDS_NRC_SAD;
                    }
                    else if ((res_data_used + 2U) >= *res_data_len)
                    {
                        uds_info(ctx, "no space for identifier and data for DID 0x%04X\n",
                                 identifier);
                        nrc = UDS_NRC_RTL;
                    }
                    else
                    {
                        size_t res_data_item_len;
                        int ret;

                        __uds_store_big_endian(&res_data[res_data_used], identifier, 2U);
                        res_data_used += 2U;
                        res_data_item_len = *res_data_len - res_data_used;
                        ret = ctx->config->data_items[d].cb_read(ctx->priv, identifier,
                                                                 &res_data[res_data_used],
                                                                 &res_data_item_len);
                        if ((res_data_used + res_data_item_len) > *res_data_len)
                        {
                            uds_info(ctx, "no space for data for DID 0x%04X\n", identifier);
                            nrc = UDS_NRC_RTL;
                        }
                        else if (0 != ret)
                        {
                            uds_err(ctx, "failed to read DID 0x%04X\n", identifier);
                            nrc = UDS_NRC_FPEORA;
                        }
                        else
                        {
                            uds_debug(ctx, "DID 0x%04X read successfully (len = %zu)\n",
                                      identifier, res_data_item_len);
                            res_data_used += res_data_item_len;
                        }
                    }
                    break;
                }
            }

            if (UDS_NRC_PR != nrc)
            {
                break;
            }
        }

        if (nrc != UDS_NRC_PR)
        {
            // An error occurred - nrc will be returned
        }
        else if (res_data_used == 0U)
        {
            /* One of the following condition verified:
             *  - none of the requested identifiers are supported by the device
             *  - none of the requested identifiers are supported in the current session
             *  - the requested dynamic identifier has not been assigned yet
             */
            nrc = UDS_NRC_ROOR;
        }
        else
        {
            *res_data_len = res_data_used;
        }
    }

    return nrc;
}

static uint8_t __uds_svc_read_memory_by_address(uds_context_t *ctx,
                                                const struct timespec *timestamp,
                                                const uint8_t *data, size_t data_len,
                                                uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len < 3U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint8_t addr_len = UDS_LOW_NIBBLE(data[0]);
        uint8_t size_len = UDS_HIGH_NIBBLE(data[0]);

        if ((1U + addr_len + size_len) > data_len)
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else
        {
            uintptr_t addr = 0U;
            size_t size = 0U;
            int ret;

            nrc = UDS_NRC_PR;

            ret = __uds_load_big_endian_addr(&data[1], addr_len, &addr);
            if (ret != 0)
            {
                nrc = UDS_NRC_ROOR;
            }

            ret = __uds_load_big_endian_size(&data[1U + addr_len], size_len, &size);
            if (ret != 0)
            {
                nrc = UDS_NRC_ROOR;
            }

            if (UDS_NRC_PR != nrc)
            {
                uds_debug(ctx, "requested memory read with invalid parameters\n");
                // Nothing to do, NRC is already set
            }
            else if (size == 0U)
            {
                uds_info(ctx, "request read of memory at %p with null size\n", (void *)addr);
                nrc = UDS_NRC_ROOR;
            }
            else
            {
                unsigned long p;

                uds_debug(ctx, "request to read memory at %p, size %zu\n", (void *)addr, size);

                for (p = 0U; p < ctx->config->num_mem_regions; p++)
                {
                    if ((addr >= ctx->config->mem_regions[p].start) &&
                        (addr <= ctx->config->mem_regions[p].stop) &&
                        (NULL != ctx->config->mem_regions[p].cb_read))
                    {
                        if (((uintptr_t)addr + size) > (uintptr_t)ctx->config->mem_regions[p].stop)
                        {
                            uds_debug(ctx, "memory read size too large\n");
                            nrc = UDS_NRC_ROOR;
                        }
                        else if (__uds_session_check(ctx, &ctx->config->mem_regions[p].sec_read) != 0)
                        {
                            nrc = UDS_NRC_ROOR;
                        }
                        else if (__uds_security_check(ctx, &ctx->config->mem_regions[p].sec_read) != 0)
                        {
                            nrc = UDS_NRC_SAD;
                        }
                        else
                        {
                            ret = ctx->config->mem_regions[p].cb_read(ctx->priv, addr,
                                                                      &res_data[0], size);
                            if (ret != 0)
                            {
                                uds_err(ctx, "failed to read memory at %p, len = %zu\n", (void *)addr, size);
                                nrc = UDS_NRC_GR;
                            }
                            else
                            {
                                *res_data_len = size;
                                nrc = UDS_NRC_PR;
                            }
                        }
                        break;
                    }
                }

                if (p == ctx->config->num_mem_regions)
                {
                    uds_debug(ctx, "memory address %p non found in any region\n", (void *)addr);
                    nrc = UDS_NRC_ROOR;
                }
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_read_scaling_data_by_identifier(uds_context_t *ctx,
                                                         const struct timespec *timestamp,
                                                         const uint8_t *data, size_t data_len,
                                                         uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len != 3U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint16_t identifier = UDS_LOAD_UINT16_BIG_ENDIAN(&data[0]);
        unsigned long d;

        uds_debug(ctx, "requested to read scaling data for DID 0x%04X\n", identifier);

        nrc = UDS_NRC_ROOR;
        for (d = 0U; d < ctx->config->num_data_items; d++)
        {
            if (ctx->config->data_items[d].identifier == identifier)
            {
                if ((0 == ctx->config->data_items[d].scaling_data_size) ||
                    (NULL == ctx->config->data_items[d].scaling_data))
                {
                    uds_info(ctx, "scaling_data not defined for ID 0x%04X\n",
                             identifier);
                    nrc = UDS_NRC_ROOR;
                }
                else if (__uds_session_check(ctx, &ctx->config->data_items[d].sec_read) != 0)
                {
                    uds_debug(ctx, "DID 0x%04X cannot be read in active session\n",
                              identifier);
                    nrc = UDS_NRC_ROOR;
                }
                else if (__uds_security_check(ctx, &ctx->config->data_items[d].sec_read) != 0)
                {
                    uds_debug(ctx, "DID 0x%04X cannot be read with current SA\n",
                              identifier);
                    nrc = UDS_NRC_SAD;
                }
                else if (*res_data_len < (2U + ctx->config->data_items[d].scaling_data_size))
                {
                    uds_info(ctx, "not enough space provided for scaling data\n");
                    nrc = UDS_NRC_GR;
                }
                else
                {
                    nrc = UDS_NRC_PR;
                    __uds_store_big_endian(&res_data[0], identifier, 2U);
                    (void)memcpy(&res_data[2],
                                 ctx->config->data_items[d].scaling_data,
                                 ctx->config->data_items[d].scaling_data_size);
                    *res_data_len = (2 + ctx->config->data_items[d].scaling_data_size);
                }
                break;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_write_data_by_identifier(uds_context_t *ctx,
                                                  const struct timespec *timestamp,
                                                  const uint8_t *data, size_t data_len,
                                                  uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len < 3U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint16_t identifier = UDS_LOAD_UINT16_BIG_ENDIAN(&data[0]);
        unsigned long d;

        uds_debug(ctx, "requested to write DID 0x%04X\n", identifier);

        nrc = UDS_NRC_ROOR;
        for (d = 0; d < ctx->config->num_data_items; d++)
        {
            if (ctx->config->data_items[d].identifier == identifier)
            {
                if (NULL == ctx->config->data_items[d].cb_write)
                {
                    uds_info(ctx, "cb_write not defined for DID 0x%04X\n",
                                identifier);
                    nrc = UDS_NRC_ROOR;
                }
                else if (__uds_session_check(ctx, &ctx->config->data_items[d].sec_write) != 0)
                {
                    uds_debug(ctx, "DID 0x%04X cannot be written in active session\n",
                              identifier);
                    nrc = UDS_NRC_ROOR;
                }
                else if (__uds_security_check(ctx, &ctx->config->data_items[d].sec_write) != 0)
                {
                    uds_debug(ctx, "DID 0x%04X cannot be written with current SA\n",
                              identifier);
                    nrc = UDS_NRC_SAD;
                }
                else
                {
                    int ret;

                    ret = ctx->config->data_items[d].cb_write(ctx->priv, identifier,
                                                              &data[2], (data_len - 2U));
                    if (ret != 0)
                    {
                        uds_err(ctx, "failed to write DID 0x%04X\n", identifier);
                        nrc = UDS_NRC_GPF;
                    }
                    else
                    {
                        nrc = UDS_NRC_PR;
                        __uds_store_big_endian(&res_data[0], identifier, 2U);
                        *res_data_len = 2U;
                    }
                }
                break;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_write_memory_by_address(uds_context_t *ctx,
                                                 const struct timespec *timestamp,
                                                 const uint8_t *data, size_t data_len,
                                                 uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len < 4U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint8_t addr_len = UDS_LOW_NIBBLE(data[0]);
        uint8_t size_len = UDS_HIGH_NIBBLE(data[0]);

        size_t min_data_len = (size_t)addr_len + (size_t)size_len + 1U;

        if (data_len < min_data_len)
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else if (*res_data_len < min_data_len)
        {
            uds_info(ctx, "not enough space provided for memory write response\n");
            nrc = UDS_NRC_GR;
        }
        else
        {
            uintptr_t addr = 0U;
            size_t size = 0U;
            int ret;

            nrc = UDS_NRC_PR;

            ret = __uds_load_big_endian_addr(&data[1], addr_len, &addr);
            if (ret != 0)
            {
                nrc = UDS_NRC_ROOR;
            }

            ret = __uds_load_big_endian_size(&data[1U + addr_len], size_len, &size);
            if (ret != 0)
            {
                nrc = UDS_NRC_ROOR;
            }

            if (UDS_NRC_PR != nrc)
            {
                uds_debug(ctx, "requested memory write with invalid parameters\n");
                // Nothing to do, NRC is already set
            }
            else if ((min_data_len + size) > data_len)
            {
                uds_info(ctx, "not enough data provided for memory write\n");
                nrc = UDS_NRC_IMLOIF;
            }
            else
            {
                unsigned long p;

                uds_debug(ctx, "request to write memory at %p, size %zu\n", (void *)addr, size);

                for (p = 0U; p < ctx->config->num_mem_regions; p++)
                {
                    if ((addr >= ctx->config->mem_regions[p].start) &&
                        (addr <= ctx->config->mem_regions[p].stop) &&
                        (NULL != ctx->config->mem_regions[p].cb_write))
                    {
                        if (((uintptr_t)addr + size) > (uintptr_t)ctx->config->mem_regions[p].stop)
                        {
                            uds_debug(ctx, "memory write size too large\n");
                            nrc = UDS_NRC_ROOR;
                        }
                        else if (__uds_session_check(ctx, &ctx->config->mem_regions[p].sec_write) != 0)
                        {
                            nrc = UDS_NRC_ROOR;
                        }
                        else if (__uds_security_check(ctx, &ctx->config->mem_regions[p].sec_write) != 0)
                        {
                            nrc = UDS_NRC_SAD;
                        }
                        else
                        {
                            ret = ctx->config->mem_regions[p].cb_write(ctx->priv, addr,
                                                                       &data[min_data_len], size);
                            if (ret != 0)
                            {
                                uds_err(ctx, "failed to write memory at %p, len = %zu\n", (void *)addr, size);
                                nrc = UDS_NRC_GPF;
                            }
                            else
                            {
                                (void)memcpy(res_data, data, min_data_len);
                                *res_data_len = min_data_len;
                                nrc = UDS_NRC_PR;
                            }
                        }
                        break;
                    }
                }

                if (p == ctx->config->num_mem_regions)
                {
                    uds_debug(ctx, "memory address %p non found in any region\n", (void *)addr);
                    nrc = UDS_NRC_ROOR;
                }
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_io_control_by_identifier(uds_context_t *ctx,
                                                  const struct timespec *timestamp,
                                                  const uint8_t *data, size_t data_len,
                                                  uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len < 3U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint16_t identifier = UDS_LOAD_UINT16_BIG_ENDIAN(&data[0]);
        uint8_t iocp = data[2];
        unsigned long d;

        uds_debug(ctx, "requested IO control with DID 0x%04X\n", identifier);

        for (d = 0; d < ctx->config->num_data_items; d++)
        {
            if (ctx->config->data_items[d].identifier == identifier)
            {
                if (NULL == ctx->config->data_items[d].cb_io)
                {
                    uds_info(ctx, "cb_io not defined for DID 0x%04X\n", identifier);
                    nrc = UDS_NRC_ROOR;
                }
                else if (__uds_session_check(ctx, &ctx->config->data_items[d].sec_io) != 0)
                {
                    uds_debug(ctx, "IO control on DID 0x%04X non supported in active session\n",
                              identifier);
                    nrc = UDS_NRC_ROOR;
                }
                else if ((iocp == UDS_IOCP_STA) && (data_len < 4U))
                {
                    // For Short Term Adjustment, the standard requires at least one controlState byte
                    nrc = UDS_NRC_IMLOIF;
                }
                else if (__uds_security_check(ctx, &ctx->config->data_items[d].sec_write) != 0)
                {
                    uds_debug(ctx, "I/O control on DID 0x%04X not allowed with current SA\n",
                              identifier);
                    nrc = UDS_NRC_SAD;
                }
                else
                {
                    uint8_t *out_data = &res_data[3];
                    size_t out_data_len = *res_data_len - 3U;
                    const uint8_t *control_data = NULL;
                    int ret;

                    if (data_len > 3U)
                    {
                        control_data = &data[3];
                    }

                    ret = ctx->config->data_items[d].cb_io(ctx->priv, identifier, iocp,
                                                           control_data, (data_len - 3U),
                                                           out_data, &out_data_len);
                    if (ret != 0)
                    {
                        uds_err(ctx, "failed to perform IO control on DID 0x%04X\n",
                                identifier);
                        nrc = UDS_NRC_FPEORA;
                    }
                    else
                    {
                        nrc = UDS_NRC_PR;
                        (void)memcpy(res_data, data, 3U);
                        *res_data_len = out_data_len + 3U;
                    }
                }
                break;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_clear_diagnostic_information(uds_context_t *ctx,
                                                      const struct timespec *timestamp,
                                                      const uint8_t *data, size_t data_len,
                                                      uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);
    UDS_UNUSED(res_data);
    UDS_UNUSED(res_data_len);

    if (data_len != 4U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint32_t godtc = __uds_load_big_endian(&data[0], 3U);
        unsigned int d;

        uds_debug(ctx, "requested clear of diagnostic data for GODTC 0x%06X\n", godtc);

        for (d = 0; d < ctx->config->num_groups_of_dtc; d++)
        {
            if ((godtc == ctx->config->groups_of_dtc[d].first) ||
                ((godtc >= ctx->config->groups_of_dtc[d].first) &&
                 (godtc <= ctx->config->groups_of_dtc[d].last)))
            {
                if (__uds_session_check(ctx, &ctx->config->groups_of_dtc[d].sec) != 0)
                {
                    uds_debug(ctx, "cannot clear GODTC 0x%06X in active session\n",
                              godtc);
                    nrc = UDS_NRC_ROOR;
                }
                else if (NULL == ctx->config->groups_of_dtc[d].cb_clear)
                {
                    uds_info(ctx, "cb_clear not defined for GODTC 0x%06X\n", godtc);
                    nrc = UDS_NRC_ROOR;
                }
                else if (ctx->config->groups_of_dtc[d].cb_clear(ctx->priv, godtc) != 0)
                {
                    uds_err(ctx, "failed to clear diagnostic data for GODTC 0x%06X\n",
                            godtc);
                        nrc = UDS_NRC_GPF;
                }
                else
                {
                    nrc = UDS_NRC_PR;
                }
                break;
            }
        }

        if (d == ctx->config->num_groups_of_dtc)
        {
            nrc = UDS_NRC_ROOR;
        }
    }

    return nrc;
}

static uint8_t __uds_rdtci_report_number_of_dtc_by_status_mask(uds_context_t *ctx,
                                                               const uint8_t *data, size_t data_len,
                                                               uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    if (data_len < 1U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if (NULL == ctx->config->dtc_information.cb_get_dtc_status_mask)
    {
        uds_debug(ctx, "cb_get_dtc_status_mask not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else
    {
        uint8_t status_mask = data[0];
        uint16_t number_of_dtc = 0U;
        unsigned long d;

        for (d = 0U; d < ctx->config->dtc_information.number_of_dtcs; d++)
        {
            uint8_t dtc_number = ctx->config->dtc_information.dtcs[d].dtc_number;
            uint8_t dtc_status_mask;
            int ret;

            ret = ctx->config->dtc_information.cb_get_dtc_status_mask(ctx->priv, dtc_number,
                                                                      &dtc_status_mask);
            if (ret != 0)
            {
                uds_err(ctx, "failed to read status of DTC 0x%06X\n", dtc_number);
            }
            else if ((dtc_status_mask & status_mask) != 0x00U)
            {
                number_of_dtc++;
            }
            else
            {
                // Nothing to do for DTCs not matching the searched status mask
            }
        }

        nrc = UDS_NRC_PR;
        res_data[0] = status_mask;
        res_data[1] = ctx->config->dtc_information.format_identifier;
        __uds_store_big_endian(&res_data[2], number_of_dtc, 2U);
        *res_data_len = 4;
    }

    return nrc;
}

static uint8_t __uds_rdtci_report_dtc_by_status_mask(uds_context_t *ctx,
                                                     const uint8_t *data, size_t data_len,
                                                     uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    if (data_len < 1U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if (NULL == ctx->config->dtc_information.cb_get_dtc_status_mask)
    {
        uds_debug(ctx, "cb_get_dtc_status_mask not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else
    {
        uint8_t status_mask = data[0];
        uint8_t * dtc_data = &res_data[1];
        unsigned int d;

        for (d = 0U; d < ctx->config->dtc_information.number_of_dtcs; d++)
        {
            uint32_t dtc_number = (ctx->config->dtc_information.dtcs[d].dtc_number & 0xFFFFFF);
            uint8_t dtc_status_mask;
            int ret;

            ret = ctx->config->dtc_information.cb_get_dtc_status_mask(ctx->priv, dtc_number,
                                                                      &dtc_status_mask);
            if (ret != 0)
            {
                uds_err(ctx, "failed to read status of DTC 0x%06X\n", dtc_number);
            }
            else if ((dtc_status_mask & status_mask) != 0x00U)
            {
                __uds_store_big_endian(&dtc_data[0], dtc_number, 3);
                dtc_data[3] = dtc_status_mask;
                dtc_data += 4;
            }
            else
            {
                // Nothing to do for DTCs not matching the searched status mask
            }
        }

        nrc = UDS_NRC_PR;
        res_data[0] = status_mask;
        *res_data_len = 1U + (dtc_data - &res_data[1]);
    }

    return nrc;
}

static uint8_t __uds_rdtci_report_dtc_snapshot_identification(uds_context_t *ctx,
                                                              const uint8_t *data, size_t data_len,
                                                              uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(data);
    UDS_UNUSED(data_len);

    if (NULL == ctx->config->dtc_information.cb_is_dtc_snapshot_record_available)
    {
        uds_debug(ctx, "cb_is_dtc_snapshot_record_available not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else
    {
        uint8_t *out_data = res_data;
        unsigned long d;

        for (d = 0; d < ctx->config->dtc_information.number_of_dtcs; d++)
        {
            uint32_t dtc_number = ctx->config->dtc_information.dtcs[d].dtc_number;
            unsigned long r;

            for (r = 0U; r < 0xFFU; r++)
            {
                if (((uintptr_t)(out_data - res_data) + 4U) > *res_data_len)
                {
                    break;
                }

                if (ctx->config->dtc_information.cb_is_dtc_snapshot_record_available(ctx->priv, dtc_number, r) != 0)
                {
                    __uds_store_big_endian(&out_data[0], dtc_number, 3U);
                    out_data[3] = r;
                    out_data += 4U;
                }
            }
        }

        nrc = UDS_NRC_PR;
        *res_data_len = (out_data - res_data);
    }

    return nrc;
}

static uint8_t __uds_rdtci_report_dtc_snapshot_record(uds_context_t *ctx,
                                                      const uint8_t *data, size_t data_len,
                                                      uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    if (data_len < 4U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if (NULL == ctx->config->dtc_information.cb_get_dtc_snapshot_record)
    {
        uds_debug(ctx, "cb_get_dtc_snapshot_record not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else if (NULL == ctx->config->dtc_information.cb_get_dtc_status_mask)
    {
        uds_debug(ctx, "cb_get_dtc_status_mask not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else
    {
        uint32_t dtc_number = __uds_load_big_endian(&data[0], 3);
        uint8_t record_number = data[3];
        uint8_t record_start = 0U;
        uint8_t record_stop = 0U;
        unsigned long d;

        // Check if dtc_number is valid
        nrc = UDS_NRC_ROOR;
        for (d = 0U; d < ctx->config->dtc_information.number_of_dtcs; d++)
        {
            if (ctx->config->dtc_information.dtcs[d].dtc_number == dtc_number)
            {
                if (0xFFU == record_number)
                {
                    record_start = 0U;
                    record_stop = 0xFEU;
                }
                else
                {
                    record_start = record_number;
                    record_stop = record_number;
                }
                nrc = UDS_NRC_PR;
                break;
            }
        }

        if (UDS_NRC_PR == nrc)
        {
            uint8_t dtc_status;
            int ret;

            ret = ctx->config->dtc_information.cb_get_dtc_status_mask(ctx->priv, dtc_number,
                                                                      &dtc_status);
            if (ret != 0)
            {
                uds_err(ctx, "failed to read DTC status mask for DTC 0x%06X\n", dtc_number);
                nrc = UDS_NRC_GR;
            }
            else
            {
                size_t used_data_len;
                unsigned int r;

                __uds_store_big_endian(&res_data[0], dtc_number, 3U);
                res_data[3] = dtc_status;
                used_data_len = 4U;

                for (r = record_start; r < record_stop; r++)
                {
                    uint8_t * record_data = &res_data[used_data_len + 1U];
                    size_t record_data_len = used_data_len - 1U;

                    ret = ctx->config->dtc_information.cb_get_dtc_snapshot_record(ctx->priv, dtc_number, r,
                                                                                  record_data, &record_data_len);
                    if ((ret != 0) && (record_start == record_stop))
                    {
                        uds_err(ctx, "failed to read snapshot record 0x%02X for DTC 0x%06X\n",
                                r, dtc_number);
                        nrc = UDS_NRC_ROOR;
                    }
                    else if ((ret == 0) && (record_data_len > 0U))
                    {
                        res_data[used_data_len] = r;
                        used_data_len += (record_data_len + 1U);
                    }
                    else
                    {
                        // Nothing to do if no record has been returned
                    }

                    if (((used_data_len + 1U) >= *res_data_len) || (nrc != UDS_NRC_PR))
                    {
                        break;
                    }
                }
                *res_data_len = used_data_len;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_rdtci_report_dtc_stored_data(uds_context_t *ctx,
                                                  const uint8_t *data, size_t data_len,
                                                  uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    if (data_len < 1U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if (NULL == ctx->config->dtc_information.cb_get_stored_data_record)
    {
        uds_debug(ctx, "cb_get_stored_data_record not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else
    {
        uint8_t record_number = data[0];
        uint8_t record_start = 0U;
        uint8_t record_stop = 0U;
        size_t used_data_len = 0U;
        unsigned int r;

        if (0xFFU == record_number)
        {
            record_start = 0U;
            record_stop = 0xFEU;
        }
        else
        {
            record_start = record_number;
            record_stop = record_number;
        }

        for (r = record_start; r < record_stop; r++)
        {
            uint8_t * record_data = &res_data[used_data_len + 1U];
            size_t record_data_len = used_data_len - 1U;
            int ret;

            ret = ctx->config->dtc_information.cb_get_stored_data_record(ctx->priv, r,
                                                                         record_data, &record_data_len);
            if ((ret != 0) && (record_start == record_stop))
            {
                uds_err(ctx, "failed to read stored data record 0x%02X\n", r);
                nrc = UDS_NRC_ROOR;
            }
            else if ((ret == 0) && (record_data_len > 0U))
            {
                res_data[used_data_len] = r;
                used_data_len += (record_data_len + 1U);
            }
            else
            {
                // Nothing to do
            }

            if (((used_data_len + 1U) >= *res_data_len) || (nrc != UDS_NRC_PR))
            {
                break;
            }
        }
        *res_data_len = used_data_len;
    }

    return nrc;
}

static uint8_t __uds_rdtci_report_dtc_extended_data(uds_context_t *ctx,
                                                    const uint8_t *data, size_t data_len,
                                                    uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    if (data_len < 4U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if (NULL == ctx->config->dtc_information.cb_get_dtc_extended_data_record)
    {
        uds_debug(ctx, "cb_get_dtc_extended_data_record not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else if (NULL == ctx->config->dtc_information.cb_get_dtc_status_mask)
    {
        uds_debug(ctx, "cb_get_dtc_status_mask not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else
    {
        uint32_t dtc_number = __uds_load_big_endian(&data[0], 3U);
        uint8_t record_number = data[3];
        uint8_t record_start = 0U;
        uint8_t record_stop = 0U;
        unsigned long d;

        // Check if dtc_number is valid
        nrc = UDS_NRC_ROOR;
        for (d = 0U; d < ctx->config->dtc_information.number_of_dtcs; d++)
        {
            if (ctx->config->dtc_information.dtcs[d].dtc_number == dtc_number)
            {
                if (0xFEU == record_number)
                {
                    // OBD extended data records
                    record_start = 0x90U;
                    record_stop = 0xEFU;

                }
                else if (0xFFU == record_number)
                {
                    record_start = 0U;
                    record_stop = 0xFDU;
                }
                else
                {
                    record_start = record_number;
                    record_stop = record_number;
                }
                nrc = UDS_NRC_PR;
                break;
            }
        }

        if (UDS_NRC_PR == nrc)
        {
            uint8_t dtc_status;
            int ret;

            ret = ctx->config->dtc_information.cb_get_dtc_status_mask(ctx->priv, dtc_number,
                                                                      &dtc_status);
            if (ret != 0)
            {
                uds_err(ctx, "failed to read DTC status mask for DTC 0x%06X\n", dtc_number);
                nrc = UDS_NRC_GR;
            }
            else
            {
                size_t used_data_len;
                unsigned int r;

                __uds_store_big_endian(&res_data[0], dtc_number, 3U);
                res_data[3] = dtc_status;

                used_data_len = 4U;

                for (r = record_start; r < record_stop; r++)
                {
                    uint8_t * record_data = &res_data[used_data_len + 1U];
                    size_t record_data_len = used_data_len - 1U;
                    ret = ctx->config->dtc_information.cb_get_dtc_extended_data_record(ctx->priv, dtc_number, r,
                                                                                       record_data, &record_data_len);
                    if ((ret != 0) && (record_start == record_stop))
                    {
                        uds_err(ctx, "failed to read extended data record 0x%02X for DTC 0x%06X\n",
                                r, dtc_number);
                        nrc = UDS_NRC_ROOR;

                    }
                    else if ((ret == 0) && (record_data_len > 0U))
                    {
                        res_data[used_data_len] = r;
                        used_data_len += (record_data_len + 1U);
                    }
                    else
                    {
                        // Nothing to do
                    }

                    if (((used_data_len + 1U) >= *res_data_len) || (nrc != UDS_NRC_PR))
                    {
                        break;
                    }
                }
                *res_data_len = used_data_len;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_read_dtc_information(uds_context_t *ctx,
                                              const struct timespec *timestamp,
                                              const uint8_t *data, size_t data_len,
                                              uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len < 1U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint8_t report_type = UDS_GET_SUBFUNCTION(data[0]);
        size_t in_data_len = (data_len - 1U);
        const uint8_t *in_data = NULL;
        uint8_t *out_data = NULL;
        size_t out_data_len = 0U;

        if (in_data_len > 0U)
        {
            in_data = &data[1];
        }

        out_data_len = (*res_data_len - 1U);
        out_data = &res_data[1];

        uds_debug(ctx, "read DTC information with reportType 0x%02X\n", report_type);

        switch (report_type)
        {
        case UDS_LEV_RNODTCBSM:
            nrc = __uds_rdtci_report_number_of_dtc_by_status_mask(ctx, in_data, in_data_len,
                                                                  out_data, &out_data_len);
            break;

        case UDS_LEV_RDTCBSM:
            nrc = __uds_rdtci_report_dtc_by_status_mask(ctx, in_data, in_data_len,
                                                        out_data, &out_data_len);
            break;

        case UDS_LEV_RDTCSSI:
            nrc = __uds_rdtci_report_dtc_snapshot_identification(ctx, in_data, in_data_len,
                                                                 out_data, &out_data_len);
            break;

        case UDS_LEV_RDTCSSBDTC:
            nrc = __uds_rdtci_report_dtc_snapshot_record(ctx, in_data, in_data_len,
                                                         out_data, &out_data_len);
            break;

        case UDS_LEV_RDTCSDBRN:
            nrc = __uds_rdtci_report_dtc_stored_data(ctx, in_data, in_data_len,
                                                     out_data, &out_data_len);
            break;

        case UDS_LEV_RDTCEDRBDN:
            nrc = __uds_rdtci_report_dtc_extended_data(ctx, in_data, in_data_len,
                                                       out_data, &out_data_len);
            break;

        case UDS_LEV_RNODTCBSMR:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RDTCBSMR:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RSIODTC:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RSUPDTC:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RFTFDTC:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RFCDTC:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RMRTFDTC:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RMRCDTC:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RMMDTCBSM:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RMDEDRBDN:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RNOMMDTCBSM:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RNOOEBDDTCBSM:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_ROBDDTCBSM:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RDTCFDC:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RDTCWPS:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RDTCEDRBR:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RUDMDTCBSM:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RUDMDTCSSBDTC:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RUDMDTCEDRBDN:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_ROBDDTCBMR:
            nrc = UDS_NRC_SFNS;
            break;
        case UDS_LEV_RWWHOBDDTCWPS:
            nrc = UDS_NRC_SFNS;
            break;
        default:
            nrc = UDS_NRC_SFNS;
            break;
        }

        if (UDS_NRC_PR == nrc)
        {
            res_data[0] = report_type;
            *res_data_len = (out_data_len + 1U);
        }
    }

    return nrc;
}

static uint8_t __uds_svc_routine_control(uds_context_t *ctx,
                                         const struct timespec *timestamp,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len < 3U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint8_t routine_control_type = UDS_GET_SUBFUNCTION(data[0]);
        uint16_t identifier = UDS_LOAD_UINT16_BIG_ENDIAN(&data[1]);
        const uint8_t *control_data = NULL;
        uint8_t *out_data = NULL;
        size_t out_data_len = 0U;
        unsigned long r;

        if (data_len > 3U)
        {
            control_data = &data[3];
        }

        if (*res_data_len > 3U)
        {
            out_data = &res_data[3];
            out_data_len = (*res_data_len - 3U);
        }

        nrc = UDS_NRC_ROOR;
        for (r = 0U; r < ctx->config->num_routines; r++)
        {
            if (ctx->config->routines[r].identifier == identifier)
            {
                if (__uds_session_check(ctx, &ctx->config->ecureset.sec_reset_hard) != 0)
                {
                    nrc = UDS_NRC_SFNSIAS;
                }
                else if (__uds_security_check(ctx, &ctx->config->ecureset.sec_reset_hard) != 0)
                {
                    nrc = UDS_NRC_SAD;
                }
                else if (UDS_LEV_RCTP_STR == routine_control_type)
                {
                    if (NULL == ctx->config->routines[r].cb_start)
                    {
                        nrc = UDS_NRC_SFNS;
                    }
                    else if (ctx->config->routines[r].cb_start(ctx->priv, identifier,
                                                               control_data, (data_len - 3U),
                                                               out_data, &out_data_len) != 0)
                    {
                        /* If start failed but routine is running, it means that
                         * it was already running and cannot be restarted */
                        if ((NULL != ctx->config->routines[r].cb_is_running) &&
                            (ctx->config->routines[r].cb_is_running(ctx->priv, identifier) != 0))
                        {
                                uds_err(ctx, "cb_start(%04X) -> routine is already running\n",
                                        identifier);
                                nrc = UDS_NRC_RSE;
                        }
                        else
                        {
                            uds_err(ctx, "cb_start(%04X) failed\n", identifier);
                            nrc = UDS_NRC_GPF;
                        }
                    }
                    else
                    {
                        nrc = UDS_NRC_PR;
                    }
                }
                else if (UDS_LEV_RCTP_STPR == routine_control_type)
                {
                    if (NULL == ctx->config->routines[r].cb_stop)
                    {
                        nrc = UDS_NRC_SFNS;
                    }
                    else if ((NULL != ctx->config->routines[r].cb_is_running) &&
                            (ctx->config->routines[r].cb_is_running(ctx->priv, identifier) == 0))
                    {
                        uds_err(ctx, "cb_stop(%04X) -> routine is not running\n", identifier);
                        nrc = UDS_NRC_RSE;
                    }
                    else if (ctx->config->routines[r].cb_stop(ctx->priv, identifier,
                                                              control_data, (data_len - 3U),
                                                              out_data, &out_data_len) != 0)
                    {
                        uds_err(ctx, "cb_stop(%04X) failed\n", identifier);
                        nrc = UDS_NRC_GPF;
                    }
                    else
                    {
                        nrc = UDS_NRC_PR;
                    }
                }
                else if (UDS_LEV_RCTP_RRR == routine_control_type)
                {
                    if (NULL == ctx->config->routines[r].cb_req_results)
                    {
                        nrc = UDS_NRC_SFNS;
                    }
                    else if (ctx->config->routines[r].cb_req_results(ctx->priv, identifier,
                                                                     out_data, &out_data_len) != 0)
                    {
                        uds_err(ctx, "cb_req_results(%04X) failed\n", identifier);
                        nrc = UDS_NRC_RSE;
                    }
                    else
                    {
                        nrc = UDS_NRC_PR;
                    }
                }
                else
                {
                    uds_err(ctx, "unsupported routine control type 0x%02X\n", routine_control_type);
                }
                break;
            }
        }

        if (UDS_NRC_PR == nrc)
        {
            (void)memcpy(res_data, data, 3U);
            *res_data_len = out_data_len + 3U;
        }
    }

    return nrc;
}

static uint8_t __uds_svc_request_download(uds_context_t *ctx,
                                          const struct timespec *timestamp,
                                          const uint8_t *data, size_t data_len,
                                          uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len < 4U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint8_t encrypting_method  = UDS_LOW_NIBBLE(data[0]);
        uint8_t compression_method = UDS_HIGH_NIBBLE(data[0]);

        uint8_t addr_len = UDS_LOW_NIBBLE(data[1]);
        uint8_t size_len = UDS_HIGH_NIBBLE(data[1]);

        if ((2U + addr_len + size_len) > data_len)
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else
        {
            uintptr_t addr = 0U;
            size_t size = 0U;
            int ret;

            nrc = UDS_NRC_PR;

            ret = __uds_load_big_endian_addr(&data[2], addr_len, &addr);
            if (ret != 0)
            {
                nrc = UDS_NRC_ROOR;
            }

            ret = __uds_load_big_endian_size(&data[2U + addr_len], size_len, &size);
            if (ret != 0)
            {
                nrc = UDS_NRC_ROOR;
            }

            if (UDS_NRC_PR != nrc)
            {
                uds_debug(ctx, "requested download with invalid parameters\n");
                // Nothing to do, NRC is already set
            }
            else if (size == 0U)
            {
                uds_info(ctx, "request download at %p with null size\n", (void *)addr);
                nrc = UDS_NRC_ROOR;
            }
            else
            {
                unsigned long p;

                uds_debug(ctx, "request to download at %p, size %zu\n", (void *)addr, size);

                for (p = 0U; p < ctx->config->num_mem_regions; p++)
                {
                    if ((addr >= ctx->config->mem_regions[p].start) &&
                        (addr <= ctx->config->mem_regions[p].stop) &&
                        (NULL != ctx->config->mem_regions[p].cb_download_request) &&
                        (NULL != ctx->config->mem_regions[p].cb_download))
                    {
                        if (((uintptr_t)addr + size) > (uintptr_t)ctx->config->mem_regions[p].stop)
                        {
                            uds_debug(ctx, "download size too large\n");
                            nrc = UDS_NRC_ROOR;
                        }
                        else if (__uds_session_check(ctx, &ctx->config->mem_regions[p].sec_download) != 0)
                        {
                            nrc = UDS_NRC_ROOR;
                        }
                        else if (__uds_security_check(ctx, &ctx->config->mem_regions[p].sec_download) != 0)
                        {
                            nrc = UDS_NRC_SAD;
                        }
                        else if (ctx->data_transfer.direction != UDS_DATA_TRANSFER_NONE)
                        {
                            nrc = UDS_NRC_CNC;
                        }
                        else
                        {
                            ret = ctx->config->mem_regions[p].cb_download_request(ctx->priv,
                                                                                  addr, size,
                                                                                  compression_method,
                                                                                  encrypting_method);
                            if (ret != 0)
                            {
                                uds_err(ctx, "failed to request download at %p, len = %zu\n", (void *)addr, size);
                                nrc = UDS_NRC_UDNA;
                            }
                            else
                            {
                                /* The max_block_len length reflects the complete message length,
                                 * including the service identifier and the data-parameters */
                                size_len = sizeof(size_t);
                                res_data[0] = UDS_FROM_NIBBLES(0U, size_len);
                                __uds_store_big_endian(&res_data[1], (ctx->config->mem_regions[p].max_block_len + 2U), size_len);
                                *res_data_len = (1U + size_len);
                                nrc = UDS_NRC_PR;

                                __uds_data_transfer_reset(ctx);
                                ctx->data_transfer.direction = UDS_DATA_TRANSFER_DOWNLOAD;
                                ctx->data_transfer.mem_region = &ctx->config->mem_regions[p];
                                /* Block sequence counter starts from 1 */
                                ctx->data_transfer.bsqc = 0x01U;
                                ctx->data_transfer.max_block_len = ctx->config->mem_regions[p].max_block_len;
                            }
                        }
                        break;
                    }
                }

                if (p == ctx->config->num_mem_regions)
                {
                    uds_debug(ctx, "download address %p non found in any region\n", (void *)addr);
                    nrc = UDS_NRC_ROOR;
                }
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_request_upload(uds_context_t *ctx,
                                        const struct timespec *timestamp,
                                        const uint8_t *data, size_t data_len,
                                        uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len < 4U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint8_t encrypting_method  = UDS_LOW_NIBBLE(data[0]);
        uint8_t compression_method = UDS_HIGH_NIBBLE(data[0]);

        uint8_t addr_len = UDS_LOW_NIBBLE(data[1]);
        uint8_t size_len = UDS_HIGH_NIBBLE(data[1]);

        if ((2U + addr_len + size_len) > data_len)
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else
        {
            uintptr_t addr = 0U;
            size_t size = 0U;
            int ret;

            nrc = UDS_NRC_PR;

            ret = __uds_load_big_endian_addr(&data[2], addr_len, &addr);
            if (ret != 0)
            {
                nrc = UDS_NRC_ROOR;
            }

            ret = __uds_load_big_endian_size(&data[2U + addr_len], size_len, &size);
            if (ret != 0)
            {
                nrc = UDS_NRC_ROOR;
            }

            if (UDS_NRC_PR != nrc)
            {
                uds_debug(ctx, "requested upload with invalid parameters\n");
                // Nothing to do, NRC is already set
            }
            else if (size == 0U)
            {
                uds_info(ctx, "request upload from %p with null size\n", (void *)addr);
                nrc = UDS_NRC_ROOR;
            }
            else
            {
                unsigned long p;

                uds_debug(ctx, "request to upload from %p, size %zu\n", (void *)addr, size);

                for (p = 0U; p < ctx->config->num_mem_regions; p++)
                {
                    if ((addr >= ctx->config->mem_regions[p].start) &&
                        (addr <= ctx->config->mem_regions[p].stop) &&
                        (NULL != ctx->config->mem_regions[p].cb_upload_request) &&
                        (NULL != ctx->config->mem_regions[p].cb_upload))
                    {
                        if (((uintptr_t)addr + size) > (uintptr_t)ctx->config->mem_regions[p].stop)
                        {
                            uds_debug(ctx, "upload size too large\n");
                            nrc = UDS_NRC_ROOR;
                        }
                        else if (__uds_session_check(ctx, &ctx->config->mem_regions[p].sec_upload) != 0)
                        {
                            nrc = UDS_NRC_ROOR;
                        }
                        else if (__uds_security_check(ctx, &ctx->config->mem_regions[p].sec_upload) != 0)
                        {
                            nrc = UDS_NRC_SAD;
                        }
                        else if (ctx->data_transfer.direction != UDS_DATA_TRANSFER_NONE)
                        {
                            nrc = UDS_NRC_CNC;
                        }
                        else
                        {
                            ret = ctx->config->mem_regions[p].cb_upload_request(ctx->priv,
                                                                                addr, size,
                                                                                compression_method,
                                                                                encrypting_method);
                            if (ret != 0)
                            {
                                uds_err(ctx, "failed to request upload from %p, len = %zu\n", (void *)addr, size);
                                nrc = UDS_NRC_UDNA;
                            }
                            else
                            {
                                /* The max_block_size length reflects the complete message length,
                                 * including the service identifier and the data-parameters */
                                size_len = (uint8_t)sizeof(size_t);
                                res_data[0] = UDS_FROM_NIBBLES(0U, size_len);
                                __uds_store_big_endian(&res_data[1], (ctx->config->mem_regions[p].max_block_len + 2), size_len);
                                *res_data_len = (1U + (size_t)size_len);
                                nrc = UDS_NRC_PR;

                                __uds_data_transfer_reset(ctx);
                                ctx->data_transfer.direction = UDS_DATA_TRANSFER_UPLOAD;
                                ctx->data_transfer.mem_region = &ctx->config->mem_regions[p];
                                /* Block sequence counter starts from 1 */
                                ctx->data_transfer.bsqc = 1U;
                                ctx->data_transfer.max_block_len = ctx->config->mem_regions[p].max_block_len;
                            }
                        }
                        break;
                    }
                }

                if (p == ctx->config->num_mem_regions)
                {
                    uds_debug(ctx, "upload address %p non found in any region\n", (void *)addr);
                    nrc = UDS_NRC_ROOR;
                }
            }
        }
    }

    return nrc;
}

static uint8_t __uds_transmit_data_download(uds_context_t *ctx, uint8_t bsqc,
                                            const uint8_t *data, size_t data_len,
                                            uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    uds_debug(ctx, "data download bsqc = 0x%02X len = %zu\n", bsqc, data_len);

    if (data_len > ctx->data_transfer.max_block_len)
    {
        nrc = UDS_NRC_ROOR;
    }
    else if (bsqc == ctx->data_transfer.bsqc)
    {
        int ret;

        if (ctx->data_transfer.direction == UDS_DATA_TRANSFER_DOWNLOAD_FILE)
        {
            ret = ctx->config->file_transfer.cb_write(ctx->priv,
                                                      ctx->data_transfer.fd,
                                                      (size_t)ctx->data_transfer.address,
                                                      data, data_len);
        }
        else if (ctx->data_transfer.direction == UDS_DATA_TRANSFER_DOWNLOAD)
        {
            ret = ctx->data_transfer.mem_region->cb_download(ctx->priv,
                                                             ctx->data_transfer.address,
                                                             data, data_len);
        }
        else
        {
            uds_err(ctx, "invalid data transfer direction\n");
            ret = -1;
        }

        if (ret != 0)
        {
            uds_err(ctx, "download of block %u failed (address %p, size %zu)\n",
                    bsqc, (void *)ctx->data_transfer.address, data_len);
            nrc = UDS_NRC_GPF;
        }
        else
        {
            nrc = UDS_NRC_PR;
            res_data[0] = bsqc;
            *res_data_len = 1;
            ctx->data_transfer.bsqc = (ctx->data_transfer.bsqc + 1) & 0xFF;
            ctx->data_transfer.address = (ctx->data_transfer.address + data_len);
        }
    }
    else if (bsqc == ((ctx->data_transfer.bsqc - 1) & 0xFF))
    {
        /* Requested download of previous block: it means that the client did
         * not receive the positive response, resend it */
        nrc = UDS_NRC_PR;
        res_data[0] = bsqc;
        *res_data_len = 1;
    }
    else
    {
        uds_warning(ctx, "wrong block sequence counter %u, expected %u or %d\n",
                    bsqc, ctx->data_transfer.bsqc,
                    (ctx->data_transfer.bsqc - 1) & 0xFF);
        nrc = UDS_NRC_WBSC;
    }

    return nrc;
}

static uint8_t __uds_transmit_data_upload(uds_context_t *ctx, uint8_t bsqc,
                                          uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    size_t read_data = ctx->data_transfer.max_block_len;
    int ret;

    if ((*res_data_len - 1) < ctx->data_transfer.max_block_len)
    {
        nrc = UDS_NRC_ROOR;
    }
    else if (bsqc == ctx->data_transfer.bsqc)
    {
        if (ctx->data_transfer.direction == UDS_DATA_TRANSFER_UPLOAD_FILE)
        {
            ret = ctx->config->file_transfer.cb_read(ctx->priv,
                                                     ctx->data_transfer.fd,
                                                     (size_t)ctx->data_transfer.address,
                                                     &res_data[1], &read_data);
        }
        else if (ctx->data_transfer.direction == UDS_DATA_TRANSFER_UPLOAD)
        {
            ret = ctx->data_transfer.mem_region->cb_upload(ctx->priv,
                                                           ctx->data_transfer.address,
                                                           &res_data[1], &read_data);
        }
        else
        {
            uds_err(ctx, "invalid data transfer direction\n");
            ret = -1;
        }

        if (ret != 0)
        {
            uds_err(ctx, "upload of block %u failed (address %p)\n",
                    bsqc, (void *)ctx->data_transfer.address);
            nrc = UDS_NRC_GPF;
        }
        else
        {
            nrc = UDS_NRC_PR;
            res_data[0] = bsqc;
            *res_data_len = (read_data + 1U);
            ctx->data_transfer.bsqc = (ctx->data_transfer.bsqc + 1U) & 0xFF;
            ctx->data_transfer.prev_address = ctx->data_transfer.address;
            ctx->data_transfer.address = (ctx->data_transfer.address + read_data);
        }
    }
    else if ((bsqc == ((ctx->data_transfer.bsqc - 1U) & 0xFF)) &&
             (ctx->data_transfer.prev_address != 0))
    {
        ret = ctx->data_transfer.mem_region->cb_upload(ctx->priv,
                                                       ctx->data_transfer.prev_address,
                                                       &res_data[1], &read_data);
        if (ret != 0)
        {
            uds_err(ctx, "re-upload of block %u failed (address %p)\n",
                    bsqc, (void *)ctx->data_transfer.prev_address);
            nrc = UDS_NRC_GPF;
        }
        else
        {
            nrc = UDS_NRC_PR;
            res_data[0] = bsqc;
            *res_data_len = (read_data + 1U);
        }
    }
    else
    {
        uds_warning(ctx, "wrong block sequence counter %u, expected %u or %u\n",
                    bsqc, ctx->data_transfer.bsqc,
                    (ctx->data_transfer.bsqc - 1U) & 0xFF);
        nrc = UDS_NRC_WBSC;
    }

    return nrc;
}

static uint8_t __uds_svc_transmit_data(uds_context_t *ctx,
                                       const struct timespec *timestamp,
                                       const uint8_t *data, size_t data_len,
                                       uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if ((UDS_DATA_TRANSFER_DOWNLOAD == ctx->data_transfer.direction) ||
        (UDS_DATA_TRANSFER_DOWNLOAD_FILE == ctx->data_transfer.direction))
    {
        if (data_len < 2U)
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else
        {
            nrc = __uds_transmit_data_download(ctx, data[0],
                                               &data[1], (data_len - 1U),
                                               res_data, res_data_len);
        }
    }
    else if ((UDS_DATA_TRANSFER_UPLOAD == ctx->data_transfer.direction) ||
             (UDS_DATA_TRANSFER_UPLOAD_FILE == ctx->data_transfer.direction) ||
             (UDS_DATA_TRANSFER_LIST_DIR == ctx->data_transfer.direction))
    {
        if (data_len < 1U)
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else
        {
            nrc = __uds_transmit_data_upload(ctx, data[0],
                                             res_data, res_data_len);
        }
    }
    else
    {
        nrc = UDS_NRC_RSE;
    }

    return nrc;
}

static uint8_t __uds_svc_request_transfer_exit(uds_context_t *ctx,
                                               const struct timespec *timestamp,
                                               const uint8_t *data, size_t data_len,
                                               uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    int ret;

    UDS_UNUSED(timestamp);
    UDS_UNUSED(data);
    UDS_UNUSED(data_len);
    UDS_UNUSED(res_data);

    *res_data_len = 0;

    if (UDS_DATA_TRANSFER_DOWNLOAD == ctx->data_transfer.direction)
    {
        nrc = UDS_NRC_PR;
        if (NULL != ctx->data_transfer.mem_region->cb_download_exit)
        {
            ret = ctx->data_transfer.mem_region->cb_download_exit(ctx->priv);
            if (ret != 0)
            {
                uds_err(ctx, "download exit failed\n");
                nrc = UDS_NRC_GPF;
            }
        }
        __uds_data_transfer_reset(ctx);
    }
    else if (UDS_DATA_TRANSFER_UPLOAD == ctx->data_transfer.direction)
    {
        nrc = UDS_NRC_PR;
        if (NULL != ctx->data_transfer.mem_region->cb_upload_exit)
        {
            ret = ctx->data_transfer.mem_region->cb_upload_exit(ctx->priv);
            if (ret != 0)
            {
                uds_err(ctx, "upload exit failed\n");
                nrc = UDS_NRC_GPF;
            }
        }
        __uds_data_transfer_reset(ctx);
    }
    else if (UDS_DATA_TRANSFER_DOWNLOAD_FILE == ctx->data_transfer.direction)
    {
        nrc = UDS_NRC_PR;
        if (NULL != ctx->config->file_transfer.cb_close)
        {
            ret = ctx->config->file_transfer.cb_close(ctx->priv,
                                                      ctx->data_transfer.file_mode,
                                                      ctx->data_transfer.fd);
            if (ret != 0)
            {
                uds_err(ctx, "file download close failed\n");
                nrc = UDS_NRC_GPF;
            }
        }
        __uds_data_transfer_reset(ctx);
    }
    else if (UDS_DATA_TRANSFER_UPLOAD_FILE == ctx->data_transfer.direction)
    {
        nrc = UDS_NRC_PR;
        if (NULL != ctx->config->file_transfer.cb_close)
        {
            ret = ctx->config->file_transfer.cb_close(ctx->priv,
                                                      ctx->data_transfer.file_mode,
                                                      ctx->data_transfer.fd);
            if (ret != 0)
            {
                uds_err(ctx, "file upload close failed\n");
                nrc = UDS_NRC_GPF;
            }
        }
        __uds_data_transfer_reset(ctx);
    }
    else if (UDS_DATA_TRANSFER_LIST_DIR == ctx->data_transfer.direction)
    {
        nrc = UDS_NRC_PR;
        if (NULL != ctx->config->file_transfer.cb_close)
        {
            ret = ctx->config->file_transfer.cb_close(ctx->priv,
                                                      ctx->data_transfer.file_mode,
                                                      ctx->data_transfer.fd);
            if (ret != 0)
            {
                uds_err(ctx, "dir close failed\n");
                nrc = UDS_NRC_GPF;
            }
        }
        __uds_data_transfer_reset(ctx);
    }
    else
    {
        nrc = UDS_NRC_RSE;
    }

    return nrc;
}

static uint8_t __uds_file_transfer_addfile(uds_context_t *ctx,
                                           const uint8_t *data, size_t data_len,
                                           uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_SFNS;

    if ((NULL == ctx->config->file_transfer.cb_open) ||
        (NULL == ctx->config->file_transfer.cb_write))
    {
        uds_debug(ctx, "cb_open or cb_write not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else if (data_len < 5U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        size_t file_path_len = UDS_LOAD_UINT16_BIG_ENDIAN(&data[1]);
        if (data_len < (5U + file_path_len))
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else if (file_path_len > UDS_FILEPATH_MAX)
        {
            nrc = UDS_NRC_ROOR;
        }
        else
        {
            uint8_t filesize_param_len = data[3U + file_path_len + 1U];
            if (data_len < (5U + file_path_len + (2U * filesize_param_len)))
            {
                nrc = UDS_NRC_IMLOIF;
            }
            else if (filesize_param_len > sizeof(size_t))
            {
                nrc = UDS_NRC_ROOR;
            }
            else
            {
                intptr_t file_fd = -1;
                int ret = -1;

                /* NOTE: file_path might not be zero-terminated */
                const char * file_path = (const char *)&data[3];
                uint8_t data_format_identifier = data[3U + file_path_len];

                uint8_t compression_method = UDS_HIGH_NIBBLE(data_format_identifier);
                uint8_t encrypting_method = UDS_LOW_NIBBLE(data_format_identifier);

                /* Extract sizes from incoming data */
                size_t filesize_uncompressed = __uds_load_big_endian(&data[4U + file_path_len],
                                                                     filesize_param_len);

                size_t filesize_compressed = __uds_load_big_endian(&data[4U + file_path_len + filesize_param_len],
                                                                   filesize_param_len);

                uds_debug(ctx, "add file at %.*s, size %zu (%zu cmp), cmp=%u, enc=%u\n",
                          (int)file_path_len, file_path,
                          filesize_uncompressed, filesize_compressed,
                          compression_method, encrypting_method);

                ret = ctx->config->file_transfer.cb_open(ctx->priv,
                                                         file_path, file_path_len,
                                                         UDS_FILE_MODE_WRITE_CREATE,
                                                         &file_fd,
                                                         &filesize_uncompressed,
                                                         &filesize_compressed,
                                                         compression_method,
                                                         encrypting_method);
                if (ret < 0)
                {
                    uds_err(ctx, "failed to open file %.*s for writing\n",
                            (int)file_path_len, file_path);
                    nrc = UDS_NRC_UDNA;
                }
                else
                {
                    const uint8_t size_len = sizeof(size_t);

                    res_data[0] = data[0];
                    /* The max_block_len length reflects the complete message length,
                     * including the service identifier and the data-parameters */
                    res_data[1] = size_len;
                    __uds_store_big_endian(&res_data[2], (ctx->config->file_transfer.max_block_len + 2U), size_len);
                    res_data[2U + size_len] = data_format_identifier;
                    *res_data_len = (3U + size_len);
                    nrc = UDS_NRC_PR;

                    __uds_data_transfer_reset(ctx);
                    ctx->data_transfer.direction = UDS_DATA_TRANSFER_DOWNLOAD_FILE;
                    ctx->data_transfer.file_mode = UDS_FILE_MODE_WRITE_CREATE;
                    ctx->data_transfer.fd = file_fd;
                    /* Block sequence counter starts from 1 */
                    ctx->data_transfer.bsqc = 0x01U;
                    ctx->data_transfer.max_block_len = ctx->config->file_transfer.max_block_len;
                }
            }
        }
    }

    return nrc;
}

static uint8_t __uds_file_transfer_delfile(uds_context_t *ctx,
                                           const uint8_t *data, size_t data_len,
                                           uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_SFNS;

    if (NULL == ctx->config->file_transfer.cb_delete)
    {
        uds_debug(ctx, "cb_delete not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else if (data_len < 5U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        size_t file_path_len = UDS_LOAD_UINT16_BIG_ENDIAN(&data[1]);
        if (data_len < (5U + file_path_len))
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else if (file_path_len > UDS_FILEPATH_MAX)
        {
            nrc = UDS_NRC_ROOR;
        }
        else
        {
            int ret;

            /* NOTE: file_path might not be zero-terminated */
            const char * file_path = (const char *)&data[3];

            uds_debug(ctx, "delete file at %.*s\n",
                          (int)file_path_len, file_path);

            ret = ctx->config->file_transfer.cb_delete(ctx->priv,
                                                       file_path, file_path_len);
            if (ret < 0)
            {
                uds_err(ctx, "failed to delete file %.*s\n",
                        (int)file_path_len, file_path);
                nrc = UDS_NRC_UDNA;
            }
            else
            {
                nrc = UDS_NRC_PR;
                res_data[0] = data[0];
                *res_data_len = 1;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_file_transfer_replfile(uds_context_t *ctx,
                                            const uint8_t *data, size_t data_len,
                                            uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_SFNS;

    if ((NULL == ctx->config->file_transfer.cb_open) ||
        (NULL == ctx->config->file_transfer.cb_write))
    {
        uds_debug(ctx, "cb_open or cb_write not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else if (data_len < 5U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        size_t file_path_len = UDS_LOAD_UINT16_BIG_ENDIAN(&data[1]);
        if (data_len < (5U + file_path_len))
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else if (file_path_len > UDS_FILEPATH_MAX)
        {
            nrc = UDS_NRC_ROOR;
        }
        else
        {
            uint8_t filesize_param_len = data[3U + file_path_len + 1U];
            if (data_len < (5U + file_path_len + (2U * filesize_param_len)))
            {
                nrc = UDS_NRC_IMLOIF;
            }
            else if (filesize_param_len > sizeof(size_t))
            {
                nrc = UDS_NRC_ROOR;
            }
            else
            {
                intptr_t file_fd = -1;
                int ret = -1;

                /* NOTE: file_path might not be zero-terminated */
                const char * file_path = (const char *)&data[3];
                uint8_t data_format_identifier = data[3U + file_path_len];

                uint8_t compression_method = UDS_HIGH_NIBBLE(data_format_identifier);
                uint8_t encrypting_method = UDS_LOW_NIBBLE(data_format_identifier);

                /* Extract sizes from incoming data */
                size_t filesize_uncompressed = __uds_load_big_endian(&data[5U + file_path_len],
                                                                     filesize_param_len);

                size_t filesize_compressed = __uds_load_big_endian(&data[5U + file_path_len + filesize_param_len],
                                                                   filesize_param_len);

                uds_debug(ctx, "replace file at %.*s, size=%zu (%zu cmp), cmp=%u, enc=%u\n",
                          (int)file_path_len, file_path,
                          filesize_uncompressed, filesize_compressed,
                          compression_method, encrypting_method);

                ret = ctx->config->file_transfer.cb_open(ctx->priv,
                                                         file_path, file_path_len,
                                                         UDS_FILE_MODE_WRITE_REPLACE,
                                                         &file_fd,
                                                         &filesize_uncompressed,
                                                         &filesize_compressed,
                                                         compression_method,
                                                         encrypting_method);
                if (ret < 0)
                {
                    uds_err(ctx, "failed to open file %.*s for writing\n",
                            (int)file_path_len, file_path);
                    nrc = UDS_NRC_UDNA;
                }
                else
                {
                    const uint8_t size_len = sizeof(size_t);

                    res_data[0] = data[0];
                    /* The max_block_len length reflects the complete message length,
                     * including the service identifier and the data-parameters */
                    res_data[1] = size_len;
                    __uds_store_big_endian(&res_data[2], (ctx->config->file_transfer.max_block_len + 2U), size_len);
                    res_data[2U + size_len] = data_format_identifier;
                    *res_data_len = (uint8_t)(3U + size_len);
                    nrc = UDS_NRC_PR;

                    __uds_data_transfer_reset(ctx);
                    ctx->data_transfer.direction = UDS_DATA_TRANSFER_DOWNLOAD_FILE;
                    ctx->data_transfer.file_mode = UDS_FILE_MODE_WRITE_REPLACE;
                    ctx->data_transfer.fd = file_fd;
                    /* Block sequence counter starts from 1 */
                    ctx->data_transfer.bsqc = 0x01;
                    ctx->data_transfer.max_block_len = ctx->config->file_transfer.max_block_len;
                }
            }
        }
    }

    return nrc;
}

static uint8_t __uds_file_transfer_rdfile(uds_context_t *ctx,
                                          const uint8_t *data, size_t data_len,
                                          uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_SFNS;

    if ((NULL == ctx->config->file_transfer.cb_open) ||
        (NULL == ctx->config->file_transfer.cb_read))
    {
        uds_debug(ctx, "cb_open or cb_read not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else if (data_len < 4U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        size_t file_path_len = UDS_LOAD_UINT16_BIG_ENDIAN(&data[1]);
        if (data_len < (4U + file_path_len))
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else if (file_path_len > UDS_FILEPATH_MAX)
        {
            nrc = UDS_NRC_ROOR;
        }
        else
        {
            intptr_t file_fd = -1;
            size_t filesize_uncompressed = 0U;
            size_t filesize_compressed = 0U;
            int ret = -1;

            /* NOTE: file_path might not be zero-terminated */
            const char * file_path = (const char *)&data[3];
            uint8_t data_format_identifier = data[3U + file_path_len];

            uint8_t compression_method = UDS_HIGH_NIBBLE(data_format_identifier);
            uint8_t encrypting_method = UDS_LOW_NIBBLE(data_format_identifier);

            ret = ctx->config->file_transfer.cb_open(ctx->priv,
                                                     file_path, file_path_len,
                                                     UDS_FILE_MODE_READ,
                                                     &file_fd,
                                                     &filesize_uncompressed,
                                                     &filesize_compressed,
                                                     compression_method,
                                                     encrypting_method);
            if (ret < 0)
            {
                uds_err(ctx, "failed to open file %.*s for reading\n",
                        (int)file_path_len, file_path);
                nrc = UDS_NRC_UDNA;
            }
            else
            {
                const uint8_t size_len = sizeof(size_t);

                uds_debug(ctx, "read file at %.*s, size=%zu (%zu cmp), cmp=%u, enc=%u\n",
                          (int)file_path_len, file_path, filesize_uncompressed,
                          filesize_compressed, compression_method, encrypting_method);

                res_data[0] = data[0];
                /* The max_block_len length reflects the complete message length,
                 * including the service identifier and the data-parameters */
                res_data[1] = size_len;
                __uds_store_big_endian(&res_data[2], (ctx->config->file_transfer.max_block_len + 2U), size_len);
                res_data[2U + size_len] = data_format_identifier;
                __uds_store_big_endian(&res_data[3U + size_len], size_len, 2);
                __uds_store_big_endian(&res_data[5U + size_len], filesize_uncompressed, size_len);
                __uds_store_big_endian(&res_data[5U + (2U * size_len)], filesize_compressed, size_len);
                *res_data_len = (uint8_t)(5U + (3U * size_len));
                nrc = UDS_NRC_PR;

                __uds_data_transfer_reset(ctx);
                ctx->data_transfer.direction = UDS_DATA_TRANSFER_UPLOAD_FILE;
                ctx->data_transfer.file_mode = UDS_FILE_MODE_READ;
                ctx->data_transfer.fd = file_fd;
                /* Block sequence counter starts from 1 */
                ctx->data_transfer.bsqc = 0x01;
                ctx->data_transfer.max_block_len = ctx->config->file_transfer.max_block_len;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_file_transfer_rddir(uds_context_t *ctx,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_SFNS;

    if ((NULL == ctx->config->file_transfer.cb_open) ||
        (NULL == ctx->config->file_transfer.cb_read))
    {
        uds_debug(ctx, "cb_open or cb_read not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else if (data_len < 4U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        size_t dir_path_len = UDS_LOAD_UINT16_BIG_ENDIAN(&data[1]);
        if (data_len < (3U + dir_path_len))
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else if (dir_path_len > UDS_FILEPATH_MAX)
        {
            nrc = UDS_NRC_ROOR;
        }
        else
        {
            intptr_t dir_fd = -1;
            size_t dir_info_len = 0U;
            int ret = -1;

            /* NOTE: dir_path might not be zero-terminated */
            const char * dir_path = (const char *)&data[3];

            uds_debug(ctx, "read dir at %.*s\n", (int)dir_path_len, dir_path);

            ret = ctx->config->file_transfer.cb_open(ctx->priv,
                                                     dir_path, dir_path_len,
                                                     UDS_FILE_MODE_LIST_DIR,
                                                     &dir_fd,
                                                     &dir_info_len, NULL,
                                                     0, 0);
            if (ret < 0)
            {
                uds_err(ctx, "failed to read dir at %.*s\n",
                        (int)dir_path_len, dir_path);
                nrc = UDS_NRC_UDNA;
            }
            else
            {
                const uint8_t size_len = sizeof(size_t);

                res_data[0] = data[0];
                /* The max_block_len length reflects the complete message length,
                 * including the service identifier and the data-parameters */
                res_data[1] = size_len;
                __uds_store_big_endian(&res_data[2], (ctx->config->file_transfer.max_block_len + 2), size_len);
                res_data[2U + size_len] = 0x00U;
                __uds_store_big_endian(&res_data[3U + size_len], size_len, 2U);
                __uds_store_big_endian(&res_data[5U + size_len], dir_info_len, size_len);
                *res_data_len = (uint8_t)(5U + (2U * size_len));
                nrc = UDS_NRC_PR;

                __uds_data_transfer_reset(ctx);
                ctx->data_transfer.direction = UDS_DATA_TRANSFER_LIST_DIR;
                ctx->data_transfer.file_mode = UDS_FILE_MODE_LIST_DIR;
                ctx->data_transfer.fd = dir_fd;
                /* Block sequence counter starts from 1 */
                ctx->data_transfer.bsqc = 0x01;
                ctx->data_transfer.max_block_len = ctx->config->file_transfer.max_block_len;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_request_file_transfer(uds_context_t *ctx,
                                               const struct timespec *timestamp,
                                               const uint8_t *data, size_t data_len,
                                               uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    UDS_UNUSED(timestamp);

    if (data_len < 4U)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        uint8_t mode_of_operation = data[0];

        switch (mode_of_operation)
        {
        case UDS_MOOP_ADDFILE:
            nrc = __uds_file_transfer_addfile(ctx, data, data_len,
                                              res_data, res_data_len);
            break;
        case UDS_MOOP_DELFILE:
            nrc = __uds_file_transfer_delfile(ctx, data, data_len,
                                              res_data, res_data_len);
            break;
        case UDS_MOOP_REPLFILE:
            nrc = __uds_file_transfer_replfile(ctx, data, data_len,
                                               res_data, res_data_len);
            break;
        case UDS_MOOP_RDFILE:
            nrc = __uds_file_transfer_rdfile(ctx, data, data_len,
                                             res_data, res_data_len);
            break;
        case UDS_MOOP_RDDIR:
            nrc = __uds_file_transfer_rddir(ctx, data, data_len,
                                            res_data, res_data_len);
            break;
        default:
            nrc = UDS_NRC_ROOR;
            break;
        }
    }

    return nrc;
}

static int __uds_process_service(uds_context_t *ctx,
                                 const struct timespec *timestamp,
                                 const uint8_t service,
                                 const uint8_t *data, size_t data_len,
                                 const uds_address_e addr_type)
{
    uint8_t *res_data = &ctx->response_buffer[1];
    size_t res_data_len = ctx->response_buffer_len - 1;
    uint8_t nrc = UDS_NRC_SNS;
    int ret = 0;

    uds_debug(ctx, "process service 0x%02X\n", service);

    switch (service)
    {
    /* Diagnostic and Communication Management */
    case UDS_SVC_DSC:
        nrc = __uds_svc_session_control(ctx, timestamp, data, data_len,
                                        res_data, &res_data_len);
        break;

    case UDS_SVC_ER:
        nrc = __uds_svc_ecu_reset(ctx, timestamp, data, data_len,
                                  res_data, &res_data_len);
        break;

    case UDS_SVC_SA:
        nrc = __uds_svc_security_access(ctx, timestamp, data, data_len,
                                        res_data, &res_data_len);
        break;

    case UDS_SVC_CC:
        nrc = __uds_svc_communication_control(ctx, timestamp, data, data_len,
                                              res_data, &res_data_len);
        break;

    case UDS_SVC_TP:
        nrc = __uds_svc_tester_present(ctx, timestamp, data, data_len,
                                       res_data, &res_data_len);
        break;

    case UDS_SVC_ATP:
        nrc = __uds_svc_access_timing_parameters(ctx, timestamp, data, data_len,
                                                 res_data, &res_data_len);
        break;

    case UDS_SVC_SDT:
        break;

    case UDS_SVC_CDTCS:
        nrc = __uds_svc_control_dtc_settings(ctx, timestamp, data, data_len,
                                             res_data, &res_data_len);
        break;

    case UDS_SVC_ROE:
        break;

    case UDS_SVC_LC:
        nrc = __uds_svc_link_control(ctx, timestamp, data, data_len,
                                     res_data, &res_data_len);
        break;

    /* Data Transmission */
    case UDS_SVC_RDBI:
        nrc = __uds_svc_read_data_by_identifier(ctx, timestamp, data, data_len,
                                                res_data, &res_data_len);
        break;

    case UDS_SVC_RMBA:
        nrc = __uds_svc_read_memory_by_address(ctx, timestamp, data, data_len,
                                               res_data, &res_data_len);
        break;

    case UDS_SVC_RSDBI:
        nrc = __uds_svc_read_scaling_data_by_identifier(ctx, timestamp, data, data_len,
                                                        res_data, &res_data_len);
        break;

    case UDS_SVC_RDBPI:
        break;

    case UDS_SVC_DDDI:
        break;

    case UDS_SVC_WDBI:
        nrc = __uds_svc_write_data_by_identifier(ctx, timestamp, data, data_len,
                                                 res_data, &res_data_len);
        break;

    case UDS_SVC_WMBA:
        nrc = __uds_svc_write_memory_by_address(ctx, timestamp, data, data_len,
                                                res_data, &res_data_len);
        break;

    /* Stored Data Transmission */
    case UDS_SVC_CDTCI:
        nrc = __uds_svc_clear_diagnostic_information(ctx, timestamp, data, data_len,
                                                     res_data, &res_data_len);
        break;

    case UDS_SVC_RDTCI:
        nrc = __uds_svc_read_dtc_information(ctx, timestamp, data, data_len,
                                             res_data, &res_data_len);
        break;

    /* InputOutput Control */
    case UDS_SVC_IOCBI:
        nrc = __uds_svc_io_control_by_identifier(ctx, timestamp, data, data_len,
                                                 res_data, &res_data_len);
        break;

    /* Routine */
    case UDS_SVC_RC:
        nrc = __uds_svc_routine_control(ctx, timestamp, data, data_len,
                                        res_data, &res_data_len);
        break;

    /* Upload Download */
    case UDS_SVC_RD:
        nrc = __uds_svc_request_download(ctx, timestamp, data, data_len,
                                         res_data, &res_data_len);
        break;

    case UDS_SVC_RU:
        nrc = __uds_svc_request_upload(ctx, timestamp, data, data_len,
                                       res_data, &res_data_len);
        break;

    case UDS_SVC_TD:
        nrc = __uds_svc_transmit_data(ctx, timestamp, data, data_len,
                                      res_data, &res_data_len);
        break;

    case UDS_SVC_RTE:
        nrc = __uds_svc_request_transfer_exit(ctx, timestamp, data, data_len,
                                              res_data, &res_data_len);
        break;

    case UDS_SVC_RFT:
        nrc = __uds_svc_request_file_transfer(ctx, timestamp, data, data_len,
                                              res_data, &res_data_len);
        break;

    default:
        uds_warning(ctx, "service not supported: 0x%02X\n", service);
        break;
    }

    if (UDS_NRC_PR == nrc)
    {
        ctx->response_buffer[0] = (service + UDS_PRINB);
        uds_debug(ctx, "send positive response to service 0x%02X\n", service);
        ret = __uds_send(ctx, ctx->response_buffer, (res_data_len + 1U));
    }
    else if (UDS_SPRMINB != nrc)
    {
        /*
         * Negative response messages with negative response codes of SNS, SNSIAS, SFNS,
         * SFNSIAS and ROOR shall not be transmitted when functional addressing was
         * used for the request message (exception see Annex A.1 in definition of NRC 0x78).
         */
        if ((UDS_ADDRESS_FUNCTIONAL != addr_type) ||
            ((UDS_NRC_SNS != nrc) && (UDS_NRC_SNSIAS != nrc) &&
             (UDS_NRC_SFNS != nrc) && (UDS_NRC_SFNSIAS != nrc) &&
             (UDS_NRC_ROOR != nrc)))
        {
            ctx->response_buffer[0] = UDS_NR_SI;
            ctx->response_buffer[1] = service;
            ctx->response_buffer[2] = nrc;
            uds_debug(ctx, "send negative response code 0x%02X to service 0x%02X\n",
                      nrc, service);
            ret = __uds_send(ctx, ctx->response_buffer, 3);
        }
    }
    else
    {
        uds_debug(ctx, "suppress positive response for service 0x%02X\n", service);
    }

    return ret;
}

static int __uds_init(uds_context_t *ctx, const uds_config_t *config,
                      uint8_t *response_buffer, size_t response_buffer_len,
                      void *priv, unsigned int loglevel,
                      const struct timespec *timestamp)
{
    int ret = 0;

    // Init context
    (void)memset(ctx, 0, sizeof(uds_context_t));

    ctx->config = config;
    ctx->response_buffer = response_buffer;
    ctx->response_buffer_len = response_buffer_len;
    ctx->priv = priv;
    ctx->loglevel = loglevel;
    ctx->current_sa_seed = UDS_INVALID_SA_INDEX;
    ctx->sa_failed_attempts = config->sa_max_attempts;

    if (NULL != timestamp)
    {
        (void)memcpy(&ctx->sa_delay_timer_timestamp, timestamp,
                     sizeof(ctx->sa_delay_timer_timestamp));
    }

    (void)memset(ctx->response_buffer, 0, ctx->response_buffer_len);

    __uds_reset_to_default_session(ctx);

    return ret;
}

static long int timespec_elapsed_ms(const struct timespec *stop,
                                    const struct timespec *start)
{
    long int ret = 0;

    if ((stop->tv_sec > start->tv_sec) ||
        ((stop->tv_sec == start->tv_sec) && (stop->tv_nsec >= start->tv_sec)))
    {
        ret = 1000L * (stop->tv_sec - start->tv_sec);
        ret += (stop->tv_nsec - start->tv_nsec + 500000L) / 1000000L;
    }

    return ret;
}

uds_context_t * uds_create_context(void)
{
    uds_context_t *ctx = calloc(1, sizeof(uds_context_t));
    return ctx;
}

void uds_destroy_context(uds_context_t * ctx)
{
    free(ctx);
}

int uds_init(uds_context_t *ctx, const uds_config_t *config,
             uint8_t *response_buffer, size_t response_buffer_len, void *priv,
             const struct timespec *timestamp)
{
    const char *env_tmp = NULL;
    unsigned int loglevel = 4;
    int ret = -1;

    // Parse environment options
    env_tmp = getenv("LIBUDS_DEBUG");
    if ((env_tmp != NULL) && (env_tmp[0] >= '0') && (env_tmp[0] <= '9'))
    {
        loglevel = env_tmp[0] - '0';
    }

    if (ctx == NULL)
    {
        ret = -1;
    }
    else if (config == NULL)
    {
        uds_err(ctx, "config shall be supplied to init function\n");
        ret = -1;
    }
    else if (response_buffer == NULL)
    {
        uds_err(ctx, "res_buffer shall be supplied to init function\n");
        ret = -1;
    }
    else if (response_buffer_len < 7U)
    {
        uds_err(ctx, "res_buffer shall be at least 7 bytes long\n");
        ret = -1;
    }
    else
    {
        ret = __uds_init(ctx, config, response_buffer, response_buffer_len,
                         priv, loglevel, timestamp);
    }

    return ret;
}

int uds_receive(uds_context_t *ctx, uds_address_e addr_type,
                const uint8_t *data, const size_t len,
                const struct timespec *timestamp)
{
    int ret = 0;

    if (NULL == ctx)
    {
        ret = -1;
    }
    else if (NULL == data)
    {
        uds_err(ctx, "receive called with null data pointer\n");
        ret = -1;
    }
    else if (len == 0U)
    {
        uds_err(ctx, "receive called with no data\n");
        ret = -1;
    }
    else
    {
        uint8_t service = data[0];
        const uint8_t *payload = NULL;
        size_t payload_len = 0U;

        if (len > 1U)
        {
            payload = &data[1];
            payload_len = (len -1U);
        }

        ret = __uds_process_service(ctx, timestamp, service,
                                    payload, payload_len, addr_type);
    }

    // Update last contact timestamp
    if ((ret == 0) && (NULL != timestamp))
    {
        (void)memcpy(&ctx->last_message_timestamp, timestamp,
                     sizeof(ctx->last_message_timestamp));
    }

    return ret;
}

int uds_cycle(uds_context_t *ctx, const struct timespec *timestamp)
{
    long int elapsed_ms = 0;

    elapsed_ms = timespec_elapsed_ms(timestamp, &ctx->last_message_timestamp);
    if ((elapsed_ms > 0) &&
        (NULL != ctx->current_session) && (ctx->current_session->s3_time > 0))
    {
        if ((unsigned long)elapsed_ms > ctx->current_session->s3_time)
        {
            uds_info(ctx, "session timer expired, reset to default\n");
            __uds_reset_to_default_session(ctx);
            if (__uds_sa_vs_session_check(ctx, ctx->current_sa, ctx->current_session) != 0)
            {
                uds_info(ctx, "secure access not allowed in default session, reset it\n");
                __uds_reset_secure_access(ctx);
            }

            if (__uds_data_transfer_active(ctx) == 0)
            {
                if ((UDS_DATA_TRANSFER_DOWNLOAD == ctx->data_transfer.direction) &&
                    (__uds_session_and_security_check(ctx, &ctx->data_transfer.mem_region->sec_download) != 0))
                {
                    __uds_data_transfer_reset(ctx);
                }
                else if ((UDS_DATA_TRANSFER_UPLOAD == ctx->data_transfer.direction) &&
                         (__uds_session_and_security_check(ctx, &ctx->data_transfer.mem_region->sec_upload) != 0))
                {
                    __uds_data_transfer_reset(ctx);
                }
                else if ((UDS_DATA_TRANSFER_DOWNLOAD_FILE == ctx->data_transfer.direction) &&
                         (__uds_session_and_security_check(ctx, &ctx->config->file_transfer.sec) != 0))
                {
                    __uds_data_transfer_reset(ctx);
                }
                else if ((UDS_DATA_TRANSFER_UPLOAD_FILE == ctx->data_transfer.direction) &&
                         (__uds_session_and_security_check(ctx, &ctx->config->file_transfer.sec) != 0))
                {
                    __uds_data_transfer_reset(ctx);
                }
                else if ((UDS_DATA_TRANSFER_LIST_DIR == ctx->data_transfer.direction) &&
                         (__uds_session_and_security_check(ctx, &ctx->config->file_transfer.sec) != 0))
                {
                    __uds_data_transfer_reset(ctx);
                }
                else
                {
                    // Nothing to do
                }
            }
        }
    }

    if (__uds_security_access_max_attempts_exceeded(ctx) != 0)
    {
        elapsed_ms = timespec_elapsed_ms(timestamp, &ctx->sa_delay_timer_timestamp);
        if ((elapsed_ms > 0) &&
            ((unsigned long)elapsed_ms >= ctx->config->sa_delay_timer_ms))
        {
            uds_info(ctx, "SA delay timer expired, reset attempts number\n");
            __uds_security_access_reset_failed_attempts(ctx);
        }
    }

    return 0;
}

void uds_reset_sa_delay_timer(uds_context_t *ctx)
{
    __uds_security_access_reset_failed_attempts(ctx);
}
