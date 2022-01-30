
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "uds.h"
#include "uds_log.h"

#include "iso14229_part1.h"

#define __UDS_GET_SUBFUNCTION(x) (x&(~UDS_SPRMINB))
#define __UDS_SUPPRESS_PR(x) (UDS_SPRMINB==(x&UDS_SPRMINB))

#define __UDS_INVALID_SA_INDEX 0xFF
#define __UDS_INVALID_DATA_IDENTIFIER 0xFFFF
#define __UDS_INVALID_GROUP_OF_DTC 0x00000000

static const uds_session_cfg_t __uds_default_session =
{
    .session_type = 0x01,
    .sa_type_mask = 0UL,
};

static inline uint8_t __uds_sat_to_sa_index(const uint8_t sat)
{
    return ((sat - 1) / 2);
}

static void __uds_reset_to_default_session(uds_context_t *ctx)
{
    unsigned int s = 0;
    for (s = 0; s < ctx->config->num_session_config; s++)
    {
        if (ctx->config->session_config[s].session_type == 0x01)
        {
            ctx->current_session = &ctx->config->session_config[s];
            break;
        }
    }

    if (s == ctx->config->num_session_config)
    {
        ctx->current_session = &__uds_default_session;
    }
}

static void __uds_reset_secure_access(uds_context_t *ctx)
{
    ctx->current_sa = NULL;
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

static inline int __uds_session_check(uds_context_t *ctx, const uds_security_cfg_t* cfg)
{
    int ret = -1;

    uds_debug(ctx, "session_check with active session = 0x%02X\n",
              ctx->current_session->session_type);
    uds_debug(ctx, "standard_sm = 0x%016lX\n", cfg->standard_session_mask);
    uds_debug(ctx, "specific_sm = 0x%016lX\n", cfg->specific_session_mask);

    if (ctx->current_session->session_type >= 128)
    {
        uds_err(ctx, "invalid current session 0x%02X\n", ctx->current_session->session_type);
    }
    else if ((ctx->current_session->session_type < 64) &&
        ((UDS_CFG_SESSION_MASK(ctx->current_session->session_type) & cfg->standard_session_mask) != 0))
    {
        ret = 0;
    }
    else if ((ctx->current_session->session_type >= 64) &&
             ((UDS_CFG_SESSION_MASK((ctx->current_session->session_type-64)) & cfg->specific_session_mask) != 0))
    {
        ret = 0;
    }

    return ret;
}

static inline int __uds_security_check(uds_context_t *ctx, const uds_security_cfg_t* cfg)
{
    int ret = -1;

    uds_debug(ctx, "security_check with current sa_index = %d\n",
              (NULL != ctx->current_sa) ? ctx->current_sa->sa_index : -1);
    uds_debug(ctx, "sa_tm = 0x%08X\n", cfg->sa_type_mask);

    if (cfg->sa_type_mask == 0)
    {
        ret = 0;
    }
    else if ((NULL != ctx->current_sa) &&
             ((UDS_CFG_SA_TYPE(ctx->current_sa->sa_index) & cfg->sa_type_mask) != 0))
    {
        ret = 0;
    }

    return ret;
}

static int __uds_send(uds_context_t *ctx, const uint8_t *data, size_t len)
{
    static int no_cb_err_once = 0;
    int ret = 0;

    if (NULL == ctx->config->cb_send)
    {
        if (no_cb_err_once == 0)
        {
            no_cb_err_once = 1;
            uds_alert(ctx, "send callback not installed!\n");
            ret = -1;
        }
    }
    else if ((NULL != data) && (len > 0))
    {
        ret = ctx->config->cb_send(ctx->priv, data, len);
        if (ret != 0)
        {
            uds_err(ctx, "send callback failed\n");
        }
    }

    return ret;
}

static uint8_t __uds_svc_session_control(uds_context_t *ctx,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint8_t requested_session = 0x00;
    unsigned int s = 0;

    if (data_len != 1)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        requested_session = __UDS_GET_SUBFUNCTION(data[0]);
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

                ctx->current_session = &ctx->config->session_config[s];
                break;
            }
        }

        if (ctx->config->num_session_config == s)
        {
            uds_info(ctx, "requested session 0x%02X not available\n", requested_session);
            nrc = UDS_NRC_SFNS;
        }
        else if (__UDS_SUPPRESS_PR(data[0]))
        {
            nrc = UDS_SPRMINB;
        }
        else
        {
            nrc = UDS_NRC_PR;
            res_data[0] = requested_session;
            res_data[1] = ((ctx->config->p2 >> 8) & 0xFF);
            res_data[2] = ((ctx->config->p2 >> 0) & 0xFF);
            res_data[3] = ((ctx->config->p2max >> 8) & 0xFF);
            res_data[4] = ((ctx->config->p2max >> 0) & 0xFF);
            *res_data_len = 5;
        }
    }

    return nrc;
}

static uint8_t __uds_svc_ecu_reset(uds_context_t *ctx,
                                   const uint8_t *data, size_t data_len,
                                   uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint8_t reset_type = 0;

    if (data_len < 1)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        reset_type = __UDS_GET_SUBFUNCTION(data[0]);

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
            if (data_len < 2)
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
        if (__UDS_SUPPRESS_PR(data[0]))
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

static int __uds_security_access_delay_timer_active(uds_context_t *ctx)
{
    // TODO: delay timer configuration and management
    return 0;
}

static uint8_t __uds_svc_security_access(uds_context_t *ctx,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint8_t sr = 0x00;
    uint8_t sa_index = __UDS_INVALID_SA_INDEX;
    const uint8_t *in_data = NULL;
    size_t in_data_len = 0;
    unsigned int l;
    int ret = 0;

    if (data_len < 1)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        sr = __UDS_GET_SUBFUNCTION(data[0]);
        sa_index = __uds_sat_to_sa_index(sr);

        in_data_len = (data_len - 1);
        if (in_data_len > 0)
        {
            in_data = &data[1];
        }

        if ((sr == 0x00) || (sr == 0x7F))
        {
            nrc = UDS_NRC_SFNS;
        }
        else if (0 == (ctx->current_session->sa_type_mask & UDS_CFG_SA_TYPE(sa_index)))
        {
            nrc = UDS_NRC_SFNSIAS;
        }
        else if (0 != __uds_security_access_delay_timer_active(ctx))
        {
            nrc = UDS_NRC_RTDNE;
        }
        else if ((sr % 2) != 0)
        {
            uds_debug(ctx, "request_seed for SA 0x%02X\n", sa_index);

            for (l = 0; l < ctx->config->num_sa_config; l++)
            {
                if (ctx->config->sa_config[l].sa_index == sa_index)
                {
                    if (NULL != ctx->config->sa_config[l].cb_request_seed)
                    {
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
                                    res_data[1 + l] = 0x00;
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
            uds_debug(ctx, "validate_key for SA 0x%02X\n", sa_index);

            for (l = 0; l < ctx->config->num_sa_config; l++)
            {
                if (ctx->config->sa_config[l].sa_index == sa_index)
                {
                    if (NULL != ctx->config->sa_config[l].cb_validate_key)
                    {
                        ret = ctx->config->sa_config[l].cb_validate_key(ctx->priv, sa_index,
                                                                        in_data, in_data_len);
                        if (ret < 0)
                        {
                            uds_info(ctx, "validate_key for SA 0x%02X failed\n", sa_index);
                            nrc = UDS_NRC_IK;
                        }
                        else
                        {
                            res_data[0] = sr;
                            *res_data_len = 1;
                            uds_debug(ctx, "activating SA 0x%02X\n", sa_index);
                            ctx->current_sa = &ctx->config->sa_config[l];
                            ctx->current_sa_seed = __UDS_INVALID_SA_INDEX;
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

static uint8_t __uds_svc_tester_present(uds_context_t *ctx,
                                        const uint8_t *data, size_t data_len,
                                        uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;

    (void)ctx;

    if (1 != data_len)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if (UDS_LEV_ZSUBF != __UDS_GET_SUBFUNCTION(data[0]))
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if (__UDS_SUPPRESS_PR(data[0]))
    {
        nrc = UDS_SPRMINB;
    }
    else
    {
        res_data[0] = UDS_LEV_ZSUBF;
        *res_data_len = 1;
        nrc = UDS_NRC_PR;
    }

    return nrc;
}

static uint8_t __uds_svc_control_dtc_settings(uds_context_t *ctx,
                                              const uint8_t *data, size_t data_len,
                                              uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint8_t dtc_setting_type = 0xFF;
    const uint8_t *extra_data = NULL;
    size_t extra_data_len = 0;

    if (data_len < 1)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        dtc_setting_type = __UDS_GET_SUBFUNCTION(data[0]);

        if (data_len > 1)
        {
            extra_data = &data[1];
            extra_data_len = (data_len - 1);
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
    }

    if (nrc == UDS_NRC_PR)
    {
        if (__UDS_SUPPRESS_PR(data[0]))
        {
            nrc = UDS_SPRMINB;
        }
        else
        {
            res_data[0] = dtc_setting_type;
            *res_data_len = 1;
        }
    }

    return nrc;
}

static uint8_t __uds_svc_read_data_by_identifier(uds_context_t *ctx,
                                                 const uint8_t *data, size_t data_len,
                                                 uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint16_t identifier = __UDS_INVALID_DATA_IDENTIFIER;
    size_t data_start = 0;
    size_t res_data_used = 0;
    size_t res_data_item_len = 0;
    unsigned long d = 0;
    int ret = 0;

    if ((0 == data_len) || ((data_len % 2) != 0))
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else if ((data_len + (data_len / 2)) > *res_data_len)
    {
        /* Available space for response shall fit at least the requested
         * identifiers and at least one additional byte for each of them */
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        nrc = UDS_NRC_PR;
        for (data_start = 0; data_start < data_len; data_start += 2)
        {
            identifier = (data[data_start] << 8) | (data[data_start + 1] << 0);

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
                    else if ((res_data_used + 2) >= *res_data_len)
                    {
                        uds_info(ctx, "no space for identifier and data for DID 0x%04X\n",
                                 identifier);
                        nrc = UDS_NRC_RTL;
                    }
                    else
                    {
                        res_data[res_data_used] = (identifier >> 8) & 0xFF;
                        res_data[res_data_used + 1] = (identifier >> 0) & 0xFF;
                        res_data_used += 2;
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
                            uds_debug(ctx, "DID 0x%04X read successfully (len = %lu)\n",
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
    }

    if ((UDS_NRC_PR == nrc) && (0 == res_data_used))
    {
        /* One of the following condition verified:
         *  - none of the requested identifiers are supported by the device
         *  - none of the requested identifiers are supported in the current session
         *  - the requested dynamic identifier has not been assigned yet
         */
        nrc = UDS_NRC_ROOR;
    }
    else if (UDS_NRC_PR == nrc)
    {
        *res_data_len = res_data_used;
    }

    return nrc;
}

static uint8_t __uds_svc_read_memory_by_address(uds_context_t *ctx,
                                                const uint8_t *data, size_t data_len,
                                                uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint8_t addr_len = 0;
    uint8_t size_len = 0;
    void * addr = 0;
    size_t size = 0;
    unsigned long p = 0;
    int ret;

    if (data_len < 3)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        addr_len = (data[0] >> 0) & 0x0F;
        size_len = (data[0] >> 4) & 0x0F;

        if ((1U + addr_len + size_len) > data_len)
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else
        {
            nrc = UDS_NRC_PR;

            /* Extract address from incoming data; p starts at addr_len because
             * address is stored inside data[] starting from data[1] */
            for (p = addr_len; p > 0; p--)
            {
                if (p <= sizeof(void*))
                {
                    addr = (void *)((uintptr_t)addr | ((0xFFULL & data[p]) << (8 * (addr_len - p))));
                }
                else if (data[p] != 0x00)
                {
                    nrc = UDS_NRC_ROOR;
                    break;
                }
            }

            /* Extract size from incoming data; p starts at size_len because
             * address is stored inside data[] starting from data[1] */
            for (p = size_len; p > 0; p--)
            {
                if (p <= sizeof(size_t))
                {
                    size |= ((0xFFUL & data[addr_len + p]) << (8 * (size_len - p)));
                }
                else if (data[addr_len + p] != 0x00)
                {
                    nrc = UDS_NRC_ROOR;
                    break;
                }
            }

            if (UDS_NRC_PR != nrc)
            {
                uds_debug(ctx, "requested memory read with invalid parameters\n");
                // Nothing to do, NRC is already set
            }
            else if (size == 0)
            {
                uds_info(ctx, "request read of memory at %p with null size\n", addr);
                nrc = UDS_NRC_ROOR;
            }
            else
            {
                uds_debug(ctx, "request to read memory at %p, size %lu\n", addr, size);

                for (p = 0; p < ctx->config->num_mem_regions; p++)
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
                            ret = ctx->config->mem_regions[p].cb_read(ctx->priv, (void *)addr,
                                                                      &res_data[0], size);
                            if (ret != 0)
                            {
                                uds_err(ctx, "failed to read memory at %p, len = %lu\n", addr, size);
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
                    uds_debug(ctx, "memory address %p non found in any region\n", addr);
                    nrc = UDS_NRC_ROOR;
                }
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_read_scaling_data_by_identifier(uds_context_t *ctx,
                                                         const uint8_t *data, size_t data_len,
                                                         uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint16_t identifier = __UDS_INVALID_DATA_IDENTIFIER;
    unsigned long d = 0;

    if (data_len != 3)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        identifier = (data[0] << 8) | (data[1] << 0);

        uds_debug(ctx, "requested to read scaling data for DID 0x%04X\n", identifier);

        nrc = UDS_NRC_ROOR;
        for (d = 0; d < ctx->config->num_data_items; d++)
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
                else if (*res_data_len < (2 + ctx->config->data_items[d].scaling_data_size))
                {
                    uds_info(ctx, "not enough space provided for scaling data\n");
                    nrc = UDS_NRC_GR;
                }
                else
                {
                    nrc = UDS_NRC_PR;
                    res_data[0] = (identifier >> 8) & 0xFF;
                    res_data[1] = (identifier >> 0) & 0xFF;
                    memcpy(&res_data[2],
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
                                                  const uint8_t *data, size_t data_len,
                                                  uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint16_t identifier = __UDS_INVALID_DATA_IDENTIFIER;
    unsigned long d = 0;
    int ret = -1;

    if (data_len < 3)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        identifier = (data[0] << 8) | (data[1] << 0);

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
                    ret = ctx->config->data_items[d].cb_write(ctx->priv, identifier,
                                                              &data[2], (data_len - 2));
                    if (ret != 0)
                    {
                        uds_err(ctx, "failed to write DID 0x%04X\n", identifier);
                        nrc = UDS_NRC_GPF;
                    }
                    else
                    {
                        nrc = UDS_NRC_PR;
                        res_data[0] = (identifier >> 8) & 0xFF;
                        res_data[1] = (identifier >> 0) & 0xFF;
                        *res_data_len = 2;
                    }
                }
                break;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_write_memory_by_address(uds_context_t *ctx,
                                                 const uint8_t *data, size_t data_len,
                                                 uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint8_t addr_len = 0;
    uint8_t size_len = 0;
    void * addr = 0;
    size_t size = 0;
    unsigned long p = 0;
    int ret;

    if (data_len < 4)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        addr_len = (data[0] >> 0) & 0x0F;
        size_len = (data[0] >> 4) & 0x0F;

        if ((1UL + addr_len + size_len) > data_len)
        {
            nrc = UDS_NRC_IMLOIF;
        }
        else if ((1UL + addr_len + size_len) > *res_data_len)
        {
            uds_info(ctx, "not enough space provided for memory write response\n");
            nrc = UDS_NRC_GR;
        }
        else
        {
            nrc = UDS_NRC_PR;

            /* Extract address from incoming data; p starts at addr_len because
             * address is stored inside data[] starting from data[1] */
            for (p = addr_len; p > 0; p--)
            {
                if (p <= sizeof(void*))
                {
                    addr = (void *)((uintptr_t)addr | ((0xFFULL & data[p]) << (8 * (addr_len - p))));
                }
                else if (data[p] != 0x00)
                {
                    nrc = UDS_NRC_ROOR;
                    break;
                }
            }

            /* Extract size from incoming data; p starts at size_len because
             * size is stored inside data[] starting from data[1 + addr_len] */
            for (p = size_len; p > 0; p--)
            {
                if (p < sizeof(size_t))
                {
                    size |= ((0xFFUL & data[addr_len + p]) << (8 * (size_len - p)));
                }
                else if (data[addr_len + p] != 0x00)
                {
                    nrc = UDS_NRC_ROOR;
                    break;
                }
            }

            if (UDS_NRC_PR != nrc)
            {
                uds_debug(ctx, "requested memory write with invalid parameters\n");
                // Nothing to do, NRC is already set
            }
            else if ((1 + addr_len + size_len + size) > data_len)
            {
                uds_info(ctx, "not enough data provided for memory write\n");
                nrc = UDS_NRC_IMLOIF;
            }
            else
            {
                uds_debug(ctx, "request to write memory at %p, size %lu\n", addr, size);

                for (p = 0; p < ctx->config->num_mem_regions; p++)
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
                            ret = ctx->config->mem_regions[p].cb_write(ctx->priv, (void *)addr,
                                                                       &data[1 + addr_len + size_len],
                                                                       size);
                            if (ret != 0)
                            {
                                uds_err(ctx, "failed to write memory at %p, len = %lu\n", addr, size);
                                nrc = UDS_NRC_GPF;
                            }
                            else
                            {
                                memcpy(res_data, data, (1 + addr_len + size_len));
                                nrc = UDS_NRC_PR;
                            }
                        }
                        break;
                    }
                }

                if (p == ctx->config->num_mem_regions)
                {
                    uds_debug(ctx, "memory address %p non found in any region\n", addr);
                    nrc = UDS_NRC_ROOR;
                }
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_io_control_by_identifier(uds_context_t *ctx,
                                                  const uint8_t *data, size_t data_len,
                                                  uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint16_t identifier = __UDS_INVALID_DATA_IDENTIFIER;
    uint8_t iocp = 0xFF;
    const uint8_t *control_data = NULL;
    uint8_t *out_data = NULL;
    size_t out_data_len = 0;
    unsigned long d = 0;
    int ret = 0;

    if (data_len < 3)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        identifier = (data[0] << 8) | (data[1] << 0);
        iocp = data[2];

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
                else if ((iocp == UDS_IOCP_STA) && data_len < 4)
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
                    if (data_len > 3)
                    {
                        control_data = &data[3];
                    }
                    out_data = &res_data[3];
                    out_data_len = *res_data_len - 3;
                    ret = ctx->config->data_items[d].cb_io(ctx->priv, identifier, iocp,
                                                           control_data, (data_len - 3),
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
                        memcpy(res_data, data, 3);
                        *res_data_len = out_data_len + 3;
                    }
                }
                break;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_clear_diagnostic_information(uds_context_t *ctx,
                                                      const uint8_t *data, size_t data_len,
                                                      uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint32_t godtc = __UDS_INVALID_GROUP_OF_DTC;
    unsigned int d = 0;

    (void)res_data;
    (void)res_data_len;

    if (data_len != 4)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        godtc = ((0x0000FFU & data[0]) << 16) |
                ((0x0000FFU & data[1]) <<  8) |
                ((0x0000FFU & data[2]) <<  0);

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
    uint8_t status_mask = 0x00;
    uint8_t dtc_status_mask = 0x00;
    uint16_t number_of_dtc = 0;
    uint32_t dtc_number = 0;
    unsigned long d = 0;
    int ret = 0;

    if (data_len < 1)
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
        status_mask = data[0];
        for (d = 0; d < ctx->config->dtc_information.number_of_dtcs; d++)
        {
            dtc_number = ctx->config->dtc_information.dtcs[d].dtc_number;
            ret = ctx->config->dtc_information.cb_get_dtc_status_mask(ctx->priv, dtc_number,
                                                                      &dtc_status_mask);
            if (ret != 0)
            {
                uds_err(ctx, "failed to read status of DTC 0x%06X\n", dtc_number);
            }
            else if ((dtc_status_mask & status_mask) != 0)
            {
                number_of_dtc++;
            }
        }

        nrc = UDS_NRC_PR;
        res_data[0] = status_mask;
        res_data[1] = ctx->config->dtc_information.format_identifier;
        res_data[2] = (number_of_dtc >> 8) & 0xFF;
        res_data[3] = (number_of_dtc >> 0) & 0xFF;
        *res_data_len = 4;
    }

    return nrc;
}

static uint8_t __uds_rdtci_report_dtc_by_status_mask(uds_context_t *ctx,
                                                     const uint8_t *data, size_t data_len,
                                                     uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint8_t status_mask = 0x00;
    uint8_t dtc_status_mask = 0x00;
    uint32_t dtc_number = 0;
    uint8_t dtc_status = 0;
    uint8_t *dtc_data = NULL;
    unsigned int d = 0;
    int ret = 0;

    if (data_len < 1)
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
        status_mask = data[0];

        dtc_data = &res_data[1];

        for (d = 0; d < ctx->config->dtc_information.number_of_dtcs; d++)
        {
            dtc_number = (ctx->config->dtc_information.dtcs[d].dtc_number & 0xFFFFFF);
            ret = ctx->config->dtc_information.cb_get_dtc_status_mask(ctx->priv, dtc_number,
                                                                      &dtc_status_mask);
            if (ret != 0)
            {
                uds_err(ctx, "failed to read status of DTC 0x%06X\n", dtc_number);
            }
            else if ((dtc_status_mask & status_mask) != 0)
            {
                dtc_data[0] = (dtc_number >> 16) & 0xFF;
                dtc_data[1] = (dtc_number >>  8) & 0xFF;
                dtc_data[2] = (dtc_number >>  0) & 0xFF;
                dtc_data[3] = dtc_status;
                dtc_data += 4;
            }
        }

        nrc = UDS_NRC_PR;
        res_data[0] = status_mask;
        *res_data_len = 1 + (dtc_data - &res_data[1]);
    }

    return nrc;
}

static uint8_t __uds_rdtci_report_dtc_snapshot_identification(uds_context_t *ctx,
                                                              const uint8_t *data, size_t data_len,
                                                              uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint8_t *out_data = res_data;
    uint32_t dtc_number = 0;
    unsigned long d = 0;
    unsigned long r = 0;

    (void)data;
    (void)data_len;

    if (NULL == ctx->config->dtc_information.cb_is_dtc_snapshot_record_available)
    {
        uds_debug(ctx, "cb_is_dtc_snapshot_record_available not defined\n");
        nrc = UDS_NRC_SFNS;
    }
    else
    {
        for (d = 0; d < ctx->config->dtc_information.number_of_dtcs; d++)
        {
            dtc_number = ctx->config->dtc_information.dtcs[d].dtc_number;
            for (r = 0; r < 0xFF; r++)
            {
                if (((uintptr_t)(out_data - res_data) + 4) > *res_data_len)
                {
                    break;
                }

                if (ctx->config->dtc_information.cb_is_dtc_snapshot_record_available(ctx->priv, dtc_number, r) != 0)
                {
                    out_data[0] = (dtc_number >> 16) & 0xFF;
                    out_data[1] = (dtc_number >>  8) & 0xFF;
                    out_data[2] = (dtc_number >>  0) & 0xFF;
                    out_data[3] = r;
                    out_data += 4;
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
    uint32_t dtc_number = 0;
    uint8_t record_number = 0xFF;
    uint8_t dtc_status = 0x00;
    uint8_t *record_data = NULL;
    size_t record_data_len = 0;
    size_t used_data_len = 0;
    uint8_t record_start = 0;
    uint8_t record_stop = 0;
    unsigned long d = 0;
    uint8_t r = 0;
    int ret = 0;

    if (data_len < 4)
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
        dtc_number = ((0x0000FFU & data[0]) << 16) |
                     ((0x0000FFU & data[1]) <<  8) |
                     ((0x0000FFU & data[2]) <<  0);
        record_number = data[3];

        // Check if dtc_number is valid
        nrc = UDS_NRC_ROOR;
        for (d = 0; d < ctx->config->dtc_information.number_of_dtcs; d++)
        {
            if (ctx->config->dtc_information.dtcs[d].dtc_number == dtc_number)
            {
                if (0xFF == record_number)
                {
                    record_start = 0;
                    record_stop = 0xFE;
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
            ret = ctx->config->dtc_information.cb_get_dtc_status_mask(ctx->priv, dtc_number,
                                                                      &dtc_status);
            if (ret != 0)
            {
                uds_err(ctx, "failed to read DTC status mask for DTC 0x%06X\n", dtc_number);
                nrc = UDS_NRC_GR;
            }
            else
            {
                res_data[0] = (dtc_number >> 16) & 0xFF;
                res_data[1] = (dtc_number >>  8) & 0xFF;
                res_data[2] = (dtc_number >>  0) & 0xFF;
                res_data[3] = dtc_status;

                used_data_len = 4;

                for (r = record_start; r < record_stop; r++)
                {
                    if ((used_data_len + 1) >= *res_data_len)
                    {
                        break;
                    }
                    record_data = &res_data[used_data_len + 1];
                    record_data_len = used_data_len - 1;
                    ret = ctx->config->dtc_information.cb_get_dtc_snapshot_record(ctx->priv, dtc_number, r,
                                                                                  record_data, &record_data_len);
                    if ((ret != 0) && (record_start == record_stop))
                    {
                        uds_err(ctx, "failed to read snapshot record 0x%02X for DTC 0x%06X\n",
                                r, dtc_number);
                        nrc = UDS_NRC_ROOR;
                        break;
                    }
                    else if ((ret == 0) && (record_data_len > 0))
                    {
                        res_data[used_data_len] = r;
                        used_data_len += (record_data_len + 1);
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
    uint8_t record_number = 0xFF;
    uint8_t *record_data = NULL;
    size_t record_data_len = 0;
    size_t used_data_len = 0;
    uint8_t record_start = 0;
    uint8_t record_stop = 0;
    uint8_t r = 0;
    int ret = 0;

    if (data_len < 1)
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
        record_number = data[0];

        if (0xFF == record_number)
        {
            record_start = 0;
            record_stop = 0xFE;
        }
        else
        {
            record_start = record_number;
            record_stop = record_number;
        }

        used_data_len = 0;

        for (r = record_start; r < record_stop; r++)
        {
            if ((used_data_len + 1) >= *res_data_len)
            {
                break;
            }
            record_data = &res_data[used_data_len + 1];
            record_data_len = used_data_len - 1;
            ret = ctx->config->dtc_information.cb_get_stored_data_record(ctx->priv, r,
                                                                         record_data, &record_data_len);
            if ((ret != 0) && (record_start == record_stop))
            {
                uds_err(ctx, "failed to read stored data record 0x%02X\n", r);
                nrc = UDS_NRC_ROOR;
                break;
            }
            else if ((ret == 0) && (record_data_len > 0))
            {
                res_data[used_data_len] = r;
                used_data_len += (record_data_len + 1);
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
    uint32_t dtc_number = 0;
    uint8_t record_number = 0xFF;
    uint8_t dtc_status = 0x00;
    uint8_t *record_data = NULL;
    size_t record_data_len = 0;
    size_t used_data_len = 0;
    uint8_t record_start = 0;
    uint8_t record_stop = 0;
    unsigned long d = 0;
    uint8_t r = 0;
    int ret = 0;

    if (data_len < 4)
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
        dtc_number = ((0x0000FFU & data[0]) << 16) |
                     ((0x0000FFU & data[1]) <<  8) |
                     ((0x0000FFU & data[2]) <<  0);
        record_number = data[3];

        // Check if dtc_number is valid
        nrc = UDS_NRC_ROOR;
        for (d = 0; d < ctx->config->dtc_information.number_of_dtcs; d++)
        {
            if (ctx->config->dtc_information.dtcs[d].dtc_number == dtc_number)
            {
                if (0xFE == record_number)
                {
                    // OBD extended data records
                    record_start = 0x90;
                    record_stop = 0xEF;

                }
                else if (0xFF == record_number)
                {
                    record_start = 0;
                    record_stop = 0xFD;
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
            ret = ctx->config->dtc_information.cb_get_dtc_status_mask(ctx->priv, dtc_number,
                                                                      &dtc_status);
            if (ret != 0)
            {
                uds_err(ctx, "failed to read DTC status mask for DTC 0x%06X\n", dtc_number);
                nrc = UDS_NRC_GR;
            }
            else
            {
                res_data[0] = (dtc_number >> 16) & 0xFF;
                res_data[1] = (dtc_number >>  8) & 0xFF;
                res_data[2] = (dtc_number >>  0) & 0xFF;
                res_data[3] = dtc_status;

                used_data_len = 4;

                for (r = record_start; r < record_stop; r++)
                {
                    if ((used_data_len + 1) >= *res_data_len)
                    {
                        break;
                    }
                    record_data = &res_data[used_data_len + 1];
                    record_data_len = used_data_len - 1;
                    ret = ctx->config->dtc_information.cb_get_dtc_extended_data_record(ctx->priv, dtc_number, r,
                                                                                       record_data, &record_data_len);
                    if ((ret != 0) && (record_start == record_stop))
                    {
                        uds_err(ctx, "failed to read extended data record 0x%02X for DTC 0x%06X\n",
                                r, dtc_number);
                        nrc = UDS_NRC_ROOR;
                        break;
                    }
                    else if ((ret == 0) && (record_data_len > 0))
                    {
                        res_data[used_data_len] = r;
                        used_data_len += (record_data_len + 1);
                    }
                }
                *res_data_len = used_data_len;
            }
        }
    }

    return nrc;
}

static uint8_t __uds_svc_read_dtc_information(uds_context_t *ctx,
                                              const uint8_t *data, size_t data_len,
                                              uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint8_t report_type = 0x00;

    const uint8_t *in_data = NULL;
    size_t in_data_len = 0;

    uint8_t *out_data = NULL;
    size_t out_data_len = 0;

    if (data_len < 1)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        report_type = __UDS_GET_SUBFUNCTION(data[0]);

        in_data_len = (data_len - 1);
        if (in_data_len > 0)
        {
            in_data = &data[1];
        }

        out_data_len = (*res_data_len - 1);
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
    }

    if (UDS_NRC_PR == nrc)
    {
        res_data[0] = report_type;
        *res_data_len = (out_data_len + 1);
    }

    return nrc;
}

static uint8_t __uds_svc_routine_control(uds_context_t *ctx,
                                         const uint8_t *data, size_t data_len,
                                         uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_GR;
    uint8_t routine_control_type = 0x00;
    uint16_t identifier = __UDS_INVALID_DATA_IDENTIFIER;

    const uint8_t *control_data = NULL;
    uint8_t *out_data = NULL;
    size_t out_data_len = 0;
    unsigned long r = 0;

    if (data_len < 3)
    {
        nrc = UDS_NRC_IMLOIF;
    }
    else
    {
        routine_control_type = __UDS_GET_SUBFUNCTION(data[0]);
        identifier = (data[1] << 8) | (data[2] << 0);

        if (data_len > 3)
        {
            control_data = &data[3];
        }

        if (*res_data_len > 3)
        {
            out_data = &res_data[3];
            out_data_len = (*res_data_len - 3);
        }

        nrc = UDS_NRC_ROOR;
        for (r = 0; r < ctx->config->num_routines; r++)
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
                                                               control_data, (data_len - 3),
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
                                                              control_data, (data_len - 3),
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
                break;
            }
        }
    }

    if (UDS_NRC_PR == nrc)
    {
        memcpy(res_data, data, 3);
        *res_data_len = out_data_len + 3;
    }

    return nrc;
}

static int __uds_process_service(uds_context_t *ctx, const uint8_t service,
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
        nrc = __uds_svc_session_control(ctx, data, data_len,
                                        res_data, &res_data_len);
        break;

    case UDS_SVC_ER:
        nrc = __uds_svc_ecu_reset(ctx, data, data_len,
                                  res_data, &res_data_len);
        break;

    case UDS_SVC_SA:
        nrc = __uds_svc_security_access(ctx, data, data_len,
                                        res_data, &res_data_len);
        break;

    case UDS_SVC_CC:
        break;

    case UDS_SVC_TP:
        nrc = __uds_svc_tester_present(ctx, data, data_len,
                                       res_data, &res_data_len);
        break;

    case UDS_SVC_ATP:
        break;

    case UDS_SVC_SDT:
        break;

    case UDS_SVC_CDTCS:
        nrc = __uds_svc_control_dtc_settings(ctx, data, data_len,
                                             res_data, &res_data_len);
        break;

    case UDS_SVC_ROE:
        break;

    case UDS_SVC_LC:
        break;

    /* Data Transmission */
    case UDS_SVC_RDBI:
        nrc = __uds_svc_read_data_by_identifier(ctx, data, data_len,
                                                res_data, &res_data_len);
        break;

    case UDS_SVC_RMBA:
        nrc = __uds_svc_read_memory_by_address(ctx, data, data_len,
                                               res_data, &res_data_len);
        break;

    case UDS_SVC_RSDBI:
        nrc = __uds_svc_read_scaling_data_by_identifier(ctx, data, data_len,
                                                        res_data, &res_data_len);
        break;

    case UDS_SVC_RDBPI:
        break;

    case UDS_SVC_DDDI:
        break;

    case UDS_SVC_WDBI:
        nrc = __uds_svc_write_data_by_identifier(ctx, data, data_len,
                                                 res_data, &res_data_len);
        break;

    case UDS_SVC_WMBA:
        nrc = __uds_svc_write_memory_by_address(ctx, data, data_len,
                                                res_data, &res_data_len);
        break;

    /* Stored Data Transmission */
    case UDS_SVC_CDTCI:
        nrc = __uds_svc_clear_diagnostic_information(ctx, data, data_len,
                                                     res_data, &res_data_len);
        break;

    case UDS_SVC_RDTCI:
        nrc = __uds_svc_read_dtc_information(ctx, data, data_len,
                                             res_data, &res_data_len);
        break;

    /* InputOutput Control */
    case UDS_SVC_IOCBI:
        nrc = __uds_svc_io_control_by_identifier(ctx, data, data_len,
                                                 res_data, &res_data_len);
        break;

    /* Routine */
    case UDS_SVC_RC:
        nrc = __uds_svc_routine_control(ctx, data, data_len,
                                        res_data, &res_data_len);
        break;

    /* Upload Download */
    case UDS_SVC_RU:
        break;

    case UDS_SVC_TD:
        break;

    case UDS_SVC_RTE:
        break;

    case UDS_SVC_RFT:
        break;

    default:
        uds_warning(ctx, "service not supported: 0x%02X\n", service);
        break;
    }

    if (UDS_NRC_PR == nrc)
    {
        ctx->response_buffer[0] = (service + UDS_PRINB);
        uds_debug(ctx, "send positive response to service 0x%02X\n", service);
        ret = __uds_send(ctx, ctx->response_buffer, (res_data_len + 1));
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
            uds_debug(ctx, "send negative response code 0x%02X\n", nrc);
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
                      void *priv, unsigned int loglevel)
{
    int ret = 0;

    // Init context
    memset(ctx, 0, sizeof(uds_context_t));

    ctx->config = config;
    ctx->response_buffer = response_buffer;
    ctx->response_buffer_len = response_buffer_len;
    ctx->priv = priv;
    ctx->loglevel = loglevel;
    ctx->current_sa_seed = __UDS_INVALID_SA_INDEX;

    memset(ctx->response_buffer, 0, ctx->response_buffer_len);

    // Check and validate config
    if (0 == ctx->config->p2)
    {
        uds_warning(ctx, "P2 time is set to 0ms\n");
    }

    if (0 == ctx->config->p2max)
    {
        uds_warning(ctx, "P2max time is set to 0ms\n");
    }

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

int uds_init(uds_context_t *ctx, const uds_config_t *config,
             uint8_t *response_buffer, size_t response_buffer_len, void *priv)
{
    char *env_tmp = NULL;
    unsigned int loglevel = 4;
    int ret = -1;

    // Parse environment options
    env_tmp = getenv("LIBUDS_DEBUG");
    if ((NULL != env_tmp) && (env_tmp[0] >= '0') && (env_tmp[0] <= '9'))
    {
        loglevel = env_tmp[0] - '0';
    }

    if (NULL == ctx)
    {
        uds_err(ctx, "context shall be supplied to init function\n");
        ret = -1;
    }
    else if (NULL == config)
    {
        uds_err(ctx, "config shall be supplied to init function\n");
        ret = -1;
    }
    else if (NULL == response_buffer)
    {
        uds_err(ctx, "res_buffer shall be supplied to init function\n");
        ret = -1;
    }
    else if (7 >= response_buffer_len)
    {
        uds_err(ctx, "res_buffer shall be at least 7 bytes long\n");
        ret = -1;
    }
    else
    {
        ret = __uds_init(ctx, config, response_buffer, response_buffer_len,
                         priv, loglevel);
    }

    return ret;
}

void uds_deinit(uds_context_t *ctx)
{
    (void)ctx;
    return;
}

int uds_receive(uds_context_t *ctx, uds_address_e addr_type,
                const uint8_t *data, const size_t len,
                const struct timespec *timestamp)
{
    uint8_t service = 0x00;
    const uint8_t *payload = NULL;
    size_t payload_len = 0;
    int ret = 0;

    if (NULL == ctx)
    {
        return -1;
    }

    if (NULL == data)
    {
        uds_err(ctx, "receive called with null data pointer\n");
        ret = -1;
    }
    else if (len == 0)
    {
        uds_err(ctx, "receive called with no data\n");
        ret = -1;
    }
    else
    {
        service = data[0];
        if (len > 1)
        {
            payload = &data[1];
            payload_len = (len -1);
        }
        ret = __uds_process_service(ctx, service, payload, payload_len, addr_type);
    }

    // Update last contact timestamp
    if (NULL != timestamp)
    {
        memcpy(&ctx->timestamp, timestamp, sizeof(ctx->timestamp));
    }

    return ret;
}

int uds_cycle(uds_context_t *ctx, const struct timespec *timestamp)
{
    long int elapsed_ms = 0;

    elapsed_ms = timespec_elapsed_ms(timestamp, &ctx->timestamp);
    if ((elapsed_ms > 0) &&
        (NULL != ctx->current_session) && (ctx->current_session->timeout_ms > 0))
    {
        if ((unsigned long)elapsed_ms > ctx->current_session->timeout_ms)
        {
            uds_info(ctx, "session timer expired, reset to default\n");
            __uds_reset_to_default_session(ctx);
            if (__uds_sa_vs_session_check(ctx, ctx->current_sa, ctx->current_session) != 0)
            {
                uds_info(ctx, "secure access not allowed in default session, reset it\n");
                __uds_reset_secure_access(ctx);
            }
        }
    }

    return 0;
}
