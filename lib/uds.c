
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

static const uds_session_cfg_t __uds_default_session =
{
    .session_type = 0x00,
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
        if (ctx->config->session_config[s].session_type == 0x00)
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

static inline int __uds_session_check(uds_context_t *ctx, const uds_security_cfg_t* cfg)
{
    int ret = -1;

    uds_debug(ctx, "session_check with active session = 0x%02X\n",
              ctx->current_session->session_type);
    uds_debug(ctx, "sm[0] = 0x%016X\n", cfg->session_mask[0]);
    uds_debug(ctx, "sm[1] = 0x%016X\n", cfg->session_mask[1]);

    if ((ctx->current_session->session_type < 64) &&
        ((1UL << ctx->current_session->session_type) & cfg->session_mask[0]) != 0)
    {
        ret = 0;
    }
    else if ((ctx->current_session->session_type >= 64) &&
             ((1UL << ctx->current_session->session_type) & cfg->session_mask[1]) != 0)
    {
        ret = 0;
    }

    return ret;
}

static inline int __uds_security_check(uds_context_t *ctx, const uds_security_cfg_t* cfg)
{
    int ret = -1;

    if (cfg->sa_type_mask == 0)
    {
        ret = 0;
    }
    else if ((UDS_CFG_SA_TYPE(ctx->current_sa->sa_index) & cfg->sa_type_mask) != 0)
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
    uint8_t nrc = UDS_NRC_PR;
    uint8_t requested_session = 0x00;
    unsigned int s = 0;

    if (1 != data_len)
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
    uint8_t nrc = UDS_NRC_SFNS;
    uint8_t reset_type = 0;

    if (1 != data_len)
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
                nrc = UDS_NRC_CNC;
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
                nrc = UDS_NRC_CNC;
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
                nrc = UDS_NRC_CNC;
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
                nrc = UDS_NRC_CNC;
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
                nrc = UDS_NRC_CNC;
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
                nrc = UDS_NRC_CNC;
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
                nrc = UDS_NRC_CNC;
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

static int __uds_svc_read_data_by_identifier(uds_context_t *ctx,
                                             const uint8_t *data, size_t data_len,
                                             uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_SFNS;
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

            uds_debug(ctx, "requested to read data with ID 0x%04X\n", identifier);

            for (d = 0; d < ctx->config->num_data_items; d++)
            {
                if (ctx->config->data_items[d].identifier == identifier)
                {
                    if (NULL == ctx->config->data_items[d].cb_read)
                    {
                        uds_warning(ctx, "cb_read not defined for data with ID 0x%04X\n",
                                    identifier);
                    }
                    else if (__uds_session_check(ctx, &ctx->config->data_items[d].sec_read) != 0)
                    {
                        uds_debug(ctx, "data with ID 0x%04X cannot be read in active session\n",
                                  identifier);
                    }
                    else if (__uds_security_check(ctx, &ctx->config->data_items[d].sec_read) != 0)
                    {
                        uds_debug(ctx, "data with ID 0x%04X cannot be read with current SA\n",
                                  identifier);
                        nrc = UDS_NRC_SAD;
                    }
                    else if ((res_data_used + 2) >= *res_data_len)
                    {
                        uds_info(ctx, "no space for identifier and data for ID 0x%04X\n");
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
                        uds_debug(ctx, "res_data_used = %lu\n", res_data_used);
                        uds_debug(ctx, "res_data_item_len = %lu\n", res_data_item_len);
                        uds_debug(ctx, "res_data_len = %lu\n", *res_data_len);
                        if ((res_data_used + res_data_item_len) > *res_data_len)
                        {
                            uds_info(ctx, "no space for data with ID 0x%04X\n", identifier);
                            nrc = UDS_NRC_RTL;
                        }
                        else if (0 != ret)
                        {
                            uds_err(ctx, "failed to read data with ID 0x%04X\n", identifier);
                            nrc = UDS_NRC_CNC;
                        }
                        else
                        {
                            uds_debug(ctx, "data with ID 0x%04X read successfully (len = %lu)\n",
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

static int __uds_svc_secure_access_delay_timer_active(uds_context_t *ctx)
{
    // TODO: delay timer configuration and management
    return 0;
}

static uint8_t __uds_svc_secure_access(uds_context_t *ctx,
                                       const uint8_t *data, size_t data_len,
                                       uint8_t *res_data, size_t *res_data_len)
{
    uint8_t nrc = UDS_NRC_SFNS;
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
            nrc = UDS_NRC_CNC;
        }
        else if (0 != __uds_svc_secure_access_delay_timer_active(ctx))
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
            nrc == UDS_NRC_RSE;
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
    uint8_t nrc = UDS_SPRMINB;

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
    uint8_t nrc = UDS_NRC_PR;
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
                nrc = UDS_NRC_CNC;
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
                nrc = UDS_NRC_CNC;
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
                nrc = UDS_NRC_CNC;
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
                nrc = UDS_NRC_CNC;
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


static int __uds_process_service(uds_context_t *ctx, const uint8_t service,
                              const uint8_t *data, size_t data_len,
                              const uds_address_e addr_type)
{
    uint8_t *res_data = &ctx->response_buffer[1];
    size_t res_data_len = sizeof(ctx->response_buffer) - 1;
    uint8_t nrc = UDS_NRC_SNS;
    int ret = 0;

    uds_debug(ctx, "process service 0x%02X\n", service);

    switch (service)
    {
    case UDS_SVC_DSC:
        nrc = __uds_svc_session_control(ctx, data, data_len,
                                        res_data, &res_data_len);
        break;

    case UDS_SVC_ER:
        nrc = __uds_svc_ecu_reset(ctx, data, data_len,
                                  res_data, &res_data_len);
        break;

    case UDS_SVC_CDTCI:
        break;

    case UDS_SVC_RDTCI:
        break;

    case UDS_SVC_RDBI:
        nrc = __uds_svc_read_data_by_identifier(ctx, data, data_len,
                                                res_data, &res_data_len);
        break;

    case UDS_SVC_RMBA:
        break;

    case UDS_SVC_RSDBI:
        break;

    case UDS_SVC_SA:
        nrc = __uds_svc_secure_access(ctx, data, data_len,
                                      res_data, &res_data_len);
        break;

    case UDS_SVC_CC:
        break;

    case UDS_SVC_RDBPI:
        break;

    case UDS_SVC_DDDI:
        break;

    case UDS_SVC_WDBI:
        break;

    case UDS_SVC_IOCBI:
        break;

    case UDS_SVC_RC:
        break;

    case UDS_SVC_RU:
        break;

    case UDS_SVC_TD:
        break;

    case UDS_SVC_RTE:
        break;

    case UDS_SVC_RFT:
        break;

    case UDS_SVC_WMBA:
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
            ((UDS_NRC_SNS != nrc) && (UDS_NRC_SNSIAS != nrc) ||
             (UDS_NRC_SFNS != nrc) || (UDS_NRC_SFNSIAS != nrc) ||
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
                      void *priv, unsigned int loglevel)
{
    int ret = 0;

    // Init context
    memset(ctx, 0, sizeof(uds_context_t));

    ctx->config = config;
    ctx->priv = priv;
    ctx->loglevel = loglevel;
    ctx->current_sa_seed = __UDS_INVALID_SA_INDEX;

    // Check and validate config
    if (0 == ctx->config->p2)
    {
        uds_warning(ctx, "P2 time is set to 0ms\n");
    }

    if (0 == ctx->config->p2max)
    {
        uds_warning(ctx, "P2max time is set to 0ms\n");
    }

    return ret;
}

int uds_init(uds_context_t *ctx, const uds_config_t *config, void *priv)
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
    else
    {
        ret = __uds_init(ctx, config, priv, loglevel);
    }

    return ret;
}

void uds_deinit(uds_context_t *ctx)
{
    return;
}

int uds_receive(uds_context_t *ctx, uds_address_e addr_type,
                const uint8_t *data, const size_t len)
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

    return ret;
}

int uds_cycle(uds_context_t *ctx)
{
    return 0;
}
