/* SPDX-License-Identifier: GPL-3.0-only */
/**
 * \file uds.h
 *
 * APIs for libuds.
 *
 * This header defines the public interfaces of libuds.
 *
 * \author Francesco Valla <valla.francesco@gmail.com>
 * \copyright (c) 2022 Francesco Valla - License: GPL-3.0-only
 */

#ifndef UDS_H__
#define UDS_H__

#include <stddef.h>
#include <stdint.h>

#include <uds/uds_context.h>
#include <uds/uds_types.h>

/**
 * \brief Initialize the UDS stack.
 *
 * \param ctx UDS context.
 * \param config UDS stack configuration.
 * \param response_buffer Buffer for UDS responses.
 * \param response_buffer_len Length of the response buffer.
 * \param priv Private data; the usage of this parameter is optional and left to the user of the
 * library.
 * \param timestamp Initialization timestamp.
 *
 * \return UDS_NO_ERROR on success, other value on error or if ctx or config are NULL
 */
uds_err_e uds_init(uds_context_t *ctx, const uds_config_t *config, uint8_t *response_buffer,
                   size_t response_buffer_len, void *priv, const uds_time_t *timestamp);

/**
 * \brief Feed data received from transport layer to the UDS stack.
 *
 * \param ctx UDS context.
 * \param addr_type Type of the address the data is coming from.
 * \param data Data received, to be fed to the UDS stack
 * \param len Length of received data.
 * \param timestamp Reception timestamp.
 *
 * \return UDS_NO_ERROR on success, other value on error
 */
uds_err_e uds_receive(uds_context_t *ctx, const uds_address_e addr_type, const uint8_t *data,
                      const size_t len, const uds_time_t *timestamp);

/**
 * \brief Stack periodic cycle function.
 *
 * This function shall be called periodically to advance internal UDS timers and trigger time-driven
 * functions, such as periodic sends.
 *
 * \param ctx UDS context.
 * \param timestamp Cycle timestamp.
 *
 * \return UDS_NO_ERROR on success, other value on error
 */
uds_err_e uds_cycle(uds_context_t *ctx, const uds_time_t *timestamp);

/**
 * \brief Reset secure access delay timer.
 *
 * This function can be called to reset the Secure Access delay timer, i.e. the number of failed
 * attempts.
 *
 * \param ctx UDS context.
 */
void uds_reset_sa_delay_timer(uds_context_t *ctx);

#endif // UDS_H__
