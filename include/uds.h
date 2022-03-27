
#ifndef __UDS_H
#define __UDS_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

#define UDS_CFG_SA_TYPE_NONE        (0x0000000000000000UL)
#define UDS_CFG_SA_TYPE_ALL         (0xFFFFFFFFFFFFFFFFUL)
#define UDS_CFG_SA_TYPE(x)          (0x0000000000000001UL << x)

#define UDS_CFG_SESSION_MASK_NONE   (0x0000000000000000UL)
#define UDS_CFG_SESSION_MASK_ALL    (0xFFFFFFFFFFFFFFFFUL)
#define UDS_CFG_SESSION_MASK(x)     (0x0000000000000001UL << x)

#define __UDS_SCALING_BYTE(dt,n)    (((dt&0xF)<<4)|(n & 0xF))

/* unSignedNumeric */
#define UDS_SCALING_USN_U8          __UDS_SCALING_BYTE(0x0,1)
#define UDS_SCALING_USN_U16         __UDS_SCALING_BYTE(0x0,2)
#define UDS_SCALING_USN_U24         __UDS_SCALING_BYTE(0x0,3)
#define UDS_SCALING_USN_U32         __UDS_SCALING_BYTE(0x0,4)

/* signedNumeric */
#define UDS_SCALING_SN_U8           __UDS_SCALING_BYTE(0x1,1)
#define UDS_SCALING_SN_U16          __UDS_SCALING_BYTE(0x1,2)
#define UDS_SCALING_SN_U24          __UDS_SCALING_BYTE(0x1,3)
#define UDS_SCALING_SN_U32          __UDS_SCALING_BYTE(0x1,4)

/* bitMappedReportedWithOutMask */
#define UDS_SCALING_BMRWOM(n)       __UDS_SCALING_BYTE(0x2,n)

/* bitMappedReportedWithMask */
#define UDS_SCALING_BMRWM           __UDS_SCALING_BYTE(0x3,0)

/* BinaryCodedDecimal */
#define UDS_SCALING_BCD(n)          __UDS_SCALING_BYTE(0x4,((n+1)/2))

/* stateEncodedVariable */
#define UDS_SCALING_SEV             __UDS_SCALING_BYTE(0x5,1)

/* ASCII */
#define UDS_SCALING_ASCII(n)        __UDS_SCALING_BYTE(0x6,n)

/* signedFloatingPoint ANSI/IEEE Std 754-1985 */
#define UDS_SCALING_SFP             __UDS_SCALING_BYTE(0x7,2)

/* Packets */
#define UDS_SCALING_PACKETS(n)      __UDS_SCALING_BYTE(0x8,n)

/* formula */
#define UDS_SCALING_FORMULA(n)      __UDS_SCALING_BYTE(0x9,(n+1))

#define UDS_SBE_FORMULA_C0txpC1             (0x00) /* y = C0 * x + C1 */
#define UDS_SBE_FORMULA_C0t_xpC1_           (0x01) /* y = C0 * (x + C1) */
#define UDS_SBE_FORMULA_C0d_xpC1_pC2        (0x02) /* y = C0 / (x + C1) + C2 */
#define UDS_SBE_FORMULA_xdC0pC1             (0x03) /* y = x / C0 + C1 */
#define UDS_SBE_FORMULA__xpC0_dC1           (0x04) /* y = (x + C0) / C1 */
#define UDS_SBE_FORMULA__xpC0_dC1pC2        (0x05) /* y = (x + C0) / C1 + C2 */
#define UDS_SBE_FORMULA_C0tx                (0x06) /* y = C0 * x */
#define UDS_SBE_FORMULA_xdC0                (0x07) /* y = x / C0 */
#define UDS_SBE_FORMULA_xpC0                (0x08) /* y = x + C0 */
#define UDS_SBE_FORMULA_xtC0dC1             (0x09) /* y = x * C0 / C1 */

/* unit/format */
#define UDS_SCALING_UNIT_FORMAT     __UDS_SCALING_BYTE(0xA,1)

#define UDS_SBE_UNIT_NONE                   (0x00)
#define UDS_SBE_UNIT_METER                  (0x01)
#define UDS_SBE_UNIT_FOOT                   (0x02)
#define UDS_SBE_UNIT_INCH                   (0x03)
#define UDS_SBE_UNIT_YARD                   (0x04)
#define UDS_SBE_UNIT_MILE_EN                (0x05)
#define UDS_SBE_UNIT_GRAM                   (0x06)
#define UDS_SBE_UNIT_TON_METRIC             (0x07)
#define UDS_SBE_UNIT_SECOND                 (0x08)
#define UDS_SBE_UNIT_MINUTE                 (0x09)
#define UDS_SBE_UNIT_HOUR                   (0x0A)
#define UDS_SBE_UNIT_DAY                    (0x0B)
#define UDS_SBE_UNIT_YEAR                   (0x0C)
#define UDS_SBE_UNIT_AMPERE                 (0x0D)
#define UDS_SBE_UNIT_VOLT                   (0x0E)
#define UDS_SBE_UNIT_COULOMB                (0x0F)
#define UDS_SBE_UNIT_OHM                    (0x10)
#define UDS_SBE_UNIT_FARAD                  (0x11)
#define UDS_SBE_UNIT_HENRY                  (0x12)
#define UDS_SBE_UNIT_SIEMENS                (0x13)
#define UDS_SBE_UNIT_WEBER                  (0x14)
#define UDS_SBE_UNIT_TESLA                  (0x15)
#define UDS_SBE_UNIT_KELVIN                 (0x16)
#define UDS_SBE_UNIT_CELSIUS                (0x17)
#define UDS_SBE_UNIT_FAHRENEIT              (0x18)
#define UDS_SBE_UNIT_CANDELA                (0x19)
#define UDS_SBE_UNIT_RADIAN                 (0x1A)
#define UDS_SBE_UNIT_DEGREE                 (0x1B)
#define UDS_SBE_UNIT_HERTZ                  (0x1C)
#define UDS_SBE_UNIT_JOULE                  (0x1D)
#define UDS_SBE_UNIT_NEWTON                 (0x1E)
#define UDS_SBE_UNIT_KILOPOND               (0x1F)
#define UDS_SBE_UNIT_POUND                  (0x20)
#define UDS_SBE_UNIT_WATT                   (0x21)
#define UDS_SBE_UNIT_HP_METRIC              (0x22)
#define UDS_SBE_UNIT_HP_UK_US               (0x23)
#define UDS_SBE_UNIT_PASCAL                 (0x24)
#define UDS_SBE_UNIT_BAR                    (0x25)
#define UDS_SBE_UNIT_ATMOSPHERE             (0x26)
#define UDS_SBE_UNIT_PSI                    (0x27)
#define UDS_SBE_UNIT_BECQEREL               (0x28)
#define UDS_SBE_UNIT_LUMEN                  (0x29)
#define UDS_SBE_UNIT_LUX                    (0x2A)
#define UDS_SBE_UNIT_LITER                  (0x2B)
#define UDS_SBE_UNIT_GALLON_UK              (0x2C)
#define UDS_SBE_UNIT_GALLON_US              (0x2D)
#define UDS_SBE_UNIT_CUBIC_INCH             (0x2E)
#define UDS_SBE_UNIT_METER_PER_SECOND       (0x2F)
#define UDS_SBE_UNIT_KM_PER_HOUR            (0x30)
#define UDS_SBE_UNIT_MILE_PER_HOUR          (0x31)
#define UDS_SBE_UNIT_RPS                    (0x32)
#define UDS_SBE_UNIT_RPM                    (0x33)
#define UDS_SBE_UNIT_COUNTS                 (0x34)
#define UDS_SBE_UNIT_PERCENT                (0x35)
#define UDS_SBE_UNIT_MG_PER_STROKE          (0x36)
#define UDS_SBE_UNIT_METER_PER_SQ_SECOND    (0x37)
#define UDS_SBE_UNIT_NEWTON_METER           (0x38)
#define UDS_SBE_UNIT_LITER_PER_MINUTE       (0x39)
#define UDS_SBE_UNIT_WATT_PER_SQ_METER      (0x3A)
#define UDS_SBE_UNIT_BAR_PER_SECOND         (0x3B)
#define UDS_SBE_UNIT_RADIAN_PER_SECOND      (0x3C)
#define UDS_SBE_UNIT_RADIAN_PER_SQ_SECOND   (0x3D)
#define UDS_SBE_UNIT_KG_PER_SQ_METER        (0x3E)
#define UDS_SBE_UNIT_RESERVED               (0x3F)
#define UDS_SBE_UNIT_EXA                    (0x40)
#define UDS_SBE_UNIT_PETA                   (0x41)
#define UDS_SBE_UNIT_TERA                   (0x42)
#define UDS_SBE_UNIT_GIGA                   (0x43)
#define UDS_SBE_UNIT_MEGA                   (0x44)
#define UDS_SBE_UNIT_KILO                   (0x45)
#define UDS_SBE_UNIT_HECTO                  (0x46)
#define UDS_SBE_UNIT_DECA                   (0x47)
#define UDS_SBE_UNIT_DECI                   (0x48)
#define UDS_SBE_UNIT_CENTI                  (0x49)
#define UDS_SBE_UNIT_MILLI                  (0x4A)
#define UDS_SBE_UNIT_MICRO                  (0x4B)
#define UDS_SBE_UNIT_NANO                   (0x4C)
#define UDS_SBE_UNIT_PICO                   (0x4D)
#define UDS_SBE_UNIT_FEMTO                  (0x4E)
#define UDS_SBE_UNIT_ATTO                   (0x4F)
#define UDS_SBE_UNIT_DATE1_YYMMDD           (0x50)
#define UDS_SBE_UNIT_DATE2_DDMMYY           (0x51)
#define UDS_SBE_UNIT_DATE3_MMDDYY           (0x52)
#define UDS_SBE_UNIT_WEEK                   (0x53)
#define UDS_SBE_UNIT_TIME1_UTC_HHMMSS       (0x54)
#define UDS_SBE_UNIT_TIME2_HHMMSS           (0x55)
#define UDS_SBE_UNIT_DATETIME1_SSMMHHDDMMYY     (0x56)
#define UDS_SBE_UNIT_DATETIME2_SSMMHHDDMMYYMOHO (0x57)
#define UDS_SBE_UNIT_DATETIME3_SSMMHHMMDDYY     (0x58)
#define UDS_SBE_UNIT_DATETIME4_SSMMHHMMDDYYMOHO (0x59)

/* stateAndConnectionType */
#define UDS_SCALING_SACT            __UDS_SCALING_BYTE(0xB,1)

#define UDS_SBE_SACT_STATE_NOT_ACTIVE       (0<<0)
#define UDS_SBE_SACT_STATE_ACTIVE           (1<<0)
#define UDS_SBE_SACT_STATE_ERROR_DETECT     (2<<0)
#define UDS_SBE_SACT_STATE_NOT_AVAILABLE    (3<<0)
#define UDS_SBE_SACT_STATE_ACTIVE_FUNC2     (4<<0)

#define UDS_SBE_SACT_SIGNAL_LOW_LEVEL       (0<<3)
#define UDS_SBE_SACT_SIGNAL_MID_LEVEL       (1<<3)
#define UDS_SBE_SACT_SIGNAL_HIGH_LEVEL      (2<<3)

#define UDS_SBE_SACT_INPUT_SIGNAL           (0<<5)
#define UDS_SBE_SACT_OUTPUT_SIGNAL          (1<<5)

#define UDS_SBE_SACT_INTERNAL_SIGNAL        (0<<6)
#define UDS_SBE_SACT_PULL_DOWN_INPUT        (1<<6)
#define UDS_SBE_SACT_PULL_UP_INPUT          (2<<6)
#define UDS_SBE_SACT_THREE_STATES_INPUT     (3<<6)
#define UDS_SBE_SACT_LOW_SIDE_SWITCH        (1<<6)
#define UDS_SBE_SACT_HIGH_SIDE_SWITCH       (2<<6)
#define UDS_SBE_SACT_THREE_STATES_SWITCH    (3<<6)

typedef enum {
    UDS_CCACT_EN_RX_EN_TX       = 0x00,
    UDS_CCACT_EN_RX_DIS_TX      = 0x01,
    UDS_CCACT_DIS_RX_EN_TX      = 0x02,
    UDS_CCACT_DIS_RX_DIS_TX     = 0x03,
    UDS_CCACT_EN_RX_DIS_TX_EAI  = 0x04,
    UDS_CCACT_EN_RX_EN_TX_EAI   = 0x05,
} uds_cc_action_e;

typedef enum {
    UDS_CCMT_NONE = 0x00,
    UDS_CCMT_NORMAL = 0x01,
    UDS_CCMT_NETWORK_MANAGEMENT = 0x02,
    UDS_CCMT_NETWORK_MANAGEMENT_AND_NORMAL = 0x03,
} uds_cc_message_type_e;

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

typedef enum {
    UDS_FILE_MODE_READ = 0,
    UDS_FILE_MODE_WRITE_CREATE = 1,
    UDS_FILE_MODE_WRITE_REPLACE = 2,
    UDS_FILE_MODE_LIST_DIR = 3,
} uds_file_mode_e;

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

    uint16_t p2_timeout_ms;
    uint16_t p2star_timeout_ms;

    unsigned long s3_time;
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

typedef struct __uds_config_communication_control
{
    int (*cb_control)(void *priv, uds_cc_action_e action,
                      uds_cc_message_type_e message_type,
                      uint8_t subnet_address, uint16_t extended_address);
    uds_security_cfg_t sec;
} uds_config_communication_control_t;

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

    const uint8_t *scaling_data;
    unsigned long scaling_data_size;
} uds_config_data_t;

typedef struct __uds_config_memory_region
{
    const uintptr_t start;
    const uintptr_t stop;

    int (*cb_read)(void *priv, const uintptr_t address,
                   uint8_t *data, const size_t data_len);
    uds_security_cfg_t sec_read;

    int (*cb_write)(void *priv, const uintptr_t address,
                    const uint8_t *data, const size_t data_len);
    uds_security_cfg_t sec_write;

    int (*cb_download_request)(void *priv, const uintptr_t address,
                               const size_t data_len,
                               const uint8_t compression_method,
                               const uint8_t encrypting_method);
    int (*cb_download)(void *priv, const uintptr_t address,
                       const uint8_t *data, const size_t data_len);
    int (*cb_download_exit)(void *priv);
    uds_security_cfg_t sec_download;

    int (*cb_upload_request)(void *priv, const uintptr_t address,
                             const size_t data_len,
                             const uint8_t compression_method,
                             const uint8_t encrypting_method);
    int (*cb_upload)(void *priv, const uintptr_t address,
                     uint8_t *data, size_t *data_len);
    int (*cb_upload_exit)(void *priv);
    uds_security_cfg_t sec_upload;
    size_t max_block_len;
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

typedef struct __uds_config_file_access
{
    int (*cb_open)(void *priv, const char *filepath, size_t filepath_len,
                   uds_file_mode_e mode, intptr_t *fd,
                   size_t *file_size, size_t *file_size_compressed,
                   const uint8_t compression_method, const uint8_t encrypting_method);

    int (*cb_list)(void *priv, intptr_t fd, size_t offset, void *buf, size_t *count);

    int (*cb_read)(void *priv, intptr_t fd, size_t offset, void *buf, size_t *count);

    int (*cb_write)(void *priv, intptr_t fd, size_t offset, const void *buf, size_t count);

    int (*cb_close)(void *priv, uds_file_mode_e mode, intptr_t fd);

    int (*cb_delete)(void *priv, const char *filepath, size_t filepath_len);

    uds_security_cfg_t sec;

    size_t max_block_len;

} uds_config_file_access_t;

typedef struct __uds_config_routine
{
    uint16_t identifier;

    uds_security_cfg_t sec;

    int (*cb_start)(void *priv, uint16_t identifier,
                    const uint8_t *data, const size_t data_len,
                    uint8_t *res_data, size_t *res_data_len);

    int (*cb_stop)(void *priv, uint16_t identifier,
                   const uint8_t *data, const size_t data_len,
                   uint8_t *res_data, size_t *res_data_len);

    int (*cb_req_results)(void *priv, uint16_t identifier,
                          uint8_t *res_data, size_t *res_data_len);

    int (*cb_is_running)(void *priv, uint16_t identifier);
} uds_config_routine_t;

typedef struct __uds_config
{
    int (*cb_send)(void *priv, const uint8_t data[], size_t len);
    void (*cb_notify_session_change)(void *priv, const uint8_t session_type);
    void (*cb_notify_sa_change)(void *priv, const uint8_t sa_index);

    const uds_session_cfg_t *session_config;
    unsigned long num_session_config;

    const uds_sa_cfg_t *sa_config;
    unsigned long num_sa_config;

    unsigned long sa_max_attempts;
    unsigned long sa_delay_timer_ms;

    const uds_config_ecureset_t ecureset;
    const uds_config_communication_control_t communication_control;
    const uds_config_dtc_settings_t dtc_settings;

    const uds_config_data_t *data_items;
    unsigned long num_data_items;

    const uds_config_memory_region_t *mem_regions;
    unsigned long num_mem_regions;

    const uds_config_group_of_dtc_t *groups_of_dtc;
    unsigned long num_groups_of_dtc;

    const uds_config_dtc_information_t dtc_information;

    const uds_config_file_access_t file_transfer;

    const uds_config_routine_t *routines;
    unsigned long num_routines;
} uds_config_t;

typedef enum __uds_data_transfer_dir
{
    UDS_DATA_TRANSFER_NONE,
    UDS_DATA_TRANSFER_DOWNLOAD,
    UDS_DATA_TRANSFER_UPLOAD,
    UDS_DATA_TRANSFER_DOWNLOAD_FILE,
    UDS_DATA_TRANSFER_UPLOAD_FILE,
    UDS_DATA_TRANSFER_LIST_DIR,
} uds_data_transfer_dir_e;

typedef struct __uds_context
{
    const uds_config_t *config;
    void *priv;

    struct timespec last_message_timestamp;

    unsigned int loglevel;
    const uds_session_cfg_t *current_session;
    uint8_t current_sa_seed;
    const uds_sa_cfg_t *current_sa;
    unsigned long sa_failed_attempts;
    struct timespec sa_delay_timer_timestamp;

    struct
    {
        uds_data_transfer_dir_e direction;
        uds_file_mode_e file_mode;
        const uds_config_memory_region_t *mem_region;
        size_t max_block_len;
        uint8_t bsqc;
        uintptr_t prev_address;
        uintptr_t address;
        intptr_t fd;
    } data_transfer;

    uint8_t *response_buffer;
    size_t response_buffer_len;
} uds_context_t;

typedef enum __uds_address
{
    UDS_ADDRESS_PHYSICAL,
    UDS_ADDRESS_FUNCTIONAL,
} uds_address_e;

int uds_init(uds_context_t *ctx, const uds_config_t *config,
             uint8_t *response_buffer, size_t response_buffer_len, void *priv,
             const struct timespec *timestamp);
void uds_deinit(uds_context_t *ctx);
int uds_receive(uds_context_t *ctx, const uds_address_e addr_type,
                const uint8_t *data, const size_t len,
                const struct timespec *timestamp);
int uds_cycle(uds_context_t *ctx, const struct timespec *timestamp);
void uds_reset_sa_delay_timer(uds_context_t *ctx);

#endif // __UDS_H
