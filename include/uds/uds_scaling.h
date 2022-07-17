
#ifndef UDS_SCALING_H__
#define UDS_SCALING_H__

#define __UDS_SCALING_BYTE(dt,n)    ((((dt)&0x0F)<<4)|(n)&0xF))

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
#define UDS_SCALING_ASCII(n)        __UDS_SCALING_BYTE(0x6,(n))

/* signedFloatingPoint ANSI/IEEE Std 754-1985 */
#define UDS_SCALING_SFP             __UDS_SCALING_BYTE(0x7,2)

/* Packets */
#define UDS_SCALING_PACKETS(n)      __UDS_SCALING_BYTE(0x8,(n))

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

#endif // UDS_SCALING_H__
