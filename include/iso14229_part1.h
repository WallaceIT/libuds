/* SPDX-License-Identifier: GPL-3.0-only */
/**
 * \file iso14229_part1.h
 *
 * Values from ISO14229-1.
 *
 * This header contains values defined by the ISO14229-1 document.
 *
 * \author Francesco Valla <valla.francesco@gmail.com>
 * \copyright (c) 2022 Francesco Valla - License: GPL-3.0-only
 */

#ifndef ISO14229_PART1_H__
#define ISO14229_PART1_H__

#define UDS_NR_SI               0x7FU // Negative Response Service Identifier

#define UDS_PRINB               0x40U // Positive response Indication Bit
#define UDS_SPRMINB             0x80U // Supppress Positive Response Message Indication Bit


// Negative response codes
#define UDS_NRC_PR              0x00U // Positive Response
#define UDS_NRC_GR              0x10U // General Reject
#define UDS_NRC_SNS             0x11U // Service Not Supported
#define UDS_NRC_SFNS            0x12U // Sub-Function Not Supported
#define UDS_NRC_IMLOIF          0x13U // Incorrect Message Length Or Invalid Format
#define UDS_NRC_RTL             0x14U // Response Tool Long
#define UDS_NRC_BRR             0x21U // Busy Repeat Request
#define UDS_NRC_CNC             0x22U // Conditions Not Correct
#define UDS_NRC_RSE             0x24U // Request Sequence Error
#define UDS_NRC_NRFSC           0x25U // No Response From Subnet Component
#define UDS_NRC_FPEORA          0x26U // Failure Prevents Execution Of Requested Action
#define UDS_NRC_ROOR            0x31U // Request Out-Of-Range
#define UDS_NRC_SAD             0x33U // Security Access Denied
#define UDS_NRC_IK              0x35U // Invalid Key
#define UDS_NRC_ENOA            0x36U // Exceeded Number Of Attempts
#define UDS_NRC_RTDNE           0x37U // Required Time Delay Not Expired
#define UDS_NRC_UDNA            0x70U // Upload/Download Not Accepted
#define UDS_NRC_TDS             0x71U // Transfer Data Suspended
#define UDS_NRC_GPF             0x72U // General Programming Failure
#define UDS_NRC_WBSC            0x73U // Wrong Block Sequence Counter
#define UDS_NRC_RCRRP           0x78U // Request Correctly Received - Response Pending
#define UDS_NRC_SFNSIAS         0x7EU // Sub-Function Not Supported In Active Session
#define UDS_NRC_SNSIAS          0x7FU // Service Not Supported In Active Session
#define UDS_NRC_RPMTH           0x81U // RPM Too High
#define UDS_NRC_RPMTL           0x82U // RPM Too Low
#define UDS_NRC_EIR             0x83U // Engine Is Running
#define UDS_NRC_EINR            0x84U // Engine Is Not Running
#define UDS_NRC_ERTTL           0x85U // Engine Run Time Too Low
#define UDS_NRC_TEMPTH          0x86U // Temperature Too High
#define UDS_NRC_TEMPTL          0x87U // Temperature Too Low
#define UDS_NRC_VSTH            0x88U // Vehicle Speed Too High
#define UDS_NRC_VSTL            0x89U // Vehicle Speed Too Low
#define UDS_NRC_TPTH            0x8AU // Throttle/Pedal Too High
#define UDS_NRC_TPTL            0x8BU // Throttle/Pedal Too Low
#define UDS_NRC_TRNIN           0x8CU // Transmission Range Not In Neutral
#define UDS_NRC_TRNIG           0x8DU // Transmission Range Not In Gear
#define UDS_NRC_BSNC            0x8FU // Brake Switch(es) Not Closed
#define UDS_NRC_SLNIP           0x90U // Shifter Lever Not In Park
#define UDS_NRC_TCCL            0x91U // Torque Converter Clutch Locked
#define UDS_NRC_VTH             0x92U // Voltage Too High
#define UDS_NRC_VTL             0x93U // Voltage Too Low

// Services
#define UDS_SVC_DSC             0x10U // Diagnostic Session Control
#define UDS_SVC_ER              0x11U // ECU Reset
#define UDS_SVC_CDTCI           0x14U // Clear Diagnostic Information
#define UDS_SVC_RDTCI           0x19U // Read DTC Information
#define UDS_SVC_RDBI            0x22U // Read Data By Identifier
#define UDS_SVC_RMBA            0x23U // Read Memory By Address
#define UDS_SVC_RSDBI           0x24U // Read Scaling Data By Identifier
#define UDS_SVC_SA              0x27U // Security Access
#define UDS_SVC_CC              0x28U // Communication Control
#define UDS_SVC_RDBPI           0x2AU // Read Data By Periodic Identifier
#define UDS_SVC_DDDI            0x2CU // Dynamically Define Data Identifier
#define UDS_SVC_WDBI            0x2EU // Write Data By Identifier
#define UDS_SVC_IOCBI           0x2FU // Input/Output Control By Identifier
#define UDS_SVC_RC              0x31U // Routine Control
#define UDS_SVC_RD              0x34U // Request Download
#define UDS_SVC_RU              0x35U // Request Upload
#define UDS_SVC_TD              0x36U // Transfer Data
#define UDS_SVC_RTE             0x37U // Request Transfer Exit
#define UDS_SVC_RFT             0x38U // Request File Transfer
#define UDS_SVC_WMBA            0x3DU // Write Memory By Address
#define UDS_SVC_TP              0x3EU // Tester Present
#define UDS_SVC_ATP             0x83U // Access Timing Parameters
#define UDS_SVC_SDT             0x84U // Secured Data Transmission
#define UDS_SVC_CDTCS           0x85U // Control DTC Setting
#define UDS_SVC_ROE             0x86U // Response On Event
#define UDS_SVC_LC              0x87U // Link Control

// Sessions (sub-functions of UDS_SVC_DSC)
#define UDS_LEV_DS_DS           0x01U // Default Session
#define UDS_LEV_DS_PRGS         0x02U // Programming Session
#define UDS_LEV_DS_EXTDS        0x03U // Extended Diagnostic Session
#define UDS_LEV_DS_SSDS         0x04U // Safety System Diagnostic Session

// Reset types (sub-functions of UDS_SVC_ER)
#define UDS_LEV_RT_HR           0x01U // Hard Reset
#define UDS_LEV_RT_KOFFONR      0x02U // Key Off-On Reset
#define UDS_LEV_RT_SR           0x03U // Soft Reset
#define UDS_LEV_RT_ERPSD        0x04U // Enable Rapid Power ShutDown
#define UDS_LEV_RT_DRPSD        0x05U // Disable Rapid Power ShutDown
#define UDS_LEV_RT_VMS_MIN      0x40U // Vehicle Manufacturer Specific
#define UDS_LEV_RT_VMS_MAX      0x5FU
#define UDS_LEV_RT_SSS_MIN      0x60U // System Supplier Specific
#define UDS_LEV_RT_SSS_MAX      0x7EU

// Security access types (sub-functions of UDS_SVC_SA)
#define UDS_LEV_SAT_RSD         0x01U // Request Seed
#define UDS_LEV_SAT_SK          0x02U // Send Key
#define UDS_LEV_SAT_SSS_MIN     0x61U // System Supplier Specific
#define UDS_LEV_SAT_SSS_MAX     0x7EU

// Control types (sub-functions of UDS_SVC_CC)
#define UDS_LEV_CTRLTP_ERXTX        0x00U // Enable Rx and Tx
#define UDS_LEV_CTRLTP_ERXDTX       0x01U // Enable Rx and Disable Tx
#define UDS_LEV_CTRLTP_DRXETX       0x02U // Disable Rx and Enable Tx
#define UDS_LEV_CTRLTP_DRXTX        0x03U // Disable RX and TX
#define UDS_LEV_CTRLTP_ERXDTXWEAI   0x04U // Enable Rx And Disable TX With Enhanced Address Information
#define UDS_LEV_CTRLTP_ERXTXWEAI    0x05U // Enable Rx And TX With Enhanced Address Information

// Communication type (parameter of UDS_SVC_CC)
#define UDS_CTP_NCM             0x01U // Normal Communication Messages
#define UDS_CTP_NWMCM           0x02U // Nextwork Management Communication Messages
#define UDS_CTP_NWMCM_NCM       0x03U // Nextwork Management Communication Messages and Normal Messages

// InputOutput Control Parameter (parameter of UDS_SVC_IOCBI)
#define UDS_IOCP_RCTECU         0x00U // Return Control To ECU
#define UDS_IOCP_RTD            0x01U // Reset To Default
#define UDS_IOCP_FCS            0x02U // Freeze Current State
#define UDS_IOCP_STA            0x03U // Short Term Adjustment

// Timing parameter access types (sub-functions of UDS_SVC_ATP)
#define UDS_LEV_TPAT_RETPS      0x01U // Read Extended Timing Parameter Set
#define UDS_LEV_TPAT_STPTDV     0x02U // Set Timing Parameters To Default Values
#define UDS_LEV_TPAT_RCATP      0x03U // Read Currently Active Timing Parameters
#define UDS_LEV_TPAT_STPTGV     0x04U // Set Timing Parameters To Given Values

// DTC setting types (sub-functions of UDS_SVC_CDTCS)
#define UDS_LEV_DTCSTP_ON       0x01U // On
#define UDS_LEV_DTCSTP_OFF      0x02U // Off
#define UDS_LEV_DTCSTP_VMS_MIN  0x40U // Vehicle Manufacturer Specific
#define UDS_LEV_DTCSTP_VMS_MAX  0x5FU
#define UDS_LEV_DTCSTP_SSS_MIN  0x60U // System Supplier Specific
#define UDS_LEV_DTCSTP_SSS_MAX  0x7EU

// Event types (sub-function of UDS_SVC_ROE)
#define UDS_LEV_ETP_STRPOE      0x00U // Stop Response On Event
#define UDS_LEV_ETP_ONDTCS      0x01U // On DTC Status Change
#define UDS_LEV_ETP_OTI         0x02U // On Timer Interrupt
#define UDS_LEV_ETP_OCODID      0x03U // On Change Of Data Identifier
#define UDS_LEV_ETP_RAE         0x04U // Report Activated Events
#define UDS_LEV_ETP_STRTROE     0x05U // Start Response On Event
#define UDS_LEV_ETP_CLRROE      0x06U // Clear Response On Event
#define UDS_LEV_ETP_OCOV        0x07U // On Comparison Of Values

#define UDS_LEV_ETP_DNSE        (0x00U << 6) // Do Not Store Event
#define UDS_LEV_ETP_SE          (0x01U << 6) // Store Event

// Link control types (sub-function of UDS_SVC_LC)
#define UDS_LEV_LCTP_VMTWFP     0x01U // Verify Mode Transition With Fixed Parameter
#define UDS_LEV_LCTP_VMTWSP     0x02U // Verify Mode Transition With Specific Parameter
#define UDS_LEV_LCTP_TM         0x03U // Transition Mode

// Report types (sub-function of UDS_SVC_RDTCI)
#define UDS_LEV_RNODTCBSM       0x01U // Report Number Of DTC By Status Mask
#define UDS_LEV_RDTCBSM         0x02U // Report DTC By Status Mask
#define UDS_LEV_RDTCSSI         0x03U // Report DTC Snapshot Identification
#define UDS_LEV_RDTCSSBDTC      0x04U // Report DTC Snapshot Record By DTC Number
#define UDS_LEV_RDTCSDBRN       0x05U // Report DTC Stored Data By Record Number
#define UDS_LEV_RDTCEDRBDN      0x06U // Report DTC Ext Data Record By DTC Number
#define UDS_LEV_RNODTCBSMR      0x07U // Report Number Of DTC By Severity Mask Record
#define UDS_LEV_RDTCBSMR        0x08U // Report DTC By Severity Mask Record
#define UDS_LEV_RSIODTC         0x09U // Report Severity Information Of DTC
#define UDS_LEV_RSUPDTC         0x0AU // Report Supported DTC
#define UDS_LEV_RFTFDTC         0x0BU // Report First Test Failed DTC
#define UDS_LEV_RFCDTC          0x0CU // Report First Test Confirmed DTC
#define UDS_LEV_RMRTFDTC        0x0DU // Report Most Recent Test Failed DTC
#define UDS_LEV_RMRCDTC         0x0EU // Report Most Recent Test Confirmed DTC
#define UDS_LEV_RMMDTCBSM       0x0FU // Report Mirror Memory DTC By Status Mask
#define UDS_LEV_RMDEDRBDN       0x10U // Report Mirror Memory Ext Data Record By DTC Number
#define UDS_LEV_RNOMMDTCBSM     0x11U // reportNumberOfMirrorMemoryDTCByStatusMask
#define UDS_LEV_RNOOEBDDTCBSM   0x12U // reportNumberOfEmissionsOBDDTCByStatusMask
#define UDS_LEV_ROBDDTCBSM      0x13U // reportEmissionsOBDDTCByStatusMask
#define UDS_LEV_RDTCFDC         0x14U // Report DTC Fault Detection Counter
#define UDS_LEV_RDTCWPS         0x15U // Report DTC With Permanent Status
#define UDS_LEV_RDTCEDRBR       0x16U // Report DTC Ext Data Record By Record Number
#define UDS_LEV_RUDMDTCBSM      0x17U // Report User Def Memory DTC By Status Mask
#define UDS_LEV_RUDMDTCSSBDTC   0x18U // Report User Def Memory DTC Snapshot Record By DTC Number
#define UDS_LEV_RUDMDTCEDRBDN   0x19U // Report User Def Memory DTC Ext Data Record By DTC Number
#define UDS_LEV_ROBDDTCBMR      0x42U // Report WWH OBD DTC By Mask Record
#define UDS_LEV_RWWHOBDDTCWPS   0x55U // Report WWH OBD DTC With Permanent Status

// Routine control types (sub-functiUons of UDS_SVC_RC)
#define UDS_LEV_RCTP_STR        0x01U // Start Routine
#define UDS_LEV_RCTP_STPR       0x02U // Stop Routine
#define UDS_LEV_RCTP_RRR        0x03U // Request Routine Results

// Mode Of Operation types (actions for UDS_SVC_RFT)
#define UDS_MOOP_ADDFILE        0x01U // Add File (download to ECU)
#define UDS_MOOP_DELFILE        0x02U // Delete File
#define UDS_MOOP_REPLFILE       0x03U // Replace File (download to ECU, replace if existent)
#define UDS_MOOP_RDFILE         0x04U // Read File (upload from ECU)
#define UDS_MOOP_RDDIR          0x05U // Read Directory

// Zero Sub-Function (sub-function of UDS_SVC_TP)
#define UDS_LEV_ZSUBF           0x00U // Zero Sub-Function

#endif // ISO14229_PART1_H__
