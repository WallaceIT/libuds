
#ifndef __ISO14229_PART1_H
#define __ISO14229_PART1_H

#define UDS_NR_SI               0x7F // Negative Response Service Identifier

#define UDS_PRINB               0x40 // Positive response Indication Bit
#define UDS_SPRMINB             0x80 // Supppress Positive Response Message Indication Bit


// Negative response codes
#define UDS_NRC_PR              0x00 // Positive Response
#define UDS_NRC_GR              0x10 // General Reject
#define UDS_NRC_SNS             0x11 // Service Not Supported
#define UDS_NRC_SFNS            0x12 // Sub-Function Not Supported
#define UDS_NRC_IMLOIF          0x13 // Incorrect Message Length Or Invalid Format
#define UDS_NRC_RTL             0x14 // Response Tool Long
#define UDS_NRC_BRR             0x21 // Busy Repeat Request
#define UDS_NRC_CNC             0x22 // Conditions Not Correct
#define UDS_NRC_RSE             0x24 // Request Sequence Error
#define UDS_NRC_NRFSC           0x25 // No Response From Subnet Component
#define UDS_NRC_FPEORA          0x26 // Failure Prevents Execution Of Requested Action
#define UDS_NRC_ROOR            0x31 // Request Out-Of-Range
#define UDS_NRC_SAD             0x33 // Security Access Denied
#define UDS_NRC_IK              0x35 // Invalid Key
#define UDS_NRC_ENOA            0x36 // Exceeded Number Of Attempts
#define UDS_NRC_RTDNE           0x37 // Required Time Delay Not Expired
#define UDS_NRC_UDNA            0x70 // Upload/Download Not Accepted
#define UDS_NRC_TDS             0x71 // Transfer Data Suspended
#define UDS_NRC_GPF             0x72 // General Programming Failure
#define UDS_NRC_WBSC            0x73 // Wrong Block Sequence Counter
#define UDS_NRC_RCRRP           0x78 // Request Correctly Received - Response Pending
#define UDS_NRC_SFNSIAS         0x7E // Sub-Function Not Supported In Active Session
#define UDS_NRC_SNSIAS          0x7F // Service Not Supported In Active Session
#define UDS_NRC_RPMTH           0x81 // RPM Too High
#define UDS_NRC_RPMTL           0x82 // RPM Too Low
#define UDS_NRC_EIR             0x83 // Engine Is Running
#define UDS_NRC_EINR            0x84 // Engine Is Not Running
#define UDS_NRC_ERTTL           0x85 // Engine Run Time Too Low
#define UDS_NRC_TEMPTH          0x86 // Temperature Too High
#define UDS_NRC_TEMPTL          0x87 // Temperature Too Low
#define UDS_NRC_VSTH            0x88 // Vehicle Speed Too High
#define UDS_NRC_VSTL            0x89 // Vehicle Speed Too Low
#define UDS_NRC_TPTH            0x8A // Throttle/Pedal Too High
#define UDS_NRC_TPTL            0x8B // Throttle/Pedal Too Low
#define UDS_NRC_TRNIN           0x8C // Transmission Range Not In Neutral
#define UDS_NRC_TRNIG           0x8D // Transmission Range Not In Gear
#define UDS_NRC_BSNC            0x8F // Brake Switch(es) Not Closed
#define UDS_NRC_SLNIP           0x90 // Shifter Lever Not In Park
#define UDS_NRC_TCCL            0x91 // Torque Converter Clutch Locked
#define UDS_NRC_VTH             0x92 // Voltage Too High
#define UDS_NRC_VTL             0x93 // Voltage Too Low

// Services
#define UDS_SVC_DSC             0x10 // Diagnostic Session Control
#define UDS_SVC_ER              0x11 // ECU Reset
#define UDS_SVC_CDTCI           0x14 // Clear Diagnostic Information
#define UDS_SVC_RDTCI           0x19 // Read DTC Information
#define UDS_SVC_RDBI            0x22 // Read Data By Identifier
#define UDS_SVC_RMBA            0x23 // Read Memory By Address
#define UDS_SVC_RSDBI           0x24 // Read Scaling Data By Identifier
#define UDS_SVC_SA              0x27 // Security Access
#define UDS_SVC_CC              0x28 // Communication Control
#define UDS_SVC_RDBPI           0x2A // Read Data By Periodic Identifier
#define UDS_SVC_DDDI            0x2C // Dynamically Define Data Identifier
#define UDS_SVC_WDBI            0x2E // Write Data By Identifier
#define UDS_SVC_IOCBI           0x2F // Input/Output Control By Identifier
#define UDS_SVC_RC              0x31 // Routine Control
#define UDS_SVC_RD              0x34 // Request Download
#define UDS_SVC_RU              0x35 // Request Upload
#define UDS_SVC_TD              0x36 // Transfer Data
#define UDS_SVC_RTE             0x37 // Request Transfer Exit
#define UDS_SVC_RFT             0x38 // Request File Transfer
#define UDS_SVC_WMBA            0x3D // Write Memory By Address
#define UDS_SVC_TP              0x3E // Tester Present
#define UDS_SVC_ATP             0x83 // Access Timing Parameters
#define UDS_SVC_SDT             0x84 // Secured Data Transmission
#define UDS_SVC_CDTCS           0x85 // Control DTC Setting
#define UDS_SVC_ROE             0x86 // Response On Event
#define UDS_SVC_LC              0x87 // Link Control

// Sessions (sub-functions of UDS_SVC_DSC)
#define UDS_LEV_DS_DS           0x01 // Default Session
#define UDS_LEV_DS_PRGS         0x02 // Programming Session
#define UDS_LEV_DS_EXTDS        0x03 // Extended Diagnostic Session
#define UDS_LEV_DS_SSDS         0x04 // Safety System Diagnostic Session

// Reset types (sub-functions of UDS_SVC_ER)
#define UDS_LEV_RT_HR           0x01 // Hard Reset
#define UDS_LEV_RT_KOFFONR      0x02 // Key Off-On Reset
#define UDS_LEV_RT_SR           0x03 // Soft Reset
#define UDS_LEV_RT_ERPSD        0x04 // Enable Rapid Power ShutDown
#define UDS_LEV_RT_DRPSD        0x05 // Disable Rapid Power ShutDown
#define UDS_LEV_RT_VMS_MIN      0x40 // Vehicle Manufacturer Specific
#define UDS_LEV_RT_VMS_MAX      0x5F
#define UDS_LEV_RT_SSS_MIN      0x60 // System Supplier Specific
#define UDS_LEV_RT_SSS_MAX      0x7E

// Security access types (sub-functions of UDS_SVC_SA)
#define UDS_LEV_SA_RSD          0x01 // Request Seed
#define UDS_LEV_SA_SK           0x02 // Send Key

// Control types (sub-functions of UDS_SVC_CC)
#define UDS_LEV_CTRLTP_ERXTX        0x00 // Enable Rx and Tx
#define UDS_LEV_CTRLTP_ERXDTX       0x01 // Enable Rx and Disable Tx
#define UDS_LEV_CTRLTP_DRXETX       0x02 // Disable Rx and Enable Tx
#define UDS_LEV_CTRLTP_DRXTX        0x03 // Disable RX and TX
#define UDS_LEV_CTRLTP_ERXDTXWEAI   0x04 // Enable Rx And Disable TX With Enhanced Address Information
#define UDS_LEV_CTRLTP_ERXTXWEAI    0x05 // Enable Rx And TX With Enhanced Address Information

// Communication type (parameter of UDS_SVC_CC)
#define UDS_CTP_NCM                 0x01 // Normal Communication Messages
#define UDS_CTP_NWMCM               0x02 // Nextwork Management Communication Messages
#define UDS_CTP_NWMCM_NCM           0x03 // Nextwork Management Communication Messages and Normal Messages

// InputOutput Control Parameter (parameter of UDS_SVC_IOCBI)
#define UDS_IOCP_RCTECU         0x00 // Return Control To ECU
#define UDS_IOCP_RTD            0x01 // Reset To Default
#define UDS_IOCP_FCS            0x02 // Freeze Current State
#define UDS_IOCP_STA            0x03 // Short Term Adjustment

// Timing parameter access types (sub-functions of UDS_SVC_ATP)
#define UDS_LEV_TPAT_RETPS      0x01 // Read Extended Timing Parameter Set
#define UDS_LEV_TPAT_STPTDV     0x02 // Set Timing Parameters To Default Values
#define UDS_LEV_TPAT_RCATP      0x03 // Read Currently Active Timing Parameters
#define UDS_LEV_TPAT_STPTGV     0x04 // Set Timing Parameters To Given Values

// DTC setting types (sub-functions of UDS_SVC_CDTCS)
#define UDS_LEV_DTCSTP_ON       0x01 // On
#define UDS_LEV_DTCSTP_OFF      0x02 // Off
#define UDS_LEV_DTCSTP_VMS_MIN  0x40 // Vehicle Manufacturer Specific
#define UDS_LEV_DTCSTP_VMS_MAX  0x5F
#define UDS_LEV_DTCSTP_SSS_MIN  0x60 // System Supplier Specific
#define UDS_LEV_DTCSTP_SSS_MAX  0x7E

// Event types (sub-function of UDS_SVC_ROE)
#define UDS_LEV_ETP_STRPOE      0x00 // Stop Response On Event
#define UDS_LEV_ETP_ONDTCS      0x01 // On DTC Status Change
#define UDS_LEV_ETP_OTI         0x02 // On Timer Interrupt
#define UDS_LEV_ETP_OCODID      0x03 // On Change Of Data Identifier
#define UDS_LEV_ETP_RAE         0x04 // Report Activated Events
#define UDS_LEV_ETP_STRTROE     0x05 // Start Response On Event
#define UDS_LEV_ETP_CLRROE      0x06 // Clear Response On Event
#define UDS_LEV_ETP_OCOV        0x07 // On Comparison Of Values

#define UDS_LEV_ETP_DNSE        (0x00 << 6) // Do Not Store Event
#define UDS_LEV_ETP_SE          (0x01 << 6) // Store Event

// Link control types (sub-function of UDS_SVC_LC)
#define UDS_LEV_LCTP_VMTWFP     0x01 // Verify Mode Transition With Fixed Parameter
#define UDS_LEV_LCTP_VMTWSP     0x02 // Verify Mode Transition With Specific Parameter
#define UDS_LEV_LCTP_TM         0x03 // Transition Mode

// Report types (sub-function of UDS_SVC_RDTCI)
#define UDS_LEV_RNODTCBSM       0x01 // Report Number Of DTC By Status Mask
#define UDS_LEV_RDTCBSM         0x02 // Report DTC By Status Mask
#define UDS_LEV_RDTCSSI         0x03 // Report DTC Snapshot Identification
#define UDS_LEV_RDTCSSBDTC      0x04 // Report DTC Snapshot Record By DTC Number
#define UDS_LEV_RDTCSDBRN       0x05 // Report DTC Stored Data By Record Number
#define UDS_LEV_RDTCEDRBDN      0x06 // Report DTC Ext Data Record By DTC Number
#define UDS_LEV_RNODTCBSMR      0x07 // Report Number Of DTC By Severity Mask Record
#define UDS_LEV_RDTCBSMR        0x08 // Report DTC By Severity Mask Record
#define UDS_LEV_RSIODTC         0x09 // Report Severity Information Of DTC
#define UDS_LEV_RSUPDTC         0x0A // Report Supported DTC
#define UDS_LEV_RFTFDTC         0x0B // Report First Test Failed DTC
#define UDS_LEV_RFCDTC          0x0C // Report First Test Confirmed DTC
#define UDS_LEV_RMRTFDTC        0x0D // Report Most Recent Test Failed DTC
#define UDS_LEV_RMRCDTC         0x0E // Report Most Recent Test Confirmed DTC
#define UDS_LEV_RMMDTCBSM       0x0F // Report Mirror Memory DTC By Status Mask
#define UDS_LEV_RMDEDRBDN       0x10 // Report Mirror Memory Ext Data Record By DTC Number
#define UDS_LEV_RNOMMDTCBSM     0x11 // reportNumberOfMirrorMemoryDTCByStatusMask
#define UDS_LEV_RNOOEBDDTCBSM   0x12 // reportNumberOfEmissionsOBDDTCByStatusMask
#define UDS_LEV_ROBDDTCBSM      0x13 // reportEmissionsOBDDTCByStatusMask
#define UDS_LEV_RDTCFDC         0x14 // Report DTC Fault Detection Counter
#define UDS_LEV_RDTCWPS         0x15 // Report DTC With Permanent Status
#define UDS_LEV_RDTCEDRBR       0x16 // Report DTC Ext Data Record By Record Number
#define UDS_LEV_RUDMDTCBSM      0x17 // Report User Def Memory DTC By Status Mask
#define UDS_LEV_RUDMDTCSSBDTC   0x18 // Report User Def Memory DTC Snapshot Record By DTC Number
#define UDS_LEV_RUDMDTCEDRBDN   0x19 // Report User Def Memory DTC Ext Data Record By DTC Number
#define UDS_LEV_ROBDDTCBMR      0x42 // Report WWH OBD DTC By Mask Record
#define UDS_LEV_RWWHOBDDTCWPS   0x55 // Report WWH OBD DTC With Permanent Status

// Routine control types (sub-functions of UDS_SVC_RC)
#define UDS_LEV_RCTP_STR        0x01 // Start Routine
#define UDS_LEV_RCTP_STPR       0x02 // Stop Routine
#define UDS_LEV_RCTP_RRR        0x03 // Request Routine Results

// Mode Of Operation types (actions for UDS_SVC_RFT)
#define UDS_MOOP_ADDFILE        0x01 // Add File (download to ECU)
#define UDS_MOOP_DELFILE        0x02 // Delete File
#define UDS_MOOP_REPLFILE       0x03 // Replace File (download to ECU, replace if existent)
#define UDS_MOOP_RDFILE         0x04 // Read File (upload from ECU)
#define UDS_MOOP_RDDIR          0x05 // Read Directory

// Zero Sub-Function (sub-function of UDS_SVC_TP)
#define UDS_LEV_ZSUBF           0x00 // Zero Sub-Function

#endif // __ISO14229_PART1_H