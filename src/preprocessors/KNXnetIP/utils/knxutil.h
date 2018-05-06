/*
 * util.h
 *
 *  Created on: May 6, 2018
 *      Author: alija
 */

#ifndef __KNXUTIL_H__
#define __KNXUTIL_H__

typedef struct _value_string {
    uint32_t   value;
    const char *text;
} value_string;

#define SEARCH_REQ 0x0201
#define SEARCH_RES 0x0202
#define DESCRIPTION_REQ 0x0203
#define DESCRIPTION_RES 0x0204
#define CONNECT_REQ 0x0205
#define CONNECT_RES 0x0206
#define CONNECTIONSTATE_REQ 0x0207
#define CONNECTIONSTATE_RES 0x0208
#define DISCONNECT_REQ 0x0209
#define DISCONNECT_RES 0x020A
#define DEVICE_CONFIGURATION_REQ 0x0310
#define DEVICE_CONFIGURATION_ACK 0x0311
#define TUNNELLING_REQ 0x0420
#define TUNNELLING_ACK 0x0421
#define ROUTING_INDICATION 0x0530
#define ROUTING_LOST 0x0531
#define ROUTING_BUSY 0x0532
#define REMOTE_DIAG_REQ 0x0740
#define REMOTE_DIAG_RES 0x0741
#define REMOTE_BASIC_CONF_REQ 0x0742
#define REMOTE_RESET_REQ 0x0743
#define DIB_DEVICE_INFO 0x01
#define DIB_SUPP_SVC 0x02
#define DIB_IP_CONF 0x03
#define DIB_IP_CURRENT 0x04
#define DIB_KNX_ADDRESS 0x05
#define DIB_MFR_DATA 0xFE
#define KNX_TUNNEL_CONNECTION 0x04
#define FLAGS_DEVICESTATUS_RESERVED 0xFE
#define FLAGS_DEVICESTATUS_PROGRAM 0x01
#define FLAGS_IPCAPABILITES_RESERVED 0xF8
#define FLAGS_IPCAPABILITES_BOOTIP 0x01
#define FLAGS_IPCAPABILITES_DHCP 0x02
#define FLAGS_IPCAPABILITES_AUTOIP 0x04
#define FLAGS_DEVICESTATE_RESERVED 0xFC
#define FLAGS_DEVICESTATE_KNX 0x01
#define FLAGS_DEVICESTATE_IP 0x02
/*for CEMI*/
#define RAW_REQ 0x10
#define DATA_REQ 0x11
#define POLL_DATA_REQ 0x13
#define POLL_DATA_CON 0x25
#define DATA_IND 0x29
#define BUSMON_IND 0x2B
#define RAW_IND 0x2D
#define DATA_CON 0x2E
#define RAW_CON 0x2F
#define DATA_CONNEC_REQ 0x41
#define DATA_INDV_REQ 0x4A
#define DATA_CONNEC_IND 0x89
#define DATA_INDV_IND 0x94
#define RESET_IND 0xF0
#define RESET_REQ 0xF1
#define PROPWRITE_CON 0xF5
#define PROPWRITE_REQ 0xF6
#define PROPINFO_IND 0xF7
#define FUNCPROPCOM_REQ 0xF8
#define FUNCPROPSTATREAD_REQ 0xF9
#define FUNCPROPCOM_CON 0xFA
#define PROPREAD_CON 0xFB
#define PROPREAD_REQ 0xFC
#define PL_INFO 0x1
#define RF_INFO 0x2
#define BUSMON_INFO 0x3
#define TIME_REL 0x4
#define TIME_DELAY 0x5
#define EXEND_TIME 0x6
#define BIBAT_INFO 0x7
#define RF_MULTI 0x8
#define PREAMBEL 0x9
#define RF_FAST_ACK 0xA
#define MANU_DATA 0xFE
#define RESER 0xFF
#define A_GROUPVALUE_RES 0x040
#define A_GROUPVALUE_WRT 0x080
#define A_ADC_RED 0x180
#define A_ADC_RES 0x1C0
#define A_MEM_RED 0x200
#define A_MEM_RES 0x240
#define A_MEM_WRT 0x280
#define A_SYS_RED 0x1C8
#define A_SYS_RES 0x1C9
#define A_SYS_WRT 0x1CA
#define A_SYS_BROAD 0x1CB
#define GROUPADD 0x80
#define COUPLER_SPECIFIC_SERVICE 0x3C0
#define A_AUTHORIZE_REQ 0x3D1
#define A_AUTHORIZE_RES 0x3D2
#define A_KEY_WRT 0x3D3
#define A_KEY_RES 0x3D4
#define A_PROPVALUE_RED 0x3D5
#define A_PROPVALUE_RES 0x3D6

static const
value_string knxnetip_service_identifier[] = {
    { SEARCH_REQ,               "SEARCH_REQUEST" },
    { SEARCH_RES,               "SEARCH_RESPONSE" },
    { DESCRIPTION_REQ,          "DESCRIPTION_REQUEST" },
    { DESCRIPTION_RES,          "DESCRIPTION_RESPONSE" },
    { CONNECT_REQ,              "CONNECT_REQUEST" },
    { CONNECT_RES,              "CONNECT_RESPONSE" },
    { CONNECTIONSTATE_REQ,      "CONNECTIONSTATE_REQUEST" },
    { CONNECTIONSTATE_RES,      "CONNECTIONSTATE_RESPONSE" },
    { DISCONNECT_REQ,           "DISCONNECT_REQUEST" },
    { DISCONNECT_RES,           "DISCONNECT_RESPONSE" },
    { DEVICE_CONFIGURATION_REQ, "DEVICE_CONFIGURATION_REQUEST" },
    { DEVICE_CONFIGURATION_ACK, "DEVICE_CONFIGURATION_ACK" },
    { TUNNELLING_REQ,           "TUNNELLING_REQUEST" },
    { TUNNELLING_ACK,           "TUNNELING_ACK" },
    { ROUTING_INDICATION,       "ROUTING_INDICATION" },
    { ROUTING_LOST,             "ROUTING_LOST_MESSAGE" },
    { ROUTING_BUSY,             "ROUTING_BUSY" },
    { REMOTE_DIAG_REQ,          "REMOTE_DIAGNOSTIC_REQUEST" },
    { REMOTE_DIAG_RES,          "REMOTE_DIAGNOSTIC_RESPONSE" },
    { REMOTE_BASIC_CONF_REQ,    "REMOTE_BASIC_CONFIGURATION_REQUEST" },
    { REMOTE_RESET_REQ,         "REMOTE_RESET_REQUEST" },
    { 0, NULL }
};


static const value_string knxnetip_service_types[] = {
    { 0x02, "KNXnet/IP Core" },
    { 0x03, "KNXnet/IP Device Management" },
    { 0x04, "KNXnet/IP Tunneling" },
    { 0x05, "KNXnet/IP Routing" },
    { 0x06, "KNXnet/IP Remote Logging" },
    { 0x07, "KNXnet/IP Remote Configuration and Diagnosis" },
    { 0x08, "KNXnet/IP Object Server" },
    { 0, NULL }
};

static const value_string knxnetip_connection_types[] = {
    { 0x03, "DEVICE_MGMT_CONNECTION" },
    { 0x04, "TUNNEL_CONNECTION" },
    { 0x06, "REMLOG_CONNECTION" },
    { 0x07, "REMCONF_CONNECTION" },
    { 0x08, "OBJSVR_CONNECTION" },
    { 0, NULL }
};


static const value_string knxnetip_connect_response_status_codes[] = {
    { 0x00, "E_NO_ERROR - The connection was established successfully" },
    { 0x22, "E_CONNECTION_TYPE - The KNXnet/IP server device does not support the requested connection type" },
    { 0x23, "E_CONNECTION_OPTION - The KNXnet/IP server device does not support one or more requested connection options" },
    { 0x24, "E_NO_MORE_CONNECTIONS - The KNXnet/IP server device could not accept the new data connection (busy)" },
    { 0, NULL }
};

static const value_string knxnetip_connectionstate_response_status_codes[] = {
    { 0x00, "E_NO_ERROR - The connection state is normal" },
    { 0x21, "E_CONNECTION_ID - The KNXnet/IP server device could not find an active data connection with the specified ID" },
    { 0x26, "E_DATA_CONNECTION - The KNXnet/IP server device detected an error concerning the data connection with the specified ID" },
    { 0x27, "E_KNX_CONNECTION - The KNXnet/IP server device detected an error concerning the EIB bus / KNX subsystem connection with the specified ID" },
    { 0, NULL }
};

static const value_string knxnetip_tunneling_error_codes[] = {
    { 0x00, "E_NO_ERROR - The message was received successfully" },
    { 0x29, "E_TUNNELLING_LAYER - The KNXnet/IP server device does not support the requested tunnelling layer" },
    { 0, NULL }
};

static const value_string knxnetip_device_configuration_ack_status_codes[] = {
    { 0x00, "E_NO_ERROR - The message was received successfully" },
    { 0, NULL }
};

static const value_string knxnetip_dib_description_type_codes[] = {
    { DIB_DEVICE_INFO, "DEVICE_INFO" },
    { DIB_SUPP_SVC,    "SUPP_SVC_FAMILIES" },
    { DIB_IP_CONF,     "IP_CONFIG" },
    { DIB_IP_CURRENT,  "IP_CUR_CONFIG" },
    { DIB_KNX_ADDRESS, "KNX_ADDRESSES" },
    { DIB_MFR_DATA,    "MFR_DATA" },
    { 0, NULL }
};

static const value_string knxnetip_dib_medium_codes[] = {
    { 0x01, "reserved" },
    { 0x02, "KNX TP" },
    { 0x04, "KNX PL110" },
    { 0x08, "reserved" },
    { 0x10, "KNX RF" },
    { 0x20, "KNX IP" },
    { 0, NULL }
};

static const value_string knxnetip_host_protocol_codes[] = {
    { 0x01, "IPV4_UDP" },
    { 0x02, "IPV4_TCP" },
    { 0, NULL }
};

static const value_string knxnetip_ip_assignment_method[] = {
    { 0x01, "manuell" },
    { 0x02, "BootP" },
    { 0x04, "DHCP" },
    { 0x08, "AutoIP" },
    { 0, NULL }
};

static const value_string knxnetip_knxlayer_values[] = {
    { 0x02, "TUNNEL_LINKLAYER" },
    { 0x04, "TUNNEL_RAW"},
    { 0x80, "TUNNEL_BUSMONITOR"},
    { 0, NULL}
};

static const value_string knxnetip_selector_types[] = {
    { 0x01, "PrgMode Selector" },
    { 0x02, "MAC Selector" },
    { 0, NULL }
};

static const value_string knxnetip_reset_codes[] = {
    { 0x01, "Restart" },
    { 0x02, "Master Reset" },
    { 0, NULL }
};

/*for CEMI*/
static const value_string cemi_messagecodes[] = {
    { RAW_REQ,              "L_Raw.req"},
    { DATA_REQ,             "L_Data.req"},
    { POLL_DATA_REQ,        "L_Poll_Data.req"},
    { POLL_DATA_CON,        "L_Poll_Data.con"},
    { DATA_IND,             "L_Data.ind"},
    { BUSMON_IND,           "L_Busmon.ind"},
    { RAW_IND,              "L_Raw.ind"},
    { DATA_CON,             "L_Data.con"},
    { RAW_CON,              "L_Raw.con"},
    { DATA_CONNEC_REQ,      "T_Data_Connected.req"},
    { DATA_INDV_REQ,        "T_Data_Individual.req"},
    { DATA_CONNEC_IND,      "T_Data_Connected.ind"},
    { DATA_INDV_IND,        "T_Data_Individual.ind"},
    { RESET_IND,            "M_Reset.ind"},
    { RESET_REQ,            "M_Reset.req"},
    { PROPWRITE_CON,        "M_PropWrite.con"},
    { PROPWRITE_REQ,        "M_PropWrite.req"},
    { PROPINFO_IND,         "M_PropInfo.ind"},
    { FUNCPROPCOM_REQ,      "M_FuncPropCommand.req"},
    { FUNCPROPSTATREAD_REQ, "M_FuncPropStateRead.req"},
    { FUNCPROPCOM_CON,      "M_FuncPropCommand/StateRead.con"},
    { PROPREAD_CON,         "M_PropRead.con"},
    { PROPREAD_REQ,         "M_PropRead.req"},
    { 0, NULL }
};

static const value_string cemi_add_type_id[] = {
    { 0x00,        "reserved" },
    { PL_INFO,     "PL Info"},
    { RF_INFO,     "RF Info"},
    { BUSMON_INFO, "Busmonitor Info"},
    { TIME_REL,    "relative timestamp"},
    { TIME_DELAY,  "time delay until send"},
    { EXEND_TIME,  "extended relative timestamp"},
    { BIBAT_INFO,  "BiBat information"},
    { RF_MULTI,    "RF Multi information"},
    { PREAMBEL,    "Preamble and postamble"},
    { RF_FAST_ACK, "RF Fast Ack information"},
    { MANU_DATA,   "Manufacturer specific data"},
    { RESER,       "reserved"},
    { 0, NULL}
};

static const value_string cemi_tpci_vals[] = {
    { 0x0, "UDT (Unnumbered Data Packet)" },
    { 0x2, "UCD (Unnumbered)"},
    { 0x1, "NDT (Numbered Data Packet)"},
    { 0x3, "NCD (Numbered Control Data)"},
    { 0, NULL}
};

static const value_string cemi_apci_codes[] = {
    { 0x000, "A_GroupValue_Read" },
    { 0x001, "A_GroupValue_Response"},
    { 0x002, "A_GroupValue_Write"},
    { 0x0C0, "A_IndividualAddress_Write"},
    { 0x100, "A_IndividualAddress_Read"},
    { 0x140, "A_IndividualAddress_Response"},
    { 0x006, "A_ADC_Read"},
    { 0x1C0, "A_ADC_Response"},
    { 0x1C4, "A_SystemNetworkParameter_Read"},
    { 0x1C9, "A_SystemNetworkParameter_Response"},
    { 0x1CA, "A_SystemNetworkParameter_Write"},
    { 0x020, "A_Memory_Read"},
    { 0x024, "A_Memory_Response"},
    { 0x028, "A_Memory_Write"},
    { 0x2C0, "A_UserMemory_Read"},
    { 0x2C1, "A_UserMemory_Response"},
    { 0x2C2, "A_UserMemory_Write"},
    { 0x2C5, "A_UserManufacturerInfo_Read"},
    { 0x2C6, "A_UserManufacturerInfo_Response"},
    { 0x2C7, "A_FunctionPropertyCommand"},
    { 0x2C8, "A_FunctionPropertyState_Read"},
    { 0x2C9, "A_FunctionPropertyState_Response"},
    { 0x300, "A_DeviceDescriptor_Read"},
    { 0x340, "A_DeviceDescriptor_Response"},
    { 0x380, "A_Restart"},
    { 0x3D1, "A_Authorize_Request"},
    { 0x3D2, "A_Authorize_Response"},
    { 0x3D3, "A_Key_Write"},
    { 0x3D4, "A_Key_Response"},
    { 0x3D5, "A_PropertyValue_Read"},
    { 0x3D6, "A_PropertyValue_Response"},
    { 0x3D7, "A_PropertyValue_Write"},
    { 0x3D8, "A_PropertyDescription_Read"},
    { 0x3D9, "A_PropertyDescription_Response"},
    { 0x3DA, "A_NetworkParameter_Read"},
    { 0x3DB, "A_NetworkParameter_Response"},
    { 0x3DC, "A_IndividualAddressSerialNumber_Read"},
    { 0x3DD, "A_IndividualAddressSerialNumber_Response"},
    { 0x3DF, "A_IndividualAddressSerialNumber_Write"},
    { 0x3E0, "A_DomainAddress_Write"},
    { 0x3E1, "A_DomainAddress_Read"},
    { 0x3E2, "A_DomainAddress_Response"},
    { 0x3E3, "A_DomainAddressSelective_Read"},
    { 0x3E4, "A_NetworkParameter_Write"},
    { 0x3E5, "A_Link_Read"},
    { 0x3E6, "A_Link_Response"},
    { 0x3E7, "A_Link_Write"},
    { 0x3E8, "A_GroupPropValue_Read"},
    { 0x3E9, "A_GroupPropValue_Response"},
    { 0x3EA, "A_GroupPropValue_Write"},
    { 0x3EB, "A_GroupPropValue_InfoReport"},
    { 0x3EC, "A_DomainAddressSerialNumber_Read"},
    { 0x3ED, "A_DomainAddressSerialNumber_Response"},
    { 0x3EE, "A_DomainAddressSerialNumber_Write"},
    { 0x3F0, "A_FileStream_InforReport"},
    { 0, NULL}
};

static const value_string cemi_propertyid[] = {
    {  1, "PID_OBJECT_TYPE" },
    {  8, "PID_SERVICE_CONTROL" },
    {  9, "PID_FIRMWARE_REVISION" },
    { 11, "PID_SERIAL_NUMBER" },
    { 12, "PID_MANUFACTURER_ID" },
    { 14, "PID_DEVICE_CONTROL" },
    { 19, "PID_MANUFACTURE_DATA" },
    { 51, "PID_ROUTING_COUNT" },
    { 52, "PID_MAX_RETRY_COUNT " },
    { 53, "PID_ERROR_FLAGS" },
    { 54, "PID_PROGMODE" },
    { 56, "PID_MAX_APDULENGTH" },
    { 57, "PID_SUBNET_ADDR" },
    { 58, "PID_DEVICE_ADDR" },
    { 59, "PID_PB_CONFIG" },
    { 60, "PID_ADDR_REPORT" },
    { 61, "PID_ADDR_CHECK" },
    { 62, "PID_OBJECT_VALUE" },
    { 63, "PID_OBJECTLINK" },
    { 64, "PID_APPLICATION" },
    { 65, "PID_PARAMETER" },
    { 66, "PID_OBJECTADDRESS" },
    { 67, "PID_PSU_TYPE" },
    { 68, "PID_PSU_STATUS" },
    { 70, "PID_DOMAIN_ADDR"},
    { 71, "PID_IO_LIST"},
    { 0, NULL }
};

static const value_string cemi_error_codes[] = {
    { 0x00, "Unspecified Error"},
    { 0x01, "Out of range"},
    { 0x02, "Out of maxrange"},
    { 0x03, "Out of minrange"},
    { 0x04, "Memory Error"},
    { 0x05, "Read only"},
    { 0x06, "Illegal command"},
    { 0x07, "Void DP"},
    { 0x08, "Type conflict"},
    { 0x09, "Prop. Index range error"},
    { 0x0A, "Value temporarily not writeable"},
    { 0, NULL }
};

static const value_string cemi_bibat_ctrl[] = {
    { 0x0, "asynchr. RF frame"},
    { 0x1, "Fast_ACK"},
    { 0x4, "synchronous L_Data frames"},
    { 0x5, "Sync frame"},
    { 0x6, "Help Call"},
    { 0x7, "Help Call Response"},
    { 0, NULL }
};

#endif /* __KNXUTIL_H__ */
