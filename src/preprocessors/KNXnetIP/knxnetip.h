/*
 * knxnetip.h
 *
 *  Created on: May 6, 2018
 *      Author: alija
 */

#ifndef __KNXNETIP_H__
#define __KNXNETIP_H__

#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#include "knxutil.h"

#define KNXNETIP_PROTOCOL_VERSION 0x10
#define KNXNETIP_HEADER_LENGTH 0x06

typedef struct _HPAI {
	uint8_t structure_length;
	uint8_t host_protocol;
	// FIXIT: Host Protocol dependent data (e.g. ip, port)
	// of variable length.
	uint32_t ip;
	uint16_t port;
} HPAI;
typedef struct _HPAIS {
	uint8_t length;
	HPAI    **pdata;
} HPAIS;

typedef struct _ConnectionHeader {
	uint8_t structure_length;
	uint8_t communication_channel_id;
	uint8_t sequence_counter;
	union {
		uint8_t reserved;
		uint8_t confackstat;
		uint8_t tunnackstat;
	};
} ConnectionHeader;

typedef struct _DIBDeviceInfo {
	uint8_t knx_medium;
	// FIXIT: Detect Programming Mode
	//        Indicator: KNXnet/IP Core (p. 25)
	uint8_t device_status;
	uint16_t knx_individual_address;
	uint16_t project_inst_id;
	uint8_t serial_number[6];
	uint32_t multicast_address;
	uint8_t mac_address[6];
	char device_friendly_name[30];
} DIBDeviceInfo;
typedef struct _DIBSuppSvcFamily {
	uint8_t id;
	uint8_t version;
} DIBSuppSvcFamily;
typedef struct _DIBIPConfig {
	uint32_t ip;
	uint32_t subnet;
	uint32_t gateway;
	uint8_t capabilities;
	uint8_t assignment_method;
} DIBIPConfig;
typedef struct _DIBIPCurrent {
	uint32_t ip;
	uint32_t subnet;
	uint32_t gateway;
	uint32_t dhcp;
	uint8_t assignment_method;
	uint8_t reserved;
} DIBIPCurrent;
typedef struct _DIBKNXAddress {
	uint16_t address;
} DIBKNXAddress;
typedef struct _DIBKNXAddressS {
	uint8_t length;
	DIBKNXAddress **pdata;
} DIBKNXAddressS;
typedef struct _DIBMFRData {
	uint16_t manufacturer_id;
	char *manufacturer_data;
} DIBMFRData;
typedef struct _DIBSuppSvc {
	uint8_t length;
	DIBSuppSvcFamily **pdata;
} DIBSuppSvc;
typedef struct _DIB {
	uint8_t structure_length;
	uint8_t dib_type;
	union {
		DIBDeviceInfo device_info;
		DIBSuppSvc device_service;
		DIBIPConfig ip_config;
		DIBIPCurrent ip_current;
		DIBKNXAddressS knx_address;
		DIBMFRData mfr_data;
	};
} DIB;
typedef struct _DIBS {
	uint8_t length;
	DIB **pdata;
} DIBS;

typedef struct _CRI {
	uint8_t structure_length;
	uint8_t connection_type;
	// FIXIT: Host Protocol dependent data (e.g. knxlayer, res)
	// of variable length.
	uint8_t knxlayer;
	uint8_t reserved;
} CRI;
typedef struct _CRIS {
	uint8_t length;
	CRI **pdata;
} CRIS;
typedef struct _CRD {
	uint8_t structure_length;
	uint8_t connection_type;
	uint16_t knxaddress;
} CRD;
typedef struct _CRDS {
	uint8_t length;
	CRD **pdata;
} CRDS;

/* cEMI Additional Information Field */
typedef struct _AddInfoPLMediumInfo {
	uint16_t domain_address;
} AddInfoPLMediumInfo;
typedef struct _AddInfoRFMediumInfo {
	uint8_t rf_info;
	uint8_t serial_number[6];
	uint8_t dl_frame_number;
} AddInfoRFMediumInfo;
typedef struct _AddInfoBusmonitor {
	uint8_t error_flags;
} AddInfoBusmonitor;
typedef struct _AddInfoTimestampRel {
	uint16_t rel_timestamp;
} AddInfoTimestampRel;
typedef struct _AddInfoTimeDelay {
	uint32_t time_delay;
} AddInfoTimeDelay;
typedef struct _AddInfoExtTimestampRel {
	uint32_t ext_rel_timestamp;
} AddInfoExtTimestampRel;
typedef struct _AddInfoBiBat {
	uint8_t bibat;
	uint8_t block_number;
} AddInfoBiBat;
typedef struct _AddInfoRFMulti {
	uint8_t transmit_frequency;
	uint8_t call_channel;
	uint8_t fast_ack;
	uint8_t receive_frequency;
} AddInfoRFMulti;
typedef struct _AddInfoPreamble {
	uint16_t preamble_length;
	uint8_t postamble_length;
} AddInfoPreamble;
typedef struct _AddInfoRFFastAck {
	uint8_t status;
	uint8_t info;
} AddInfoRFFastAck;
typedef struct _AddInfoRFFastAckS {
	uint8_t length;
	AddInfoRFFastAck **pdata;
} AddInfoRFFastAckS;
typedef struct _AddInfoManufacturer {
	uint16_t manufacturer_id;
	uint8_t subfunction;
	uint8_t *data;
} AddInfoManufacturer;
typedef struct _AddInfoManufacturerS {
	uint8_t length;
	AddInfoManufacturer **pdata;
} AddInfoManufacturerS;
typedef struct _AddInfo {
	uint8_t type_id;
	uint8_t structure_length;
	union {
		AddInfoPLMediumInfo 	pl;
		AddInfoRFMediumInfo		rf;
		AddInfoBusmonitor 		bm;
		AddInfoTimestampRel 	rts;
		AddInfoTimeDelay    	td;
		AddInfoExtTimestampRel 	ets;
		AddInfoBiBat			bb;
		AddInfoRFMulti          rfm;
		AddInfoPreamble			pa;
		AddInfoRFFastAckS		rffa;
		AddInfoManufacturer     mf;
	};
} AddInfo;
typedef struct _AddInfoS {
	uint8_t length;
	AddInfo **pdata;
} AddInfoS;

/* cEMI */

/* Application Layer Protocol Data Unit */
typedef struct _APDU {
	/* Application Layer Protocol Control Information */
	uint16_t apci;
	// FIXIT: Cleanup data structure, create Message
	// Type specific structures
	uint8_t channel_nr;
	uint8_t cemi_data;
	uint8_t memory_number;
	uint16_t memory_address;
	uint32_t apci_key;
	uint32_t apci_level;
	uint8_t apci_object_index;
	uint8_t apci_property_id;
	uint8_t number_of_elements;
	uint16_t start_index;
	uint8_t *data;
} APDU;

/* Transport Layer Protocol Data Unit */
typedef struct _TPDU {
	/* Transport Layer Protocol Control Information */
	uint8_t tpci;
	APDU apdu;
} TPDU;

/* Network Layer Protocol Data Unit */
typedef struct _NPDU {
	union {
		uint8_t structure_length;
		uint8_t number_of_slots;
	};
	union {
		TPDU tpdu;
		uint8_t *poll_data;
	};
} NPDU;

/* Data Link Layer Protocol Data Unit */
typedef struct _LPDU {
	uint8_t message_code;
	uint8_t add_info_length;
	AddInfoS add_info;
	uint8_t control_field1;
	uint8_t control_field2;
	uint16_t src;
	uint16_t dest;
	// FIXIT: Cleanup data structure based on message code
	uint16_t interface_object_type;
	uint8_t object_instance;
	uint8_t property_id;
	uint8_t number_of_elements;
	uint8_t start_index;
	NPDU npdu;
} LPDU;

typedef struct _cEMI {
	LPDU lpdu;
	// FIXIT: Cleanup data structure based on message code
//	uint8_t bm_status;
//	uint16_t bm_timestamp;
//	uint8_t bm_control;
//	uint8_t framechecksum;
	uint8_t *raw_data;
} cEMI;



typedef struct _KNXnetIPHeader
{
	uint8_t length;
	uint8_t version;
	uint16_t servicetype;
	uint16_t totallength;
} KNXnetIPHeader;
typedef struct _KNXnetIPBody
{
	uint8_t communication_channel_id;
	uint8_t connection_status;
	uint8_t reserved;
	uint8_t connectionstate_status;
	HPAIS hpai;
	ConnectionHeader conn_header;
	union {
		DIBS dib;
		CRIS cri;
		CRDS crd;
		cEMI cemi;
	};
} KNXnetIPBody;

typedef struct _KNXnetIPPacket
{
	KNXnetIPHeader header;
	KNXnetIPBody body;
} KNXnetIPPacket;

void free_knxnetip(KNXnetIPPacket *p);
int dissect_knxnetip(const uint8_t *data, KNXnetIPPacket *p);

#endif /* __KNXNETIP_H__ */
