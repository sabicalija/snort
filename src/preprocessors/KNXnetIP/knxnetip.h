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
	uint8_t length;
	uint8_t host_protocol;
	uint32_t ip;
	uint16_t port;
} HPAI;

typedef struct _HPAIS {
	uint8_t length;
	HPAI    **pdata;
} HPAIS;

typedef struct _DIBDeviceInfo {
	uint8_t knx_medium;
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

typedef struct _DIBKNXAddressS {
	uint8_t length;
	DIBKNXAddress **pdata;
} DIBKNXAddressS;

typedef struct _DIBKNXAddress {
	uint16_t address;
} DIBKNXAddress;

typedef struct _DIBMFRData {

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

} CRI;

typedef struct _CRD {

} CRD;

typedef struct _cEMI {

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
	HPAIS hpai;
	union {
		DIBS dib;
		CRI cri;
		CRD crd;
	};
} KNXnetIPBody;

typedef struct _KNXnetIPPacket
{
	KNXnetIPHeader header;
	KNXnetIPBody body;
} KNXnetIPPacket;

void dissect_knxnetip(const uint8_t *data);

#endif /* __KNXNETIP_H__ */
