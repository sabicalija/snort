/*
 * knxnetip_dib.h
 * 
 *  Created on: May 11, 2018
 *  Author: Alija Sabic
 *  E-Mail: sabic@technikum-wien.at
 */

#ifndef __KNXNETIP_DIB_H__
#define __KNXNETIP_DIB_H__

#include <stdint.h>

/* Dissect Description Information Block (DIB) structure. */
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

typedef struct _DIBMFRData {
	uint16_t manufacturer_id;
	char *manufacturer_data;
} DIBMFRData;

typedef struct _DIBSuppSvc {
	uint8_t length;
	DIBSuppSvcFamily **pdata;
} DIBSuppSvc;

/* Variable length structures */
typedef struct _DIBKNXAddressS {
	uint8_t length;
	DIBKNXAddress **pdata;
} DIBKNXAddressS;

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

#endif /* __KNXNETIP_DIB_H__ */