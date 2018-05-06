/*
 * knx_ui_config.h
 *
 *  Created on: May 6, 2018
 *  Author: Alija Sabic
 *  E-Mail: sabic@technikum-wien.at
 */

#ifndef __KNX_USER_INTERFACE_CONFIG__
#define __KNX_USER_INTERFACE_CONFIG__

#include <stdbool.h>
#include <stdint.h>

// DEFINES
#define GLOBAL_KEYWORD 			"knxnetip"
#define SERVER_KEYWORD 			"knxnetip_server"

#define GLOBAL_CONFIG   		(0)

/*
 *  These are the definitions of the parser section delimiting
 *  keywords to configure KNXnetIP.  When one of these keywords
 *  are seen, we begin a new section.
 */
#define GLOBAL 					"global"
#define SERVER					"server"

/*
 *  The definition of the configuration separators in the snort.conf
 *  configure line.
 */
#define CONF_SEPARATORS 		" \t\n\r"

#define MAX_FILENAME 1000

/*
 * IP Address list delimiters
 */
#define KNX_START_IPADDR_LIST 	"{"
#define KNX_END_IPADDR_LIST   	"}"

/*
 * Port list delimiters
 */
#define KNX_START_PORT_LIST   	"{"
#define KNX_END_PORT_LIST     	"}"

/*
 * Service list delimiters
 */
#define KNX_START_SVC_LIST    	"{"
#define KNX_END_SVC_LIST      	"}"

typedef struct _KNXNETIP_IPS {
	uint8_t length;
	uint32_t **pdata;
} KNXNETIP_IPS;

typedef struct _KNXNETIP_PORTS {
	uint8_t length;
	uint16_t **pdata;
} KNXNETIP_PORTS;

typedef struct _KNXNETIP_SRVS {
	uint8_t length;
	uint16_t **pdata;
} KNXNETIP_SRVS;

typedef struct _KNXNETIP_GRPADDRS {
	uint8_t length;
	uint16_t **pdata;
} KNXNETIP_GRPADDRS;

/*
 * This it the configuration construct that holds the
 * specific options for a server. Each unique server has
 * it's own structure and there is a global structure
 * for servers that don't have a unique configuration.
 */
typedef struct _KNXNETIP_SERVER_CONF {
	bool bProgramming;
	bool bPhysicalAddressing;
	char filename[MAX_FILENAME];
	KNXNETIP_IPS ip;
	KNXNETIP_PORTS port;
	KNXNETIP_SRVS service;
	KNXNETIP_GRPADDRS group_address;
} KNXNETIP_SERVER_CONF;

/*
 * This is the configuration for the global KNXnetIP
 * configuration. It contains the global aspects of the
 * preprocessor configuration.
 */
typedef struct _KNXNETIP_CONF
{
	uint8_t length;
	KNXNETIP_SERVER_CONF **pdata;
} KNXNETIP_CONF;

int knx_ui_append_conf(KNXNETIP_CONF *GlobalConf);
int knx_ui_config_init_global_conf(KNXNETIP_CONF *GlobalConf);

#endif /* __KNX_USER_INTERFACE_CONFIG__ */
