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
#include <netinet/in.h>

// DEFINES
#define KNXNETIP_CONF_KEYWORD 			"knxnetip"
#define KNXNETIP_CONF_SERVER_KEYWORD 	"knxnetip_server"

#define GLOBAL_CONFIG   		(0)

/*
 *  These are the definitions of the parser section delimiting
 *  keywords to configure KNXnetIP.  When one of these keywords
 *  are seen, we begin a new section.
 */
#define GLOBAL 							"global"
#define SERVER							"server"

/*
 *  The definition of the configuration separators in the snort.conf
 *  configure line.
 */
#define CONF_SEPARATORS 				" \t\n\r"
#define CONF_GRPADDR_COMMENT			'#'

#define MAX_FILENAME 					(80)
#define MAX_LINE						(200)

/*
 * IP Address list delimiters
 */
#define KNX_START_IPADDR_LIST 			"{"
#define KNX_END_IPADDR_LIST   			"}"

/*
 * Port list delimiters
 */
#define KNX_START_PORT_LIST   			"{"
#define KNX_END_PORT_LIST     			"}"

/*
 * Service list delimiters
 */
#define KNX_START_SVC_LIST    			"{"
#define KNX_END_SVC_LIST      			"}"

typedef struct _KNXNETIP_GRPADDR {
	uint8_t main;
	uint8_t mid;
	uint16_t sub;
} KNXNETIP_GRPADDR;

typedef struct _KNXNETIP_IPS {
	uint8_t length;
	struct sockaddr_in **pdata;
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
	KNXNETIP_GRPADDR **pdata;
} KNXNETIP_GRPADDRS;

/*
 * This it the configuration construct that holds the
 * specific options for a server. Each unique server has
 * it's own structure and there is a global structure
 * for servers that don't have a unique configuration.
 */
typedef struct _KNXNETIP_SERVER_CONF {
	bool bProgramming;
	bool bIndividualAddressing;
	bool bGroupAddressing;
	bool bPayload;
	char *filename;
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

typedef void (*fprint)(const char *format,...);

int knx_ui_append_server_conf(KNXNETIP_CONF *config);
int knx_ui_append_conf(KNXNETIP_CONF *config);
int knx_ui_load_ip(KNXNETIP_CONF *config);
int knx_ui_load_ports(KNXNETIP_CONF *config);
int knx_ui_load_services(KNXNETIP_CONF *config);
int knx_ui_load_filename(KNXNETIP_CONF *config);
int knx_ui_load_group_address(KNXNETIP_CONF *config);
int knx_ui_append_group_address(KNXNETIP_SERVER_CONF *srv_config, char *line);
int knx_ui_process_group_address(KNXNETIP_GRPADDRS *grpaddr, char *line, int start, int end);
int knx_ui_print_group_addresses(fprint f, KNXNETIP_GRPADDRS *grpaddr);
int knx_ui_print_ip_addresses(fprint f, KNXNETIP_IPS *ipaddr);
int knx_ui_print_ports(fprint f, KNXNETIP_PORTS *ports);
int knx_ui_print_services(fprint f, KNXNETIP_SRVS *services);
#endif /* __KNX_USER_INTERFACE_CONFIG__ */
