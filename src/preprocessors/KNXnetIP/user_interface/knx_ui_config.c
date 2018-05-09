/*
 * knx_ui_config.c
 *
 *  Created on: May 6, 2018
 *  Author: Alija Sabic
 *  E-Mail: sabic@technikum-wien.at
 */
#include "knx_ui_config.h"

#include <regex.h>
#include <string.h>
#include "util.h"

static KNXNETIP_SERVER_CONF *get_last_config_entry(KNXNETIP_CONF *config)
{
	return config->pdata[config->length-1];
}

int knx_ui_append_server_conf(KNXNETIP_CONF *config)
{
	uint8_t new_size = config->length + 1;

	//
	// Allocate pointer table for new KNXNETIP_SERVER_CONF entries
	//
	KNXNETIP_SERVER_CONF **new_table = (KNXNETIP_SERVER_CONF**)SnortAlloc((new_size) * sizeof(KNXNETIP_SERVER_CONF *));
	if (new_table == NULL)
	{
		return -1;
	}

	// Copy current KNXNETIP_SERVER_CONF table
	for (int i = 0; i < config->length; i++)
	{
		new_table[i] = config->pdata[i];
	}

	// Replace old with new pointer table
	if (new_size != 1) {
		free(config->pdata);
	}
	config->pdata = new_table;

	//
	// Allocate new KNXNETIP_SERVER_CONF entry
	//
	KNXNETIP_SERVER_CONF *new_entry = (KNXNETIP_SERVER_CONF *)SnortAlloc(sizeof(KNXNETIP_SERVER_CONF));
	if (new_entry == NULL)
	{
		return -1;
	}

	// Append new entry to pointer table
	config->pdata[new_size-1] = new_entry;
	config->length += 1;

	return 0;
}

int knx_ui_append_conf(KNXNETIP_CONF *config)
{
	return knx_ui_append_server_conf(config);
}

static int append_ip_address(KNXNETIP_IPS *ipaddr)
{
	uint8_t new_size = ipaddr->length + 1;

	// Allocate new pointer table
	struct sockaddr_in **new_table = (struct sockaddr_in **)SnortAlloc((new_size) * sizeof(struct sockaddr_in *));
	if (new_table == NULL)
	{
		return -1;
	}

	// Copy current table
	for (int i = 0; i < ipaddr->length; i++)
	{
		new_table[i] = ipaddr->pdata[i];
	}

	// Replace old/new table
	if (new_size != 1)
	{
		if (ipaddr->pdata)
			free(ipaddr->pdata);
	}
	ipaddr->pdata = new_table;

	// Allocate new entry
	struct sockaddr_in *new_entry = (struct sockaddr_in *)SnortAlloc(sizeof(struct sockaddr_in));
	if (new_entry == NULL)
	{
		return -1;
	}

	// Append new entry to table
	ipaddr->pdata[new_size-1] = new_entry;
	ipaddr->length += 1;

	return 0;
}


static int knx_ui_load_ip_address(KNXNETIP_CONF *config, char *sIp)
{
	KNXNETIP_SERVER_CONF *srvcfg = get_last_config_entry(config);
	append_ip_address(&srvcfg->ip);

	struct sockaddr_in *entry = srvcfg->ip.pdata[srvcfg->ip.length-1];
	inet_pton(AF_INET, sIp, &entry->sin_addr);

	return 0;
}

int knx_ui_load_ip(KNXNETIP_CONF *config)
{
	int ret = 0;
	char *pIpAddressList = NULL, *pIpAddressListCopy = NULL, *brkt = NULL;

	char *pcToken = strtok(NULL, CONF_SEPARATORS);
	if(pcToken == NULL)
	{
		return -1;
	}

	/*
	 * Convert string to IP address.
	 */
	if (strcmp(KNX_START_IPADDR_LIST, pcToken) == 0)
	{
		/* Process IP list */
		if ((pIpAddressList = strtok(NULL, KNX_END_IPADDR_LIST)) == NULL)
		{
			ret = -1;
			goto cleanup;
		}
	}
	else
	{
		/* Process IP */
		pIpAddressList = pcToken;
	}

	/* Copy IP address(es) */
	pIpAddressListCopy = strdup(pIpAddressList);
	if (pIpAddressListCopy == NULL)
	{
		return -1;
	}


	for (pcToken = strtok_r(pIpAddressList, CONF_SEPARATORS, &brkt);
		 pcToken;
		 pcToken = strtok_r(NULL, CONF_SEPARATORS, &brkt))
	{
		knx_ui_load_ip_address(config, pcToken);
	}


	ret = 0;

cleanup:
	if (pIpAddressListCopy)
	{
		free(pIpAddressListCopy);
	}

	return ret;
}

static int append_port(KNXNETIP_PORTS *ports)
{
	uint8_t new_size = ports->length + 1;

	// Allocate new pointer table
	uint16_t **new_table = (uint16_t **)SnortAlloc((new_size) * sizeof(uint16_t *));
	if (new_table == NULL)
	{
		return -1;
	}

	// Copy current table
	for (int i = 0; i < ports->length; i++)
	{
		new_table[i] = ports->pdata[i];
	}

	// Replace old/new table
	if (new_size != 1)
	{
		if (ports->pdata)
			free(ports->pdata);
	}
	ports->pdata = new_table;

	// Allocate new entry
	uint16_t *new_entry = (uint16_t *)SnortAlloc(sizeof(uint16_t));
	if (new_entry == NULL)
	{
		return -1;
	}

	// Append new entry to table
	ports->pdata[new_size-1] = new_entry;
	ports->length += 1;

	return 0;
}

static int knx_ui_load_port(KNXNETIP_CONF *config, char *sPort)
{
	KNXNETIP_SERVER_CONF *srvcfg = get_last_config_entry(config);
	append_port(&srvcfg->port);

	char *result = "";
	uint16_t conv =	(uint16_t) strtol(sPort, &result, 10);

	uint16_t *port = srvcfg->port.pdata[srvcfg->port.length-1];

	*port = conv;
	return 0;
}

int knx_ui_load_ports(KNXNETIP_CONF *config)
{
	int ret = 0;
	char *pPortList = NULL, *pPortListCopy = NULL, *brkt = NULL;

	char *pcToken = strtok(NULL, CONF_SEPARATORS);
	if(pcToken == NULL)
	{
		return -1;
	}

	/*
	 * Convert string to port.
	 */
	if (strcmp(KNX_START_PORT_LIST, pcToken) == 0)
	{
		/* Process port list */
		if ((pPortList = strtok(NULL, KNX_END_PORT_LIST)) == NULL)
		{
			ret = -1;
			goto cleanup;
		}
	}
	else
	{
		/* Process port */
		pPortList = pcToken;
	}

	/* Copy port(s) */
	pPortListCopy = strdup(pPortList);
	if (pPortListCopy == NULL)
	{
		return -1;
	}

	for (pcToken = strtok_r(pPortList, CONF_SEPARATORS, &brkt);
		 pcToken;
		 pcToken = strtok_r(NULL, CONF_SEPARATORS, &brkt))
	{
		knx_ui_load_port(config, pcToken);
	}

	ret = 0;

cleanup:
	if (pPortListCopy)
	{
		free(pPortListCopy);
	}

	return ret;
}

int knx_ui_load_service(KNXNETIP_CONF *config)
{


	return 0;
}

int knx_ui_load_filename(KNXNETIP_CONF *config)
{
	uint8_t entry = config->length-1;
	char *pcToken = strtok(NULL, CONF_SEPARATORS);

	config->pdata[entry]->filename = pcToken;

	return 0;
}

int knx_ui_load_group_address(KNXNETIP_CONF *config)
{
	int ns;
	KNXNETIP_SERVER_CONF *srvcfg = get_last_config_entry(config);
	FILE *f = NULL;

	f = fopen(srvcfg->filename,"r");
	if (f == NULL) {
		return -1;
	}

	char format[MAX_LINE] = {0};
	sprintf(format, "%%%d[^\n]%%*[\n]", MAX_LINE);

	do
	{
		char line[MAX_LINE] = {0};
		ns = fscanf(f, format, line);
		knx_ui_append_group_address(srvcfg, line);

	} while (ns != EOF);

	fclose(f);

	return 0;
}

static int is_comment(char *line)
{
	for (int i = 0; i < MAX_LINE; i++)
	{
		char c = *(line + i);

		if (c == '\0')
		{
			// If line is no comment, continue processing.
			return 0;
		}

		if (isspace(c) || c == CONF_GRPADDR_COMMENT)
		{
			if (c == CONF_GRPADDR_COMMENT)
			{
				return -1;
			}
			else {
				continue;
			}
		}
	}

	return 0;
}

int knx_ui_append_group_address(KNXNETIP_SERVER_CONF *srv_config, char *line)
{
	if (is_comment(line))
	{
		return 0;
	}

	int ret = 0;
	regex_t regex;
	regmatch_t regmatch;

	/* Compile regular expression */
	ret = regcomp(&regex, "[0-31]\\/[0-7]\\/[0-255]", 0);
	if (ret)
	{
		return -1;
	}

	/* Execute regular expression */
	ret = regexec(&regex, line, 1, &regmatch, 0);
	if (ret)
	{
		// No match.
		regfree(&regex);
		return -1;
	}

	knx_ui_process_group_address(&srv_config->group_address, line, (int)regmatch.rm_so, (int)regmatch.rm_eo);

	regfree(&regex);
	return 0;

}
static int append_group_address(KNXNETIP_GRPADDRS *grpaddr)
{
	uint8_t new_size = grpaddr->length + 1;

	// Allocate new pointer table
	KNXNETIP_GRPADDRS **new_table = (KNXNETIP_GRPADDRS **)SnortAlloc((new_size) * sizeof(KNXNETIP_GRPADDRS *));
	if (new_table == NULL)
	{
		return -1;
	}

	// Copy current table
	for (int i = 0; i < grpaddr->length; i++)
	{
		new_table[i] = grpaddr->pdata[i];
	}

	// Replace old/new table
	if (new_size != 1)
	{
		if (grpaddr->pdata)
			free(grpaddr->pdata);
	}
	grpaddr->pdata = new_table;

	// Allocate new entry
	KNXNETIP_GRPADDR *new_entry = (KNXNETIP_GRPADDR *)SnortAlloc(sizeof(KNXNETIP_GRPADDR));
	if (new_entry == NULL)
	{
		return -1;
	}

	// Append new entry to table
	grpaddr->pdata[new_size-1] = new_entry;
	grpaddr->length += 1;

	return 0;
}
int knx_ui_process_group_address(KNXNETIP_GRPADDRS *grpaddr, char *line, int start, int end)
{
	append_group_address(grpaddr);
	KNXNETIP_GRPADDR *entry = grpaddr->pdata[grpaddr->length-1];
	int cnt = 0;

	for(int i = start, j = start; i <= end; i++)
	{
		if (line[i] == '/' || i == end)
		{

			char num[10] = {0};

			for (int k = 0; k < 10 && k < (i - j); k++)
			{
				num[k] = line[j+k];
			}

			char *result = "";

			switch (cnt)
			{
				// Main
				case 0:
					entry->main = (uint8_t) strtol(num, &result, 10);
					break;

				// Mid
				case 1:
					entry->mid = (uint8_t) strtol(num, &result, 10);
					break;

				// Sub
				case 2:
					entry->sub = (uint16_t) strtol(num, &result, 10);
					break;
			}

			j = i + 1;
			cnt++;
		}

	}

	return 0;
}
int knx_ui_print_group_addresses(fprint f, KNXNETIP_GRPADDRS *grpaddr)
{
	int items_per_line = 5;
	f("      Loaded Group Addresses:\n");
	f("                               ");
	for (int i = 0; i < grpaddr->length; i++)
	{
		KNXNETIP_GRPADDR *e = grpaddr->pdata[i];

		if (!(i % items_per_line)) {
			f("        ");
		}
		f("%d/%d/%d ", e->main, e->mid, e->sub);
		if (!((i + 1) % items_per_line)) {
			f("\n");
			if (i != (grpaddr->length-1))
			{
				f("                               ");
			}
		}
	}

	if (items_per_line != 1)
	{
		f("\n");
	}

	return 0;
}

int knx_ui_print_ip_addresses(fprint f, KNXNETIP_IPS *ipaddr)
{
	int items_per_line = 1;
	if(ipaddr->length > 1)
	{
		f("      IP Addresses:");
	}
	else
	{
		f("      IP Address:  ");
	}

	for (int i = 0; i < ipaddr->length; i++)
	{
		struct sockaddr_in *e = ipaddr->pdata[i];
		char ipstring[MAX_LINE] = {0};
		inet_ntop(AF_INET, &e->sin_addr, ipstring, MAX_LINE);

		if (!(i % items_per_line)) {
			f("                    ");
		}
		if (i == (ipaddr->length-1))
		{
			f("%s ",ipstring);
		}
		else
		{
			f("%s, ",ipstring);
		}
		if (!((i + 1) % items_per_line)) {
			f("\n");
			if (i != (ipaddr->length-1))
			{
				f("                   ");
			}
		}
	}

	if (items_per_line != 1)
	{
		f("\n");
	}
	return 0;
}

int knx_ui_print_ports(fprint f, KNXNETIP_PORTS *ports)
{
	int items_per_line = 15;

	if(ports->length > 1)
	{
		f("      Port:        ");
	}
	else
	{
		f("      Ports:       ");
	}

	for (int i = 0; i < ports->length; i++)
	{
		uint16_t *e = ports->pdata[i];

		if (!(i % items_per_line)) {
			f("                    ");
		}
		if (i == (ports->length-1))
		{
			f("%d ",*e);
		}
		else
		{
			f("%d, ",*e);
		}
		if (!((i + 1) % items_per_line)) {
			f("\n");
			if (i != (ports->length-1))
			{
				f("                   ");
			}
		}
	}

	if (items_per_line != 1)
	{
		f("\n");
	}
	return 0;
}
