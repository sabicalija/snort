/*
 * knx_ui_config.c
 *
 *  Created on: May 6, 2018
 *  Author: Alija Sabic
 *  E-Mail: sabic@technikum-wien.at
 */
#include "knx_ui_config.h"

#include <string.h>
#include "util.h"

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

int knx_ui_load_filename(KNXNETIP_CONF *config)
{
	uint8_t entry = config->length-1;
	char *pcToken = strtok(NULL, CONF_SEPARATORS);

	config->pdata[entry]->filename = pcToken;

	return 0;
}
