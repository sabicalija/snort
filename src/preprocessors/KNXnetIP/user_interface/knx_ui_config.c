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

int knx_ui_append_conf(KNXNETIP_CONF *GlobalConf)
{
	uint8_t new_size = GlobalConf->length + 1;

	// Allocate larger array for new KNXNETIP_SERVER_CONF entry
	KNXNETIP_SERVER_CONF **new_data = (KNXNETIP_SERVER_CONF**)SnortAlloc((new_size) * sizeof(KNXNETIP_SERVER_CONF));
	memset(new_data, 0, (new_size) * sizeof(KNXNETIP_SERVER_CONF));

	// Copy current KNXNETIP_SERVER_CONF data in new array
	for (int i = 0; i < GlobalConf->length; i++)
	{
		new_data[i] = GlobalConf->pdata[i];
	}

	if (new_size != 1) {
		free(GlobalConf->pdata);
	}
	GlobalConf->pdata = new_data;

	// Allocate new KNXNETIP_SERVER_CONF entry
	KNXNETIP_SERVER_CONF *new_entry = (KNXNETIP_SERVER_CONF *)calloc(1, sizeof(KNXNETIP_SERVER_CONF *));
	if (new_entry == NULL)
	{
		// FIXIT: add error message
		return -1;
	}

	// Append new entry
	GlobalConf->pdata[new_size-1] = new_entry;
	GlobalConf->length += 1;

	return 0;
}

int knx_ui_config_init_global_conf(KNXNETIP_CONF *GlobalConf)
{
	memset(GlobalConf, 0, sizeof(KNXNETIP_CONF));
	knx_ui_append_conf(GlobalConf);
	return 0;
}
