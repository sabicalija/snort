/*
 * knx_ad.c
 *
 *  Created on: May 11, 2018
 *  Author: Alija Sabic
 *  E-Mail: sabic@technikum-wien.at
 */
#include "knx_ad.h"

#include "util.h"

#include <stdbool.h>

static uint8_t get_destination_address_type(KNXnetIPPacket *knx)
{
	return (knx->body.cemi.lpdu.control_field2 & 0x80);
}

static uint16_t get_group_address(KNXNETIP_GRPADDR *grpaddr)
{
	uint16_t ga = 0;

	uint16_t ga_main = (((uint16_t)grpaddr->main & 0x000f) << 11);
	uint16_t ga_mid =  (((uint16_t)grpaddr->mid & 0x0007) << 8);
	uint16_t ga_sub =  (grpaddr->sub & 0x00ff);

	ga = ( ga_main | ga_mid | ga_sub );

	return ga;
}

static void log_payload(KNXNETIP_SERVER_CONF *config, KNXnetIPPacket *knx, const uint8_t *data, char *prv_text)
{

	if (config->bPayload)
	{
		if (prv_text == NULL || (strlen(prv_text) < 15))
			LogMessage("\t");
		if (prv_text == NULL || (strlen(prv_text) < 20))
			LogMessage("\t");
		LogMessage("  \tUDP Payload: \e[33m");
		for (int i = 0; i < knx->header.totallength; i = i + 1)
		{
			LogMessage("%02x ", *(data + i));
		}
	}
	LogMessage("\e[39m\n");

}

int detect_knxnetip(Packet *p, KNXnetIPPacket *knx, KNXNETIP_SERVER_CONF *config)
{
	static int i = 0;
	boolean bIndividualAddressingDetected = false;

	i++;
	LogMessage("KNXnet/IP packet detection (\e[30m\e[47m#%3d\e[39m\e[49m)\n",i);

	/* Check individual addressing */
	if (config->bIndividualAddressing)
	{
		if (knx->header.servicetype == TUNNELING_REQ)
		{
			if (get_destination_address_type(knx) == DAT_INDIVIDUAL)
			{
				LogMessage("\e[31m  -> Physical/Individual addressing detected.");
				log_payload(config, knx, p->data, "                ");
				bIndividualAddressingDetected = true;
			}

		}

	}

	/* Check programming */
	// Note: If bIndividualAddressingDetected + SERVICE TYPE(S)


	/* Check services */
	if (config->service.length > 0)
	{
		boolean srv_id_detected = false;
		for (int j = 0; (j < config->service.length) && !srv_id_detected; j++)
		{

			for (int k = 0; (knxnetip_service_identifier[k].value != 0) && !srv_id_detected ; k++)
			{
				const value_string *e = &knxnetip_service_identifier[k];

				if (e->value == knx->header.servicetype) {

					LogMessage("\e[31m  -> Service %s detected.", e->text);
					log_payload(config, knx, p->data, e->text);

					srv_id_detected = true;
				}
			}
		}
	}

	/* Check group address */
	if (config->bGroupAddressing)
	{
		// boolean group_valid_src = false;
		boolean group_valid_dest = false;
		if (knx->header.servicetype == TUNNELING_REQ)
		{
			if (get_destination_address_type(knx) == DAT_GROUP)
			{
				for (int j = 0; j < config->group_address.length; j++)
				{
					// FIXIT: src address is always individual
					// if (get_group_address(config->group_address.pdata[j]) == knx->body.cemi.lpdu.src)
					// {
					//     group_valid_src = true;
					// }

					if (get_group_address(config->group_address.pdata[j]) == knx->body.cemi.lpdu.dest)
					{
						group_valid_dest = true;
					}
				}

				if (!group_valid_dest)
				{
					LogMessage("\e[31m  -> Invalid Group Address (\e[33m%d/%d/%d\e[31m).",
												(knx->body.cemi.lpdu.dest & 0x7800) >> 11,
												(knx->body.cemi.lpdu.dest & 0x0700) >>  8,
												(knx->body.cemi.lpdu.dest & 0x00ff));
					log_payload(config, knx, p->data, NULL);
				}
			}
		}
	}



	return 0;
}
