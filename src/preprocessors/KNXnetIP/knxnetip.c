/*
 * knxnetip.c
 *
 *  Created on: May 6, 2018
 *  Author: Alija Sabic
 *  E-Mail: sabic@technikum-wien.at
 */
#include "knxnetip.h"
#include "util.h"

#define ENC_BIG_ENDIAN 0
#define ENC_LITTLE_ENDIAN 1

static void dissect(uint8_t *dest, const uint8_t *src, int *offset, int size, int endianess)
{
	switch(endianess)
	{
		case ENC_LITTLE_ENDIAN:
			for (int i = 0; i < size; i++)
			{
				memcpy(dest + i, src + *offset + i, sizeof(uint8_t));
			}
			break;

		case ENC_BIG_ENDIAN:
		default:
			for (int i = 0; i < size; i++)
			{
				memcpy(dest + (size-1) - i, src + *offset + i, sizeof(uint8_t));
			}
			break;
	}
	*offset += size;
}

/*
 * Dissect Host Protocol Address Information (HPAI) structure.
 */
static boolean append_hpai(KNXnetIPPacket *p)
{
	uint8_t new_size = p->body.hpai.length + 1;

	// Allocate new table
	HPAI **new_table = (HPAI**)SnortAlloc((new_size) * sizeof(HPAI *));

	// Copy current table
	for (int i = 0; i < p->body.hpai.length; i++)
	{
		new_table[i] = p->body.hpai.pdata[i];
	}

	// Replace old/new table
	if (new_size != 1) {
		free(p->body.hpai.pdata);
	}
	p->body.hpai.pdata = new_table;

	// Allocate new entry
	HPAI *new_entry = (HPAI *)SnortAlloc(sizeof(HPAI));

	// Append new entry to table
	p->body.hpai.pdata[new_size-1] = new_entry;
	p->body.hpai.length = new_size;

	return false;
}
static boolean dissect_hpai(KNXnetIPPacket *p, const uint8_t *data, int *offset)
{
	append_hpai(p);

	uint8_t entry = p->body.hpai.length - 1;
	HPAI *hpai_entry = p->body.hpai.pdata[entry];

	dissect((uint8_t *)&hpai_entry->structure_length, data, offset, sizeof(uint8_t),  ENC_BIG_ENDIAN);
	dissect((uint8_t *)&hpai_entry->host_protocol, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&hpai_entry->ip,     data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&hpai_entry->port,   data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);

	// FIXIT: Host Protocol (in)dependent data of variable length
	if (hpai_entry->structure_length != 8)
		return true;

	return false;
}

/*
 * Dissect Description Information Block (DIB) structure.
 */
static boolean append_dib(KNXnetIPPacket *p)
{
	uint8_t new_size = p->body.dib.length + 1;

	// Allocate new table
	DIB **new_table = (DIB **)SnortAlloc((new_size) * sizeof(DIB *));

	// Copy current table
	for (int i = 0; i < p->body.dib.length; i++)
	{
		new_table[i] = p->body.dib.pdata[i];
	}

	// Replace old/new table
	if (new_size != 1) {
		free(p->body.dib.pdata);
	}
	p->body.dib.pdata = new_table;

	// Allocate new entry
	DIB *new_entry = (DIB *)SnortAlloc(sizeof(DIB));

	// Append new entry to table
	p->body.dib.pdata[new_size-1] = new_entry;
	p->body.dib.length = new_size;

	return false;
}
static boolean append_dib_knxaddress(DIBKNXAddressS *dibknx, const uint8_t *data, int *offset)
{
	uint8_t new_size = dibknx->length + 1;

	// Allocate new table
	DIBKNXAddress **new_table = (DIBKNXAddress **)SnortAlloc((new_size) * sizeof(DIBKNXAddress *));

	// Copy current table
	for (int i = 0; i < dibknx->length; i++)
	{
		new_table[i] = dibknx->pdata[i];
	}

	// Replace old/new table
	if (new_size != 1) {
		free(dibknx->pdata);
	}
	dibknx->pdata = new_table;

	// Allocate new entry
	DIBKNXAddress *new_entry = (DIBKNXAddress *)SnortAlloc(sizeof(DIBKNXAddress));
	dissect((uint8_t *)&new_entry->address, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);

	// Append new entry to table
	dibknx->pdata[new_size-1] = new_entry;
	dibknx->length = new_size;

	return false;
}
static boolean append_dib_mfr_data(DIB* dib, const uint8_t *data, int *offset)
{
	// Allocate buffer
	uint8_t size = dib->structure_length - 4;
	char *man_data = (char *)SnortAlloc(size * sizeof(char));

	dissect((uint8_t *)man_data, data, offset, size* sizeof(uint8_t), ENC_LITTLE_ENDIAN);

	// Store reference
	dib->mfr_data.manufacturer_data = man_data;

	return false;
}
static boolean append_dib_svc(KNXnetIPPacket *p)
{
	uint8_t entry = p->body.dib.length - 1;
	uint8_t new_size = p->body.dib.pdata[entry]->device_service.length + 1;

	// Allocate new table
	DIBSuppSvcFamily **new_table = (DIBSuppSvcFamily **)SnortAlloc((new_size) * sizeof(DIBSuppSvcFamily *));

	// Copy current table
	for (int i = 0; i < p->body.dib.pdata[entry]->device_service.length; i++)
	{
		new_table[i] = p->body.dib.pdata[entry]->device_service.pdata[i];
	}

	// Replace old/new table
	if (new_size != 1) {
		free(p->body.dib.pdata[entry]->device_service.pdata);
	}
	p->body.dib.pdata[entry]->device_service.pdata = new_table;

	// Allocate new entry
	DIBSuppSvcFamily *new_entry = (DIBSuppSvcFamily *)SnortAlloc(sizeof(DIBSuppSvcFamily));

	// Append new entry to table
	p->body.dib.pdata[entry]->device_service.pdata[new_size-1] = new_entry;
	p->body.dib.pdata[entry]->device_service.length = new_size;

	return false;
}
static boolean dissect_dib_svc(KNXnetIPPacket *p, const uint8_t *data, int *offset)
{
	append_dib_svc(p);

	uint8_t entry = p->body.dib.pdata[p->body.dib.length-1]->device_service.length - 1;
	DIBSuppSvcFamily *dib_svc_fam = p->body.dib.pdata[p->body.dib.length-1]->device_service.pdata[entry];

	dissect((uint8_t *)&dib_svc_fam->id, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&dib_svc_fam->version, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);

	return false;
}
static boolean dissect_dib(KNXnetIPPacket *p, const uint8_t *data, int *offset)
{
	append_dib(p);

	uint8_t entry = p->body.dib.length - 1;
	DIB *dib_entry = p->body.dib.pdata[entry];

	dissect((uint8_t *)&dib_entry->structure_length, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&dib_entry->dib_type, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);

	switch(dib_entry->dib_type)
	{
		case DIB_DEVICE_INFO:
			if (dib_entry->structure_length != 54) {
				// FIXIT: alert!
				return true;
			}
			dissect((uint8_t *)&dib_entry->device_info.knx_medium, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->device_info.device_status, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->device_info.knx_individual_address, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->device_info.project_inst_id, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->device_info.serial_number, data, offset, 6 * sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			dissect((uint8_t *)&dib_entry->device_info.multicast_address, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->device_info.mac_address, data, offset, 6 * sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			dissect((uint8_t *)&dib_entry->device_info.device_friendly_name, data, offset, 30 * sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			break;

		case DIB_SUPP_SVC:
			for(int i = 0; i < ((dib_entry->structure_length-2)/ sizeof(DIBSuppSvcFamily)); i++)
			{
				dissect_dib_svc(p, data, offset);
			}
			break;

		// FIXIT: Implementation not tested due to missing packet captures.
		case DIB_IP_CONF:
			dissect((uint8_t *)&dib_entry->ip_config.ip, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->ip_config.subnet, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->ip_config.gateway, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->ip_config.capabilities, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->ip_config.assignment_method, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			break;

		// FIXIT: Implementation not tested due to missing packet captures.
		case DIB_IP_CURRENT:
			dissect((uint8_t *)&dib_entry->ip_current.ip, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->ip_current.subnet, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->ip_current.gateway, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->ip_current.dhcp, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->ip_current.assignment_method, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
			break;

		case DIB_KNX_ADDRESS:
			if ((dib_entry->structure_length % 2) != 0) {
				// FIXIT: alert!
				return true;
			}
			for (int i = 0; i < (dib_entry->structure_length - 2); i = i + 2)
			{
				append_dib_knxaddress(&dib_entry->knx_address, data, offset);
			}
			break;

		// FIXIT: Implementation not tested due to missing packet captures.
		case DIB_MFR_DATA:
			dissect((uint8_t *)&dib_entry->mfr_data.manufacturer_id, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);
			append_dib_mfr_data(dib_entry, data, offset);
			break;

		/* Malformed/Malicious packet */
		// FIXIT: alert!
		default:
			break;
	}

	return false;
}

/*
 * Dissect Connection Request Information (CRI) structure.
 */
static boolean append_cri(KNXnetIPPacket *p)
{
	uint8_t new_size = p->body.cri.length + 1;

	// Allocate new table
	CRI **new_table = (CRI **)SnortAlloc((new_size) * sizeof(CRI *));

	// Copy current table
	for (int i = 0; i < p->body.cri.length; i++)
	{
		new_table[i] = p->body.cri.pdata[i];
	}

	// Replace old/new table
	if (new_size != 1) {
		free(p->body.cri.pdata);
	}
	p->body.cri.pdata = new_table;

	// Allocate new entry
	CRI *new_entry = (CRI *)SnortAlloc(sizeof(CRI));

	// Append new entry to table
	p->body.cri.pdata[new_size-1] = new_entry;
	p->body.cri.length = new_size;

	return false;
}
static boolean dissect_cri(KNXnetIPPacket *p, const uint8_t *data, int *offset)
{
	append_cri(p);

	uint8_t entry = p->body.cri.length - 1;
	CRI *cri_entry = p->body.cri.pdata[entry];

	dissect((uint8_t *)&cri_entry->structure_length, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&cri_entry->connection_type, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&cri_entry->knxlayer, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&cri_entry->reserved, data, offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);

	// FIXIT: Host Protocol (in)dependent data of variable length
	if (cri_entry->structure_length != 4)
		return true;

	return false;
}

/*
 * Dissect Connection Response Data Block (CRD) structure.
 */
static boolean append_crd(KNXnetIPPacket *p)
{
	uint8_t new_size = p->body.crd.length + 1;

	// Allocate new table
	CRD **new_table = (CRD **)SnortAlloc((new_size) * sizeof(CRD *));

	// Copy current table
	for (int i = 0; i < p->body.crd.length; i++)
	{
		new_table[i] = p->body.crd.pdata[i];
	}

	// Replace old/new table
	if (new_size != 1) {
		free(p->body.crd.pdata);
	}
	p->body.crd.pdata = new_table;

	// Allocate new entry
	CRD *new_entry = (CRD *)SnortAlloc(sizeof(CRD));

	// Append new entry to table
	p->body.crd.pdata[new_size-1] = new_entry;
	p->body.crd.length = new_size;

	return false;
}
static boolean dissect_crd(KNXnetIPPacket *p, const uint8_t *data, int *offset)
{
	append_crd(p);

	uint8_t entry = p->body.crd.length - 1;
	CRD *crd_entry = p->body.crd.pdata[entry];

	dissect((uint8_t *)&crd_entry->structure_length, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&crd_entry->connection_type, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);

	// FIXIT: Host Protocol (in)dependent data of variable length
	if (crd_entry->structure_length != 4)
		return true;

	if (crd_entry->connection_type == KNX_TUNNEL_CONNECTION)
	{
		dissect((uint8_t *)&crd_entry->knxaddress, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);
	}

	// FIXIT: Implement other connection types (if necessary).
	else
	{
		return true;
	}

	return false;
}

/*
 * Dissect Connection Header structure.
 */
static boolean dissect_conn_header(KNXnetIPPacket *p, const uint8_t *data, int *offset)
{
	dissect((uint8_t *)&p->body.conn_header.structure_length, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&p->body.conn_header.communication_channel_id, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&p->body.conn_header.sequence_counter, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	return false;
}

/*
 * Dissect cEMI structure.
 */

static boolean append_add_info_rffa(AddInfoRFFastAckS *add_info_rffa)
{
	uint8_t new_size = add_info_rffa->length + 1;

	// Allocate new table
	AddInfoRFFastAck **new_table = (AddInfoRFFastAck **)SnortAlloc((new_size) * sizeof(AddInfoRFFastAck *));

	// Copy current table
	for (int i = 0; i < add_info_rffa->length; i++)
	{
		new_table[i] = add_info_rffa->pdata[i];
	}

	// Replace old/new table
	if (new_size != 1)
	{
		free(add_info_rffa->pdata);
	}
	add_info_rffa->pdata = new_table;

	// Allocate new entry
	AddInfoRFFastAck *new_entry = (AddInfoRFFastAck *)SnortAlloc(sizeof(AddInfoRFFastAck));

	// Append new entry to table
	add_info_rffa->pdata[new_size-1] = new_entry;
	add_info_rffa->length = new_size;

	return false;
}
static boolean append_add_info(cEMI *cemi)
{
	uint8_t new_size = cemi->lpdu.add_info.length + 1;

	// Allocate new table
	AddInfo **new_table = (AddInfo **)SnortAlloc((new_size) * sizeof(AddInfo *));

	// Copy current table
	for (int i = 0; i < cemi->lpdu.add_info.length; i++)
	{
		new_table[i] = cemi->lpdu.add_info.pdata[i];
	}

	// Replace old/new table
	if (new_size != 1)
	{
		free(cemi->lpdu.add_info.pdata);
	}
	cemi->lpdu.add_info.pdata = new_table;

	// Allocate new entry
	AddInfo *new_entry = (AddInfo *)SnortAlloc(sizeof(AddInfo));

	// Append new entry to table
	cemi->lpdu.add_info.pdata[new_size-1] = new_entry;
	cemi->lpdu.add_info.length = new_size;

	return false;
}

static boolean dissect_lpdu(cEMI *cemi, const uint8_t *data, int *offset)
{
	LPDU *lpdu = &cemi->lpdu;

	dissect((uint8_t *)&lpdu->control_field1, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&lpdu->control_field2, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&lpdu->src, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&lpdu->dest, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);

	return false;
}
static boolean dissect_npdu(cEMI *cemi, const uint8_t *data, int *offset)
{
	if (cemi->lpdu.message_code == POLL_DATA_REQ)
	{
		dissect((uint8_t *)&cemi->lpdu.npdu.number_of_slots, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
		cemi->lpdu.npdu.number_of_slots &= 0xf;
	}
	else if (cemi->lpdu.message_code == POLL_DATA_CON)
	{
		dissect((uint8_t *)&cemi->lpdu.npdu.number_of_slots, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
		cemi->lpdu.npdu.number_of_slots &= 0xf;
		cemi->lpdu.npdu.poll_data = (uint8_t *)SnortAlloc(cemi->lpdu.npdu.number_of_slots * sizeof(uint8_t));
		dissect((uint8_t *)cemi->lpdu.npdu.poll_data, data, offset, cemi->lpdu.npdu.number_of_slots * sizeof(uint8_t), ENC_LITTLE_ENDIAN);
	}
	else {
		dissect((uint8_t *)&cemi->lpdu.npdu.structure_length, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	}

	return false;
}
static boolean dissect_tpdu(cEMI *cemi, const uint8_t *data, int *offset)
{
	dissect((uint8_t *)&cemi->lpdu.npdu.tpdu.tpci, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
	cemi->lpdu.npdu.tpdu.tpci &= 0xfc;

	/* Revert 1 byte, as this field contains ACPI as well */
	*offset -= 1;
	return false;
}
static boolean dissect_apdu(cEMI *cemi, const uint8_t *data, int *offset)
{
	uint16_t type;
	uint8_t length = cemi->lpdu.npdu.structure_length;
	APDU *apdu = &cemi->lpdu.npdu.tpdu.apdu;

	if (length != 0)
	{
		uint16_t apci_bytes;
		dissect((uint8_t *)&apci_bytes, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);
		apdu->apci = apci_bytes & 0x3FF;
		type = apci_bytes & 0x3C0;

		switch (type)
		{
			case A_ADC_RED:
			case A_ADC_RES:
				type = apdu->apci & 0x1FF;
				if (type == A_SYS_RED || type == A_SYS_RES || type == A_SYS_WRT || type == A_SYS_BROAD)
				{
					// apdu->apci = apci_bytes 0x3ff;
				}
				else
				{
					apdu->apci &= 0x3c0;
					apdu->channel_nr &= 0x3f;
				}
				break;

			case A_GROUPVALUE_RES:
			case A_GROUPVALUE_WRT:
				apdu->apci = apci_bytes & 0x3c0;
				apdu->cemi_data = (uint8_t) apci_bytes & 0x3f;
				if (type == A_GROUPVALUE_RES && length > 1)
				{
					apdu->data = (uint8_t *)SnortAlloc((length-1) * sizeof(uint8_t));
					dissect((uint8_t*)apdu->data, data, offset, (length-1) * sizeof(uint8_t), ENC_LITTLE_ENDIAN);
				}
				break;

			case A_MEM_RED:
			case A_MEM_RES:
			case A_MEM_WRT:
				apdu->apci = apci_bytes & 0x3c0;
				apdu->memory_number = apci_bytes & 0x3f;
				dissect((uint8_t *)&apdu->memory_address, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);
				if (length > 3)
				{
					apdu->data = (uint8_t *)SnortAlloc((length-3) * sizeof(uint8_t));
					dissect((uint8_t *)apdu->data, data, offset, (length-3) * sizeof(uint8_t), ENC_LITTLE_ENDIAN);
				}
				break;

			case COUPLER_SPECIFIC_SERVICE:

				// apdu->apci = apci_bytes 0x3ff;

				switch(apdu->apci)
				{
					case A_AUTHORIZE_REQ:
					case A_KEY_WRT:
						dissect((uint8_t *)&apdu->apci_level, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
						dissect((uint8_t *)&apdu->apci_key, data, offset, sizeof(uint32_t), ENC_LITTLE_ENDIAN);
						break;

					case A_AUTHORIZE_RES:
					case A_KEY_RES:
						dissect((uint8_t *)&apdu->apci_level, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
						break;

					case A_PROPVALUE_RED:
					case A_PROPVALUE_RES:
						dissect((uint8_t *)&apdu->apci_object_index, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
						dissect((uint8_t *)&apdu->apci_property_id, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
						dissect((uint8_t *)&apdu->start_index, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);
						apdu->number_of_elements = (uint8_t) ((apdu->start_index & 0xf000) > 8);
						apdu->start_index &= 0x0fff;
						if (apdu->apci == A_PROPVALUE_RES)
						{
							apdu->data = (uint8_t *)SnortAlloc((length-5) * sizeof(uint8_t));
							dissect((uint8_t *)apdu->data, data, offset, (length-5) * sizeof(uint8_t), ENC_LITTLE_ENDIAN);
						}
						break;

					default:
						// FIXIT: Unsupported ACPI
						break;
				}

				break;

			default:
				// FIXIT: Unsupported type.
				break;
		}

	}

	return false;
}

static boolean validate_length(uint8_t *length, uint8_t size)
{
	if (*length >= size)
	{
		*length -= size;
	}
	else
	{
		// FIXIT: Malformed packet. Alert!
		return true;
	}

	return false;
}

static boolean dissect_cemi(KNXnetIPPacket *p, const uint8_t *data, int *offset)
{
	cEMI *cemi = &p->body.cemi;
	uint16_t structure_length = p->header.totallength - KNXNETIP_HEADER_LENGTH;

	// FIXIT: Resolve by cleaning up LPDU data structure */
	uint8_t reserved[6];

	dissect((uint8_t *)&cemi->lpdu.message_code, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);


	/* Check if M_ message (mgmt)
	 *
	 * Code of Wireshark 2.6.0 contains a bug apparently,
	 * checking for M_ messages falsely, i.e.:
	 *
	 *  if ((messagecode & 0xF0) < 0xF0))
	 *
	 *  which should result in every message code idenfied
	 *  as non M_ message, and checking for additional info
	 *  rf.:
	 *   - Wireshark 2.6.0 source code - packet-knxnetip.c
	 *   - KNX Spec. v2.1 - 3.6.3 External Message Interface p. 58, 115
	 */
	if ((cemi->lpdu.message_code & 0xF0) < 0xD0)
	{

		/* Dissect Additional Information */
		dissect((uint8_t *)&cemi->lpdu.add_info_length, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);

		uint8_t add_info_length = cemi->lpdu.add_info_length;

		while(add_info_length > 0)
		{
			append_add_info(cemi);
			AddInfo *add_info_entry = cemi->lpdu.add_info.pdata[cemi->lpdu.add_info.length-1];

			dissect((uint8_t *)&add_info_entry->type_id, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&add_info_entry->structure_length, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);

			if (validate_length(&add_info_length, 2))
				return true;

			// FIXIT: Additional Information dissect not tested.

			switch (add_info_entry->type_id)
			{
				case PL_INFO:
					dissect((uint8_t *)&add_info_entry->pl.domain_address, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);

					if (validate_length(&add_info_length, 2))
						return true;
					break;

				case RF_INFO:
					dissect((uint8_t *)&add_info_entry->rf.rf_info, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
					dissect((uint8_t *)add_info_entry->rf.serial_number, data, offset, 6 * sizeof(uint8_t), ENC_BIG_ENDIAN);
					dissect((uint8_t *)&add_info_entry->rf.dl_frame_number, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);

					if (validate_length(&add_info_length, 8))
						return true;
					break;

				case BUSMON_INFO:
					dissect((uint8_t *)&add_info_entry->bm.error_flags, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);

					if (validate_length(&add_info_length, 1))
						return true;
					break;

				case TIME_REL:
					dissect((uint8_t *)&add_info_entry->rts.rel_timestamp, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);

					if (validate_length(&add_info_length, 2))
						return true;
					break;

				case TIME_DELAY:
					dissect((uint8_t *)&add_info_entry->td.time_delay, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);

					if (validate_length(&add_info_length, 4))
						return true;
					break;

				case EXEND_TIME:
					dissect((uint8_t *)&add_info_entry->ets.ext_rel_timestamp, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);

					if (validate_length(&add_info_length, 4))
						return true;
					break;

				case BIBAT_INFO:
					dissect((uint8_t *)&add_info_entry->bb.bibat, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
					dissect((uint8_t *)&add_info_entry->bb.block_number, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);

					if (validate_length(&add_info_length, 2))
						return true;
					break;

				case RF_MULTI:
					dissect((uint8_t *)&add_info_entry->rfm.transmit_frequency, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
					dissect((uint8_t *)&add_info_entry->rfm.call_channel, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
					dissect((uint8_t *)&add_info_entry->rfm.fast_ack, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
					dissect((uint8_t *)&add_info_entry->rfm.receive_frequency, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);

					if (validate_length(&add_info_length, 4))
						return true;
					break;

				case PREAMBEL:
					dissect((uint8_t *)&add_info_entry->pa.preamble_length, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);
					dissect((uint8_t *)&add_info_entry->pa.postamble_length, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);

					if (validate_length(&add_info_length, 3))
						return true;

					break;

				case RF_FAST_ACK:
					for(int i = 0; i < add_info_entry->structure_length; i++)
					{
						append_add_info_rffa(&add_info_entry->rffa);
						AddInfoRFFastAck *rffa_entry = add_info_entry->rffa.pdata[add_info_entry->rffa.length-1];

						dissect((uint8_t *)&rffa_entry->status, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
						dissect((uint8_t *)&rffa_entry->info, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);

						if (validate_length(&add_info_length, 2))
							return true;
					}
					break;

				case MANU_DATA:
					dissect((uint8_t *)&add_info_entry->mf.manufacturer_id, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);
					dissect((uint8_t *)&add_info_entry->mf.subfunction, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);

					if (validate_length(&add_info_length, 3))
						return true;

					uint8_t mf_data_length = add_info_entry->structure_length - 3;
					add_info_entry->mf.data = (uint8_t *)SnortAlloc(mf_data_length * sizeof(uint8_t));
					dissect((uint8_t *)add_info_entry->mf.data, data, offset, mf_data_length * sizeof(uint8_t), ENC_LITTLE_ENDIAN);

					if (validate_length(&add_info_length, mf_data_length))
						return true;
					break;

				default:
					// FIXIT: Unknown/unsupported add. information type.
					// Alert!!
					break;
			}


		}


	}

	// FIXIT: CEMI dissect not tested.
	switch (cemi->lpdu.message_code)
	{
		case DATA_REQ:
		case DATA_CON:
		case DATA_IND:
		case POLL_DATA_REQ:
		case POLL_DATA_CON:
			dissect_lpdu(cemi, data, offset);
			dissect_npdu(cemi, data, offset);

			if (cemi->lpdu.message_code != POLL_DATA_CON &&
				cemi->lpdu.message_code != POLL_DATA_REQ)
			{
				dissect_tpdu(cemi, data, offset);
				dissect_apdu(cemi, data, offset);
			}
			break;

		case RAW_REQ:
		case RAW_CON:
		case RAW_IND:
		case BUSMON_IND:
//			*offset -= 7;
//			uint16_t structure_length;
//			dissect((uint8_t *)&structure_length, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);
//			*offset += 5;

			// FIXIT: Check endianess
			cemi->raw_data = (uint8_t *)SnortAlloc((structure_length - 5) * sizeof(uint8_t));
			dissect((uint8_t *)cemi->raw_data, data, offset, (structure_length - 5) * sizeof(uint8_t), ENC_LITTLE_ENDIAN);

			break;

		case DATA_INDV_IND:
		case DATA_INDV_REQ:
		case DATA_CONNEC_IND:
		case DATA_CONNEC_REQ:

			// FIXIT: Resolve by cleaning up LPDU data structure */
//			uint8_t reserved[6];
			dissect((uint8_t *)reserved, data, offset, 6 * sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			dissect_npdu(cemi, data, offset);
			// FIXIT: Resolve by cleaning up TPDU data structure */
			uint8_t reserved2;
			dissect((uint8_t *)&reserved2, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			dissect_apdu(cemi, data, offset);
			break;

		case PROPREAD_REQ:
		case PROPREAD_CON:
		case PROPWRITE_REQ:
		case PROPWRITE_CON:
		case PROPINFO_IND:
			// FIXIT: Continue note:
			//  - Cleanup Data Structures
			//  - Implement PROPREAD_REQ, FUNCPROPCOM_REQ
			break;

		case FUNCPROPCOM_REQ:
		case FUNCPROPSTATREAD_REQ:
		case FUNCPROPCOM_CON:
			break;

		case RESET_REQ:
		case RESET_IND:
			break;

		default:
			break;
	}


	return false;
}

void free_knxnetip(KNXnetIPPacket *p)
{
	/* HPAI */
	switch(p->header.servicetype)
	{
		case SEARCH_REQ:
		case SEARCH_RES:
		case DESCRIPTION_REQ:
		case CONNECT_REQ:
		case CONNECT_RES:
		case CONNECTIONSTATE_REQ:
		case DISCONNECT_REQ:
			for (int i = 0; i < p->body.hpai.length; i++)
			{
				if (p->body.hpai.pdata[i]) {
					free(p->body.hpai.pdata[i]);
				}
			}

			if (p->body.hpai.pdata) {
				free(p->body.hpai.pdata);
			}
			break;
	}

	CRIS *cris = &p->body.cri;
	CRDS *crds = &p->body.crd;
	DIBS *dibs = &p->body.dib;
	cEMI *cemi = &p->body.cemi;

	switch(p->header.servicetype)
	{
		case CONNECT_REQ:

			/* CRI */
			for (int i = 0; i < cris->length; i++)
			{
				if(cris->pdata[i])
					free(cris->pdata[i]);
			}

			if (cris->pdata)
				free(cris->pdata);
			break;

		case CONNECT_RES:

			/* CRD */
			for (int i = 0; i < crds->length; i++)
			{
				if(crds->pdata[i])
					free(crds->pdata[i]);
			}

			if (crds->pdata)
				free(crds->pdata);
			break;

		case DEVICE_CONFIGURATION_REQ:
		case TUNNELLING_REQ:

			/* cEMI */
			if (cemi->lpdu.message_code & 0xF0)
			{
				/* AddInfo */
				for (int i = 0; i < cemi->lpdu.add_info.length; i++)
				{
					switch (cemi->lpdu.add_info.pdata[i]->type_id)
					{
						/* AddInfoRFFastAckS */
						case RF_FAST_ACK:
							for (int j = 0; j < cemi->lpdu.add_info.pdata[i]->rffa.length; j++)
							{
								if (cemi->lpdu.add_info.pdata[i]->rffa.pdata[j])
									free(cemi->lpdu.add_info.pdata[i]->rffa.pdata[j]);
							}

							if (cemi->lpdu.add_info.pdata[i]->rffa.pdata)
								free(cemi->lpdu.add_info.pdata[i]->rffa.pdata);
							break;

						/* AddInfoManufacturer */
						case MANU_DATA:
							if (cemi->lpdu.add_info.pdata[i]->mf.data)
								free(cemi->lpdu.add_info.pdata[i]->mf.data);
							break;

						default:
							break;
					}

					if (cemi->lpdu.add_info.pdata[i])
						free(cemi->lpdu.add_info.pdata[i]);
				}

				if (cemi->lpdu.add_info.pdata)
					free(cemi->lpdu.add_info.pdata);
			}

			switch (cemi->lpdu.message_code)
			{
				case DATA_REQ:
				case DATA_CON:
				case DATA_IND:
				case POLL_DATA_REQ:
				case POLL_DATA_CON:

					if (cemi->lpdu.message_code == POLL_DATA_CON)
					{
						if (cemi->lpdu.npdu.poll_data)
							free(cemi->lpdu.npdu.poll_data);
					}

					if (cemi->lpdu.npdu.tpdu.apdu.data)
						free(cemi->lpdu.npdu.tpdu.apdu.data);

					break;

				case RAW_REQ:
				case RAW_CON:
				case RAW_IND:
				case BUSMON_IND:

					if (cemi->raw_data)
						free(cemi->raw_data);

					break;

				default:
					break;
			}

			break;

		case SEARCH_RES:
		case DESCRIPTION_RES:

			/* DIB */
			for (int i = 0; i < dibs->length; i++)
			{
				/* DIBKNXAddress */
				if (dibs->pdata[i]->dib_type == DIB_KNX_ADDRESS)
				{
					DIBKNXAddressS *dibknx = &dibs->pdata[i]->knx_address;
					for (int j= 0; j < dibknx->length; j++)
					{
						if (dibknx->pdata[j]) {
							free(dibknx->pdata[j]);
						}
					}
					if (dibknx->pdata) {
						free(dibknx->pdata);
					}
				}

				/* DIBMFRData */
				if (dibs->pdata[i]->dib_type == DIB_MFR_DATA)
				{
					DIBMFRData *dibmfr = &dibs->pdata[i]->mfr_data;
					if (dibmfr->manufacturer_data) {
						free(dibmfr->manufacturer_data);
					}
				}

				/* DIBSuppSvc */
				if (p->body.dib.pdata[i]->dib_type == DIB_SUPP_SVC)
				{
					for (int j = 0; j < p->body.dib.pdata[i]->device_service.length; j++)
					{
						if (p->body.dib.pdata[i]->device_service.pdata[j]) {
							free(p->body.dib.pdata[i]->device_service.pdata[j]);
						}
					}
					if (p->body.dib.pdata[i]->device_service.pdata) {
						free(p->body.dib.pdata[i]->device_service.pdata);
					}
				}

				if (p->body.dib.pdata[i]) {
					free(p->body.dib.pdata[i]);
				}
			}

			if (p->body.dib.pdata) {
				free(p->body.dib.pdata);
			}
			break;

	}
}

void dissect_knxnetip(const uint8_t *data)
{
	KNXnetIPPacket knx;
	int offset = 0;
	boolean err = false;

	memset(&knx, 0, sizeof(KNXnetIPPacket));

	/* Header */
	dissect((uint8_t *)&knx.header.length,      data, &offset, sizeof(uint8_t),  ENC_BIG_ENDIAN);
	dissect((uint8_t *)&knx.header.version,     data, &offset, sizeof(uint8_t),  ENC_BIG_ENDIAN);
	dissect((uint8_t *)&knx.header.servicetype, data, &offset, sizeof(uint16_t), ENC_BIG_ENDIAN);
	dissect((uint8_t *)&knx.header.totallength, data, &offset, sizeof(uint16_t), ENC_BIG_ENDIAN);


	/* Body */
	switch(knx.header.servicetype)
	{
		case SEARCH_REQ:
			dissect_hpai(&knx, data, &offset);
			break;

		case SEARCH_RES:
			dissect_hpai(&knx, data, &offset);
			err = dissect_dib(&knx, data, &offset);
			err = dissect_dib(&knx, data, &offset);
			break;

		case DESCRIPTION_REQ:
			dissect_hpai(&knx, data, &offset);
			break;

		case DESCRIPTION_RES:
			err = dissect_dib(&knx, data, &offset);
			err = dissect_dib(&knx, data, &offset);
			break;

		case CONNECT_REQ:
			dissect_hpai(&knx, data, &offset);
			dissect_hpai(&knx, data, &offset);
			dissect_cri(&knx, data, &offset);
			break;

		case CONNECT_RES:
			dissect((uint8_t *)&knx.body.communication_channel_id, data, &offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&knx.body.connection_status, data, &offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			dissect_hpai(&knx, data, &offset);
			dissect_crd(&knx, data, &offset);
			break;

		case CONNECTIONSTATE_REQ:
		case DISCONNECT_REQ:
			dissect((uint8_t *)&knx.body.communication_channel_id, data, &offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&knx.body.reserved, data, &offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			dissect_hpai(&knx, data, &offset);
			break;

		case CONNECTIONSTATE_RES:
		case DISCONNECT_RES:
			dissect((uint8_t *)&knx.body.communication_channel_id, data, &offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&knx.body.connectionstate_status, data, &offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			break;

		case DEVICE_CONFIGURATION_ACK:
			dissect_conn_header(&knx, data, &offset);
			dissect((uint8_t *)&knx.body.conn_header.confackstat, data, &offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			break;

		case DEVICE_CONFIGURATION_REQ:
		case TUNNELLING_REQ:
			dissect_conn_header(&knx, data, &offset);
			dissect((uint8_t *)&knx.body.conn_header.reserved, data, &offset, sizeof(uint8_t), ENC_LITTLE_ENDIAN);
			dissect_cemi(&knx, data, &offset);
			break;

		case TUNNELLING_ACK:
			dissect_conn_header(&knx, data, &offset);
			dissect((uint8_t *)&knx.body.conn_header.tunnackstat, data, &offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			break;

		case ROUTING_INDICATION:
			break;

		case ROUTING_LOST:
			break;

		case ROUTING_BUSY:
			break;

		case REMOTE_DIAG_REQ:
			break;

		case REMOTE_DIAG_RES:
			break;

		case REMOTE_BASIC_CONF_REQ:
			break;

		case REMOTE_RESET_REQ:
			break;

		default:
			break;
	}


	free_knxnetip(&knx);
}
