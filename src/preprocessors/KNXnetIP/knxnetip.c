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

	// FIXIT: Host Protocol dependent data of variable length
	if (hpai_entry->structure_length != 8)
		return true;

	return false;
}

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

	for (int i = 0; i < dibknx->length; i++)
	{
		new_table[i] = dibknx->pdata[i];
	}

	if (new_size != 1) {
		free(dibknx->pdata);
	}
	dibknx->pdata = new_table;

	// Allocate new entry
	DIBKNXAddress *new_entry = (DIBKNXAddress *)SnortAlloc(sizeof(DIBKNXAddress));
	dissect((uint8_t *)&new_entry->address, data, offset, sizeof(uint16_t), ENC_BIG_ENDIAN);

	// Append new entry
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

	// Allocate larger array for new DIBSuppSvcFamily entry
	DIBSuppSvcFamily **new_data = (DIBSuppSvcFamily **)SnortAlloc((new_size) * sizeof(DIBSuppSvcFamily*));

//	memset(new_data, 0, (new_size) * sizeof(DIBSuppSvcFamily*));

	// Copy current DIBSuppSvcFamily pointer in new array
	for (int i = 0; i < p->body.dib.pdata[entry]->device_service.length; i++)
	{
		new_data[i] = p->body.dib.pdata[entry]->device_service.pdata[i];
	}

	if (new_size != 1) {
		free(p->body.dib.pdata[entry]->device_service.pdata);
	}
	p->body.dib.pdata[entry]->device_service.pdata = new_data;

	// Allocate new DIBSuppSvcFamily entry
	DIBSuppSvcFamily *new_entry = (DIBSuppSvcFamily *)SnortAlloc(sizeof(DIBSuppSvcFamily));

	// Append new entry
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

		case DIB_IP_CONF:
			dissect((uint8_t *)&dib_entry->ip_config.ip, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->ip_config.subnet, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->ip_config.gateway, data, offset, sizeof(uint32_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->ip_config.capabilities, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			dissect((uint8_t *)&dib_entry->ip_config.assignment_method, data, offset, sizeof(uint8_t), ENC_BIG_ENDIAN);
			break;

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
			break;

		case CONNECTIONSTATE_RES:
		case DISCONNECT_RES:
			break;

		case DEVICE_CONFIGURATION_ACK:
			break;

		case DEVICE_CONFIGURATION_REQ:
		case TUNNELLING_REQ:
			break;

		case TUNNELLING_ACK:
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

		case REMOTE_RESET_REQ:
			break;

		default:
			break;
	}


	free_knxnetip(&knx);
}
