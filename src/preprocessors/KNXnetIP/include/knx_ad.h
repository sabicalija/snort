/*
 * knx_ad.h
 *
 *  Created on: May 11, 2018
 *  Author: Alija Sabic
 *  E-Mail: sabic@technikum-wien.at
 */

#ifndef __KNX_ANOMALY_DETECTION__
#define __KNX_ANOMALY_DETECTION__

#include "decode.h"

#include "knxnetip.h"
#include "knx_ui_config.h"

int detect_knxnetip(Packet *p, KNXnetIPPacket *knx, KNXNETIP_SERVER_CONF *config);

#endif /* __KNX_ANOMALY_DETECTION__ */
