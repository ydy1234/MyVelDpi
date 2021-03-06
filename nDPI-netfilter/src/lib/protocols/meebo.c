/*
 * meebo.c
 *
 * Copyright (C) 2009-2011 by ipoque GmbH
 * Copyright (C) 2011-15 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 * 
 */


#include "ndpi_api.h"

#ifdef NDPI_PROTOCOL_MEEBO

static void ndpi_int_meebo_add_connection(struct ndpi_detection_module_struct
					  *ndpi_struct, struct ndpi_flow_struct *flow)
{
  ndpi_set_detected_protocol(ndpi_struct, flow, NDPI_PROTOCOL_MEEBO, NDPI_PROTOCOL_UNKNOWN);
}

void ndpi_search_meebo(struct ndpi_detection_module_struct
		       *ndpi_struct, struct ndpi_flow_struct *flow)
{
  struct ndpi_packet_struct *packet = &flow->packet;
	

  // struct ndpi_id_struct *src=ndpi_struct->src;
  // struct ndpi_id_struct *dst=ndpi_struct->dst;


  NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "search meebo.\n");

  /* catch audio/video flows which are flash (rtmp) */
  if (
#ifdef NDPI_CONTENT_FLASH
      packet->detected_protocol_stack[0] == NDPI_CONTENT_FLASH
#else
      (packet->tcp->source == htons(1935) || packet->tcp->dest == htons(1935))
#endif
      ) {

    /* TODO: once we have an amf decoder we can more directly access the rtmp fields
     *       if so, we may also exclude earlier */
    if (packet->payload_packet_len > 900) {
      if (memcmp(packet->payload + 116, NDPI_STATICSTRING("tokbox/")) == 0 ||
	  memcmp(packet->payload + 316, NDPI_STATICSTRING("tokbox/")) == 0) {
	NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "found meebo/tokbox flash flow.\n");
	ndpi_int_meebo_add_connection(ndpi_struct, flow);
	return;
      }
    }

    if (flow->packet_counter < 16 && flow->packet_direction_counter[flow->setup_packet_direction] < 6) {
      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "need next packet.\n");
      return;
    }

    NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "exclude meebo.\n");
    NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MEEBO);
    return;
  }

  if ((
#ifdef	NDPI_PROTOCOL_HTTP
       packet->detected_protocol_stack[0] == NDPI_PROTOCOL_HTTP ||
#endif
       ((packet->payload_packet_len > 3 && memcmp(packet->payload, "GET ", 4) == 0)
	|| (packet->payload_packet_len > 4 && memcmp(packet->payload, "POST ", 5) == 0))
       ) && flow->packet_counter == 1) {
    u_int8_t host_or_referer_match = 0;

    ndpi_parse_packet_line_info(ndpi_struct, flow);
    if ( memcmp_packet_hdr(packet,host_line_idx, NDPI_STATICSTRING("meebo.com"),-1) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "Found Meebo host\n");
      host_or_referer_match = 1;
    } else if ( memcmp_packet_hdr(packet,host_line_idx, NDPI_STATICSTRING("tokbox.com"),-1) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "Found tokbox host\n");
      /* set it to 2 to avoid having plain tokbox traffic detected as meebo */
      host_or_referer_match = 2;
    } else if ( memcmp_packet_hdr(packet,host_line_idx,
			 NDPI_STATICSTRING("74.114.28.110"),-1) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "Found meebo IP\n");
      host_or_referer_match = 1;
    } else if ( memcmp_packet_hdr(packet,referer_line_idx,
		      NDPI_STATICSTRING("http://www.meebo.com/"),0) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "Found meebo referer\n");
      host_or_referer_match = 1;
    } else if ( memcmp_packet_hdr(packet,referer_line_idx,
		      NDPI_STATICSTRING("http://mee.tokbox.com/"),0) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "Found tokbox referer\n");
      host_or_referer_match = 1;
    } else if ( memcmp_packet_hdr(packet,referer_line_idx,
		      NDPI_STATICSTRING("http://74.114.28.110/"),0) == 0) {

      NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "Found meebo IP referer\n");
      host_or_referer_match = 1;
    }

    if (host_or_referer_match) {
      if (host_or_referer_match == 1) {
	NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG,
		 "Found Meebo traffic based on host/referer\n");
	ndpi_int_meebo_add_connection(ndpi_struct, flow);
	return;
      }
    }
  }

  if (packet->detected_protocol_stack[0] == NDPI_PROTOCOL_MEEBO) {
    NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG,
	     "in case that ssl meebo has been detected return.\n");
    return;
  }

  if (flow->packet_counter < 5 && packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN
      && NDPI_COMPARE_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_SSL) == 0) {
    NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "ssl not yet excluded. need next packet.\n");
    return;
  }
#ifdef NDPI_CONTENT_FLASH
  if (flow->packet_counter < 5 && packet->detected_protocol_stack[0] == NDPI_PROTOCOL_UNKNOWN &&
      !NDPI_FLOW_PROTOCOL_EXCLUDED(ndpi_struct, flow, NDPI_CONTENT_FLASH)) {
    NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "flash not yet excluded. need next packet.\n");
    return;
  }
#endif

  NDPI_LOG(NDPI_PROTOCOL_MEEBO, ndpi_struct, NDPI_LOG_DEBUG, "exclude meebo.\n");
  NDPI_ADD_PROTOCOL_TO_BITMASK(flow->excluded_protocol_bitmask, NDPI_PROTOCOL_MEEBO);
}


void init_meebo_dissector(struct ndpi_detection_module_struct *ndpi_struct, u_int32_t *id, NDPI_PROTOCOL_BITMASK *detection_bitmask)
{
  ndpi_set_bitmask_protocol_detection("Meebo", ndpi_struct, detection_bitmask, *id,
				      NDPI_PROTOCOL_MEEBO,
				      ndpi_search_meebo,
				      NDPI_SELECTION_BITMASK_PROTOCOL_V4_V6_TCP_WITH_PAYLOAD_WITHOUT_RETRANSMISSION,
				      SAVE_DETECTION_BITMASK_AS_UNKNOWN,
				      ADD_TO_DETECTION_BITMASK);
  
  /* Add protocol bitmask dependencies to detected bitmask*/
#ifdef NDPI_CONTENT_FLASH
  NDPI_ADD_PROTOCOL_TO_BITMASK(ndpi_struct->callback_buffer[*id].detection_bitmask, NDPI_CONTENT_FLASH);
#endif

  *id += 1;
}

#endif
