/*
 * This file is part of bgpstream
 *
 * CAIDA, UC San Diego
 * bgpstream-info@caida.org
 *
 * Copyright (C) 2012 The Regents of the University of California.
 * Authors: Alistair King, Chiara Orsini
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "config.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "bgpdump_lib.h"
#include "utils.h"

#include "bgpstream.h"
#include "bgpstream_utils.h"

#include "bgpstream_debug.h"
#include "bgpstream_record.h"

#include "bgpstream_elem_int.h"
#include "utils/bgpstream_utils_rtr.h"

/* ==================== PROTECTED FUNCTIONS ==================== */

/* ==================== PUBLIC FUNCTIONS ==================== */

bgpstream_elem_t *bgpstream_elem_create() {
  // allocate memory for new element
  bgpstream_elem_t *ri = NULL;

  if((ri =
      (bgpstream_elem_t *) malloc_zero(sizeof(bgpstream_elem_t))) == NULL) {
    goto err;
  }
  // all fields are initialized to zero

  // need to create as path
  if((ri->aspath = bgpstream_as_path_create()) == NULL) {
    goto err;
  }

  // and a community set
  if((ri->communities = bgpstream_community_set_create()) == NULL) {
    goto err;
  }

  return ri;

 err:
  bgpstream_elem_destroy(ri);
  return NULL;
}

void bgpstream_elem_destroy(bgpstream_elem_t *elem) {

  if(elem == NULL) {
    return;
  }

  bgpstream_as_path_destroy(elem->aspath);
  elem->aspath = NULL;

  bgpstream_community_set_destroy(elem->communities);
  elem->communities = NULL;

  free(elem);
}

void bgpstream_elem_clear(bgpstream_elem_t *elem) {
  bgpstream_as_path_clear(elem->aspath);
  bgpstream_community_set_clear(elem->communities);
}

bgpstream_elem_t *bgpstream_elem_copy(bgpstream_elem_t *dst,
                                      bgpstream_elem_t *src)
{
  /* save all ptrs before memcpy */
  bgpstream_as_path_t *dst_aspath = dst->aspath;
  bgpstream_community_set_t *dst_comms = dst->communities;

  /* do a memcpy and then manually copy the as path and communities */
  memcpy(dst, src, sizeof(bgpstream_elem_t));

  /* restore all ptrs */
  dst->aspath = dst_aspath;
  dst->communities = dst_comms;

  if(bgpstream_as_path_copy(dst->aspath, src->aspath) != 0)
    {
      return NULL;
    }

  if(bgpstream_community_set_copy(dst->communities, src->communities) != 0)
    {
      return NULL;
    }

  return dst;
}


int bgpstream_elem_type_snprintf(char *buf, size_t len,
                                 bgpstream_elem_type_t type)
{
  /* ensure we have enough bytes to write our single character */
  if(len == 0) {
    return 1;
  } else if(len == 1) {
    buf[0] = '\0';
    return 1;
  }

  switch(type)
    {
    case BGPSTREAM_ELEM_TYPE_RIB:
      buf[0] = 'R';
      break;

    case BGPSTREAM_ELEM_TYPE_ANNOUNCEMENT:
      buf[0] = 'A';
      break;

    case BGPSTREAM_ELEM_TYPE_WITHDRAWAL:
      buf[0] = 'W';
      break;

    case BGPSTREAM_ELEM_TYPE_PEERSTATE:
      buf[0] = 'S';
      break;

    default:
      buf[0] = '\0';
      break;
    }

  buf[1] = '\0';
  return 1;
}

int bgpstream_elem_peerstate_snprintf(char *buf, size_t len,
                                      bgpstream_elem_peerstate_t state)
{
  size_t written = 0;

  switch(state)
    {
    case BGPSTREAM_ELEM_PEERSTATE_IDLE:
      strncpy(buf, "IDLE", len);
      written = strlen("IDLE");
      break;

    case BGPSTREAM_ELEM_PEERSTATE_CONNECT:
      strncpy(buf, "CONNECT", len);
      written = strlen("CONNECT");
      break;

    case BGPSTREAM_ELEM_PEERSTATE_ACTIVE:
      strncpy(buf, "ACTIVE", len);
      written = strlen("ACTIVE");
      break;

    case BGPSTREAM_ELEM_PEERSTATE_OPENSENT:
      strncpy(buf, "OPENSENT", len);
      written = strlen("OPENSENT");
      break;

    case BGPSTREAM_ELEM_PEERSTATE_OPENCONFIRM:
      strncpy(buf, "OPENCONFIRM", len);
      written = strlen("OPENCONFIRM");
      break;

    case BGPSTREAM_ELEM_PEERSTATE_ESTABLISHED:
      strncpy(buf, "ESTABLISHED", len);
      written = strlen("ESTABLISHED");
      break;

    case BGPSTREAM_ELEM_PEERSTATE_CLEARING:
      strncpy(buf, "CLEARING", len);
      written = strlen("CLEARING");
      break;

    case BGPSTREAM_ELEM_PEERSTATE_DELETED:
      strncpy(buf, "DELETED", len);
      written = strlen("DELETED");
      break;

    default:
      if(len > 0) {
        buf[0] = '\0';
      }
      break;
    }

  /* we promise to always nul-terminate */
  if(written > len) {
    buf[len-1] = '\0';
  }

  return written;
}

#define B_REMAIN (len-written)
#define B_FULL   (written >= len)
#define ADD_PIPE                                \
  do {                                          \
  if(B_REMAIN > 1)                              \
    {                                           \
      *buf_p = '|';                             \
      buf_p++;                                  \
      *buf_p = '\0';                            \
      written++;                                \
    }                                           \
  else                                          \
    {                                           \
      return NULL;                              \
    }                                           \
  } while(0)

#define SEEK_STR_END                            \
  do {                                          \
    while(*buf_p != '\0')                       \
      {                                         \
        written++;                              \
        buf_p++;                                \
      }                                         \
 } while(0)

char *bgpstream_elem_custom_snprintf(char *buf, size_t len,
                                     bgpstream_elem_t const *elem, int print_type)
{
  assert(elem);

  size_t written = 0; /* < how many bytes we wanted to write */
  size_t c = 0; /* < how many chars were written */
  char *buf_p = buf;

  bgpstream_as_path_seg_t *seg;

  /* common fields */

  /* [message_type|]peer_asn|peer_ip| */

  if(print_type)
    {
      /* MESSAGE TYPE */
      c = bgpstream_elem_type_snprintf(buf_p, B_REMAIN, elem->type);
      written += c;
      buf_p += c;

      if(B_FULL)
        return NULL;

      ADD_PIPE;
    }

  /* PEER ASN */
  c = snprintf(buf_p, B_REMAIN, "%"PRIu32, elem->peer_asnumber);
  written += c;
  buf_p += c;
  ADD_PIPE;

  /* PEER IP */
  if(bgpstream_addr_ntop(buf_p, B_REMAIN, &elem->peer_address) == NULL)
    return NULL;
  SEEK_STR_END;
  ADD_PIPE;

  if(B_FULL)
    return NULL;

  /* conditional fields */
  switch(elem->type)
    {
    case BGPSTREAM_ELEM_TYPE_RIB:
    case BGPSTREAM_ELEM_TYPE_ANNOUNCEMENT:

      /* PREFIX */
      if(bgpstream_pfx_snprintf(buf_p, B_REMAIN,
                                (bgpstream_pfx_t*)&(elem->prefix)) == NULL)
        {
          return NULL;
        }
      SEEK_STR_END;
      ADD_PIPE;

      /* NEXT HOP */
      if(bgpstream_addr_ntop(buf_p, B_REMAIN, &elem->nexthop) == NULL)
        {
          return NULL;
        }
      SEEK_STR_END;
      ADD_PIPE;

      /* AS PATH */
      c = bgpstream_as_path_snprintf(buf_p, B_REMAIN, elem->aspath);
      written += c;
      buf_p += c;

      if(B_FULL)
        return NULL;

      ADD_PIPE;

      /* ORIGIN AS */
      if((seg = bgpstream_as_path_get_origin_seg(elem->aspath)) != NULL)
        {
          c = bgpstream_as_path_seg_snprintf(buf_p, B_REMAIN, seg);
          written += c;
          buf_p += c;
        }

      ADD_PIPE;

      /* COMMUNITIES */
      c = bgpstream_community_set_snprintf(buf_p, B_REMAIN, elem->communities);
      written += c;
      buf_p += c;

      if(B_FULL)
        return NULL;

      ADD_PIPE;

      /* OLD STATE (empty) */
      ADD_PIPE;

      /* NEW STATE (empty) */
      if(B_FULL)
        return NULL;

      /* RPKI Validation */
      char buf_rpki[1024];
      c = bgpstream_elem_get_rpki_validation_result_snprintf(buf_rpki, sizeof(buf_rpki), elem);
      strcat(buf, buf_rpki);
      written += c;
      buf_p += c;
      /* END OF LINE */
      break;

    case BGPSTREAM_ELEM_TYPE_WITHDRAWAL:

      /* PREFIX */
      if(bgpstream_pfx_snprintf(buf_p, B_REMAIN,
                                (bgpstream_pfx_t*)&(elem->prefix)) == NULL)
        {
          return NULL;
        }
      SEEK_STR_END;
      ADD_PIPE;
      /* NEXT HOP (empty) */
      ADD_PIPE;
      /* AS PATH (empty) */
      ADD_PIPE;
      /* ORIGIN AS (empty) */
      ADD_PIPE;
      /* COMMUNITIES (empty) */
      ADD_PIPE;
      /* OLD STATE (empty) */
      ADD_PIPE;
      /* NEW STATE (empty) */
      if(B_FULL)
        return NULL;
      /* END OF LINE */
      break;

    case BGPSTREAM_ELEM_TYPE_PEERSTATE:

      /* PREFIX (empty) */
      ADD_PIPE;
      /* NEXT HOP (empty) */
      ADD_PIPE;
      /* AS PATH (empty) */
      ADD_PIPE;
      /* ORIGIN AS (empty) */
      ADD_PIPE;
      /* COMMUNITIES (empty) */
      ADD_PIPE;

      /* OLD STATE */
      c = bgpstream_elem_peerstate_snprintf(buf_p, B_REMAIN,
                                            elem->old_state);
      written += c;
      buf_p += c;

      if(B_FULL)
        return NULL;

      ADD_PIPE;

      /* NEW STATE (empty) */
      c = bgpstream_elem_peerstate_snprintf(buf_p, B_REMAIN, elem->new_state);
      written += c;
      buf_p += c;

      if(B_FULL)
        return NULL;
      /* END OF LINE */
      break;

    default:
      fprintf(stderr, "Error during elem processing\n");
      return NULL;
    }

  return buf;
}

char *bgpstream_elem_snprintf(char *buf, size_t len,
                              bgpstream_elem_t const *elem)
{
  return bgpstream_elem_custom_snprintf(buf, len, elem, 1);
}

int bgpstream_elem_get_rpki_validation_result_snprintf(char *buf, size_t len, bgpstream_elem_t const *elem)
{
  char result_output[1024];

  if(elem->annotations.rpki_validation_status != -1){
    snprintf(result_output, sizeof(result_output), "%i;", elem->annotations.rpki_validation_status);
    for (int i = 0; i < elem->annotations.rpki_validation_result.asn_used; i++){
      char asn[1024];
      snprintf(asn, sizeof(asn), "%"PRIu32"-", elem->annotations.rpki_validation_result.asn_pfx[i].asn);
      strcat(result_output, asn);
      for (int j = 0; j < elem->annotations.rpki_validation_result.asn_pfx[i].pfx_used; j++){
          char valid_prefix[INET6_ADDRSTRLEN]; 
          bgpstream_pfx_snprintf(valid_prefix, INET6_ADDRSTRLEN, elem->annotations.rpki_validation_result.asn_pfx[i].pfx[j]);
          strcat(result_output, valid_prefix);
          if(j != elem->annotations.rpki_validation_result.asn_pfx[i].pfx_used - 1){
            strcat(result_output, " ");
          }
      }

      if(i != elem->annotations.rpki_validation_result.asn_used - 1){
        strcat(result_output, ";");
      }
    }
  }
  else {
    snprintf(result_output, sizeof(result_output), "%i", elem->annotations.rpki_validation_status);
  }

  bgpstream_rpki_validation_result_free(&elem->annotations.rpki_validation_result);
  return snprintf(buf, len, "%s", result_output);

}

void bgpstream_elem_get_rpki_validation_result(bgpstream_elem_t *elem)
{
  if(elem->annotations.rpki_validation_status == 0)
  {
    char prefix[INET6_ADDRSTRLEN];
    bgpstream_pfx_t *addr_pfx;

    switch(elem->prefix.address.version)
    {
      case BGPSTREAM_ADDR_VERSION_IPV4:
        addr_pfx = (bgpstream_pfx_t*)&(elem->prefix);
        bgpstream_addr_ntop(prefix, INET_ADDRSTRLEN, &(addr_pfx->address));
        break;

      case BGPSTREAM_ADDR_VERSION_IPV6:
        addr_pfx = (bgpstream_pfx_t*)&(elem->prefix);
        bgpstream_addr_ntop(prefix, INET6_ADDRSTRLEN, &(addr_pfx->address));
        break;

      default:
        addr_pfx = NULL;
        break;
    }

    if(addr_pfx != NULL)
    {
      struct rtr_mgr_config *cfg_tr = bgpstream_get_rtr_config();
      
      uint32_t origin_asn = 0;
      bgpstream_as_path_seg_t *origin_seg = bgpstream_as_path_get_origin_seg(elem->aspath);
      if (origin_seg != NULL && origin_seg->type == BGPSTREAM_AS_PATH_SEG_ASN) {
        origin_asn = ((bgpstream_as_path_seg_asn_t*)origin_seg)->asn;
      }

      struct reasoned_result res_reasoned = bgpstream_rtr_validate_reason(cfg_tr, origin_asn, prefix, elem->prefix.mask_len);
      elem->annotations.rpki_validation_status = pfxv2int(res_reasoned.result);

      if(elem->annotations.rpki_validation_status != -1){
          bgpstream_rpki_validation_result_init(&elem->annotations.rpki_validation_result, 2);       
          char valid_prefix[INET6_ADDRSTRLEN];

          for(int i = 0; i < res_reasoned.reason_len; i++){
            bgpstream_rpki_validation_result_insert_asn(&elem->annotations.rpki_validation_result, res_reasoned.reason[i].asn); 
            lrtr_ip_addr_to_str(&(res_reasoned.reason[i].prefix), prefix, sizeof(prefix)); 
            snprintf(valid_prefix, sizeof(valid_prefix), "%s/%i", prefix, res_reasoned.reason[i].max_len);
            bgpstream_pfx_storage_t pfx;
            bgpstream_str2pfx(valid_prefix,&pfx);
            bgpstream_rpki_validation_result_insert_pfx(&elem->annotations.rpki_validation_result, res_reasoned.reason[i].asn,
                                      (bgpstream_pfx_t*)&pfx);
          }
      }
    }
  }
}
