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

#ifndef __BGPSTREAM_ELEM_H
#define __BGPSTREAM_ELEM_H

#include "bgpstream_utils.h"
#include "bgpstream_utils_as_path.h"

/** @file
 *
 * @brief Header file that exposes the public interface of a bgpstream elem.
 *
 * @author Chiara Orsini
 *
 */

/**
 * @name Public Opaque Data Structures
 *
 * @{ */

/** @} */

/**
 * @name Public Enums
 *
 * @{ */

/** Peer state encodes the state of the peer:
 *  - 0 - the state of the peer is unknown
 *  - [1-6] - the state encoded is one of the six FSM
 *            states described in RFC1771
 *  - [7-8] - inactive state in which all routes are cleared,
 *            more infor in quagga documentation http://goo.gl/NS9mSv
 */
typedef enum {

  /** Peer state unknown */
  BGPSTREAM_ELEM_PEERSTATE_UNKNOWN     = 0,

  /** Peer state idle */
  BGPSTREAM_ELEM_PEERSTATE_IDLE        = 1,

  /** Peer state connect */
  BGPSTREAM_ELEM_PEERSTATE_CONNECT     = 2,

  /** Peer state active */
  BGPSTREAM_ELEM_PEERSTATE_ACTIVE      = 3,

  /** Peer state open-sent */
  BGPSTREAM_ELEM_PEERSTATE_OPENSENT    = 4,

  /** Peer state open-confirm */
  BGPSTREAM_ELEM_PEERSTATE_OPENCONFIRM = 5,

  /** Peer state established */
  BGPSTREAM_ELEM_PEERSTATE_ESTABLISHED = 6,

  /** Peer state clearing */
  BGPSTREAM_ELEM_PEERSTATE_CLEARING    = 7,

  /** Peer state clearing */
  BGPSTREAM_ELEM_PEERSTATE_DELETED     = 8,

} bgpstream_elem_peerstate_t;


/** Elem types */
typedef enum {

  /** Unknown */
  BGPSTREAM_ELEM_TYPE_UNKNOWN      = 0,

  /** RIB Entry */
  BGPSTREAM_ELEM_TYPE_RIB          = 1,

  /** Announcement */
  BGPSTREAM_ELEM_TYPE_ANNOUNCEMENT = 2,

  /** Withdrawal */
  BGPSTREAM_ELEM_TYPE_WITHDRAWAL   = 3,

  /** Peer state change */
  BGPSTREAM_ELEM_TYPE_PEERSTATE    = 4,

} bgpstream_elem_type_t;

/** @} */

/**
 * @name Public Data Structures
 *
 * @{ */

/** A BGP Stream Elem object for Annotations */
typedef struct struct_bgpstream_elem_annotations_t{

  /** RPKI validation status
   *
   * RPKI validation status for a given prefix
   */
  char *rpki_validation_status;

  /** RPKI validation result
   *
   * RPKI validation result (all valid ASNs) for a given prefix
   */
  bgpstream_rpki_validation_result_t rpki_validation_result;

} bgpstream_elem_annotations_t;

/** A BGP Stream Elem object */
typedef struct struct_bgpstream_elem_t {

  /** Type */
  bgpstream_elem_type_t type;

  /** Epoch time when this elem was generated by the collector */
  uint32_t timestamp;

  /** Peer IP address */
  bgpstream_addr_storage_t peer_address;

  /** Peer AS number */
  uint32_t peer_asnumber;

  /* Type-dependent fields */

  /** IP prefix
   *
   * Available only for RIB, Announcement and Withdrawal elem types
   */
  bgpstream_pfx_storage_t prefix;

  /** Next hop
   *
   * Available only for RIB and Announcement elem types
   */
  bgpstream_addr_storage_t nexthop;

  /** AS path
   *
   * Available only for RIB and Announcement elem types
   */
  bgpstream_as_path_t *aspath;

  /** Communities
   *
   * Available only for RIB and Announcement elem types
   */
  bgpstream_community_set_t *communities;

  /** Old peer state
   *
   * Available only for the Peer-state elem type
   */
  bgpstream_elem_peerstate_t old_state;

  /** New peer state
   *
   * Available only for the Peer-state elem type
   */
  bgpstream_elem_peerstate_t new_state;

  /** Annotations
   *
   * All additional annotations
   */
  bgpstream_elem_annotations_t annotations;

} bgpstream_elem_t;


/** @} */

/**
 * @name Public API Functions
 *
 * @{ */

/** Create a new BGP Stream Elem instance
 *
 * @return a pointer to an Elem instance if successful, NULL otherwise
 */
bgpstream_elem_t *bgpstream_elem_create();

/** Destroy the given BGP Stream Elem instance
 *
 * @param elem        pointer to a BGP Stream Elem instance to destroy
 */
void bgpstream_elem_destroy(bgpstream_elem_t *elem);

/** Clear the given BGP Stream Elem instance
 *
 * @param elem        pointer to a BGP Stream Elem instance to clear
 */
void bgpstream_elem_clear(bgpstream_elem_t *elem);

/** Copy the given BGP Stream Elem to the given destination
 *
 * @param dst           pointer to an elem to copy into
 * @param src           pointer to an elem to copy from
 * @return pointer to dst if successful, NULL otherwise
 *
 * The `dst` elem must have been created using bgpstream_elem_create, or if
 * being re-used, cleared using bgpstream_elem_clear before calling this
 * function.
 */
bgpstream_elem_t *bgpstream_elem_copy(bgpstream_elem_t *dst,
                                      bgpstream_elem_t *src);

/** Write the string representation of the elem type into the provided buffer
 *
 * @param buf           pointer to a char array
 * @param len           length of the char array
 * @param type          BGP Stream Elem type to convert to string
 * @return the number of characters that would have been written if len was
 * unlimited
 */
int bgpstream_elem_type_snprintf(char *buf, size_t len,
                                 bgpstream_elem_type_t type);

/** Write the string representation of the elem peerstate into the provided
 *  buffer
 *
 * @param buf           pointer to a char array
 * @param len           length of the char array
 * @param state         BGP Stream Elem peerstate to convert to string
 * @return the number of characters that would have been written if len was
 * unlimited
 */
int bgpstream_elem_peerstate_snprintf(char *buf, size_t len,
                                      bgpstream_elem_peerstate_t state);

/** Write the string representation of the elem into the provided buffer
 *
 * @param buf           pointer to a char array
 * @param len           length of the char array
 * @param elem          pointer to a BGP Stream Elem to convert to string
 * @return pointer to the start of the buffer if successful, NULL otherwise
 */
char *bgpstream_elem_snprintf(char *buf, size_t len,
                              const bgpstream_elem_t *elem);

/** Insert a new prefix to the ASN-prefix dynamic array
 *
 * @param elem       the elem which will be validated
 */
void bgpstream_elem_get_rpki_validation_result(bgpstream_elem_t *elem);

/** @} */

#endif /* __BGPSTREAM_ELEM_H */
