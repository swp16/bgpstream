#include "bgpstream_test.h"

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdbool.h>
#include <string.h>

int test_rtr_validation()
{
  struct rtr_mgr_config *cfg_tr = bgpstream_rtr_start_connection("rpki-validator.realmv6.org", "8282", NULL, NULL, NULL, NULL, NULL, NULL);

  struct pfx_record pfx_v4;
  char ipv4_address[16];
  pfx_v4.min_len = 24;
  pfx_v4.max_len = 24;
  pfx_v4.socket = NULL;
  pfx_v4.asn = 12654;
  strcpy( ipv4_address, "93.175.146.0\0");
  lrtr_ip_str_to_addr( ipv4_address, &pfx_v4.prefix);
  pfx_table_remove(cfg_tr->groups[0].sockets[0]->pfx_table, &pfx_v4);
  
  struct pfx_record pfx_v6;
  char ipv6_address[46];
  pfx_v6.min_len = 48;
  pfx_v6.max_len = 48;
  pfx_v6.socket = NULL;
  pfx_v6.asn = 12654;
  strcpy( ipv6_address, "2001:7fb:fd02::\0");
  lrtr_ip_str_to_addr( ipv6_address, &pfx_v6.prefix);
  pfx_table_remove(cfg_tr->groups[0].sockets[0]->pfx_table, &pfx_v6);
  
  struct reasoned_result res; 
  
  CHECK("RTR: Adds a valid pfx_record to pfx_table", pfx_table_add(cfg_tr->groups[0].sockets[0]->pfx_table, &pfx_v4) == PFX_SUCCESS);
  res = bgpstream_rtr_validate_reason( cfg_tr, pfx_v4.asn, ipv4_address, pfx_v4.max_len);
  CHECK("RTR: Compare valid IPv4 ROA with validation result", res.result == BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_VALID);

  CHECK("RTR: Adds a valid pfx_record to pfx_table", pfx_table_add(cfg_tr->groups[0].sockets[0]->pfx_table, &pfx_v6) == PFX_SUCCESS);
  res = bgpstream_rtr_validate_reason( cfg_tr, pfx_v6.asn, ipv6_address, pfx_v6.max_len);
  CHECK("RTR: Compare valid IPv6 ROA with validation result", res.result == BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_VALID);
  
  res = bgpstream_rtr_validate_reason( cfg_tr, 196615, ipv4_address, pfx_v4.max_len);
  CHECK("RTR: Compare invalid IPv4 ROA with validation result", res.result == BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_INVALID);

  res = bgpstream_rtr_validate_reason( cfg_tr, 196615, ipv6_address, pfx_v6.max_len);
  CHECK("RTR: Compare invalid IPv6 ROA with validation result", res.result == BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_INVALID);
  
  pfx_v4.asn = 12345;
  lrtr_ip_str_to_addr( "84.205.83.0\0", &pfx_v4.prefix);
  pfx_table_remove(cfg_tr->groups[0].sockets[0]->pfx_table, &pfx_v4);
  res = bgpstream_rtr_validate_reason(cfg_tr, 12345, "84.205.83.0\0", pfx_v4.max_len);
  CHECK("RTR: Compare none existend IPv4 ROA with validation result", res.result == BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_NOTFOUND);

  pfx_v6.asn = 12345;
  lrtr_ip_str_to_addr( "2001:7fb:ff03::\0", &pfx_v6.prefix);
  pfx_table_remove(cfg_tr->groups[0].sockets[0]->pfx_table, &pfx_v6);
  res = bgpstream_rtr_validate_reason(cfg_tr, 12345, "2001:7fb:ff03::\0", pfx_v6.max_len);
  CHECK("RTR: Compare none existend IPv6 ROA with validation result", res.result == BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_NOTFOUND);

  free(res.reason);
  bgpstream_rtr_close_connection( cfg_tr);

  return 0;
}

int main()
{
  #if defined(FOUND_RTR)
  CHECK_SECTION("RTRLIB", test_rtr_validation() == 0);
  #endif
  return 0;
}

