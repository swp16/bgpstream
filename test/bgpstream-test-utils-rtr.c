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
  int ipv4_len = 16;
  int ipv6_len = 46;
  struct rtr_mgr_config *cfg_tr = bgpstream_rtr_start_connection("rpki-validator.realmv6.org", "8282", NULL, NULL, NULL, NULL, NULL, NULL); 

  char ipv4_prefix[ipv4_len];
  strncpy( ipv4_prefix, "93.175.146.0\0", ipv4_len);
  uint32_t origin_asn = 12654;
  uint32_t mask_len = 24;
  struct reasoned_result res_reasoned = bgpstream_rtr_validate_reason(cfg_tr, origin_asn, ipv4_prefix, mask_len);
  fprintf(stderr, "%" PRIu32 " : %d", res_reasoned.result, (int)BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_VALID);
  CHECK("RTR: Compare valid IPv4 ROA with validator", res_reasoned.result == BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_VALID);

  char ipv6_prefix[ipv6_len];
  strncpy(ipv6_prefix, "2001:7fb:fd02::\0", ipv6_len);
  origin_asn = 12654;
  mask_len = 48;
  res_reasoned = bgpstream_rtr_validate_reason(cfg_tr, origin_asn, ipv6_prefix, mask_len);
  CHECK("RTR: Compare valid IPv6 ROA with validator", res_reasoned.result == BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_VALID);

  strncpy(ipv4_prefix, "93.175.147.0\0", ipv4_len);
  origin_asn = 196615;
  mask_len = 24;
  res_reasoned = bgpstream_rtr_validate_reason(cfg_tr, origin_asn, ipv4_prefix, mask_len);
  CHECK("RTR: Compare invalid IPv4 ROA with validator", res_reasoned.result == BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_INVALID);
 
  strncpy(ipv6_prefix, "2001:7fb:fd03::\0", ipv6_len);
  origin_asn = 196615;
  mask_len = 48;
  res_reasoned = bgpstream_rtr_validate_reason(cfg_tr, origin_asn, ipv6_prefix, mask_len);
  CHECK("RTR: Compare invalid IPv6 ROA with validator", res_reasoned.result == BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_INVALID);

  strncpy(ipv4_prefix, "84.205.83.0\0", ipv4_len);
  origin_asn = 12345;
  mask_len = 24;
  res_reasoned = bgpstream_rtr_validate_reason(cfg_tr, origin_asn, ipv4_prefix, mask_len);
  CHECK("RTR: Compare none existend IPv4 ROA with validator", res_reasoned.result == BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_NOTFOUND);

  strncpy(ipv6_prefix, "2001:7fb:ff03::\0", ipv6_len);
  origin_asn = 12345;
  mask_len = 48;
  res_reasoned = bgpstream_rtr_validate_reason(cfg_tr, origin_asn, ipv6_prefix, mask_len);
  CHECK("RTR: Compare none existend IPv6 ROA with validator", res_reasoned.result == BGPSTREAM_ELEM_RPKI_VALIDATION_STATUS_NOTFOUND);

  free(res_reasoned.reason);
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
