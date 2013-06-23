/* $Id: udns_dntosp.c,v 1.3 2004/06/29 07:46:39 mjt Exp $
 * dns_dntosp() = convert DN to asciiz string using static buffer
 */

#include "udns.h"

static char name[DNS_MAXNAME];

const char *dns_dntosp(const unsigned char *dn) {
  return dns_dntop(dn, name, sizeof(name)) > 0 ? name : 0;
}
