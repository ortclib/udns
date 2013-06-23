/* $Id: udns_misc.c,v 1.3 2004/06/29 07:46:39 mjt Exp $
 */

#include "udns.h"

int dns_findname(const struct dns_nameval *nv, const char *name) {
  register const char *a, *b;
  for(; nv->name; ++nv)
    for(a = name, b = nv->name; ; ++a, ++b)
      if (DNS_DNUC(*a) != *b) break;
      else if (!*a) return nv->val;
  return -1;
}

const char *dns_strerror(int err) {
  if (err >= 0) return "Successeful completion";
  switch(err) {
  case DNS_E_TEMPFAIL:	return "Temporary failure in name resolution";
  case DNS_E_PROTOCOL:	return "Protocol error";
  case DNS_E_NXDOMAIN:	return "Domain name does not exists";
  case DNS_E_NODATA:	return "Valid domain but no data of requested type";
  case DNS_E_NOMEM:	return "Out of memory";
  case DNS_E_BADQUERY:	return "Malformed query";
  default:		return "Unknown error";
  }
}
