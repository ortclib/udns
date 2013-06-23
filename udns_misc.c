/* $Id: udns_misc.c,v 1.4 2004/06/30 13:41:57 mjt Exp $
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
  if (err >= 0) return "successeful completion";
  switch(err) {
  case DNS_E_TEMPFAIL:	return "temporary failure in name resolution";
  case DNS_E_PROTOCOL:	return "protocol error";
  case DNS_E_NXDOMAIN:	return "domain name does not exists";
  case DNS_E_NODATA:	return "valid domain but no data of requested type";
  case DNS_E_NOMEM:	return "out of memory";
  case DNS_E_BADQUERY:	return "malformed query";
  default:		return "unknown error";
  }
}
