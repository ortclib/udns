/* $Id: udns_rr_a.c,v 1.11 2005/04/05 22:51:32 mjt Exp $
   parse/query A/AAAA IN records

   Copyright (C) 2005  Michael Tokarev <mjt@corpit.ru>
   This file is part of UDNS library, an async DNS stub resolver.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with this library, in file named COPYING.LGPL; if not,
   write to the Free Software Foundation, Inc., 59 Temple Place,
   Suite 330, Boston, MA  02111-1307  USA

 */

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "udns.h"

/* here, we use common routine to parse both IPv4 and IPv6 addresses.
 */

/* this structure should match dns_rr_a[46] */
struct dns_rr_a {
  dns_rr_common(dnsa);
  unsigned char *dnsa_addr;
};

static int
dns_parse_a(int qtyp, unsigned size,
            const unsigned char *pkt, const unsigned char *pkte,
            void **result) {
  struct dns_rr_a *ret;
  struct dns_parse p;
  struct dns_rr rr;
  int r;

  /* first, validate and count number of addresses */
  dns_initparse(&p, DNS_C_IN, qtyp, pkt, pkte);
  while((r = dns_nextrr(&p, &rr)) > 0)
    if (rr.dnsrr_dsz != size)
      return DNS_E_PROTOCOL;
  if (r < 0)
    return DNS_E_PROTOCOL;
  else if (!p.dnsp_nrr)
    return DNS_E_NODATA;

  ret = malloc(sizeof(*ret) + size * p.dnsp_nrr + dns_stdrr_size(&p));
  if (!ret)
    return DNS_E_NOMEM;

  ret->dnsa_nrr = p.dnsp_nrr;
  ret->dnsa_addr = (unsigned char*)(ret+1);

  /* copy the RRs */
  for (dns_rewind(&p), r = 0; dns_nextrr(&p, &rr); ++r)
    memcpy(ret->dnsa_addr + size * r, rr.dnsrr_dptr, size);

  dns_stdrr_finish((struct dns_rr_null *)ret,
                   (char *)(ret->dnsa_addr + size * p.dnsp_nrr), &p);
  *result = ret;
  return 0;
}

int
dns_parse_a4(const unsigned char *pkt, const unsigned char *pkte, void **ret) {
  assert(sizeof(struct in_addr) == 4);
  return dns_parse_a(DNS_T_A, 4, pkt, pkte, ret);
}

struct dns_query *
dns_submit_a4(struct dns_ctx *ctx, const char *name, int flags,
              dns_query_a4_fn *cbck, void *data, time_t now) {
  return
    dns_submit_p(ctx, name, DNS_C_IN, DNS_T_A, flags,
                 dns_parse_a4, (dns_query_fn*)cbck, data, now);
}

struct dns_rr_a4 *
dns_resolve_a4(struct dns_ctx *ctx, const char *name, int flags) {
  return (struct dns_rr_a4 *)
    dns_resolve_p(ctx, name, DNS_C_IN, DNS_T_A, flags, dns_parse_a4);
}

int
dns_parse_a6(const unsigned char *pkt, const unsigned char *pkte, void **ret) {
  assert(sizeof(struct in6_addr) == 16);
  return dns_parse_a(DNS_T_AAAA, 16, pkt, pkte, ret);
}

struct dns_query *
dns_submit_a6(struct dns_ctx *ctx, const char *name, int flags,
              dns_query_a6_fn *cbck, void *data, time_t now) {
  return
    dns_submit_p(ctx, name, DNS_C_IN, DNS_T_AAAA, flags,
                 dns_parse_a6, (dns_query_fn*)cbck, data, now);
}

struct dns_rr_a6 *
dns_resolve_a6(struct dns_ctx *ctx, const char *name, int flags) {
  return (struct dns_rr_a6 *)
    dns_resolve_p(ctx, name, DNS_C_IN, DNS_T_AAAA, flags, dns_parse_a6);
}
