/* $Id: udns_rr_a.c,v 1.4 2004/06/29 07:46:39 mjt Exp $
 * parse/query A/AAAA IN records
 */

#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "udns.h"

/* here, we use common routine to parse both IPv4 and IPv6 addresses.
 */

/* this structure should match dns_rr_a[46] */
struct dns_rr_a {
  char *dnsa_cname;
  unsigned dnsa_ttl;
  int dnsa_naddr;
  unsigned char *dnsa_addr;
};

static int
dns_parse_a(struct dns_query *q, int qtyp,
            const unsigned char *pkt, const unsigned char *pkte) {
  struct dns_rr_a *ret;
  struct dns_parse p;
  struct dns_rr rr;
  int r, c;
  unsigned ttl;
  const unsigned size = qtyp == DNS_T_A ? 4 : 16;

  /* first, validate and count number of addresses */
  c = 0;
  ttl = 0xffffffffu;
  for (r = dns_firstrr(&p, &rr, q->dnsq_dn, DNS_C_IN, qtyp, pkt, pkte);
       r > 0; r = dns_nextrr(&p, &rr)) {
    if (rr.dnsrr_dsz != size)
      return DNS_E_PROTOCOL;
    if (ttl > rr.dnsrr_ttl) ttl = rr.dnsrr_ttl;
    ++c;
  }
  if (r < 0)
    return DNS_E_PROTOCOL;
  else if (!c)
    return DNS_E_NODATA;

  ret = malloc(sizeof(*ret) + size * c + dns_dntop_size(rr.dnsrr_dn));
  if (!ret)
    return DNS_E_NOMEM;

  ret->dnsa_naddr = c;
  ret->dnsa_ttl = ttl;
  ret->dnsa_addr = (unsigned char*)(ret+1);

  /* copy the RRs */
  c = 0;
  for (r = dns_firstrr(&p, &rr, q->dnsq_dn, DNS_C_IN, DNS_T_A, pkt, pkte);
       r > 0; r = dns_nextrr(&p, &rr))
    memcpy(ret->dnsa_addr + size * c++, rr.dnsrr_dptr, size);

  ret->dnsa_cname = (char*)(ret->dnsa_addr + size*c);
  dns_dntop(rr.dnsrr_dn, ret->dnsa_cname, DNS_MAXNAME);

  q->dnsq_result = ret;
  return 0;
}

int dns_parse_a4(struct dns_query *q,
                 const unsigned char *pkt, const unsigned char *pkte) {
  assert(sizeof(struct in_addr) == 4);
  return dns_parse_a(q, DNS_T_A, pkt, pkte);
}

int dns_submit_a4(struct dns_ctx *ctx, struct dns_query *q,
                  const char *name, int flags,
                  dns_query_a4_fn *cbck, time_t now) {
  return
    dns_submit_p(ctx, q, name, DNS_C_IN, DNS_T_A, flags,
                 (dns_query_fn*)cbck, dns_parse_a4, now);
}

struct dns_rr_a4 *
dns_resolve_a4(struct dns_ctx *ctx, const char *name, int flags, int *statusp) {
  return (struct dns_rr_a4 *)
    dns_resolve_p(ctx, name, DNS_C_IN, DNS_T_A, flags, dns_parse_a4, statusp);
}

int dns_parse_a6(struct dns_query *q,
                 const unsigned char *pkt, const unsigned char *pkte) {
  assert(sizeof(struct in6_addr) == 16);
  return dns_parse_a(q, DNS_T_AAAA, pkt, pkte);
}

int dns_submit_a6(struct dns_ctx *ctx, struct dns_query *q,
                  const char *name, int flags,
                  dns_query_a6_fn *cbck, time_t now) {
  return
    dns_submit_p(ctx, q, name, DNS_C_IN, DNS_T_AAAA, flags,
                 (dns_query_fn*)cbck, dns_parse_a6, now);
}

struct dns_rr_a6 *
dns_resolve_a6(struct dns_ctx *ctx, const char *name, int flags, int *statusp) {
  return (struct dns_rr_a6 *)
    dns_resolve_p(ctx, name, DNS_C_IN, DNS_T_AAAA, flags, dns_parse_a6,
                  statusp);
}
