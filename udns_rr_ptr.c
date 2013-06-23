/* $Id: udns_rr_ptr.c,v 1.5 2004/06/29 07:46:39 mjt Exp $
 * parse/query PTR records
 */

#include <stdlib.h>
#include "udns.h"

int dns_parse_ptr(struct dns_query *q,
                 const unsigned char *pkt, const unsigned char *pkte) {
  struct dns_rr_ptr *ret = NULL;
  struct dns_parse p;
  struct dns_rr rr;
  const unsigned char *cur;
  int r, l, c;
  char *sp;
  unsigned ttl;
  unsigned char ptr[DNS_MAXDN];

  /* first, validate the answer and count size of the result */
  l = c = 0;
  ttl = 0xffffffffu;
  for(r = dns_firstrr(&p, &rr, q->dnsq_dn, DNS_C_IN, DNS_T_PTR, pkt, pkte);
      r > 0; r = dns_nextrr(&p, &rr)) {
    cur = rr.dnsrr_dptr;
    r = dns_getdn(pkt, &cur, rr.dnsrr_dend, ptr, sizeof(ptr));
    if (r <= 0 || cur != rr.dnsrr_dend)
      return DNS_E_PROTOCOL;
    l += dns_dntop_size(ptr);
    if (ttl > rr.dnsrr_ttl) ttl = rr.dnsrr_ttl;
    ++c;
  }
  if (r < 0)
    return DNS_E_PROTOCOL;
  if (!c)
    return DNS_E_NODATA;

  /* next, allocate and set up result */
  l += dns_dntop_size(rr.dnsrr_dn);
  ret = malloc(sizeof(*ret) + sizeof(char **) * c + l);
  if (!ret)
    return DNS_E_NOMEM;
  ret->dnsptr_nptr = c;
  ret->dnsptr_ttl = ttl;
  ret->dnsptr_ptr = (char **)(ret+1);

  /* and 3rd, fill in result, finally */
  sp = (char*)(ret->dnsptr_ptr + c);
  c = 0;
  for(r = dns_firstrr(&p, &rr, q->dnsq_dn, DNS_C_IN, DNS_T_PTR, pkt, pkte);
      r > 0; r = dns_nextrr(&p, &rr)) {
    ret->dnsptr_ptr[c] = sp;
    cur = rr.dnsrr_dptr;
    dns_getdn(pkt, &cur, pkte, ptr, sizeof(ptr));
    sp += dns_dntop(ptr, sp, DNS_MAXNAME);
    ++c;
  }
  ret->dnsptr_cname = sp;
  dns_dntop(rr.dnsrr_dn, sp, DNS_MAXNAME);

  q->dnsq_result = ret;
  return 0;
}

int dns_submit_a4ptr(struct dns_ctx *ctx, struct dns_query *q,
                     const struct in_addr *addr,
                     dns_query_ptr_fn *cbck, time_t now) {
  dns_a4todn(addr, 0, q->dnsq_dn, sizeof(q->dnsq_dn));
  return
    dns_submit(ctx, q, DNS_C_IN, DNS_T_PTR, DNS_NOSRCH,
               (dns_query_fn *)cbck, dns_parse_ptr, now);
}

struct dns_rr_ptr *
dns_resolve_a4ptr(struct dns_ctx *ctx, const struct in_addr *addr,
                  int *statusp)
{
  unsigned char dn[DNS_A4RSIZE];
  dns_a4todn(addr, 0, dn, sizeof(dn));
  return (struct dns_rr_ptr *)
   dns_resolve_dn(ctx, dn, DNS_C_IN, DNS_T_PTR, DNS_NOSRCH, dns_parse_ptr,
                  statusp);
}

#ifdef AF_INET6
int dns_submit_a6ptr(struct dns_ctx *ctx, struct dns_query *q,
                     const struct in6_addr *addr,
                     dns_query_ptr_fn *cbck, time_t now) {
  dns_a6todn(addr, 0, q->dnsq_dn, sizeof(q->dnsq_dn));
  return
    dns_submit(ctx, q, DNS_C_IN, DNS_T_PTR, DNS_NOSRCH,
               (dns_query_fn *)cbck, dns_parse_ptr, now);
}

struct dns_rr_ptr *
dns_resolve_a6ptr(struct dns_ctx *ctx, const struct in6_addr *addr,
                  int *statusp)
{
  unsigned char dn[DNS_A6RSIZE];
  dns_a6todn(addr, 0, dn, sizeof(dn));
  return (struct dns_rr_ptr *)
   dns_resolve_dn(ctx, dn, DNS_C_IN, DNS_T_PTR, DNS_NOSRCH, dns_parse_ptr,
                  statusp);
}
#endif
