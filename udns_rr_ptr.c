/* $Id: udns_rr_ptr.c,v 1.9 2004/06/30 20:44:48 mjt Exp $
 * parse/query PTR records
 */

#include <stdlib.h>
#include "udns.h"

int
dns_parse_ptr(const unsigned char *pkt, const unsigned char *pkte,
              void **result) {
  struct dns_rr_ptr *ret = NULL;
  struct dns_parse p;
  struct dns_rr rr;
  const unsigned char *cur;
  int r, l, c;
  char *sp;
  unsigned char ptr[DNS_MAXDN];

  /* first, validate the answer and count size of the result */
  l = c = 0;
  for(r = dns_firstrr(&p, &rr, DNS_C_IN, DNS_T_PTR, pkt, pkte);
      r > 0; r = dns_nextrr(&p, &rr)) {
    cur = rr.dnsrr_dptr;
    r = dns_getdn(pkt, &cur, rr.dnsrr_dend, ptr, sizeof(ptr));
    if (r <= 0 || cur != rr.dnsrr_dend)
      return DNS_E_PROTOCOL;
    l += dns_dntop_size(ptr);
    ++c;
  }
  if (r < 0)
    return DNS_E_PROTOCOL;
  if (!c)
    return DNS_E_NODATA;

  /* next, allocate and set up result */
  ret = malloc(sizeof(*ret) + sizeof(char **) * c + l + dns_stdrr_size(&p));
  if (!ret)
    return DNS_E_NOMEM;
  ret->dnsptr_nrr = c;
  ret->dnsptr_ptr = (char **)(ret+1);

  /* and 3rd, fill in result, finally */
  sp = (char*)(ret->dnsptr_ptr + c);
  c = 0;
  for(r = dns_firstrr(&p, &rr, DNS_C_IN, DNS_T_PTR, pkt, pkte);
      r > 0; r = dns_nextrr(&p, &rr)) {
    ret->dnsptr_ptr[c] = sp;
    cur = rr.dnsrr_dptr;
    dns_getdn(pkt, &cur, pkte, ptr, sizeof(ptr));
    sp += dns_dntop(ptr, sp, DNS_MAXNAME);
    ++c;
  }
  dns_stdrr_finish((struct dns_rr_null*)ret, sp, &p);
  *result = ret;
  return 0;
}

struct dns_query *
dns_submit_a4ptr(struct dns_ctx *ctx, const struct in_addr *addr,
                 dns_query_ptr_fn *cbck, void *data, time_t now) {
  unsigned char dn[DNS_A4RSIZE];
  dns_a4todn(addr, 0, dn, sizeof(dn));
  return
    dns_submit_dn(ctx, dn, DNS_C_IN, DNS_T_PTR, DNS_NOSRCH,
                  dns_parse_ptr, (dns_query_fn *)cbck, data, now);
}

struct dns_rr_ptr *
dns_resolve_a4ptr(struct dns_ctx *ctx, const struct in_addr *addr) {
  return (struct dns_rr_ptr *)
    dns_resolve(ctx, dns_submit_a4ptr(ctx, addr, NULL, NULL, 0));
}

struct dns_query *
dns_submit_a6ptr(struct dns_ctx *ctx, const struct in6_addr *addr,
                 dns_query_ptr_fn *cbck, void *data, time_t now) {
  unsigned char dn[DNS_A6RSIZE];
  dns_a6todn(addr, 0, dn, sizeof(dn));
  return
    dns_submit_dn(ctx, dn, DNS_C_IN, DNS_T_PTR, DNS_NOSRCH,
                  dns_parse_ptr, (dns_query_fn *)cbck, data, now);
}

struct dns_rr_ptr *
dns_resolve_a6ptr(struct dns_ctx *ctx, const struct in6_addr *addr) {
  return (struct dns_rr_ptr *)
    dns_resolve(ctx, dns_submit_a6ptr(ctx, addr, NULL, NULL, 0));
}
