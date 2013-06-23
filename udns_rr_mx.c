/* $Id: udns_rr_mx.c,v 1.9 2004/06/30 20:44:48 mjt Exp $
 * parse/query MX IN records
 */

#include <string.h>
#include "udns.h"

int
dns_parse_mx(const unsigned char *pkt, const unsigned char *pkte,
             void **result) {
  struct dns_rr_mx *ret = NULL;
  struct dns_parse p;
  struct dns_rr rr;
  const unsigned char *cur;
  int r, l, c;
  char *sp;
  unsigned char mx[DNS_MAXDN];

  /* first, validate the answer and count size of the result */
  l = c = 0;
  for(r = dns_firstrr(&p, &rr, DNS_C_IN, DNS_T_MX, pkt, pkte);
      r > 0; r = dns_nextrr(&p, &rr)) {
    cur = rr.dnsrr_dptr + 2;
    r = dns_getdn(pkt, &cur, rr.dnsrr_dend, mx, sizeof(mx));
    if (r <= 0 || cur != rr.dnsrr_dend)
      return DNS_E_PROTOCOL;
    l += dns_dntop_size(mx);
    ++c;
  }
  if (r < 0)
    return DNS_E_PROTOCOL;
  if (!c)
    return DNS_E_NODATA;

  /* next, allocate and set up result */
  l += dns_stdrr_size(&p);
  ret = malloc(sizeof(*ret) + sizeof(struct dns_mx) * c + l);
  if (!ret)
    return DNS_E_NOMEM;
  ret->dnsmx_nrr = c;
  ret->dnsmx_mx = (struct dns_mx *)(ret+1);

  /* and 3rd, fill in result, finally */
  sp = (char*)(ret->dnsmx_mx + c);
  c = 0;
  for(r = dns_firstrr(&p, &rr, DNS_C_IN, DNS_T_MX, pkt, pkte);
      r > 0; r = dns_nextrr(&p, &rr)) {
    ret->dnsmx_mx[c].name = sp;
    cur = rr.dnsrr_dptr;
    ret->dnsmx_mx[c].priority = dns_get16(cur);
    cur += 2;
    dns_getdn(pkt, &cur, pkte, mx, sizeof(mx));
    sp += dns_dntop(mx, sp, DNS_MAXNAME);
    ++c;
  }
  dns_stdrr_finish((struct dns_rr_null *)ret, sp, &p);
  *result = ret;
  return 0;
}

struct dns_query *
dns_submit_mx(struct dns_ctx *ctx, const char *name, int flags,
              dns_query_mx_fn *cbck, void *data, time_t now) {
  return
    dns_submit_p(ctx, name, DNS_C_IN, DNS_T_MX, flags,
                 dns_parse_mx, (dns_query_fn *)cbck, data, now);
}

struct dns_rr_mx *
dns_resolve_mx(struct dns_ctx *ctx, const char *name, int flags) {
  return (struct dns_rr_mx *)
    dns_resolve_p(ctx, name, DNS_C_IN, DNS_T_MX, flags, dns_parse_mx);
}
