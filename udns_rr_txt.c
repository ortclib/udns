/* $Id: udns_rr_txt.c,v 1.4 2004/06/29 07:46:39 mjt Exp $
 * parse/query TXT records
 */

#include <string.h>
#include <stdlib.h>
#include "udns.h"

int dns_parse_txt(struct dns_query *q,
                  const unsigned char *pkt, const unsigned char *pkte) {
  struct dns_rr_txt *ret = NULL;
  struct dns_parse p;
  struct dns_rr rr;
  int r, l, c;
  unsigned char *sp;
  const unsigned char *cp, *ep;
  unsigned ttl;

  /* first, validate the answer and count size of the result */
  l = c = 0;
  ttl = 0xffffffffu;
  for(r = dns_firstrr(&p, &rr, q->dnsq_dn, 0, DNS_T_TXT, pkt, pkte);
      r > 0; r = dns_nextrr(&p, &rr)) {
    cp = rr.dnsrr_dptr; ep = rr.dnsrr_dend;
    while(cp < ep) {
      r = *cp++;
      if (cp + r > ep)
        return DNS_E_PROTOCOL;
      l += r;
      cp += r;
    }
    if (ttl > rr.dnsrr_ttl) ttl = rr.dnsrr_ttl;
    ++c;
  }
  if (r < 0)
    return DNS_E_PROTOCOL;
  if (!c)
    return DNS_E_NODATA;

  /* next, allocate and set up result */
  l += dns_dntop_size(rr.dnsrr_dn) + c;
  ret = malloc(sizeof(*ret) + sizeof(struct dns_txt) * c + l);
  if (!ret)
    return DNS_E_NOMEM;
  ret->dnstxt_ntxt = c;
  ret->dnstxt_ttl = ttl;
  ret->dnstxt_txt = (struct dns_txt *)(ret+1);

  /* and 3rd, fill in result, finally */
  sp = (unsigned char*)(ret->dnstxt_txt + c);
  c = 0;
  for(r = dns_firstrr(&p, &rr, q->dnsq_dn, 0, DNS_T_TXT, pkt, pkte);
      r > 0; r = dns_nextrr(&p, &rr)) {
    ret->dnstxt_txt[c].txt = sp;
    cp = rr.dnsrr_dptr; ep = rr.dnsrr_dend;
    while(cp < ep) {
      r = *cp++;
      memcpy(sp, cp, r);
      sp += r;
      cp += r;
    }
    ret->dnstxt_txt[c].len = sp - ret->dnstxt_txt[c].txt;
    *sp++ = '\0';
    ++c;
  }
  ret->dnstxt_cname = sp;
  dns_dntop(rr.dnsrr_dn, sp, DNS_MAXNAME);

  q->dnsq_result = ret;
  return 0;
}

int dns_submit_txt(struct dns_ctx *ctx, struct dns_query *q,
                   const char *name, int qcls, int flags,
                   dns_query_txt_fn *cbck, time_t now) {
  return
    dns_submit_p(ctx, q, name, qcls, DNS_T_TXT, flags,
                 (dns_query_fn *)cbck, dns_parse_txt, now);
}

struct dns_rr_txt *
dns_resolve_txt(struct dns_ctx *ctx, const char *name, int qcls, int flags,
                int *statusp)
{
  return (struct dns_rr_txt *)
    dns_resolve_p(ctx, name, qcls, DNS_T_TXT, flags, dns_parse_txt, statusp);
}
