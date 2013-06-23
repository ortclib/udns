/* $Id: udns_rr_txt.c,v 1.11 2004/07/03 00:50:25 mjt Exp $
 * parse/query TXT records
 */

#include <string.h>
#include <stdlib.h>
#include "udns.h"

int dns_parse_txt(const unsigned char *pkt, const unsigned char *pkte,
                  void **result) {
  struct dns_rr_txt *ret = NULL;
  struct dns_parse p;
  struct dns_rr rr;
  int r, l;
  unsigned char *sp;
  const unsigned char *cp, *ep;

  /* first, validate the answer and count size of the result */
  l = 0;
  dns_initparse(&p, DNS_C_ANY, DNS_T_TXT, pkt, pkte);
  while((r = dns_nextrr(&p, &rr)) > 0) {
    cp = rr.dnsrr_dptr; ep = rr.dnsrr_dend;
    while(cp < ep) {
      r = *cp++;
      if (cp + r > ep)
        return DNS_E_PROTOCOL;
      l += r;
      cp += r;
    }
  }
  if (r < 0)
    return DNS_E_PROTOCOL;
  if (!p.dnsp_nrr)
    return DNS_E_NODATA;

  /* next, allocate and set up result */
  l +=  (sizeof(struct dns_txt) + 1) * p.dnsp_nrr + dns_stdrr_size(&p);
  ret = malloc(sizeof(*ret) + l);
  if (!ret)
    return DNS_E_NOMEM;
  ret->dnstxt_nrr = p.dnsp_nrr;
  ret->dnstxt_txt = (struct dns_txt *)(ret+1);

  /* and 3rd, fill in result, finally */
  sp = (unsigned char*)(ret->dnstxt_txt + p.dnsp_nrr);
  for(dns_rewind(&p), r = 0; dns_nextrr(&p, &rr) > 0; ++r) {
    ret->dnstxt_txt[r].txt = sp;
    cp = rr.dnsrr_dptr; ep = rr.dnsrr_dend;
    while(cp < ep) {
      l = *cp++;
      memcpy(sp, cp, l);
      sp += l;
      cp += l;
    }
    ret->dnstxt_txt[r].len = sp - ret->dnstxt_txt[r].txt;
    *sp++ = '\0';
  }
  dns_stdrr_finish((struct dns_rr_null *)ret, sp, &p);
  *result = ret;
  return 0;
}

struct dns_query *
dns_submit_txt(struct dns_ctx *ctx, const char *name, int qcls, int flags,
               dns_query_txt_fn *cbck, void *data, time_t now) {
  return
    dns_submit_p(ctx, name, qcls, DNS_T_TXT, flags,
                 dns_parse_txt, (dns_query_fn *)cbck, data, now);
}

struct dns_rr_txt *
dns_resolve_txt(struct dns_ctx *ctx, const char *name, int qcls, int flags) {
  return (struct dns_rr_txt *)
    dns_resolve_p(ctx, name, qcls, DNS_T_TXT, flags, dns_parse_txt);
}
