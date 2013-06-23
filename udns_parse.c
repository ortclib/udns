/* $Id: udns_parse.c,v 1.4 2004/06/29 07:46:39 mjt Exp $
 * raw DNS packet parsing routines
 */

#include <string.h>
#include "udns.h"

const unsigned char *
dns_skipdn(const unsigned char *cur, const unsigned char *pkte) {
  unsigned c;
  for(;;) {
    if (cur >= pkte)
      return NULL;
    c = *cur++;
    if (!c)
      return cur;
    if (c & 192) {		/* jump */
      return cur + 1 >= pkte ? NULL : cur + 1;
    }
    cur += c;
  }
}

int
dns_getdn(const unsigned char *pkt,
          const unsigned char **curp,
          const unsigned char *pkte,
          register unsigned char *dn, unsigned dnsiz) {
  unsigned c;
  const unsigned char *cp = *curp;	/* max jump position (jump only back) */
  const unsigned char *pp = cp;		/* current packet pointer */
  unsigned char *dp = dn;		/* current dn pointer */
  unsigned char *const de		/* end of the DN */
       = dn + (dnsiz < DNS_MAXDN ? dnsiz : DNS_MAXDN);
  const unsigned char *jump = NULL;	/* ptr after first jump if any */

  for(;;) {		/* loop by labels */
    if (pp >= pkte)		/* reached end of packet? */
      return -1;
    c = *pp++;			/* length of the label */
    if (!c) {			/* empty label: terminate */
      if (dn >= de)		/* can't fit terminator */
        goto noroom;
      *dp++ = 0;
      /* return next pos: either after the first jump or current */
      *curp = jump ? jump : pp;
      return dp - dn;
    }
    if (c & 192) {		/* jump */
      if (pp >= pkte)		/* eop instead of jump pos */
        return -1;
      c = ((c & ~192) << 8) | *pp;	/* new pos */
      if (c < DNS_HSIZE || pkt + c >= cp)
        return -1;
      if (!jump) jump = pp + 1;	/* remember first jump */
      cp = pp = pkt + c;	/* don't allow to jump past previous jump */
      continue;
    }
    if (c > DNS_MAXLABEL)	/* too long label? */
      return -1;
    if (pp + c > pkte)		/* label does not fit in packet? */
      return -1;
    if (dp + c + 1 > de)	/* if enouth room for the label */
      goto noroom;
    *dp++ = c;			/* label length */
    memcpy(dp, pp, c);		/* and the label itself */
    dp += c;
    pp += c;			/* advance to the next label */
  }
noroom:
  return dnsiz < DNS_MAXDN ? 0 : -1;
}

int dns_initparse(struct dns_parse *p,
                  const unsigned char *qdn, int qcls, int qtyp,
                  const unsigned char *pkt, const unsigned char *pkte) {
  p->dnsp_pkt = pkt;
  p->dnsp_pkte = pkte;
  if ((p->dnsp_cur = dns_skipdn(dns_payload(pkt), pkte)) == 0 ||
      (p->dnsp_cur += DNS_HSIZE + 2) > pkte)
    return -1;
  p->dnsp_numrr = dns_numan(pkt);
  p->dnsp_qdn = qdn;
  p->dnsp_qcls = qcls;
  p->dnsp_qtyp = qtyp;
  return 1;
}

int dns_nextrr(struct dns_parse *p, struct dns_rr *rr) {
  const unsigned char *cur = p->dnsp_cur;
  while(p->dnsp_numrr > 0) {
    --p->dnsp_numrr;
    if (dns_getdn(p->dnsp_pkt, &cur, p->dnsp_pkte,
                  rr->dnsrr_dn, sizeof(rr->dnsrr_dn)) <= 0)
      return -1;
    if (cur + 10 > p->dnsp_pkte)
      return -1;
    rr->dnsrr_typ = dns_get16(cur);
    rr->dnsrr_cls = dns_get16(cur+2);
    rr->dnsrr_ttl = dns_get32(cur+4);
    rr->dnsrr_dsz = dns_get16(cur+8);
    rr->dnsrr_dptr = cur = cur + 10;
    rr->dnsrr_dend = cur = cur + rr->dnsrr_dsz;
    if (cur > p->dnsp_pkte)
      return -1;
    if (p->dnsp_qdn && !dns_dnequal(p->dnsp_qdn, rr->dnsrr_dn))
      continue;
    if ((!p->dnsp_qcls || p->dnsp_qcls == rr->dnsrr_cls) &&
        (!p->dnsp_qtyp || p->dnsp_qtyp == rr->dnsrr_typ)) {
      p->dnsp_cur = cur;
      return 1;
    }
    if (p->dnsp_qdn && rr->dnsrr_typ == DNS_T_CNAME) {
      dns_dntodn(rr->dnsrr_dn, p->dnsp_dnbuf, sizeof(p->dnsp_dnbuf));
      p->dnsp_qdn = p->dnsp_dnbuf;
    }
  }
  p->dnsp_cur = cur;
  return 0;
}

int dns_firstrr(struct dns_parse *p, struct dns_rr *rr,
                const unsigned char *searchdn, int qcls, int qtyp,
                const unsigned char *pkt, const unsigned char *pkte) {
  dns_initparse(p, searchdn, qcls, qtyp, pkt, pkte);
  return dns_nextrr(p, rr);
}
