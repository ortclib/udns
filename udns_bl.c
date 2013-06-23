/* $Id: udns_bl.c,v 1.4 2004/06/29 07:46:39 mjt Exp $
 * DNSBL stuff
 */

#include "udns.h"

int dns_submit_a4dnsbl(struct dns_ctx *ctx, struct dns_query *q,
                       const struct in_addr *addr, const char *dnsbl,
                       dns_query_a4_fn *cbck, time_t now) {
  if (dns_a4ptodn(addr, dnsbl, q->dnsq_dn, sizeof(q->dnsq_dn)) <= 0)
    return DNS_E_BADQUERY;
  return
    dns_submit(ctx, q, DNS_C_IN, DNS_T_A, DNS_NOSRCH,
               (dns_query_fn*)cbck, dns_parse_a4, now);
}

int dns_submit_a4dnsbl_txt(struct dns_ctx *ctx, struct dns_query *q,
                           const struct in_addr *addr, const char *dnsbl,
                           dns_query_txt_fn *cbck, time_t now) {
  if (dns_a4ptodn(addr, dnsbl, q->dnsq_dn, sizeof(q->dnsq_dn)) <= 0)
    return DNS_E_BADQUERY;
  return
    dns_submit(ctx, q, DNS_C_IN, DNS_T_TXT, DNS_NOSRCH,
               (dns_query_fn*)cbck, dns_parse_txt, now);
}

struct dns_rr_a4 *
dns_resolve_a4dnsbl(struct dns_ctx *ctx, const struct in_addr *addr,
                    const char *dnsbl, int *statusp) {
  unsigned char dn[DNS_MAXDN];
  if (dns_a4ptodn(addr, dnsbl, dn, sizeof(dn)) <= 0) {
    if (statusp) *statusp = DNS_E_BADQUERY;
    return NULL;
  }
  return (struct dns_rr_a4 *)
    dns_resolve_dn(ctx, dn, DNS_C_IN, DNS_T_A, DNS_NOSRCH,
                   dns_parse_a4, statusp);
}

struct dns_rr_txt *
dns_resolve_a4dnsbl_txt(struct dns_ctx *ctx, const struct in_addr *addr,
                        const char *dnsbl, int *statusp) {
  unsigned char dn[DNS_MAXDN];
  if (dns_a4ptodn(addr, dnsbl, dn, sizeof(dn)) <= 0) {
    if (statusp) *statusp = DNS_E_BADQUERY;
    return NULL;
  }
  return (struct dns_rr_txt *)
    dns_resolve_dn(ctx, dn, DNS_C_IN, DNS_T_TXT, DNS_NOSRCH,
                   dns_parse_txt, statusp);
}


int dns_submit_a6dnsbl(struct dns_ctx *ctx, struct dns_query *q,
                       const struct in6_addr *addr, const char *dnsbl,
                       dns_query_a4_fn *cbck, time_t now) {
  if (dns_a6ptodn(addr, dnsbl, q->dnsq_dn, sizeof(q->dnsq_dn)) <= 0)
    return DNS_E_BADQUERY;
  return
    dns_submit(ctx, q, DNS_C_IN, DNS_T_A, DNS_NOSRCH,
               (dns_query_fn*)cbck, dns_parse_a4, now);
}

int dns_submit_a6dnsbl_txt(struct dns_ctx *ctx, struct dns_query *q,
                           const struct in6_addr *addr, const char *dnsbl,
                           dns_query_txt_fn *cbck, time_t now) {
  if (dns_a6ptodn(addr, dnsbl, q->dnsq_dn, sizeof(q->dnsq_dn)) <= 0)
    return DNS_E_BADQUERY;
  return
    dns_submit(ctx, q, DNS_C_IN, DNS_T_TXT, DNS_NOSRCH,
               (dns_query_fn*)cbck, dns_parse_txt, now);
}

struct dns_rr_a4 *
dns_resolve_a6dnsbl(struct dns_ctx *ctx, const struct in6_addr *addr,
                   const char *dnsbl, int *statusp) {
  unsigned char dn[DNS_MAXDN];
  if (dns_a6ptodn(addr, dnsbl, dn, sizeof(dn)) <= 0) {
    if (statusp) *statusp = DNS_E_BADQUERY;
    return NULL;
  }
  return (struct dns_rr_a4 *)
    dns_resolve_dn(ctx, dn, DNS_C_IN, DNS_T_A, DNS_NOSRCH,
                   dns_parse_a4, statusp);
}

struct dns_rr_txt *
dns_resolve_a6dnsbl_txt(struct dns_ctx *ctx, const struct in6_addr *addr,
                        const char *dnsbl, int *statusp) {
  unsigned char dn[DNS_MAXDN];
  if (dns_a6ptodn(addr, dnsbl, dn, sizeof(dn)) <= 0) {
    if (statusp) *statusp = DNS_E_BADQUERY;
    return NULL;
  }
  return (struct dns_rr_txt *)
    dns_resolve_dn(ctx, dn, DNS_C_IN, DNS_T_TXT, DNS_NOSRCH,
                   dns_parse_txt, statusp);
}

static int
dns_rhsbltodn(const char *name, const char *rhsbl, unsigned char dn[DNS_MAXDN])
{
  int l = dns_sptodn(name, dn, DNS_MAXDN);
  if (l <= 0) return 0;
  l = dns_sptodn(rhsbl, dn+l-1, DNS_MAXDN-l+1);
  if (l <= 0) return 0;
  return 1;
}

int dns_submit_rhsbl(struct dns_ctx *ctx, struct dns_query *q,
                     const char *name, const char *rhsbl,
                     dns_query_a4_fn *cbck, time_t now) {
  if (!dns_rhsbltodn(name, rhsbl, q->dnsq_dn))
    return DNS_E_BADQUERY;
  return dns_submit(ctx, q, DNS_C_IN, DNS_T_A, DNS_NOSRCH,
                    (dns_query_fn*)cbck, dns_parse_a4, now);
}
int dns_submit_rhsbl_txt(struct dns_ctx *ctx, struct dns_query *q,
                         const char *name, const char *rhsbl,
                         dns_query_txt_fn *cbck, time_t now) {
  if (!dns_rhsbltodn(name, rhsbl, q->dnsq_dn))
    return DNS_E_BADQUERY;
  return dns_submit(ctx, q, DNS_C_IN, DNS_T_TXT, DNS_NOSRCH,
                    (dns_query_fn*)cbck, dns_parse_txt, now);
}

struct dns_rr_a4 *
dns_resolve_rhsbl(struct dns_ctx *ctx,
                  const char *name, const char *rhsbl, int *statusp) {
  unsigned char dn[DNS_MAXDN];
  if (!dns_rhsbltodn(name, rhsbl, dn)) {
    if (statusp) *statusp = DNS_E_BADQUERY;
    return NULL;
  }
  return (struct dns_rr_a4*)
    dns_resolve_dn(ctx, dn, DNS_C_IN, DNS_T_A, DNS_NOSRCH,
                   dns_parse_a4, statusp);
}

struct dns_rr_txt *
dns_resolve_rhsbl_txt(struct dns_ctx *ctx,
                      const char *name, const char *rhsbl, int *statusp) {
  unsigned char dn[DNS_MAXDN];
  if (!dns_rhsbltodn(name, rhsbl, dn)) {
    if (statusp) *statusp = DNS_E_BADQUERY;
    return NULL;
  }
  return (struct dns_rr_txt*)
    dns_resolve_dn(ctx, dn, DNS_C_IN, DNS_T_TXT, DNS_NOSRCH,
                   dns_parse_txt, statusp);
}
