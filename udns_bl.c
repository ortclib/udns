/* $Id: udns_bl.c,v 1.6 2004/06/30 10:43:36 mjt Exp $
 * DNSBL stuff
 */

#include "udns.h"

struct dns_query *
dns_submit_a4dnsbl(struct dns_ctx *ctx,
                   const struct in_addr *addr, const char *dnsbl,
                   dns_query_a4_fn *cbck, void *data, time_t now) {
  unsigned char dn[DNS_MAXDN];
  if (dns_a4ptodn(addr, dnsbl, dn, sizeof(dn)) <= 0) {
    dns_setstatus(ctx, DNS_E_BADQUERY);
    return NULL;
  }
  return
    dns_submit_dn(ctx, dn, DNS_C_IN, DNS_T_A, DNS_NOSRCH,
                  dns_parse_a4, (dns_query_fn*)cbck, data, now);
}

struct dns_query *
dns_submit_a4dnsbl_txt(struct dns_ctx *ctx,
                       const struct in_addr *addr, const char *dnsbl,
                       dns_query_txt_fn *cbck, void *data, time_t now) {
  unsigned char dn[DNS_MAXDN];
  if (dns_a4ptodn(addr, dnsbl, dn, sizeof(dn)) <= 0) {
    dns_setstatus(ctx, DNS_E_BADQUERY);
    return NULL;
  }
  return
    dns_submit_dn(ctx, dn, DNS_C_IN, DNS_T_TXT, DNS_NOSRCH,
                  dns_parse_txt, (dns_query_fn*)cbck, data, now);
}

struct dns_rr_a4 *
dns_resolve_a4dnsbl(struct dns_ctx *ctx,
                    const struct in_addr *addr, const char *dnsbl) {
  return (struct dns_rr_a4 *)
    dns_resolve(ctx, dns_submit_a4dnsbl(ctx, addr, dnsbl, 0, 0, 0));
}

struct dns_rr_txt *
dns_resolve_a4dnsbl_txt(struct dns_ctx *ctx,
                        const struct in_addr *addr, const char *dnsbl) {
  return (struct dns_rr_txt *)
    dns_resolve(ctx, dns_submit_a4dnsbl_txt(ctx, addr, dnsbl, 0, 0, 0));
}


struct dns_query *
dns_submit_a6dnsbl(struct dns_ctx *ctx,
                   const struct in6_addr *addr, const char *dnsbl,
                   dns_query_a4_fn *cbck, void *data, time_t now) {
  unsigned char dn[DNS_MAXDN];
  if (dns_a6ptodn(addr, dnsbl, dn, sizeof(dn)) <= 0) {
    dns_setstatus(ctx, DNS_E_BADQUERY);
    return NULL;
  }
  return
    dns_submit_dn(ctx, dn, DNS_C_IN, DNS_T_A, DNS_NOSRCH,
                  dns_parse_a4, (dns_query_fn*)cbck, data, now);
}

struct dns_query *
dns_submit_a6dnsbl_txt(struct dns_ctx *ctx,
                       const struct in6_addr *addr, const char *dnsbl,
                       dns_query_txt_fn *cbck, void *data, time_t now) {
  unsigned char dn[DNS_MAXDN];
  if (dns_a6ptodn(addr, dnsbl, dn, sizeof(dn)) <= 0) {
    dns_setstatus(ctx, DNS_E_BADQUERY);
    return NULL;
  }
  return
    dns_submit_dn(ctx, dn, DNS_C_IN, DNS_T_TXT, DNS_NOSRCH,
                  dns_parse_txt, (dns_query_fn*)cbck, data, now);
}

struct dns_rr_a4 *
dns_resolve_a6dnsbl(struct dns_ctx *ctx,
                    const struct in6_addr *addr, const char *dnsbl) {
  return (struct dns_rr_a4 *)
    dns_resolve(ctx, dns_submit_a6dnsbl(ctx, addr, dnsbl, 0, 0, 0));
}

struct dns_rr_txt *
dns_resolve_a6dnsbl_txt(struct dns_ctx *ctx,
                        const struct in6_addr *addr, const char *dnsbl) {
  return (struct dns_rr_txt *)
    dns_resolve(ctx, dns_submit_a6dnsbl_txt(ctx, addr, dnsbl, 0, 0, 0));
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

struct dns_query *
dns_submit_rhsbl(struct dns_ctx *ctx, const char *name, const char *rhsbl,
                 dns_query_a4_fn *cbck, void *data, time_t now) {
  unsigned char dn[DNS_MAXDN];
  if (!dns_rhsbltodn(name, rhsbl, dn)) {
    dns_setstatus(ctx, DNS_E_BADQUERY);
    return NULL;
  }
  return
    dns_submit_dn(ctx, dn, DNS_C_IN, DNS_T_A, DNS_NOSRCH,
                  dns_parse_a4, (dns_query_fn*)cbck, data, now);
}
struct dns_query *
dns_submit_rhsbl_txt(struct dns_ctx *ctx, const char *name, const char *rhsbl,
                     dns_query_txt_fn *cbck, void *data, time_t now) {
  unsigned char dn[DNS_MAXDN];
  if (!dns_rhsbltodn(name, rhsbl, dn)) {
    dns_setstatus(ctx, DNS_E_BADQUERY);
    return NULL;
  }
  return
    dns_submit_dn(ctx, dn, DNS_C_IN, DNS_T_TXT, DNS_NOSRCH,
                  dns_parse_txt, (dns_query_fn*)cbck, data, now);
}

struct dns_rr_a4 *
dns_resolve_rhsbl(struct dns_ctx *ctx, const char *name, const char *rhsbl) {
  return (struct dns_rr_a4*)
    dns_resolve(ctx, dns_submit_rhsbl(ctx, name, rhsbl, 0, 0, 0));
}

struct dns_rr_txt *
dns_resolve_rhsbl_txt(struct dns_ctx *ctx, const char *name, const char *rhsbl)
{
  return (struct dns_rr_txt*)
    dns_resolve(ctx, dns_submit_rhsbl_txt(ctx, name, rhsbl, 0, 0, 0));
}
