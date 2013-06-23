/* $Id: dnsget.c,v 1.10 2005/04/08 15:37:21 mjt Exp $
   simple host/dig-like application using UDNS library

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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/time.h>
#include <stdarg.h>
#include <errno.h>
#include "udns.h"

static char *progname;
static int verbose = 1;
static int errors;
static int notfound;

/* verbosity level:
 * <0 - bare result
 *  0 - bare result and error messages
 *  1 - readable result
 *  2 - received packet contents and `trying ...' stuff
 *  3 - sent and received packet contents
 */

static void die(int errnum, const char *fmt, ...) {
  va_list ap;
  fprintf(stderr, "%s: ", progname);
  va_start(ap, fmt); vfprintf(stderr, fmt, ap); va_end(ap);
  if (errnum) fprintf(stderr, ": %s\n", strerror(errnum));
  else putc('\n', stderr);
  fflush(stderr);
  exit(1);
}

struct query {
  const char *name;		/* original query string */
  unsigned char *dn;		/* the DN being looked up */
  enum dns_type qtyp;		/* type of the query */
};

static void query_free(struct query *q) {
  free(q->dn);
  free(q);
}

static struct query *
query_new(const char *name, const unsigned char *dn, enum dns_type qtyp) {
  struct query *q = malloc(sizeof(*q));
  unsigned l = dns_dnlen(dn);
  unsigned char *cdn = malloc(l);
  if (!q || !cdn) die(0, "out of memory");
  memcpy(cdn, dn, l);
  q->name = name;
  q->dn = cdn;
  q->qtyp = qtyp;
  return q;
}

static enum dns_class qcls = DNS_C_IN;

static void
dnserror(struct query *q, int errnum) {
  if (verbose >= 0)
    fprintf(stderr, "%s: unable to lookup %s record for %s: %s\n", progname,
            dns_typename(q->qtyp), dns_dntosp(q->dn), dns_strerror(errnum));
  if (errnum == DNS_E_NXDOMAIN || errnum == DNS_E_NODATA)
    ++notfound;
  else
    ++errors;
  query_free(q);
}

static void xperr() {
  printf("<parse error>\n");
  ++errors;
}

static void
printrr(const struct dns_parse *p, struct dns_rr *rr) {
  const unsigned char *pkt = p->dnsp_pkt;
  const unsigned char *dptr = rr->dnsrr_dptr;
  const unsigned char *dend = rr->dnsrr_dend;
  unsigned char *dn = rr->dnsrr_dn;
  const unsigned char *c;
  unsigned n;

  if (verbose > 0) {
    if (verbose > 1) {
      if (!p->dnsp_rrl && !rr->dnsrr_dn[0] && rr->dnsrr_typ == DNS_T_OPT) {
        printf(";EDNS0 OPT record (UDPsize: %d): %d bytes\n",
               rr->dnsrr_cls, rr->dnsrr_dsz);
        return;
      }
      n = printf("%s.", dns_dntosp(rr->dnsrr_dn));
      printf("%s%u\t%s\t%s\t",
             n > 15 ? "\t" : n > 7 ? "\t\t" : "\t\t\t",
             rr->dnsrr_ttl,
             dns_classname(rr->dnsrr_cls),
             dns_typename(rr->dnsrr_typ));
    }
    else
      printf("%s. %s ", dns_dntosp(rr->dnsrr_dn), dns_typename(rr->dnsrr_typ));
  }

  switch(rr->dnsrr_typ) {

  case DNS_T_CNAME:
  case DNS_T_PTR:
  case DNS_T_NS:
  case DNS_T_MB:
  case DNS_T_MD:
  case DNS_T_MF:
  case DNS_T_MG:
  case DNS_T_MR:
    if (dns_getdn(pkt, &dptr, dend, dn, DNS_MAXDN) <= 0) xperr();
    else printf("%s.\n", dns_dntosp(dn));
    break;

  case DNS_T_A:
    if (rr->dnsrr_dsz != 4) xperr();
    else printf("%d.%d.%d.%d\n", dptr[0], dptr[1], dptr[2], dptr[3]);
    break;

  case DNS_T_AAAA:
    if (rr->dnsrr_dsz != 16) xperr();
    else printf("%s\n", inet_ntop(AF_INET6, dptr, dn, DNS_MAXDN));
    break;

  case DNS_T_MX:
    c = dptr + 2;
    if (dns_getdn(pkt, &c, dend, dn, DNS_MAXDN) <= 0 || c != dend) xperr();
    else printf("%d %s.\n", dns_get16(dptr), dns_dntosp(dn));
    break;

  case DNS_T_TXT:
    /* first verify it */
    for(c = dptr; c < dend; c += n) {
      n = *c++;
      if (c + n > dend) {
        xperr();
        c = 0;
        break;
      }
    }
    if (!c) break;
    c = dptr;
    if (verbose > 0) {
      const unsigned char *e;
      int i = 0;
      while(c < dend) {
        n = *c++;
        e = c + n;
        printf("%s\"", i++?" ":"");
        while(c < e) {
          if (*c < ' ' || *c >= 127) printf("\\%02x", *c);
          else if (*c == '\\' || *c == '"') printf("\\%c", *c);
          else putchar(*c);
          ++c;
        }
        putchar('"');
      }
    }
    else {
      while(c < dend) {
        n = *c++;
        fwrite(c, n, 1, stdout);
        c += n;
      }
    }
    putchar('\n');
    break;

  case DNS_T_SOA:
    c = dptr;
    if (dns_getdn(pkt, &c, dend, dn, DNS_MAXDN) <= 0 ||
        dns_getdn(pkt, &c, dend, dn, DNS_MAXDN) <= 0 ||
        c + 4*5 != dend) {
      xperr(); break;
    }
    dns_getdn(pkt, &dptr, dend, dn, DNS_MAXDN);
    printf("%s. ", dns_dntosp(dn));
    dns_getdn(pkt, &dptr, dend, dn, DNS_MAXDN);
    printf("%s. ", dns_dntosp(dn));
    printf("%u %u %u %u %u\n",
           dns_get32(dptr), dns_get32(dptr+4), dns_get32(dptr+8),
           dns_get32(dptr+12), dns_get32(dptr+16));
    break;

  case DNS_T_MINFO:
    c = dptr;
    if (dns_getdn(pkt, &c, dend, dn, DNS_MAXDN) <= 0 ||
        dns_getdn(pkt, &c, dend, dn, DNS_MAXDN) <= 0 ||
	c != dend) {
      xperr(); break;
    }
    dns_getdn(pkt, &dptr, dend, dn, DNS_MAXDN);
    printf("%s. ", dns_dntosp(dn));
    dns_getdn(pkt, &dptr, dend, dn, DNS_MAXDN);
    printf("%s.\n", dns_dntosp(dn));
    break;

  case DNS_T_HINFO:
  case DNS_T_WKS:
  case DNS_T_A6:
  case DNS_T_NULL:

  default:
    printf("<unknown RR type (size %d)>\n", rr->dnsrr_dsz);
    break;
  }

}

static int
printsection(struct dns_parse *p, int nrr, const char *sname) {
  struct dns_rr rr;
  int r;
  if (!nrr) return 0;
  if (verbose > 1) printf("\n;; %s section (%d):\n", sname, nrr);

  p->dnsp_rrl = nrr;
  while((r = dns_nextrr(p, &rr)) > 0)
    printrr(p, &rr);
  if (r < 0) printf("<<ERROR>>\n");
  return r;
}

/* dbgcb will only be called if verbose > 1 */
static void
dbgcb(int code, const struct sockaddr *sa, unsigned slen,
      const unsigned char *pkt, int r,
      const struct dns_query *unused_q, void *unused_data) {
  struct dns_parse p;
  const unsigned char *qdn;

  if (code > 0)	{
    printf(";; trying %s.\n", dns_dntosp(dns_payload(pkt)));
    printf(";; sending %d bytes query to ", r);
  }
  else
    printf(";; received %d bytes response from ", r);
  if (sa->sa_family == AF_INET && slen >= sizeof(struct sockaddr_in)) {
    char buf[4*4];
    printf("%s port %d\n",
           inet_ntop(AF_INET, &((struct sockaddr_in*)sa)->sin_addr,
                     buf, sizeof(buf)),
           htons(((struct sockaddr_in*)sa)->sin_port));
  }
  else if (sa->sa_family == AF_INET6 && slen >= sizeof(struct sockaddr_in6)) {
    char buf[6*5+4*4];
    printf("%s port %d\n",
           inet_ntop(AF_INET6, &((struct sockaddr_in6*)sa)->sin6_addr,
                     buf, sizeof(buf)),
           htons(((struct sockaddr_in6*)sa)->sin6_port));
  }
  else
    printf("<<unknown socket type %d>>\n", sa->sa_family);
  if (code > 0 && verbose < 3) {
    putchar('\n');
    return;
  }

  if (code == -2) printf(";; reply from unexpected source\n");
  if (code == -5) printf(";; reply to a query we didn't sent (or old)\n");
  if (r < DNS_HSIZE) {
    printf(";; short packet (%d bytes)\n", r);
    return;
  }
  if (dns_numqd(pkt) != 1) {
    printf(";; unexpected number of entries in QUERY section: %d\n",
           dns_numqd(pkt));
    return;
  }
  if (dns_opcode(pkt) != 0) {
    printf(";; unexpected opcode %d\n", dns_opcode(pkt));
    return;
  }
  if (dns_tc(pkt) != 0)
    printf(";; warning TC bit set, probably incomplete reply\n");

  printf(";; ->>HEADER<<- opcode: QUERY, status: %s, id: %d, size: %d\n",
         dns_rcodename(dns_rcode(pkt)), dns_qid(pkt), r);
  printf(";; flags:");
  if (dns_qr(pkt)) printf(" qr");
  if (dns_rd(pkt)) printf(" rd");
  if (dns_ra(pkt)) printf(" ra");
  if (dns_aa(pkt)) printf(" aa");
  if (dns_tc(pkt)) printf(" tc");
  printf("; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
         dns_numqd(pkt), dns_numan(pkt), dns_numns(pkt), dns_numar(pkt));
  printf("\n;; QUERY SECTION (%d):\n", dns_numqd(pkt));

  qdn = dns_payload(pkt);
  if (dns_getdn(pkt, &qdn, pkt + r, p.dnsp_dnbuf, DNS_MAXDN) <= 0 ||
      qdn + 4 > pkt + r) {
    printf("; invalid query section\n");
    return;
  }

  dns_initparse(&p, 0, 0, pkt, pkt + r);
  p.dnsp_qdn = 0;

  r = printf(";%s.", dns_dntosp(p.dnsp_dnbuf));
  printf("%s%s\t%s\n",
         r > 23 ? "\t" : r > 15 ? "\t\t" : r > 7 ? "\t\t\t" : "\t\t\t\t",
         dns_classname(dns_get16(qdn+2)), dns_typename(dns_get16(qdn)));

  r = printsection(&p, dns_numan(pkt), "ANSWER");
  if (r == 0)
    r = printsection(&p, dns_numns(pkt), "AUTHORITY");
  if (r == 0)
    r = printsection(&p, dns_numar(pkt), "ADDITIONAL");
  putchar('\n');
}

static void dnscb(struct dns_ctx *ctx, void *result, void *data) {
  int r = dns_status(ctx);
  struct query *q = data;
  struct dns_parse p;
  struct dns_rr rr;
  unsigned nrr;
  const unsigned char *qdn;
  if (!result) {
    dnserror(q, r);
    return;
  }
  dns_initparse(&p, 0, 0, result, result + r);
  qdn = p.dnsp_qdn;
  p.dnsp_qdn = 0;
  nrr = 0;
  while((r = dns_nextrr(&p, &rr)) > 0) {
    if (!dns_dnequal(qdn, rr.dnsrr_dn)) continue;
    if ((qcls == DNS_C_ANY || qcls == rr.dnsrr_cls) &&
        (q->qtyp == DNS_T_ANY || q->qtyp == rr.dnsrr_typ))
      ++nrr;
    else if (rr.dnsrr_typ == DNS_T_CNAME && !nrr) {
      if (dns_getdn(result, &rr.dnsrr_dptr, rr.dnsrr_dend,
                    p.dnsp_dnbuf, sizeof(p.dnsp_dnbuf)) <= 0 ||
          rr.dnsrr_dptr != rr.dnsrr_dend) {
        r = DNS_E_PROTOCOL;
        break;
      }
      else {
        if (verbose == 1) {
          printf("%s.", dns_dntosp(qdn));
          printf(" CNAME %s.\n", dns_dntosp(p.dnsp_dnbuf));
        }
        qdn = p.dnsp_dnbuf;
      }
    }
  }
  if (!r && !nrr)
    r = DNS_E_NODATA;
  if (r < 0) {
    dnserror(q, r);
    free(result);
    return;
  }
  if (verbose < 2) {	/* else it is already printed by dbgfn */
    dns_rewind(&p);
    p.dnsp_qdn = dns_payload(result);
    p.dnsp_qtyp = q->qtyp;
    p.dnsp_qcls = qcls;
    while(dns_nextrr(&p, &rr))
      printrr(&p, &rr);
  }
  free(result);
  query_free(q);
}

int main(int argc, char **argv) {
  int i;
  int fd;
  fd_set fds;
  struct timeval tv;
  time_t now;
  int nserv = 0;
  struct query *q;
  enum dns_type qtyp = 0;

  if (!(progname = strrchr(argv[0], '/'))) progname = argv[0];
  else argv[0] = ++progname;

  if (argc <= 1)
    die(0, "try `%s -h' for help", progname);

  if (dns_init(0) < 0)
    die(errno, "unable to initialize dns library");
  while((i = getopt(argc, argv, "vqt:c:n:p:h")) != EOF) switch(i) {
  case 'v': ++verbose; break;
  case 'q': --verbose; break;
  case 't':
    if (optarg[0] == '*' && !optarg[1])
      i = DNS_T_ANY;
    else if ((i = dns_findtypename(optarg)) <= 0)
      die(0, "unrecognized query type `%s'", optarg);
    qtyp = i;
    break;
  case 'c':
    if (optarg[0] == '*' && !optarg[1])
      i = DNS_C_ANY;
    else if ((i = dns_findclassname(optarg)) < 0)
      die(0, "unrecognized query class `%s'", optarg);
    qcls = i;
    break;
  case 'n':
    if (!nserv++)
      dns_add_serv(0, 0);
    if (dns_add_serv(0, optarg) < 0)
      die(errno, "unable to add nameserver `%s'", optarg);
    break;
  case 'p':
    if (dns_set_opt(NULL, DNS_OPT_PORT, atoi(optarg)) < 0)
      die(0, "invalid port `%s'", optarg);
    break;
  case 'h':
    printf(
"%s: simple DNS query tool (using udns version %s)\n"
"Usage: %s [options] domain-name...\n"
"where options are:\n"
" -h - print this help and exit\n"
" -v - be more verbose\n"
" -q - be less verbose\n"
" -t type - set query type (A, AA, PTR etc)\n"
" -c class - set query class (IN (default), CH, HS, *)\n"
" -n ns - use given nameserver(s) (IP addresses) instead of default\n"
" -p port - use this port for queries instead of default 53\n"
      , progname, dns_version(), progname);
    return 0;
  default:
    die(0, "try `%s -h' for help", progname);
  }

  argc -= optind; argv += optind;

  fd = dns_open(NULL);
  if (fd < 0)
    die(errno, "unable to open dns library");
  if (verbose > 1)
    dns_set_dbgfn(NULL, dbgcb);

  now = time(NULL);
  for (i = 0; i < argc; ++i) {
    char *name = argv[i];
    union {
      struct in_addr addr;
      struct in6_addr addr6;
    } a;
    unsigned char dn[DNS_MAXDN];
    enum dns_type l_qtyp = 0;
    int abs;
    if (inet_pton(AF_INET, name, &a.addr) > 0) {
      dns_a4todn(&a.addr, 0, dn, sizeof(dn));
      l_qtyp = DNS_T_PTR;
      abs = 1;
    }
    else if (inet_pton(AF_INET6, name, &a.addr6) > 0) {
      dns_a6todn(&a.addr6, 0, dn, sizeof(dn));
      l_qtyp = DNS_T_PTR;
      abs = 1;
    }
    else if (!dns_ptodn(name, strlen(name), dn, sizeof(dn), &abs))
      die(0, "invalid name `%s'\n", name);
    else
      l_qtyp = DNS_T_A;
    if (qtyp) l_qtyp = qtyp;
    q = query_new(name, dn, l_qtyp);
    if (abs) abs = DNS_NOSRCH;
    if (!dns_submit_dn(NULL, dn, qcls, l_qtyp, abs, 0, dnscb, q, now))
      dnserror(q, dns_status(0));
  }

  FD_ZERO(&fds);
  while((i = dns_timeouts(0, -1, now)) > 0) {
    FD_SET(fd, &fds);
    tv.tv_sec = i;
    tv.tv_usec = 0;
    i = select(fd+1, &fds, 0, 0, &tv);
    now = time(NULL);
    if (i > 0) dns_ioevent(NULL, now);
  }

  return errors ? 1 : notfound ? 100 : 0;
}
