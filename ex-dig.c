/* $Id: ex-dig.c,v 1.9 2005/04/05 22:51:32 mjt Exp $
   example dig-like application using libdns

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
#include <sys/select.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include "udns.h"

static void rawdata(const char *reason, const struct dns_rr *rr) {
  const unsigned char *x, *e;
  int n;
  printf("<%s> (%d bytes)", reason, rr->dnsrr_dsz);
  if (!rr->dnsrr_dsz) {
    putchar('\n');
    return;
  }
  x = rr->dnsrr_dptr;
  e = x + rr->dnsrr_dsz;
  n = 0;
  while(x < e) {
    if (!(n & 31))
      printf(n ? "\n;\t" : "\n; Raw:\t");
    ++n;
    printf(" %02X", *x++);
  }
  putchar('\n');
}

static void printdn(const unsigned char *dn) {
  int l;
  l = printf("%s.", dns_dntosp(dn));
  if (l > 16) putchar(' ');
  if (l < 24) putchar('\t');
  if (l < 16) putchar('\t');
  if (l < 8) putchar('\t');
}

static void printrr(const unsigned char *pkt, struct dns_rr *rr) {
  int n, l;
  const unsigned char *cur, *e;
  printdn(rr->dnsrr_dn);
#if 0
#define MIN	60
#define HOUR	(MIN*60)
#define DAY	(HOUR*24)
#define WEEK	(DAY*7)
  n = rr->dnsrr_ttl;
  if (n > WEEK) { printf("%dw", n / WEEK); n %= WEEK; }
  if (n > DAY)  { printf("%dd", n / DAY);  n %= DAY; }
  if (n > HOUR) { printf("%dh", n / HOUR); n %= HOUR; }
  if (n > MIN)  { printf("%dm", n / MIN);  n %= MIN; }
  printf("%ds", n);
#else
  printf("%u", rr->dnsrr_ttl);
#endif
  printf("\t%s\t%s\t",
          dns_classname(rr->dnsrr_cls), dns_typename(rr->dnsrr_typ));

  switch(rr->dnsrr_typ) {

  case DNS_T_A:
    if (rr->dnsrr_dsz != 4)
      rawdata("wrong size", rr);
    else
      printf("%d.%d.%d.%d\n", rr->dnsrr_dptr[0], rr->dnsrr_dptr[1],
             rr->dnsrr_dptr[2], rr->dnsrr_dptr[3]);
    break;

  case DNS_T_AAAA:
    if (rr->dnsrr_dsz != 16)
      rawdata("wrong size", rr);
    else {
      char nm[128];
      printf("%s\n", inet_ntop(AF_INET6, rr->dnsrr_dptr, nm, sizeof(nm)));
    }
    break;

  case DNS_T_MX:
    if (rr->dnsrr_dsz < 3)
      rawdata("short RR", rr);
    else {
      printf("%d ", dns_get16(rr->dnsrr_dptr));
      cur = rr->dnsrr_dptr + 2;
      if (dns_getdn(pkt, &cur, rr->dnsrr_dptr + rr->dnsrr_dsz,
                    rr->dnsrr_dn, DNS_MAXDN) < 0)
        puts("<unable to parse domain name>");
      else {
        printf("%s", dns_dntosp(rr->dnsrr_dn));
        if (cur != rr->dnsrr_dend)
          puts(" <extra garbage in RR>");
        else
          putchar('\n');
      }
    }
    break;

  case DNS_T_NS:
  case DNS_T_CNAME:
    cur = rr->dnsrr_dptr;
    if (dns_getdn(pkt, &cur, rr->dnsrr_dend,
        rr->dnsrr_dn, DNS_MAXDN) < 0)
      rawdata("unable to parse DN", rr);
    else {
      printf("%s", dns_dntosp(rr->dnsrr_dn));
      if (cur != rr->dnsrr_dend)
        printf(" <extra garbage in RR>");
      putchar('\n');
    }
    break;

  case DNS_T_TXT:
    cur = rr->dnsrr_dptr;
    n = 0;
    while(cur < rr->dnsrr_dend) {
      if (n++) printf("\t\t\t\t");
      l = *cur++;
      if (cur + l > rr->dnsrr_dend) {
        printf("<short RR>\n");
	break;
      }
      e = cur + l;
      putchar('"');
      while(cur < e) {
        if (*cur < ' ' || *cur >= 0x7f) printf("\\%d", *cur);
	else if (*cur == '\\' || *cur == '"') printf("\\%c", *cur);
	else putchar(*cur);
	++cur;
      }
      printf("\"\n");
    }
    break;

  case DNS_T_SOA:
    cur = rr->dnsrr_dptr;
    if (dns_getdn(pkt, &cur, rr->dnsrr_dend, rr->dnsrr_dn, DNS_MAXDN) <= 0) {
      printf("<short RR>\n"); break;
    }
    printf("%s.", dns_dntosp(rr->dnsrr_dn));
    if (dns_getdn(pkt, &cur, rr->dnsrr_dend, rr->dnsrr_dn, DNS_MAXDN) <= 0) {
      printf(" <short RR>\n"); break;
    }
    printf(" %s.", dns_dntosp(rr->dnsrr_dn));
    for (n = 0; n < 5; ++n) {
      if (cur + 4 > rr->dnsrr_dend) {
        printf(" <short RR>\n");
        cur = NULL;
	break;
      }
      printf(" %u", dns_get32(cur));
      cur += 4;
    }
    if (cur)
      printf(cur == rr->dnsrr_dend ? "\n" : " <extra garbage after RR>\n");
    break;

  default: rawdata("unknown type", rr);
  }
}

static int rrloop(const char *name, struct dns_parse *p, int nent, int ar) {
  struct dns_rr rr;
  if (!nent) return 0;
  printf("\n;; %s SECTION (%d):\n", name, nent);
  p->dnsp_rrl = nent;
  while((nent = dns_nextrr(p, &rr)) > 0) {
    if (ar && !p->dnsp_rrl && rr.dnsrr_typ == DNS_T_OPT && !rr.dnsrr_dn[0])
    {	/* OPT record is special */
      printf(";; EDNS0 OPTIONS (size %d): UDPsize=%d\n",
             rr.dnsrr_dsz, rr.dnsrr_cls);
    }
    else
      printrr(p->dnsp_pkt, &rr);
  };
  return nent;
}

static int print_packet(const unsigned char *pkt, int len) {
  struct dns_parse p;
  int n, r;

  printf(";; Got answer (%d bytes):\n", len);
  printf(";; ->>HEADER<<- opcode: ");
  switch(dns_opcode(pkt)) {
  case 0: printf("QUERY"); break;
  case 1: printf("IQUERY"); break;
  case 2: printf("STATUS"); break;
  case 4: printf("NOTIFY"); break;
  case 5: printf("UPDATE"); break;
  default: printf("<unknown opcode %d>", dns_opcode(pkt));
  }
  printf(", status: %s, id: %d\n",
         dns_rcodename(dns_rcode(pkt)), dns_qid(pkt));
  printf(";; flags:");
  n = 0;
  if (dns_qr(pkt)) ++n, printf(" qr");
  if (dns_aa(pkt)) ++n, printf(" aa");
  if (dns_tc(pkt)) ++n, printf(" tc");
  if (dns_rd(pkt)) ++n, printf(" rd");
  if (dns_ra(pkt)) ++n, printf(" ra");
  if (!n) printf("<none>");
  printf("; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
         dns_numqd(pkt), dns_numan(pkt),
	 dns_numns(pkt), dns_numar(pkt));

  p.dnsp_pkt = pkt; p.dnsp_end = pkt + len;
  p.dnsp_cur = dns_payload(pkt);
  p.dnsp_qdn = NULL;
  p.dnsp_qcls = p.dnsp_qtyp = 0;
  n = dns_numqd(pkt);
  if (n) {
    printf(";; QUESTION SECTION (%d):\n", n);
    do {
      if ((r = dns_getdn(pkt, &p.dnsp_cur, p.dnsp_end,
                         p.dnsp_dnbuf, DNS_MAXDN)) <= 0)
        return r;
      if (p.dnsp_cur + 4 > p.dnsp_end)
        return DNS_E_PROTOCOL;
      printf("; %s.\t%s\t%s\n",
             dns_dntosp(p.dnsp_dnbuf),
             dns_classname(dns_get16(p.dnsp_cur+2)),
             dns_typename(dns_get16(p.dnsp_cur)));
      p.dnsp_cur += 4;
    } while(--n);
  }

  if ((r = rrloop("ANSWER",     &p, dns_numan(pkt), 0)) < 0 ||
      (r = rrloop("AUTHORITY",  &p, dns_numns(pkt), 0)) < 0 ||
      (r = rrloop("ADDITIONAL", &p, dns_numar(pkt), 1)) < 0)
    return r;
  putchar('\n');

  return 0;
}

static void dcallback(const unsigned char *pkt, int alen) {
  alen = print_packet(pkt, alen);
  if (alen != 0)
    printf("; ERROR\n");
}

static void qcallback(struct dns_ctx *ctx, void *result, void *data) {
  if (!result)
    printf("unable to find %s: %s\n",
           (char*)data, dns_strerror(dns_status(ctx)));
  else
    free(result);
}

static int findcode(const char *code, const char *name, const struct dns_nameval *nvt) {
  int c = dns_findname(nvt, name);
  if (c < 0) {
    fprintf(stderr, "unknown %s `%s'\n", code, name);
    exit(1);
  }
  return c;
}

int main(int argc, char **argv) {
  int n;
  time_t now;
  int qtyp = DNS_T_A;
  int qcls = DNS_C_IN;
  int flags = 0;
  int fd;
  fd_set rfd;

  dns_init(0);
  dns_set_dbgfn(NULL, dcallback);

  while((n = getopt(argc, argv, "t:c:o:p:u:")) != EOF)
   switch(n) {
   case 't': qtyp = findcode("type", optarg, dns_typetab); break;
   case 'c': qcls = findcode("class", optarg, dns_classtab); break;
   case 'o':
     if (strcmp(optarg, "aaonly") == 0) flags |= DNS_AAONLY;
     else if (strcmp(optarg, "nord") == 0) flags |= DNS_NORD;
     else if (strcmp(optarg, "nosrch") == 0) flags |= DNS_NOSRCH;
     else {
       fprintf(stderr, "unknown option `%s'\n", optarg);
       return 1;
     }
     break;
   case 'p':
     if (dns_set_opt(NULL, DNS_OPT_PORT, atoi(optarg)) < 0) {
       fprintf(stderr, "invalid port `%s'\n", optarg);
       return 1;
     }
     break;
   case 'u':
     if (dns_set_opt(NULL, DNS_OPT_UDPSIZE, atoi(optarg)) < 0) {
       fprintf(stderr, "invalid udp buffer size `%s'\n", optarg);
       return 1;
     }
     break;
   default: return 1;
   }

  dns_open(NULL);
  now = time(NULL);
  for (n = optind; n < argc; ++n)
    dns_submit_p(NULL, argv[n], qcls, qtyp, flags, 0, qcallback, argv[n], now);

  FD_ZERO(&rfd);
  fd = dns_sock(NULL);
  while(dns_active(NULL)) {
    struct timeval tv;
    FD_SET(fd, &rfd);
    n = dns_timeouts(NULL, -1, now);
    if (n < 0) break;
    tv.tv_sec = n;
    tv.tv_usec = 0;
    n = select(fd+1, &rfd, NULL, NULL, &tv);
    now = time(NULL);
    if (n > 0)
      dns_ioevent(NULL, now);
  }

  return 0;
}

