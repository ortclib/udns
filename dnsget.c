#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include "udns.h"

static char *progname;
static int verbose = 1;
static int errors;
static int notfound;

static const struct qtype {
  const char *name;
  enum dns_type qtyp;
  int flags;
} qtypes[] = {
  { "a",    DNS_T_A,    0 },
  { "aaaa", DNS_T_AAAA, 0 },
  { "ptr",  DNS_T_PTR,  1 },
  { "mx",   DNS_T_MX,   0 },
  { "txt",  DNS_T_TXT,  0 },
  { 0, 0, 0 }
};

static const struct qtype *qt;
static enum dns_class qcls = DNS_C_IN;

static void
dnserror(const char *name, int errnum) {
  if (verbose >= 0)
    fprintf(stderr, "%s: unable to lookup %s record for %s: %s\n",
            progname, qt->name, name, dns_strerror(errnum));
  if (errnum == DNS_E_NXDOMAIN || errnum == DNS_E_NODATA)
    ++notfound;
  else
    ++errors;
}

static void xperr() {
  printf("<parse error>\n");
  ++errors;
}

static int
printsection(const unsigned char *pkt,
             const unsigned char **curp,
             const unsigned char *end,
	     enum dns_class qcls, enum dns_type qtyp,
             int nrr, const char *name) {
  unsigned char dn[DNS_MAXDN];
  enum dns_class cls;
  enum dns_type  typ;
  unsigned ttl;
  unsigned dsz;
  const unsigned char *dptr, *dend, *c, *cur = *curp;
  int n;
  if (!nrr) return 0;
  if (verbose > 1) printf("\n;; %s section (%d):\n", name, nrr);

  while(nrr--) {
    if (dns_getdn(pkt, &cur, end, dn, sizeof(dn)) <= 0)
      return -1;
    if (cur + 10 > end) return -1;
    typ = dns_get16(cur); cur += 2;
    cls = dns_get16(cur); cur += 2;
    ttl = dns_get32(cur); cur += 4;
    dsz = dns_get16(cur); cur += 2;
    dptr = cur;
    dend = cur = cur + dsz;
    if (cur > end) return -1;
    if (qcls && cls != qcls) continue;
    if (qtyp &&
        (typ != qtyp && (typ != DNS_T_CNAME || verbose <= 0)))
      continue;
    if (verbose > 0) {
      if (verbose > 1) {
        if (!nrr && !dn[0] && typ == DNS_T_OPT) {
          printf(";EDNS0 OPT record (UDPsize: %d): %d bytes\n", cls, dsz);
          continue;
	}
        n = printf("%s.", dns_dntosp(dn));
        printf("%s%u\t%s\t%s\t",
               n > 15 ? "\t" : n > 7 ? "\t\t" : "\t\t\t",
               ttl, dns_classname(cls), dns_typename(typ));
      }
      else printf("%s. %s ", dns_dntosp(dn), dns_typename(typ));
    }
    switch(typ) {

    case DNS_T_CNAME:
    case DNS_T_PTR:
    case DNS_T_NS:
    case DNS_T_MB:
    case DNS_T_MD:
    case DNS_T_MF:
    case DNS_T_MG:
    case DNS_T_MR:
      if (dns_getdn(pkt, &dptr, dend, dn, sizeof(dn)) <= 0) {
        xperr(); continue;
      }
      printf("%s.\n", dns_dntosp(dn));
      break;

    case DNS_T_A:
      if (dsz != 4) xperr();
      else printf("%d.%d.%d.%d\n", dptr[3], dptr[2], dptr[1], dptr[0]);
      break;

    case DNS_T_AAAA:
      if (dsz != 16) xperr();
      else printf("%s\n", inet_ntop(AF_INET6, dptr, dn, 16));
      break;

    case DNS_T_MX:
      c = dptr + 2;
      if (dns_getdn(pkt, &c, dend, dn, sizeof(dn)) <= 0) xperr();
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
      if (!c) continue;
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
      if (dns_getdn(pkt, &dptr, dend, dn, sizeof(dn)) <= 0) { xperr(); break; }
      printf("%s. ", dns_dntosp(dn));
      if (dns_getdn(pkt, &dptr, dend, dn, sizeof(dn)) <= 0) { xperr(); break; }
      printf("%s. ", dns_dntosp(dn));
      if (dptr + 4*5 != dend) { xperr(); break; }
      printf("%u %u %u %u %u\n",
             dns_get32(dptr), dns_get32(dptr+4), dns_get32(dptr+8),
             dns_get32(dptr+12), dns_get32(dptr+16));
      break;

    case DNS_T_MINFO:
      if (dns_getdn(pkt, &dptr, dend, dn, sizeof(dn)) <= 0) { xperr(); break; }
      printf("%s. ", dns_dntosp(dn));
      if (dns_getdn(pkt, &dptr, dend, dn, sizeof(dn)) <= 0) { xperr(); break; }
      printf("%s.\n", dns_dntosp(dn));
      break;

    case DNS_T_HINFO:
    case DNS_T_WKS:
    case DNS_T_A6:
    case DNS_T_NULL:

    default:
      printf("<unknown RR type (size %d)>\n", dsz);
      break;
    }
  }
  *curp = cur;
  return 0;
}

static void dnscb(struct dns_ctx *ctx, void *result, void *data) {
  int r = dns_status(ctx);
  const char *name = data;
  const unsigned char *pkt = result;
  const unsigned char *end = pkt + r;
  const unsigned char *cur, *qdn;
  enum dns_class qcls;
  enum dns_type  qtyp;
  if (!result) {
    dnserror(name, r);
    return;
  }
  qdn = dns_payload(pkt);
  cur = qdn + dns_dnlen(qdn);
  if (verbose > 1) {
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
    r = printf(";%s.", dns_dntosp(qdn));
    printf("%s%s\t%s\n",
           r > 23 ? "\t" : r > 15 ? "\t\t" : r > 7 ? "\t\t\t" : "\t\t\t\t",
           dns_classname(dns_get16(cur+2)), dns_typename(dns_get16(cur)));
    qcls = 0; qtyp = 0;
  }
  else {
    qtyp = dns_get16(cur);   if (qtyp == DNS_T_ANY) qtyp = 0;
    qcls = dns_get16(cur+2); if (qcls == DNS_C_ANY) qcls = 0;
  }
  cur += 4;
  r = printsection(pkt, &cur, end, qcls, qtyp, dns_numan(pkt), "ANSWER");
  if (r < 0 || verbose <= 1) { free(result); return; }
  if (r == 0)
    r = printsection(pkt, &cur, end, 0, 0, dns_numns(pkt), "AUTHORITY");
  if (r == 0)
    r = printsection(pkt, &cur, end, 0, 0, dns_numar(pkt), "ADDITIONAL");
  putchar('\n');
  free(result);
}

int main(int argc, char **argv) {
  int i;
  int fd;
  fd_set fds;
  struct timeval tv;
  time_t now;
  struct qtype qtp;

  if (!(progname = strrchr(argv[0], '/'))) progname = argv[0];
  else argv[0] = ++progname;

  while((i = getopt(argc, argv, "vqt:c:")) != EOF) switch(i) {
  case 'v': ++verbose; break;
  case 'q': --verbose; break;
  case 't':
#if 0
    for (i = 0; qtypes[i].name; ++i)
      if (strcmp(qtypes[i].name, optarg) == 0)
        break;
    if (!qtypes[i].name) {
      fprintf(stderr, "%s: unrecognized query type %s\n", progname, optarg);
      return 1;
    }
    qt = &qtypes[i];
#else
    i = dns_findtypename(optarg);
    if (!i) {
      fprintf(stderr, "%s: unrecognized query type %s\n", progname, optarg);
      return 1;
    }
    qtp.qtyp = i;
    qtp.name = optarg;
    qt = &qtp;
#endif
    break;
  case 'c':
    if (strcmp(optarg, "in") == 0) qcls = DNS_C_IN;
    else if (strcmp(optarg, "ch") == 0) qcls = DNS_C_CH;
    else if (strcmp(optarg, "hs") == 0) qcls = DNS_C_HS;
    else if (strcmp(optarg, "any") == 0) qcls = DNS_C_ANY;
    else if (strcmp(optarg, "*") == 0) qcls = DNS_C_ANY;
    else {
      fprintf(stderr, "%s: unrecognized class type %s\n", progname, optarg);
      return 1;
    }
    break;
  default: return 1;
  }

  argc -= optind; argv += optind;

  fd = dns_init(1);
  if (fd < 0) {
    fprintf(stderr, "%s: unable to initialize dns library: %m\n", progname);
    return 1;
  }

  now = time(NULL);
  if (!qt) qt = qtypes;
  for(i = 0; i < argc; ++i) {
    if (!dns_submit_p(0, argv[i], qcls, qt->qtyp, 0, 0, dnscb, argv[i], now))
      dnserror(argv[i], dns_status(0));
  }

  FD_ZERO(&fds);
  while((i = dns_timeouts(0, -1, now)) > 0) {
    FD_SET(fd, &fds);
    tv.tv_sec = i;
    tv.tv_usec = 0;
    i = select(fd+1, &fds, 0, 0, &tv);
    now = time(NULL);
    if (i > 0) dns_ioevent(0, now);
  }

  return errors ? 1 : notfound ? 100 : 0;
}
