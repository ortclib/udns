/* $Id: udns_dn.c,v 1.3 2004/06/29 07:46:39 mjt Exp $
 * domain names manipulation routines
 */

#include <string.h>
#include "udns.h"

unsigned dns_dnlen(const unsigned char *dn) {
  register const unsigned char *d = dn;
  while(*d)
    d += 1 + *d;
  return (unsigned)(d - dn) + 1;
}

unsigned dns_dnlabels(register const unsigned char *dn) {
  register unsigned l = 0;
  while(*dn)
    ++l, dn += 1 + *dn;
  return l;
}

unsigned dns_dnequal(register const unsigned char *dn1,
                     register const unsigned char *dn2) {
  register unsigned c;
  const unsigned char *dn = dn1;
  for(;;) {
    if ((c = *dn1++) != *dn2++)
      return 0;
    if (!c)
      return (unsigned)(dn1 - dn);
    while(c--) {
      if (DNS_DNLC(*dn1) != DNS_DNLC(*dn2))
        return 0;
      ++dn1; ++dn2;
    }
  }
}

unsigned
dns_dntodn(const unsigned char *sdn, unsigned char *ddn, unsigned ddnsiz) {
  unsigned sdnlen = dns_dnlen(sdn);
  if (ddnsiz < sdnlen)
    return 0;
  memcpy(ddn, sdn, sdnlen);
  return sdnlen;
}

int
dns_ptodn(const char *name, unsigned namelen,
          unsigned char *dn, unsigned dnsiz,
          int *isabs)
{
  unsigned char *dp;		/* current position in dn (len byte first) */
  unsigned char *const de	/* end of dn: last byte that can be filled up */
      = dn + (dnsiz >= DNS_MAXDN ? DNS_MAXDN : dnsiz) - 1;
  const unsigned char *np = (const unsigned char *)name;
  const unsigned char *ne = np + (namelen ? namelen : strlen(np));
  unsigned char *llab;	/* start of last label (llab[-1] will be length) */
  unsigned c;		/* next input character, or length of last label */

  if (!dnsiz)
    return 0;
  dp = llab = dn + 1;

  while(np < ne) {

    if (*np == '.') {	/* label delimiter */
      c = dp - llab;		/* length of the label */
      if (!c) {			/* empty label */
        if (np == (const unsigned char *)name && np + 1 == ne) {
          /* special case for root dn, aka `.' */
          ++np;
          break;
        }
        return -1;		/* zero label */
      }
      if (c > DNS_MAXLABEL)
        return -1;		/* label too long */
      llab[-1] = (unsigned char)c; /* update len of last label */
      llab = ++dp; /* start new label, llab[-1] will be len of it */
      ++np;
      continue;
    }

    /* check whenever we may put out one more byte */
    if (dp >= de) /* too long? */
      return dnsiz >= DNS_MAXDN ? -1 : 0;
    if (*np != '\\') { /* non-escape, simple case */
      *dp++ = *np++;
      continue;
    }
    /* handle \-style escape */
    /* note that traditionally, domain names (gethostbyname etc)
     * used decimal \dd notation, not octal \ooo (RFC1035), so
     * we're following this tradition here.
     */
    if (++np == ne)
      return -1;			/* bad escape */
    else if (*np >= '0' && *np <= '9') { /* decimal number */
      /* we allow not only exactly 3 digits as per RFC1035,
       * but also 2 or 1, for better usability. */
      c = *np++ - '0';
      if (np < ne && *np >= '0' && *np <= '9') { /* 2digits */
        c = c * 10 + *np++ - '0';
        if (np < ne && *np >= '0' && *np <= '9') {
          c = c * 10 + *np++ - '0';
          if (c > 255)
            return -1;			/* bad escape */
        }
      }
    }
    else
      c = *np++;
    *dp++ = (unsigned char)c; /* place next out byte */
  }

  if ((c = dp - llab) > DNS_MAXLABEL)
    return -1;				/* label too long */
  if ((llab[-1] = (unsigned char)c) != 0) {
    *dp++ = 0;
    if (isabs)
      *isabs = 0;
  }
  else if (isabs)
    *isabs = 1;

  return dp - dn;
}

const unsigned char dns_inaddr_arpa_dn[14] = "\07in-addr\04arpa";

unsigned char *
dns_a4todn_(const struct in_addr *addr, unsigned char *dn, unsigned char *dne) {
  unsigned char *p;
  unsigned n;
  const unsigned char *s = ((const unsigned char *)addr) + 4;
  while(--s >= (const unsigned char *)addr) {
    n = *s;
    p = dn + 1;
    if (n > 99) {
      if (p + 2 > dne) return 0;
      *p++ = n / 100 + '0';
      *p++ = (n % 100 / 10) + '0';
      *p = n % 10 + '0';
    }
    else if (n > 9) {
      if (p + 1 > dne) return 0;
      *p++ = n / 10 + '0';
      *p = n % 10 + '0';
    }
    else {
      if (p > dne) return 0;
      *p = n + '0';
    }
    *dn = p - dn;
    dn = p + 1;
  }
  return dn;
}

int dns_a4todn(const struct in_addr *addr, const unsigned char *tdn,
               unsigned char *dn, unsigned dnsiz) {
  unsigned char *dne = dn + (dnsiz > DNS_MAXDN ? DNS_MAXDN : dnsiz);
  unsigned char *p;
  unsigned l;
  p = dns_a4todn_(addr, dn, dne);
  if (!p) return 0;
  if (!tdn)
    tdn = dns_inaddr_arpa_dn;
  l = dns_dnlen(tdn);
  if (p + l > dne) return dnsiz >= DNS_MAXDN ? -1 : 0;
  memcpy(p, tdn, l);
  return (p + l) - dn;
}

int dns_a4ptodn(const struct in_addr *addr, const char *tname,
                unsigned char *dn, unsigned dnsiz) {
  unsigned char *p;
  int r;
  if (!tname)
    return dns_a4todn(addr, NULL, dn, dnsiz);
  p = dns_a4todn_(addr, dn, dn + dnsiz);
  if (!p) return 0;
  r = dns_sptodn(tname, p, dnsiz - (p - dn));
  return r != 0 ? r : dnsiz >= DNS_MAXDN ? -1 : 0;
}

const unsigned char dns_ip6_arpa_dn[10] = "\03ip6\04arpa";

unsigned char *
dns_a6todn_(const struct in6_addr *addr,
            unsigned char *dn, unsigned char *dne) {
  unsigned n;
  const unsigned char *s = ((const unsigned char *)addr) + 16;
  if (dn + 64 > dne) return 0;
  while(--s >= (const unsigned char *)addr) {
    *dn++ = 1;
    n = *s & 0x0f;
    *dn++ = n > 9 ? n + 'a' - 10 : n + '0';
    *dn++ = 1;
    n = *s >> 4;
    *dn++ = n > 9 ? n + 'a' - 10 : n + '0';
  }
  return dn;
}

int dns_a6todn(const struct in6_addr *addr, const unsigned char *tdn,
               unsigned char *dn, unsigned dnsiz) {
  unsigned char *dne = dn + (dnsiz > DNS_MAXDN ? DNS_MAXDN : dnsiz);
  unsigned char *p;
  unsigned l;
  p = dns_a6todn_(addr, dn, dne);
  if (!p) return 0;
  if (!tdn)
    tdn = dns_ip6_arpa_dn;
  l = dns_dnlen(tdn);
  if (p + l > dne) return dnsiz >= DNS_MAXDN ? -1 : 0;
  memcpy(p, tdn, l);
  return (p + l) - dn;
}

int dns_a6ptodn(const struct in6_addr *addr, const char *tname,
                unsigned char *dn, unsigned dnsiz) {
  unsigned char *p;
  int r;
  if (!tname)
    return dns_a6todn(addr, NULL, dn, dnsiz);
  p = dns_a6todn_(addr, dn, dn + dnsiz);
  if (!p) return 0;
  r = dns_sptodn(tname, p, dnsiz - (p - dn));
  return r != 0 ? r : dnsiz >= DNS_MAXDN ? -1 : 0;
}

/* return size of buffer required to convert the dn into asciiz string.
 * Keep in sync with dns_dntop() below.
 */
unsigned dns_dntop_size(const unsigned char *dn) {
  unsigned size = 0;			/* the size reqd */
  const unsigned char *le;		/* label end */

  while(*dn) {
    /* *dn is the length of the next label, non-zero */
    if (size)
      ++size;		/* for the dot */
    le = dn + *dn + 1;
    ++dn;
    do {
      switch(*dn) {
      case '.':
      case '\\':
      /* Special modifiers in zone files. */
      case '"':
      case ';':
      case '@':
      case '$':
        size += 2;
        break;
      default:
        if (*dn <= 0x20 || *dn >= 0x7f)
          /* \ddd decimal notation */
          size += 4;
        else
          size += 1;
      }
    } while(++dn < le);
  }
  size += 1;	/* zero byte at the end - string terminator */
  return size > DNS_MAXNAME ? 0 : size;
}

/* Convert the dn into asciiz string.
 * Keep in sync with dns_dntop_size() above.
 */
int dns_dntop(const unsigned char *dn, char *name, unsigned namesiz) {
  char *np = name;			/* current name ptr */
  char *const ne = name + namesiz;	/* end of name */
  const unsigned char *le;		/* label end */

  while(*dn) {
    /* *dn is the length of the next label, non-zero */
    if (np != name) {
      if (np >= ne) goto toolong;
      *np++ = '.';
    }
    le = dn + *dn + 1;
    ++dn;
    do {
      switch(*dn) {
      case '.':
      case '\\':
      /* Special modifiers in zone files. */
      case '"':
      case ';':
      case '@':
      case '$':
        if (np + 2 > ne) goto toolong;
        *np++ = '\\';
        *np++ = *dn;
        break;
      default:
        if (*dn <= 0x20 || *dn >= 0x7f) {
          /* \ddd decimal notation */
          if (np + 4 >= ne) goto toolong;
          *np++ = '\\';
          *np++ = '0' + (*dn / 100);
          *np++ = '0' + ((*dn % 100) / 10);
          *np++ = '0' + (*dn % 10);
        }
        else {
          if (np >= ne) goto toolong;
          *np++ = *dn;
        }
      }
    } while(++dn < le);
  }
  if (np >= ne) goto toolong;
  *np++ = '\0';
  return np - name;
toolong:
  return namesiz >= DNS_MAXNAME ? -1 : 0;
}

#ifdef TEST
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
  int i;
  int sz;
  unsigned char dn[DNS_MAXDN+10];
  unsigned char *dl, *dp;
  int isabs;

  sz = (argc > 1) ? atoi(argv[1]) : 0;

  for(i = 2; i < argc; ++i) {
    int r = dns_ptodn(argv[i], 0, dn, sz, &isabs);
    printf("%s: ", argv[i]);
    if (r < 0) printf("error\n");
    else if (!r) printf("buffer too small\n");
    else {
      printf("len=%d dnlen=%d size=%d name:",
             r, dns_dnlen(dn), dns_dntop_size(dn));
      dl = dn;
      while(*dl) {
        printf(" %d=", *dl);
        dp = dl + 1;
        dl = dp + *dl;
        while(dp < dl) {
          if (*dp <= ' ' || *dp >= 0x7f)
            printf("\\%03d", *dp);
          else if (*dp == '.' || *dp == '\\')
            printf("\\%c", *dp);
          else
            putchar(*dp);
          ++dp;
        }
      }
      if (isabs) putchar('.');
      putchar('\n');
    }
  }
  return 0;
}

#endif /* TEST */
