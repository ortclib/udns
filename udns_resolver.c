/* $Id: udns_resolver.c,v 1.13 2004/06/30 20:32:07 mjt Exp $
 * resolver stuff (main module)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <assert.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>
#ifdef HAVE_CONFIG_H
# include <config.h>
#endif
#ifdef HAVE_POLL
# include <sys/poll.h>
#endif
#include "udns.h"

#define DNS_INTERNAL	0xffff	/* internal flags mask */
#define DNS_SERVSENT	0x00ff	/* bitmask: nameservers we tried */
#define DNS_INITED	0x01ff	/* the context is initialized */
#define DNS_ASIS_SKIP	0x0200	/* skip the as-is query */
#define DNS_ASIS_LAST	0x0400	/* perform the as-is query last */

#define DNS_QEXTRA	16	/* size of extra buffer space */
#define DNS_QBUF	DNS_HSIZE+DNS_MAXDN+DNS_QEXTRA

struct dns_query {
  unsigned char dnsq_buf[DNS_QBUF];	/* the query buffer */
  unsigned dnsq_len;			/* length of the query packet */
  enum dns_class dnsq_cls;		/* requested RR class */
  enum dns_type  dnsq_typ;		/* requested RR type */
  unsigned dnsq_flags;			/* misc. flags for this query */
  dns_parse_fn *dnsq_parse;		/* parse: raw => application */
  dns_query_fn *dnsq_cbck;		/* the callback to call when done */
  void *dnsq_cbdata;			/* user data for the callback */
  unsigned dnsq_origdnl;		/* original length of the dnsq_dn */
  time_t dnsq_deadline;			/* when the query will "expire" */
  unsigned dnsq_try;			/* number of tries made so far */
  unsigned dnsq_servi;			/* current server index */
  unsigned dnsq_srchi;			/* current search index */
  int dnsq_srchs;			/* status from search query */
  struct dns_ctx *dnsq_ctx;		/* the resolver context */
  struct dns_query *dnsq_next;		/* active list */
};

struct dns_ctx {		/* resolver context */
  unsigned dnsc_flags;			/* various flags */
  unsigned dnsc_timeout;		/* timeout (base value) for queries */
#define LIM_TIMEOUT	1,300
  unsigned dnsc_ntries;			/* number of retries */
#define LIM_NTRIES	1,50
  unsigned dnsc_ndots;			/* ndots to assume absolute name */
#define LIM_NDOTS	0,1000
  unsigned dnsc_port;			/* default port (DNS_PORT) */
#define LIM_PORT	1,65535
  unsigned dnsc_udpbuf;			/* size of UDP buffer */
#define LIM_UDPBUF	DNS_MAXPACKET,65536
  int dnsc_udpsock;			/* UDP socket */
  /* array of nameserver addresses */
  struct sockaddr_in dnsc_serv[DNS_MAXSERV];
  unsigned dnsc_nserv;			/* number of nameservers */
  /* search list for unqualified names */
  unsigned char dnsc_srch[DNS_MAXSRCH][DNS_MAXDN];
  unsigned dnsc_nsrch;			/* number of srch[] */

  unsigned short dnsc_nextid;		/* next queue ID to use */

  dns_utm_fn *dnsc_utmfn;		/* register/cancel timer events */
  void *dnsc_uctx;			/* data pointer passed to utmfn() */
  void (*dnsc_udbgfn)(const unsigned char *r, int l);

  struct dns_query *dnsc_qactive;	/* active query list */
  unsigned char *dnsc_pbuf;		/* packet buffer (udpbuf size) */
  int dnsc_qstatus;			/* last query status value */
};

#define ISSPACE(x) (x == ' ' || x == '\t' || x == '\r' || x == '\n')

static const char space[] = " \t\r\n";

struct dns_ctx dns_defctx;

#define SETCTX(ctx) if (!ctx) ctx = &dns_defctx
#define SETCTXINITED(ctx) SETCTX(ctx); assert(CTXINITED(ctx))
#define CTXINITED(ctx) (ctx->dnsc_flags & DNS_INITED)
#define SETCTXFRESH(ctx) SETCTXINITED(ctx); assert(!CTXOPEN(ctx))
#define SETCTXOPEN(ctx) SETCTXINITED(ctx); assert(CTXOPEN(ctx))
#define CTXOPEN(ctx) (ctx->dnsc_udpsock >= 0)
#define CTXACTIVE(ctx) (ctx->dnsc_qactive != NULL)

static int dns_add_serv(struct dns_ctx *ctx, const char *ns) {
  struct sockaddr_in *sin = &ctx->dnsc_serv[ctx->dnsc_nserv];
  if (!inet_aton(ns, &sin->sin_addr))
    return 0;
  ++ctx->dnsc_nserv;
  return 1;
}

int dns_set_serv(struct dns_ctx *ctx, const char **servv) {
  SETCTXFRESH(ctx);
  ctx->dnsc_nserv = 0;
  while(*servv && ctx->dnsc_nserv < DNS_MAXSERV)
    dns_add_serv(ctx, *servv++);
  return ctx->dnsc_nserv;
}

static int
dns_set_num(const char *opt, const char *name, int *valp, int min, int max) {
  while(*name) if (*name++ != *opt++) return 0;
  if (*opt++ != ':') return 0;
  if (*opt < '0' || *opt > '9') return 1;
  if ((*valp = atoi(opt)) > max) *valp = max;
  else if (min && *valp < min) *valp = min;
  return 1;
}

static void dns_opts(struct dns_ctx *ctx, const char *opts) {
  for(;;) {
    while(ISSPACE(*opts)) ++opts;
    if (!*opts) break;
    if (!(dns_set_num(opts, "ndots", &ctx->dnsc_ndots, LIM_NDOTS) ||
          dns_set_num(opts, "retrans", &ctx->dnsc_timeout, LIM_TIMEOUT) ||
          dns_set_num(opts, "retry", &ctx->dnsc_ntries, LIM_NTRIES) ||
          dns_set_num(opts, "udpbuf", &ctx->dnsc_udpbuf, LIM_UDPBUF) ||
          dns_set_num(opts, "port", &ctx->dnsc_port, LIM_PORT)))
      (void)0;			/* unknown option? */
    while(*opts && !ISSPACE(*opts)) ++opts;
  }
}

int dns_set_opts(struct dns_ctx *ctx, const char *opts) {
  SETCTXFRESH(ctx);
  dns_opts(ctx, opts);
  return 0;
}

int dns_set_opt(struct dns_ctx *ctx, enum dns_opt opt, int val) {
  int prev;
  SETCTXFRESH(ctx);
  switch(opt) {
#define _oneopt(name,field,minval,maxval) \
  case name: \
    prev = ctx->field; \
    if (val >= 0) { \
      if (val < minval || val > maxval) return -1; \
      ctx->field = val; \
    } \
    break
#define oneopt(name,field,lim) _oneopt(name,field,lim)
  oneopt(DNS_OPT_NDOTS,  dnsc_ndots,  LIM_NDOTS);
  oneopt(DNS_OPT_TIMEOUT,dnsc_timeout,LIM_TIMEOUT);
  oneopt(DNS_OPT_NTRIES, dnsc_ntries, LIM_NTRIES);
  oneopt(DNS_OPT_UDPSIZE,dnsc_udpbuf, LIM_UDPBUF);
  oneopt(DNS_OPT_PORT,   dnsc_port,   LIM_PORT);
#undef oneopt
#undef _oneopt
  case DNS_OPT_FLAGS:
    prev = ctx->dnsc_flags & ~DNS_INTERNAL;
    if (val >= 0)
      ctx->dnsc_flags = val & DNS_INTERNAL;
  default:
    return -1;
  }
  return prev;
}

static int dns_add_srch(struct dns_ctx *ctx, const char *srch) {
  if (dns_sptodn(srch, ctx->dnsc_srch[ctx->dnsc_nsrch], DNS_MAXDN) <= 0)
    return 0;
  ++ctx->dnsc_nsrch;
  return 1;
}

int dns_set_srch(struct dns_ctx *ctx, const char **srchv) {
  SETCTXFRESH(ctx);
  ctx->dnsc_nsrch = 0;
  while(*srchv && ctx->dnsc_nsrch < DNS_MAXSRCH)
    dns_add_srch(ctx, *srchv++);
  return ctx->dnsc_nsrch;
}

void dns_set_dbgfn(struct dns_ctx *ctx, void (*fn)(const unsigned char *, int))
{
  SETCTXINITED(ctx);
  ctx->dnsc_udbgfn = fn;
}

void dns_set_tmcbck(struct dns_ctx *ctx, dns_utm_fn *utmfn, void *arg) {
  SETCTXINITED(ctx);
  ctx->dnsc_utmfn = utmfn;
  ctx->dnsc_uctx = arg;
}

static void dns_firstid(struct dns_ctx *ctx) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  ctx->dnsc_nextid = (tv.tv_usec ^ getpid()) & 0xffff;
}

int dns_init(int do_open) {
  FILE *f;
  char *v;
  char buf[2048];
  int srch_set = 0, serv_set = 0;
  struct dns_ctx *ctx = &dns_defctx;

  assert(!CTXINITED(ctx));

  memset(ctx, 0, sizeof(*ctx));
  ctx->dnsc_timeout = 4;
  ctx->dnsc_ntries = 3;
  ctx->dnsc_ndots = 1;
  ctx->dnsc_udpbuf = DNS_EDNS0PACKET;
  ctx->dnsc_port = DNS_PORT;
  ctx->dnsc_udpsock = -1;

  buf[sizeof(buf)-1] = '\0';

  if ((v = getenv("NSCACHEIP")) != NULL ||
      (v = getenv("NAMESERVERS")) != NULL) {
    strncpy(buf, v, sizeof(buf) - 1);
    for (v = strtok(v, space);
         v && ctx->dnsc_nserv < DNS_MAXSERV;
         v = strtok(NULL, space))
      dns_add_serv(ctx, v);
    if (ctx->dnsc_nserv)
      serv_set = 1;
  }
  if ((v = getenv("LOCALDOMAIN")) != NULL) {
    strncpy(buf, v, sizeof(buf) - 1);
    if ((v = strtok(v, space)) != NULL)
      dns_add_srch(ctx, v);
    srch_set = 1;
  }

  if ((f = fopen("/etc/resolv.conf", "r")) != NULL) {
    while(fgets(buf, sizeof buf, f)) {
      v = buf;
      while(*v && !ISSPACE(*v)) ++v;
      if (!*v) continue;
      *v++ = '\0';
      while(ISSPACE(*v)) ++v;
      if (!*v) continue;
      if (strcmp(buf, "domain") == 0) {
        if (!srch_set && !ctx->dnsc_nsrch &&
            (v = strtok(v, space)) != NULL)
          dns_add_srch(ctx, v);
      }
      else if (strcmp(buf, "search") == 0) {
        if (!srch_set) {
          ctx->dnsc_nsrch = 0;
          for (v = strtok(v, space);
               v && ctx->dnsc_nsrch < DNS_MAXSRCH;
               v = strtok(NULL, space))
            dns_add_srch(ctx, v);
          srch_set = 1;
        }
      }
      else if (strcmp(buf, "nameserver") == 0) {
        if (!serv_set &&
            ctx->dnsc_nserv < DNS_MAXSERV &&
            (v = strtok(v, space)) != NULL)
          dns_add_serv(ctx, v);
      }
      else if (strcmp(buf, "options") == 0)
        dns_opts(ctx, v);
    }
    if (ferror(f)) {
      fclose(f);
      return -1;
    }
    fclose(f);
  }
  else if (errno != ENOENT)
    return -1;

  if (!srch_set && !ctx->dnsc_nsrch &&
      gethostname(buf, sizeof(buf) - 1) == 0 &&
      (v = strchr(buf, '.')) != NULL &&
      *++v != '\0')
    dns_add_srch(ctx, v);

  if ((v = getenv("RES_OPTIONS")) != NULL)
    dns_opts(ctx, v);

  dns_firstid(ctx);
  ctx->dnsc_flags |= DNS_INITED;
  return do_open ? dns_open(ctx) : 0;
}

struct dns_ctx *dns_new(const struct dns_ctx *ctx) {
  struct dns_ctx *n;
  SETCTXINITED(ctx);
  n = calloc(sizeof(*n), 1);
  if (!n)
    return NULL;
  n->dnsc_udpsock = -1;
  dns_firstid(n);
  return n;
}

void dns_free(struct dns_ctx *ctx) {
  struct dns_query *q;
  SETCTXINITED(ctx);
  if (ctx->dnsc_udpsock >= 0)
    close(ctx->dnsc_udpsock);
  if (ctx->dnsc_pbuf)
    free(ctx->dnsc_pbuf);
  while((q = ctx->dnsc_qactive) != NULL) {
    ctx->dnsc_qactive = q->dnsq_next;
    free(q);
  }
  if (ctx != &dns_defctx)
    free(ctx);
  else
    memset(ctx, 0, sizeof(*ctx));
}

int dns_open(struct dns_ctx *ctx) {
  int sock;
  unsigned i;
  SETCTXINITED(ctx);
  assert(!CTXOPEN(ctx));

  /* create the socket */
  sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    ctx->dnsc_qstatus = DNS_E_TEMPFAIL;
    return -1;
  }
  if (fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) < 0 ||
      fcntl(sock, F_SETFD, FD_CLOEXEC) < 0) {
    close(sock);
    ctx->dnsc_qstatus = DNS_E_TEMPFAIL;
    return -1;
  }
  /* allocate the packet buffer */
  if (!(ctx->dnsc_pbuf = malloc(ctx->dnsc_udpbuf))) {
    close(sock);
    ctx->dnsc_qstatus = DNS_E_NOMEM;
    errno = ENOMEM;
    return -1;
  }
  /* ensure we have at least one server */
  if (!ctx->dnsc_nserv) {
    ctx->dnsc_serv[0].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ctx->dnsc_nserv = 1;
  }
  /* fix family and port for each sockaddr */
  for (i = 0; i < ctx->dnsc_nserv; ++i) {
    ctx->dnsc_serv[i].sin_family = AF_INET;
    ctx->dnsc_serv[i].sin_port = htons(ctx->dnsc_port);
  }

  ctx->dnsc_udpsock = sock;
  return sock;
}

void dns_close(struct dns_ctx *ctx) {
  SETCTXINITED(ctx);
  if (ctx->dnsc_udpsock < 0) return;
  close(ctx->dnsc_udpsock);
  ctx->dnsc_udpsock = -1;
  free(ctx->dnsc_pbuf);
  ctx->dnsc_pbuf = NULL;
}

int dns_sock(const struct dns_ctx *ctx) {
  SETCTXINITED(ctx);
  return ctx->dnsc_udpsock;
}

int dns_active(const struct dns_ctx *ctx) {
  SETCTXINITED(ctx);
  return CTXACTIVE(ctx);
}

int dns_status(const struct dns_ctx *ctx) {
  SETCTX(ctx);
  return ctx->dnsc_qstatus;
}
void dns_setstatus(struct dns_ctx *ctx, int status) {
  SETCTX(ctx);
  ctx->dnsc_qstatus = status;
}

static inline void
dns_utimer_cancel(struct dns_ctx *ctx, struct dns_query *q) {
  if (ctx->dnsc_utmfn)
    ctx->dnsc_utmfn(ctx->dnsc_uctx, q, 0);
}

static int
dns_end_query(struct dns_query *q, struct dns_query **qp,
              int status, void *result) {
  struct dns_ctx *ctx = q->dnsq_ctx;
  dns_query_fn *cbck = q->dnsq_cbck;
  void *cbdata = q->dnsq_cbdata;
  ctx->dnsc_qstatus = status;
  if (*qp) {
    assert(cbck != NULL);
    *qp = q->dnsq_next;
  }
  else {
    /* if there's no qp, this is new, just-submitted query */
    assert(status < 0);
  }
  /* force the query to be unconnected */
  /*memset(q, 0, sizeof(*q));*/
  q->dnsq_ctx = NULL;
  free(q);
  /*XXX a query may have no callback, right? */
  if (qp)
    cbck(ctx, status < 0 ? 0 : result, cbdata);
  return status;
}

static int dns_next_srch(struct dns_ctx *ctx, struct dns_query *q) {
  int ol = q->dnsq_origdnl - 1;
  unsigned char *p = dns_payload(q->dnsq_buf) + ol;
  const unsigned char *dn;
  int n;
  while (q->dnsq_srchi < ctx->dnsc_nsrch) {
    dn = ctx->dnsc_srch[q->dnsq_srchi++];
    if (!*dn) {			/* root dn */
      if (q->dnsq_flags & DNS_ASIS_SKIP)
        continue;
      q->dnsq_flags |= DNS_ASIS_SKIP;
      *p = '\0';
      n = 1;
    }
    else if ((n = dns_dntodn(dn, p, DNS_MAXDN - ol)) <= 0)
      continue;
    return n + ol;
  }
  return 0;
}

static int
dns_search_next(struct dns_ctx *ctx, struct dns_query *q, int status) {
  unsigned char save[DNS_QEXTRA+4];
  unsigned char *p;
  unsigned l, sl;

  assert(q->dnsq_next == 0);
  if (q->dnsq_flags & DNS_NOSRCH)
    return status;
  if (!q->dnsq_srchs)
    q->dnsq_srchs = status;

  p = dns_payload(q->dnsq_buf);
  l = dns_dnlen(p);
  sl = q->dnsq_len - l - DNS_HSIZE;
  assert(sl <= sizeof(save));
  memcpy(save, p + l, sl); 
  l = dns_next_srch(ctx, q);
  if (!l) {
    if (!(q->dnsq_flags & DNS_ASIS_LAST))
      return q->dnsq_srchs;
    q->dnsq_flags &= ~DNS_ASIS_LAST;
    l = q->dnsq_origdnl;
    p[l-1] = '\0';
  }
  memcpy(p + l, save, sl);
  q->dnsq_len = p + l + sl - q->dnsq_buf;
  q->dnsq_try = 0; q->dnsq_servi = 0;
  q->dnsq_flags &= ~DNS_SERVSENT;
  return 0;
}

static int
dns_resend(struct dns_query *q, struct dns_query **qp, int n, time_t now) {
  struct dns_ctx *ctx = q->dnsq_ctx;

  if (n && ++q->dnsq_servi >= ctx->dnsc_nserv) {
    if (++q->dnsq_try >= ctx->dnsc_ntries) {
      n = q->dnsq_srchs ? q->dnsq_srchs : DNS_E_TEMPFAIL;
      assert(n < 0);
      return dns_end_query(q, qp, n, 0);
    }
    q->dnsq_servi = 0;
  }
  /* send the query */
  n = 10;
  while (sendto(ctx->dnsc_udpsock, q->dnsq_buf, q->dnsq_len, 0,
                (struct sockaddr *)&ctx->dnsc_serv[q->dnsq_servi],
                sizeof(struct sockaddr_in)) < 0) {
    /*XXX just ignore the sendto() error for now and try again.
     * In the future, it may be possible to retrieve the error code
     * and find which operation/query failed.
     *XXX try the next server too?
     */
    if (--n) continue;
    /* if we can't send the query, fail it. */
    return dns_end_query(q, qp, DNS_E_TEMPFAIL, 0);
  }

  /* we sent this query to this nameserver */
  q->dnsq_flags |= 1 << q->dnsq_servi;

  /* set up the timeout, report error if failed */
  n = q->dnsq_try ?
    ctx->dnsc_timeout << q->dnsq_try / ctx->dnsc_nserv : ctx->dnsc_timeout;
  if (ctx->dnsc_utmfn &&
      ctx->dnsc_utmfn(ctx->dnsc_uctx, q, n) != 0) {
    return dns_end_query(q, qp, DNS_E_TEMPFAIL, 0);
  }

  q->dnsq_deadline = (now ? now : time(NULL)) + n;
  return 0;
}

static void dns_dummy_cb(struct dns_ctx *ctx, void *result, void *data) {
  if (result) free(result);
  data = ctx = 0;	/* used */
}

struct dns_query *
dns_submit_dn(struct dns_ctx *ctx,
              const unsigned char *dn, int qcls, int qtyp, int flags,
              dns_parse_fn *parse, dns_query_fn *cbck, void *data, time_t now) {
  unsigned char *p;
  unsigned dnl;
  struct dns_query *q;
  SETCTXOPEN(ctx);

  q = calloc(sizeof(*q), 1);
  if (!q) {
    ctx->dnsc_qstatus = DNS_E_NOMEM;
    return NULL;
  }
  flags = (flags | ctx->dnsc_flags) & ~DNS_INTERNAL;
  if (!ctx->dnsc_nsrch) q->dnsq_flags |= DNS_NOSRCH;
  if (!(flags & DNS_NORD)) q->dnsq_buf[DNS_H_F1] |= DNS_HF1_RD;
  if (flags & DNS_AAONLY) q->dnsq_buf[DNS_H_F1] |= DNS_HF1_AA;
  q->dnsq_buf[DNS_H_QDCNT2] = 1;

  q->dnsq_origdnl = dns_dnlen(dn);
  assert(q->dnsq_origdnl > 0 && q->dnsq_origdnl <= DNS_MAXDN);
  memcpy(dns_payload(q->dnsq_buf), dn, q->dnsq_origdnl);
  p = dns_payload(q->dnsq_buf) + q->dnsq_origdnl;
  if (flags & DNS_NOSRCH)
    ;
  else if (dns_dnlabels(dn) > ctx->dnsc_ndots)
    flags |= DNS_ASIS_SKIP;
  else if ((dnl = dns_next_srch(ctx, q)) > 0) {
    p = dns_payload(q->dnsq_buf) + dnl;
    flags |= DNS_ASIS_LAST;
  }
  else
    p[-1] = '\0';
  q->dnsq_flags = flags;
  q->dnsq_typ = qtyp;
  p = dns_put16(p, qtyp);
  q->dnsq_cls = qcls;
  p = dns_put16(p, qcls);
  if (ctx->dnsc_udpbuf > DNS_MAXPACKET) {
    p++;			/* empty (root) DN */
    p = dns_put16(p, DNS_T_OPT);
    p = dns_put16(p, ctx->dnsc_udpbuf);
    p += 2;		/* EDNS0 RCODE & VERSION */
    p += 2;		/* rest of the TTL field */
    p += 2;		/* RDLEN */
    q->dnsq_buf[DNS_H_ARCNT2] = 1;
  }
  assert(p <= q->dnsq_buf + DNS_QBUF);
  q->dnsq_len = p - q->dnsq_buf;

  q->dnsq_parse = parse;
  q->dnsq_cbck = cbck ? cbck : dns_dummy_cb;
  q->dnsq_cbdata = data;
  q->dnsq_ctx = ctx;

  /* caution: we're trying to submit a query
   * which isn't yet in the active list! */
  if (dns_resend(q, NULL, 0, now) == 0) {
    q->dnsq_next = ctx->dnsc_qactive;
    ctx->dnsc_qactive = q;
    return q;
  }
  else /* dns_end_query() freed the query object for us */
    return NULL;
}

struct dns_query *
dns_submit_p(struct dns_ctx *ctx,
             const char *name, int qcls, int qtyp, int flags,
             dns_parse_fn *parse, dns_query_fn *cbck, void *data, time_t now) {
  int isabs;
  unsigned char dn[DNS_MAXDN];
  if (dns_ptodn(name, 0, dn, DNS_MAXDN, &isabs) <= 0) {
    ctx->dnsc_qstatus = DNS_E_BADQUERY;
    return NULL;
  }
  if (isabs)
    flags |= DNS_NOSRCH;
  return dns_submit_dn(ctx, dn, qcls, qtyp, flags, parse, cbck, data, now);
}

/* handle user timer timeout (may happen only for active requests).
 * Note the user timer has been cancelled (expired in fact) already. */
void dns_tmevent(struct dns_query *q, time_t now) {
  struct dns_ctx *ctx = q->dnsq_ctx;
  struct dns_query **qp;
  assert(ctx != NULL);
  assert(q->dnsq_deadline > 0 && (now ? now : time(NULL)) >= q->dnsq_deadline);
  qp = &ctx->dnsc_qactive;
  while(*qp != q) {
    assert(*qp != NULL);
    assert((*qp)->dnsq_ctx == ctx);
    qp = &(*qp)->dnsq_next;
  }
  dns_resend(q, qp, 1, now);
}

/* process readable fd condition.
 * To be usable in edje-triggered environment, the routine
 * should consume all input so it should loop over.
 * Note it isn't really necessary to loop here, because
 * an application may perform the loop just fine by it's own,
 * but in this case we should return some sensitive result,
 * to indicate when to stop calling and error conditions.
 * Note also we may encounter all sorts of recvfrom()
 * errors which aren't fatal, and at the same time we may
 * loop forever if an error IS fatal.
 * Current loop/goto looks just terrible... */
void dns_ioevent(struct dns_ctx *ctx, time_t now) {
  int r;
  unsigned servi;
  struct dns_query *q, **qp;
  unsigned char *pbuf;
  void *result;

  SETCTX(ctx);
  if (!CTXOPEN(ctx))
    return;
  pbuf = ctx->dnsc_pbuf;

again:

  assert(CTXOPEN(ctx));

  for(;;) { /* receive the reply */
    struct sockaddr_in sin;
    socklen_t sinlen;
    sinlen = sizeof(sin);
    r = recvfrom(ctx->dnsc_udpsock, pbuf, ctx->dnsc_udpbuf, 0,
                 (struct sockaddr *)&sin, &sinlen);
    if (r < 0) {
      /*XXX just ignore recvfrom() errors for now.
       * in the future it may be possible to determine which
       * query failed and requeue it.
       * Note there may be various error conditions, triggered
       * by both local problems and remote problems.  It isn't
       * quite trivial to determine whenever an error is local
       * or remote.  On local errors, we should stop, while
       * remote errors should be ignored (for now anyway).
       */
      if (errno == EAGAIN) return;
      continue;
    }
    if (r < DNS_HSIZE)
      continue;
    /* ignore replies from wrong server */
    if (sin.sin_family != AF_INET)
      continue;
    if (sinlen != sizeof(sin))
      continue;
    servi = 0;
    while(memcmp(&ctx->dnsc_serv[servi], &sin, sizeof(sin)) != 0)
      if (++servi >= ctx->dnsc_nserv)
        goto again;
 
    if (ctx->dnsc_udbgfn)
      ctx->dnsc_udbgfn(pbuf, r);

    if (dns_numqd(pbuf) != 1) continue;	/* too many questions? */
    if (dns_opcode(pbuf)) continue;	/*XXX ignore non-query replies ? */

    /* truncation bit (TC).  Ooh, we don't handle TCP (yet?),
     * but we do handle larger UDP sizes.
     * Note that e.g. djbdns will only send header if resp.
     * does not fit, not whatever is fit in 512 bytes. */
    if (dns_tc(pbuf))
      continue;	/* just ignore response for now.. any hope? */

    /* find the request for this reply, in active queue
     * (by looking at QID).
     * Note we pick any request, even queued for another
     * server - in case first server replies a bit later
     * than we expected. */
    for (qp = &ctx->dnsc_qactive; ; qp = &q->dnsq_next) {
      int l;
      if (!(q = *qp))	/* no more requests: old reply? */
        goto again;
      /* skip requests that has not been sent to this
       * server yet. */
      if (!(q->dnsq_flags & (1 << servi)))
        continue;
      if (q->dnsq_buf[DNS_H_QID1] != pbuf[DNS_H_QID1] ||
          q->dnsq_buf[DNS_H_QID2] != pbuf[DNS_H_QID2])
        continue;
      if (!(l = dns_dnequal(dns_payload(q->dnsq_buf), dns_payload(pbuf))))
        continue;
      if (DNS_HSIZE + l + 4 > r)
        goto again;
      if (memcmp(dns_payload(q->dnsq_buf) + l, dns_payload(pbuf) + l, 4) != 0)
        continue;
      break;
    }
    break;

  }

  /* we got a reply for our query */
  dns_utimer_cancel(ctx, q);

  /* process the RCODE */
  switch(dns_rcode(pbuf)) {

  case DNS_R_SERVFAIL:
  case DNS_R_NOTIMPL:
  case DNS_R_REFUSED:
    /* for these rcodes, advance this request
     * to the next server and reschedule */
  default: /* unknown rcode? hmmm... */
    dns_resend(q, qp, 1, now);
    goto again;

  case DNS_R_NXDOMAIN:
    if ((r = dns_search_next(ctx, q, DNS_E_NXDOMAIN)) == 0)
      dns_resend(q, qp, 0, now);
    else
      dns_end_query(q, qp, r, 0);
    break;

  case DNS_R_NOERROR:
    if (!dns_numan(pbuf)) {
      if ((r = dns_search_next(ctx, q, DNS_E_NODATA)) == 0)
        dns_resend(q, qp, 0, now);
      else
        dns_end_query(q, qp, r, 0);
      break;
    }
    if (q->dnsq_parse)
      r = q->dnsq_parse(pbuf, pbuf + r, &result);
    else if ((result = malloc(r)) != NULL)
      memcpy(result, pbuf, r);
    else
      r = DNS_E_NOMEM;
    dns_end_query(q, qp, r, result);
    break;

  }

  goto again;
}

/* handle all timeouts */
int dns_timeouts(struct dns_ctx *ctx, int maxwait, time_t now) {
  struct dns_query *q, **qp;
  int timeout, towait = maxwait;
  SETCTX(ctx);
  if (!CTXACTIVE(ctx)) return maxwait;
  if (!now) now = time(NULL);
  qp = &ctx->dnsc_qactive;
  while ((q = *qp) != NULL) {
    if (q->dnsq_deadline <= now &&
        dns_resend(q, qp, 1, now) != 0) {
      /* start over */
      qp = &ctx->dnsc_qactive;
      towait = maxwait;
    }
    else {
      if (towait != 0) {
        timeout = q->dnsq_deadline - now;
        if (towait < 0 || timeout < towait)
          towait = timeout;
      }
      qp = &q->dnsq_next;
    }
  }
  return towait;
}

struct dns_resolve_data {
  int   dnsrd_done;
  void *dnsrd_result;
};

static void dns_resolve_cb(struct dns_ctx *ctx, void *result, void *data) {
  struct dns_resolve_data *d = data;
  d->dnsrd_result = result;
  d->dnsrd_done = 1;
  ctx = ctx;
}

void *dns_resolve(struct dns_ctx *ctx, struct dns_query *q) {
  time_t now;
#ifdef HAVE_POLL
  struct pollfd pfd;
#else
  fd_set rfd;
  struct timeval tv;
#endif
  struct dns_resolve_data d;
  int n;
  SETCTXOPEN(ctx);

  if (!q)
    return NULL;

  assert(ctx == q->dnsq_ctx);
  /* do not allow re-resolving syncronous queries */
  assert(q->dnsq_cbck != dns_resolve_cb && "can't resolve syncronous query");
  if (q->dnsq_cbck == dns_resolve_cb) {
    ctx->dnsc_qstatus = DNS_E_BADQUERY;
    return NULL;
  }
  q->dnsq_cbck = dns_resolve_cb;
  q->dnsq_cbdata = &d;
  d.dnsrd_done = 0;

#ifdef HAVE_POLL
  pfd.fd = ctx->dnsc_udpsock;
  pfd.events = POLLIN;
#else
  FD_ZERO(&rfd);
#endif

  now = time(NULL);
  while(!d.dnsrd_done && (n = dns_timeouts(ctx, -1, now)) >= 0) {
#ifdef HAVE_POLL
    n = poll(&pfd, 1, n * 1000);
#else
    tv.tv_sec = n;
    tv.tv_usec = 0;
    FD_SET(ctx->dnsc_udpsock, &rfd);
    n = select(ctx->dnsc_udpsock + 1, &rfd, NULL, NULL, &tv);
#endif
    now = time(NULL);
    if (n > 0)
      dns_ioevent(ctx, now);
  }

  return d.dnsrd_result;
}

void *dns_resolve_dn(struct dns_ctx *ctx,
                     const unsigned char *dn, int qcls, int qtyp, int flags,
                     dns_parse_fn *parse) {
  return
    dns_resolve(ctx,
      dns_submit_dn(ctx, dn, qcls, qtyp, flags, parse, NULL, NULL, 0));
}

void *dns_resolve_p(struct dns_ctx *ctx,
                    const char *name, int qcls, int qtyp, int flags,
                    dns_parse_fn *parse) {
  return
    dns_resolve(ctx,
      dns_submit_p(ctx, name, qcls, qtyp, flags, parse, NULL, NULL, 0));
}

int dns_cancel(struct dns_ctx *ctx, struct dns_query *q) {
  struct dns_query **qp;
  SETCTX(ctx);
  assert(q->dnsq_ctx == ctx);
  /* do not allow cancelling syncronous queries */
  assert(q->dnsq_cbck != dns_resolve_cb && "can't cancel syncronous query");
  if (q->dnsq_cbck == dns_resolve_cb)
    return (ctx->dnsc_qstatus = DNS_E_BADQUERY);
  for(qp = &ctx->dnsc_qactive; *qp; qp = &(*qp)->dnsq_next) {
    if (*qp != q) continue;
    *qp = q->dnsq_next;
    dns_utimer_cancel(ctx, q);
    free(q);
    return 0;
  }
  return (ctx->dnsc_qstatus = DNS_E_BADQUERY);
}
