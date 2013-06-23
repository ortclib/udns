/* $Id: udns_resolver.c,v 1.4 2004/06/29 07:46:39 mjt Exp $
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
#define DNS_ASIS_SKIP	0x0100	/* skip the as-is query */
#define DNS_ASIS_LAST	0x0200	/* perform the as-is query last */
#define DNS_DONE	0x0400	/* the query finished */

struct dns_ctx {		/* resolver context */
  int dnsc_flags;		/* various flags */
  int dnsc_timeout;		/* timeout (base value) for queries */
#define LIM_TIMEOUT	1,300
  int dnsc_ntries;		/* number of retries */
#define LIM_NTRIES	1,50
  int dnsc_ndots;		/* ndots to assume absolute name */
#define LIM_NDOTS	0,1000
  int dnsc_port;		/* default port (DNS_PORT) */
#define LIM_PORT	1,65535
  int dnsc_udpbuf;		/* size of UDP buffer */
#define LIM_UDPBUF	DNS_MAXPACKET,65536
  int dnsc_maxreq;		/* max. no of parallel queries */
#define LIM_MAXREQ	1,65536
  int dnsc_udpsock;		/* UDP socket */
  /* array of nameserver addresses */
  struct sockaddr_in dnsc_serv[DNS_MAXSERV];
  int dnsc_nserv;		/* number of nameservers (entries in serv[]) */
  /* search list for unqualified names */
  unsigned char dnsc_srch[DNS_MAXSRCH][DNS_MAXDN];
  int dnsc_nsrch;		/* number of search entries (in srch[]) */

  int dnsc_nextid;		/* next queue ID to use */

  /* routine to register (timeout>0) or cancel (timeout==0) timer events */
  int (*dnsc_utmfn)(void *uctx, struct dns_query *q, int timeout);
  /* data pointer passed to utmfn() */
  void *dnsc_uctx;
  void (*dnsc_udbgfn)(const unsigned char *r, int l);

  /* internal state, do not touch these */
  struct dns_query *dnsc_qactive;	/* active request queue */
  struct dns_query *dnsc_qsched;	/* to-schedule request queue */
  struct dns_query *dnsc_qtodo;		/* todo request queue */
  struct dns_query *dnsc_qdone;		/* completed queries */
  int dnsc_nactive;		/* number of active (qactive+qsched) reqs */
  int dnsc_nreq;		/* total number of reqs (nactive+qtodo) */
  int dnsc_loop;		/* reenterancy check */
  unsigned char *dnsc_pbuf;	/* packet buffer (udpbuf size) */
};

#define ISSPACE(x) (x == ' ' || x == '\t' || x == '\r' || x == '\n')

static const char space[] = " \t\r\n";

struct dns_ctx dns_defctx;

#define INITCTX(ctx) \
	if (!(ctx ? ctx : (ctx = &dns_defctx))->dnsc_nserv) dns_init()
#define SETCTX(ctx) if (!ctx) ctx = &dns_defctx
#define CTXACTIVE(ctx) ctx->dnsc_nactive
#define CTXINITED(ctx) ctx->dnsc_nserv
#define CTXFRESH(ctx) (ctx->dnsc_nserv && !ctx->dnsc_nactive)

static int dns_add_serv(struct dns_ctx *ctx, const char *ns) {
  struct sockaddr_in *sin = &ctx->dnsc_serv[ctx->dnsc_nserv];
  if (!inet_aton(ns, &sin->sin_addr))
    return 0;
  ++ctx->dnsc_nserv;
  return 1;
}

int dns_set_serv(struct dns_ctx *ctx, const char **servv) {
  INITCTX(ctx);
  assert(CTXFRESH(ctx));
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
          dns_set_num(opts, "maxreq", &ctx->dnsc_maxreq, LIM_MAXREQ) ||
          dns_set_num(opts, "port", &ctx->dnsc_port, LIM_PORT)))
      (void)0;			/* unknown option? */
    while(*opts && !ISSPACE(*opts)) ++opts;
  }
}

int dns_set_opts(struct dns_ctx *ctx, const char *opts) {
  INITCTX(ctx);
  assert(CTXFRESH(ctx));
  dns_opts(ctx, opts);
  return 0;
}

int dns_set_opt(struct dns_ctx *ctx, enum dns_opt opt, int val) {
  int prev;
  INITCTX(ctx);
  assert(CTXFRESH(ctx));
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
  oneopt(DNS_OPT_MAXREQ, dnsc_maxreq, LIM_MAXREQ);
  oneopt(DNS_OPT_PORT,   dnsc_port,   LIM_PORT);
#undef oneopt
#undef _oneopt
  case DNS_OPT_FLAGS:
    prev = ctx->dnsc_flags;
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
  INITCTX(ctx);
  assert(CTXFRESH(ctx));
  ctx->dnsc_nsrch = 0;
  while(*srchv && ctx->dnsc_nsrch < DNS_MAXSRCH)
    dns_add_srch(ctx, *srchv++);
  return ctx->dnsc_nsrch;
}

void dns_set_dbgfn(struct dns_ctx *ctx, void (*fn)(const unsigned char *, int))
{
  INITCTX(ctx);
  ctx->dnsc_udbgfn = fn;
}

void dns_set_tmcbck(struct dns_ctx *ctx, dns_utm_fn *utmfn, void *arg) {
  INITCTX(ctx);
  ctx->dnsc_utmfn = utmfn;
  ctx->dnsc_uctx = arg;
}

static void dns_firstid(struct dns_ctx *ctx) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  ctx->dnsc_nextid = (tv.tv_usec ^ getpid()) & 0xffff;
}

void dns_init(void) {
  FILE *f;
  char *v;
  char buf[2048];
  int srch_set = 0, serv_set = 0;
  struct dns_ctx *ctx = &dns_defctx;

  assert(!CTXACTIVE(ctx));
  if (CTXINITED(ctx))
    return;

  memset(ctx, 0, sizeof(*ctx));
  ctx->dnsc_timeout = 5;
  ctx->dnsc_ntries = 3;
  ctx->dnsc_ndots = 1;
  ctx->dnsc_udpbuf = DNS_EDNS0PACKET;
  ctx->dnsc_maxreq = 128;
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
    fclose(f);
  }

  if (!srch_set && !ctx->dnsc_nsrch &&
      gethostname(buf, sizeof(buf) - 1) == 0 &&
      (v = strchr(buf, '.')) != NULL &&
      *++v != '\0')
    dns_add_srch(ctx, v);

  if ((v = getenv("RES_OPTIONS")) != NULL)
    dns_opts(ctx, v);

  dns_firstid(ctx);
}

struct dns_ctx *dns_new(const struct dns_ctx *ctx) {
  struct dns_ctx *n;
  INITCTX(ctx);
  n = malloc(sizeof(*n));
  if (!n)
    return NULL;
  *n = *ctx;
  n->dnsc_qactive = n->dnsc_qsched = n->dnsc_qtodo = n->dnsc_qdone = 0;
  n->dnsc_nactive = n->dnsc_nreq = 0;
  n->dnsc_loop = 0;
  if (n->dnsc_udpsock >= 0) {
    close(n->dnsc_udpsock);
    n->dnsc_udpsock = -1;
  }
  dns_firstid(n);
  return n;
}

/*XXX dns_free() ignores any and all queries-in-progress */
void dns_free(struct dns_ctx *ctx) {
  SETCTX(ctx);
  if (!CTXINITED(ctx)) return;
  assert(!ctx->dnsc_loop);
  if (ctx->dnsc_udpsock >= 0)
    close(ctx->dnsc_udpsock);
  if (ctx->dnsc_pbuf)
    free(ctx->dnsc_pbuf);
  if (ctx != &dns_defctx)
    free(ctx);
  else
    memset(ctx, 0, sizeof(*ctx));
}

int dns_open(struct dns_ctx *ctx) {
  int r;
  INITCTX(ctx);
  if (ctx->dnsc_udpsock >= 0)
    return ctx->dnsc_udpsock;

  /* ensure we have at least one server */
  if (!ctx->dnsc_nserv) {
    ctx->dnsc_serv[0].sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ctx->dnsc_nserv = 1;
  }
  /* fix family and port for each sockaddr */
  for (r = 0; r < ctx->dnsc_nserv; ++r) {
    ctx->dnsc_serv[r].sin_family = AF_INET;
    ctx->dnsc_serv[r].sin_port = htons(ctx->dnsc_port);
  }

  /* create the socket */
  r = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (r < 0)
    return -1;
  if (fcntl(r, F_SETFL, fcntl(r, F_GETFL) | O_NONBLOCK) < 0 ||
      fcntl(r, F_SETFD, FD_CLOEXEC) < 0) {
    close(r);
    return -1;
  }
  ctx->dnsc_udpsock = r;
  return r;
}

void dns_close(struct dns_ctx *ctx) {
  SETCTX(ctx);
  if (!CTXINITED(ctx)) return;
  if (ctx->dnsc_udpsock < 0) return;
  close(ctx->dnsc_udpsock);
  ctx->dnsc_udpsock = -1;
}

int dns_sock(const struct dns_ctx *ctx) {
  SETCTX(ctx);
  return CTXINITED(ctx) ? ctx->dnsc_udpsock : -1;
}

int dns_requests(const struct dns_ctx *ctx) {
  SETCTX(ctx);
  return ctx->dnsc_nreq;
}

/* the queue algorithm.
 * There are 4 queues (lists) assotiated with a dns_ctx:
 *  ctx->dnsc_qactive is an active queue, requests which
 *    are dispatched and queries for which where sent to
 *    nameserver(s).  For every request in active queue,
 *    the dnsq_deadline is greather than zero (actual time
 *    when the timeout will expire), and if applicable, user
 *    timer has been set up (ctx->dnsc_utmfn).  When some
 *    data arrives on the socket, we look up the active queue
 *    to find the request.
 *  ctx->dnsc_qtodo is the to-do queue: requests which aren't yet
 *    scheduled (either new ones or requests exceeding dnsc_maxrq).
 *    When some active requests are done, next request from todo
 *    queue will be picked up.  dnsq_deadline is -1 for all
 *    requests in this queue.
 *  ctx->dnsc_qsched - requests that should be dns_reschedule()d
 *    ((re)sent to server(s)).  This is internal, short-living queue
 *    inside dns_reschedule(), and is empty in normal cases.
 *    No timer is set for requests sitting in this queue, and
 *    dnsq_deadline is zero.
 *  ctx->dnsc_qdone - completed requests awaiting to be picked up
 *    by an application.  This queue is used only when an application
 *    provided no callback routine, and will pick up completed requests
 *    by it's own.  dnsq_deadline for all entries in this queue is -2.
 * ctx->dnsc_nactive (number of active requests) is the number
 * of entries in qactive and qsched queues.
 *
 * New request goes into the dnsc_qtodo queue first.  dns_reschedule()
 * when moves it into dnsc_qsched queue, when dnsc_nactive is less than
 * dnsc_maxreq, and when process the dnsc_qsched queue by sending the
 * queries to nameservers, setting up timers and moving requests into
 * the dnsc_qactive queue.
 *
 * When request moves out of dnsc_qactive queue (either to dnsc_qsched
 * queue or when done), user timer assotiated with the request should
 * be cancelled, but only if we aren't processing timer callback (in
 * which case the timer has already been cancelled).  When we move
 * request from dnsc_qsched into dnsc_qactive queue, user timer is
 * set instead.
 *
 * The way all this works allows us to cancel requests and to add
 * newrequests at any time while in the dns_reschedule() routine.
 * Note dns_reschedule() only touches topmost requests in all queries,
 * it does not advance to any next element of those queues without
 * removing the topmost element -- it picks up a request from the
 * top of dnsc_qsched or dnsc_qtodo and immediately places it into
 * dnsc_qactive, OR finishes expired query.  This way, it is safe
 * to call dns_cancel() or to queue more requests from within the
 * callback while dns_reschedule() is executing.
 */

static void dns_reschedule(struct dns_ctx *ctx, time_t now);

static inline void
dns_utimer_cancel(struct dns_ctx *ctx, struct dns_query *q) {
  if (ctx->dnsc_utmfn)
    ctx->dnsc_utmfn(ctx->dnsc_uctx, q, 0);
}

static void
dns_end_query(struct dns_ctx *ctx, struct dns_query *q, int status) {
  q->dnsq_status = status;
  if (status < 0)
    q->dnsq_result = NULL;
  --ctx->dnsc_nreq;
  if (q->dnsq_cbck) {
    q->dnsq_next = NULL;
    q->dnsq_ctx = NULL;
    q->dnsq_cbck(q, status, q->dnsq_result);
  }
  else {
    q->dnsq_deadline = -2;
    q->dnsq_flags |= DNS_DONE;
    q->dnsq_next = ctx->dnsc_qdone;
    ctx->dnsc_qdone = q;
  }
}

void dns_cancel(struct dns_query *q) {
  struct dns_ctx *ctx = q->dnsq_ctx;
  struct dns_query **qp;
  assert(dns_active(q));

  if (q->dnsq_deadline > 0) {
    qp = &ctx->dnsc_qactive;
    dns_utimer_cancel(ctx, q);
    assert(ctx->dnsc_nactive > 0);
    --ctx->dnsc_nactive;
    --ctx->dnsc_nreq;
  }
  else if (!q->dnsq_deadline) {
    qp = &ctx->dnsc_qtodo;
    assert(ctx->dnsc_nactive > 0);
    --ctx->dnsc_nactive;
    --ctx->dnsc_nreq;
  }
  else if (q->dnsq_deadline == -1) {
    qp = &ctx->dnsc_qsched;
    assert(ctx->dnsc_nreq > 0);
    --ctx->dnsc_nreq;
  }
  else {
    assert(q->dnsq_deadline == -2);
    qp = &ctx->dnsc_qdone;
  }

  while(*qp != q) {
    assert(*qp);
    assert((*qp)->dnsq_ctx == ctx);
    qp = &(*qp)->dnsq_next;
  }

  *qp = q->dnsq_next;
  q->dnsq_next = NULL;
  q->dnsq_ctx = NULL;
}

static int dns_next_srch(struct dns_ctx *ctx, struct dns_query *q) {
  int ol = q->dnsq_origdnl - 1;
  unsigned char *p = q->dnsq_dn + ol;
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

  p = q->dnsq_dn;
  l = dns_dnlen(p);
  sl = q->dnsq_qlen - l - DNS_HSIZE;
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
  q->dnsq_qlen = p + l + sl - q->dnsq_hdr;
  q->dnsq_next = ctx->dnsc_qsched;
  ctx->dnsc_qsched = q;
  q->dnsq_deadline = 0;
  q->dnsq_try = 0; q->dnsq_servi = 0;
  q->dnsq_flags &= ~DNS_SERVSENT;
  return 0;
}

/* schedule the given request to next nameserver
 * incrementing try# as appropriate */
static int dns_next_server(struct dns_ctx *ctx, struct dns_query *q) {
  int n = 0;
  ++q->dnsq_servi;
  do {
    while(q->dnsq_servi < ctx->dnsc_nserv)
      if (!(q->dnsq_flags & (1 << q->dnsq_servi)))
        return 1;
      else
        ++q->dnsq_servi;
    q->dnsq_servi = 0;
    if (n++)
      q->dnsq_try = ctx->dnsc_ntries;
  } while(++q->dnsq_try < ctx->dnsc_ntries);
  return 0;
}

/* reschedule and send any pending queries.
 */
static void dns_reschedule(struct dns_ctx *ctx, time_t now) {
  struct dns_query *q;
  int timeout;
  int ntries;

  /* reenterancy check: this is NOT a reenterant routine. */
  /* ..hmm... why not? */
  assert(!ctx->dnsc_loop);
  ctx->dnsc_loop = 1;

  for(;;) {

    /* move from todo to the sched queue, up to maxreq requests. */
    while((q = ctx->dnsc_qtodo) != NULL &&
          ctx->dnsc_nactive < ctx->dnsc_maxreq) {
      assert(q->dnsq_ctx == ctx);
      assert(q->dnsq_deadline == -1 && q->dnsq_try == 0 && q->dnsq_servi == 0);
      q->dnsq_deadline = 0;
      ctx->dnsc_qtodo = q->dnsq_next;
      q->dnsq_next = ctx->dnsc_qsched;
      ctx->dnsc_qsched = q;
      ++ctx->dnsc_nactive;
    }

    /* is there anything to do? */
    if (!(q = ctx->dnsc_qsched))
      break;

    if (!now)
      now = time(NULL);

    /* now, try to submit requests in the sched queue
     * (and move them into active queue) */
    do {

      assert(q->dnsq_ctx == ctx);
      assert(q->dnsq_deadline == 0);

      /* if number of tries exceeded, report failure */
      if (q->dnsq_try >= ctx->dnsc_ntries) {
        ctx->dnsc_qsched = q->dnsq_next;
        q->dnsq_ctx = NULL;
        --ctx->dnsc_nactive;
        dns_end_query(ctx, q, q->dnsq_srchs ? q->dnsq_srchs : DNS_E_TEMPFAIL);
        continue;
      }

      /* send the query */
      ntries = ctx->dnsc_maxreq;
      while (sendto(ctx->dnsc_udpsock, q->dnsq_hdr, q->dnsq_qlen, 0,
                    (struct sockaddr *)&ctx->dnsc_serv[q->dnsq_servi],
                    sizeof(struct sockaddr_in)) < 0) {
        /*XXX just ignore the sendto() error for now and try again.
         * In the future, it may be possible to retrieve the error code
         * and find which operation/query failed.
         *XXX try the next server too?
         */
        if (!--ntries)
          break;
      }
      if (!ntries) {	/* if we can't send the query, fail it. */
        ctx->dnsc_qsched = q->dnsq_next;
        q->dnsq_ctx = NULL;
        --ctx->dnsc_nactive;
        dns_end_query(ctx, q, DNS_E_TEMPFAIL);
        continue;
      }

      /* we sent this query to this nameserver */
      q->dnsq_flags |= 1 << q->dnsq_servi;

      /* set up the timeout, report error if failed */
      timeout = q->dnsq_try ?
         ctx->dnsc_timeout << q->dnsq_try / ctx->dnsc_nserv :
         ctx->dnsc_timeout;
      if (ctx->dnsc_utmfn && ctx->dnsc_utmfn(ctx->dnsc_uctx, q, timeout) != 0) {
        ctx->dnsc_qsched = q->dnsq_next;
        --ctx->dnsc_nactive;
        dns_end_query(ctx, q, DNS_E_TEMPFAIL);
        continue;
      }

      /* place into active queue */
      q->dnsq_deadline = now + timeout;
      ctx->dnsc_qsched = q->dnsq_next;
      q->dnsq_next = ctx->dnsc_qactive;
      ctx->dnsc_qactive = q;

    } while((q = ctx->dnsc_qsched) != NULL);

  }

  ctx->dnsc_loop = 0;
}

int dns_submit(struct dns_ctx *ctx, struct dns_query *q,
               int qcls, int qtyp, int flags,
               dns_query_fn *cbck, dns_parse_fn *parse,
               time_t now) {
  unsigned char *p;
  int dnl;
  struct dns_query **qp;

  INITCTX(ctx);
  assert(!dns_active(q));
  q->dnsq_origdnl = dns_dnlen(q->dnsq_dn);
  assert(q->dnsq_origdnl > 0 && q->dnsq_origdnl <= DNS_MAXDN);

  q->dnsq_cls = qcls;
  q->dnsq_typ = qtyp;
  q->dnsq_cbck = cbck;
  q->dnsq_parse = parse;

  q->dnsq_try = 0;
  q->dnsq_deadline = -1;
  q->dnsq_srchi = 0;
  q->dnsq_srchs = 0;
  q->dnsq_result = NULL;
  q->dnsq_status = DNS_E_TEMPFAIL;

  memset(q->dnsq_hdr, 0, DNS_HSIZE);
  dns_put16(q->dnsq_hdr, ctx->dnsc_nextid);
  if (++ctx->dnsc_nextid > 0xffff) ctx->dnsc_nextid = 1;
  if (!(q->dnsq_flags & DNS_NORD)) q->dnsq_hdr[DNS_H_F1] |= DNS_HF1_RD;
  if (q->dnsq_flags & DNS_AAONLY) q->dnsq_hdr[DNS_H_F1] |= DNS_HF1_AA;
  q->dnsq_hdr[DNS_H_QDCNT2] = 1;

  flags = (flags | ctx->dnsc_flags) & ~DNS_INTERNAL;
  if (!ctx->dnsc_nsrch) q->dnsq_flags |= DNS_NOSRCH;
  p = q->dnsq_dn;
  if (flags & DNS_NOSRCH)
    p += q->dnsq_origdnl;
  else if ((int)dns_dnlabels(p) > ctx->dnsc_ndots) {
    p += q->dnsq_origdnl;
    flags |= DNS_ASIS_SKIP;
  }
  else if ((dnl = dns_next_srch(ctx, q)) > 0) {
    p += dnl;
    flags |= DNS_ASIS_LAST;
  }
  else {
    p += q->dnsq_origdnl;
    p[-1] = '\0';
  }
  q->dnsq_flags = flags;
  p = dns_put16(p, q->dnsq_typ);
  p = dns_put16(p, q->dnsq_cls);
  if (ctx->dnsc_udpbuf < DNS_MAXPACKET)
    ctx->dnsc_udpbuf = DNS_MAXPACKET;
  else if (ctx->dnsc_udpbuf > 32768)
    ctx->dnsc_udpbuf = 32768;
  if (ctx->dnsc_udpbuf > DNS_MAXPACKET) {
    *p++ = 0;			/* empty (root) DN */
    p = dns_put16(p, DNS_T_OPT);
    p = dns_put16(p, ctx->dnsc_udpbuf);
    *p++ = 0; *p++ = 0;		/* EDNS0 RCODE & VERSION */
    *p++ = 0; *p++ = 0;		/* rest of the TTL field */
    *p++ = 0; *p++ = 0;		/* RDLEN */
    q->dnsq_hdr[DNS_H_ARCNT2] = 1;
  }
  assert(p <= q->dnsq_extra + DNS_QEXTRA);
  q->dnsq_qlen = p - q->dnsq_hdr;

  if (/*ctxx->dnsc_udpbuf > DNS_MAXPACKET &&*/ !ctx->dnsc_pbuf &&
      !(ctx->dnsc_pbuf = malloc(ctx->dnsc_udpbuf)))
    return -1;
  if (ctx->dnsc_udpsock < 0 && dns_open(ctx) < 0)
    return -1;

  qp = &ctx->dnsc_qtodo;
  while(*qp)
    qp = &(*qp)->dnsq_next;
  *qp = q;
  q->dnsq_next = NULL;
  q->dnsq_ctx = ctx;
  ++ctx->dnsc_nreq;
  if (ctx->dnsc_nactive < ctx->dnsc_maxreq && !ctx->dnsc_loop)
    dns_reschedule(ctx, now);
  return 0;
}

int dns_submit_dn(struct dns_ctx *ctx, struct dns_query *q,
                  const unsigned char *dn, int qcls, int qtyp, int flags,
                  dns_query_fn *cbck, dns_parse_fn *parse,
                  time_t now) {
  int len = dns_dnlen(dn);
  if (len > DNS_MAXDN)
    return -1;
  memcpy(q->dnsq_dn, dn, len);
  return dns_submit(ctx, q, qcls, qtyp, flags, cbck, parse, now);
}

int dns_submit_p(struct dns_ctx *ctx, struct dns_query *q,
                 const char *name, int qcls, int qtyp, int flags,
                 dns_query_fn *cbck, dns_parse_fn *parse,
                 time_t now) {
  int isabs;
  if (dns_ptodn(name, 0, q->dnsq_dn, DNS_MAXDN, &isabs) <= 0)
    return -1;
  if (isabs)
    flags |= DNS_NOSRCH;
  return dns_submit(ctx, q, qcls, qtyp, flags, cbck, parse, now);
}

/* handle user timer timeout (may happen only for active requests).
 * Note the user timer has been cancelled (expired in fact) already. */
void dns_tmevent(struct dns_query *q, time_t now) {
  struct dns_ctx *ctx = q->dnsq_ctx;
  struct dns_query **qp;
  assert(dns_active(q));
  assert(q->dnsq_deadline > 0 && (!now || q->dnsq_deadline <= now));
  assert(!ctx->dnsc_loop);
  assert(ctx->dnsc_nactive > 0);
  qp = &ctx->dnsc_qactive;
  while(*qp != q) {
    assert(*qp != NULL);
    assert((*qp)->dnsq_ctx == ctx);
    qp = &(*qp)->dnsq_next;
  }
  *qp = q->dnsq_next;
  q->dnsq_next = ctx->dnsc_qsched;
  ctx->dnsc_qsched = q;
  q->dnsq_deadline = 0;
  dns_next_server(ctx, q);
  dns_reschedule(ctx, now);
}

/* process readable fd condition for a given server */
static int dns_recv(struct dns_ctx *ctx, time_t now) {
  int r;
  int servi;
  struct dns_query *q, **qp;
  unsigned char *pbuf;

  pbuf = ctx->dnsc_pbuf;

  { /* receive the reply */
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
      return errno == EAGAIN ? -1 : 0;
    }
    /* ignore replies from wrong server */
    if (sin.sin_family != AF_INET)
      return 0;
    if (sinlen != sizeof(sin))
      return 0;
    servi = 0;
    while(memcmp(&ctx->dnsc_serv[servi], &sin, sizeof(sin)) != 0)
      if (++servi >= ctx->dnsc_nserv)
        return 0;
  }
  
  if (r < DNS_HSIZE) return 0;		/* short packet */

  if (ctx->dnsc_udbgfn)
    ctx->dnsc_udbgfn(pbuf, r);

  if (dns_numqd(pbuf) != 1) return 0;	/* too many questions? */
  if (dns_opcode(pbuf) != 0) return 0;	/*XXX ignore non-query replies ? */

  /* truncation bit (TC).  Ooh, we don't handle TCP (yet?),
   * but we do handle larger UDP sizes.
   * Note that e.g. djbdns will only send header if resp.
   * does not fit, not whatever is fit in 512 bytes. */
  if (dns_tc(pbuf))
    return 0;	/* just ignore response for now.. any hope? */

  /* find the request for this reply, in active queue
   * (by looking at QID).
   * Note we pick any request, even queued for another
   * server - in case first server replies a bit later
   * than we expected. */
  for (qp = &ctx->dnsc_qactive; ; qp = &q->dnsq_next) {
    int l;
    if (!(q = *qp))	/* no more requests: old reply? */
      return 0;
    assert(q->dnsq_deadline > 0);
    assert(q->dnsq_ctx == ctx);
    /* skip requests that has not been sent to this
     * server yet. */
    if (!(q->dnsq_flags & (1 << servi)))
      continue;
    if (q->dnsq_hdr[DNS_H_QID1] != pbuf[DNS_H_QID1] ||
        q->dnsq_hdr[DNS_H_QID2] != pbuf[DNS_H_QID2])
      continue;
    if (!(l = dns_dnequal(q->dnsq_dn, dns_payload(pbuf))))
      continue;
    if (DNS_HSIZE + l + 4 > r)
      return 0;
    if (memcmp(q->dnsq_dn + l, dns_payload(pbuf) + l, 4) != 0)
      continue;
    break;
  }

  *qp = q->dnsq_next;
  q->dnsq_next = NULL;
  dns_utimer_cancel(ctx, q);

  /* process the RCODE */
  switch(dns_rcode(pbuf)) {

  case DNS_R_SERVFAIL:
  case DNS_R_NOTIMPL:
  case DNS_R_REFUSED:
    /* for these rcodes, advance this request
     * to the next server and reschedule */
  default: /* unknown rcode? hmmm... */
    q->dnsq_next = ctx->dnsc_qsched; ctx->dnsc_qsched = q;
    q->dnsq_deadline = 0;
    dns_next_server(ctx, q);
    dns_reschedule(ctx, now);
    return 0;

  case DNS_R_NXDOMAIN:
    if ((r = dns_search_next(ctx, q, DNS_E_NXDOMAIN)) == 0) {
      dns_reschedule(ctx, now);
      return 0;
    }
    break;

  case DNS_R_NOERROR:
    if (!dns_numan(pbuf)) {
      if ((r = dns_search_next(ctx, q, DNS_E_NODATA)) == 0) {
        dns_reschedule(ctx, now);
        return 0;
      }
      break;
    }
    if (q->dnsq_parse)
      r = q->dnsq_parse(q, pbuf, pbuf + r);
    else if ((q->dnsq_result = malloc(r)) != NULL)
      memcpy(q->dnsq_result, pbuf, r);
    else
      r = DNS_E_NOMEM;
    break;

  }

  /* ok, this reply looks satisfactory */
  --ctx->dnsc_nactive;
  dns_end_query(ctx, q, r);
  if (ctx->dnsc_qtodo && !ctx->dnsc_loop)
    dns_reschedule(ctx, now);
  return 0;
}

/* process readable fd condition for a given server */
void dns_ioevent(struct dns_ctx *ctx, time_t now) {
  SETCTX(ctx);
  if (!CTXINITED(ctx))
    return;
  assert(ctx->dnsc_udpsock >= 0);
  assert(!ctx->dnsc_loop);
  while(dns_recv(ctx, now) == 0)
    ;
}

struct dns_query *
dns_pick(struct dns_ctx *ctx, struct dns_query *q,
         int *statusp, void **resultp) {
  SETCTX(ctx);
  if (q) {
    struct dns_query **qp = &ctx->dnsc_qdone;
    while(*qp != q)
      if (!*qp) return NULL;
      else qp = &(*qp)->dnsq_next;
    *qp = q->dnsq_next;
  }
  else if (!(q = ctx->dnsc_qdone))
    return NULL;
  else
    ctx->dnsc_qdone = q->dnsq_next;
  q->dnsq_next = NULL;
  q->dnsq_ctx = NULL;
  if (statusp) *statusp = q->dnsq_status;
  if (resultp) *resultp = q->dnsq_result;
  else {
    free(q->dnsq_result);
    q->dnsq_result = NULL;
  }
  return q;
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
    assert(q->dnsq_deadline > 0);
    if (q->dnsq_deadline <= now) {
      *qp = q->dnsq_next;
      q->dnsq_next = ctx->dnsc_qsched; ctx->dnsc_qsched = q;
      q->dnsq_deadline = 0;
      dns_next_server(ctx, q);
      towait = 0;
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
  if (ctx->dnsc_qsched) {
    dns_reschedule(ctx, now);
    if (towait < 0 || towait > ctx->dnsc_timeout) {
      towait = maxwait;
      for(q = ctx->dnsc_qactive; q; q = q->dnsq_next) {
        timeout = q->dnsq_deadline - now;
        if (towait < 0 || timeout < towait)
          towait = timeout;
      }
    }
  }
  return towait;
}

static void
dns_resolve_cb(struct dns_query *q, int status, unsigned char *result) {
  q = q;
  status = status;
  result = result;
}

void *dns_resolve_dn(struct dns_ctx *ctx,
                     const unsigned char *dn, int qcls, int qtyp, int flags,
                     dns_parse_fn *parse, int *statusp) {
  struct dns_query *q;
  time_t now;
#ifdef HAVE_POLL
  struct pollfd pfd;
  int timeout;
#else
  fd_set rfd;
  struct timeval tv;
#endif
  int n;
  void *result;

  INITCTX(ctx);

  q = calloc(sizeof(*q), 1);
  if (!q) {
    if (statusp) *statusp = DNS_E_NOMEM;
    return NULL;
  }
  now = time(NULL);
  n = dns_submit_dn(ctx, q, dn, qcls, qtyp, flags, dns_resolve_cb, parse, now);
  if (n != 0) {
    if (statusp) *statusp = n;
    free(q);
    return NULL;
  }

#ifdef HAVE_POLL
  pfd.fd = ctx->dnsc_udpsock;
  pfd.events = POLLIN;
#else
  FD_ZERO(&rfd);
#endif

  while(dns_active(q)) {
#ifdef HAVE_POLL
    timeout = dns_timeouts(ctx, -1, now);
    n = poll(&pfd, 1, timeout * 1000);
#else
    tv.tv_sec = dns_timeouts(ctx, -1, now);
    tv.tv_usec = 0;
    FD_SET(ctx->dnsc_udpsock, &rfd);
    n = select(ctx->dnsc_udpsock + 1, &rfd, NULL, NULL, &tv);
#endif
    now = time(NULL);
    if (n > 0)
      dns_ioevent(ctx, now);
  }

  if (statusp) *statusp = q->dnsq_status;
  result = q->dnsq_result;
  free(q);
  return result;
}

void *dns_resolve_p(struct dns_ctx *ctx,
                    const char *name, int qcls, int qtyp, int flags,
                    dns_parse_fn *parse, int *statusp) {
  unsigned char dn[DNS_MAXDN];
  int isabs;
  if (dns_ptodn(name, 0, dn, sizeof(dn), &isabs) <= 0) {
     if (statusp) *statusp = DNS_E_BADQUERY;
     return NULL;
  }
  if (isabs) flags |= DNS_NOSRCH;
  return dns_resolve_dn(ctx, dn, qcls, qtyp, flags, parse, statusp);
}

