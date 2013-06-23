/* $Id: udns.h,v 1.19 2004/07/09 01:18:00 mjt Exp $
 * header file for the dns library.
 */

#ifndef UDNS_VERSION	/* include guard */

#define UDNS_VERSION "0.0.1"

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef AF_INET6
struct in6_addr {
  unsigned char s6_addr[16];
};
#endif

/**************************************************************************/
/**************** Common definitions **************************************/

extern const char *dns_version(void);

struct dns_ctx;
struct dns_query;

#define DNS_MAXDN	255	/* max DN length */
#define DNS_MAXLABEL	63	/* max DN label length */
#define DNS_MAXNAME	1024	/* max asciiz domain name length */
#define DNS_HSIZE	12	/* DNS packet header size */
#define DNS_PORT	53	/* default domain port */
#define DNS_MAXSERV	6	/* max servers to consult */
#define DNS_MAXSRCH	5	/* max searchlist entries */
#define DNS_MAXPACKET	512	/* max traditional-DNS UDP packet size */
#define DNS_EDNS0PACKET	4096	/* EDNS0 packet size to use */

enum dns_class {	/* DNS RR Classes */
  DNS_C_INVALID	= 0,	/* invalid class */
  DNS_C_IN	= 1,	/* Internet */
  DNS_C_CH	= 3,	/* CHAOS */
  DNS_C_HS	= 4,	/* HESIOD */
  DNS_C_ANY	= 255	/* wildcard */
};

enum dns_type {		/* DNS RR Types */
  DNS_T_INVALID		= 0,	/* Cookie. */
  DNS_T_A		= 1,	/* Host address. */
  DNS_T_NS		= 2,	/* Authoritative server. */
  DNS_T_MD		= 3,	/* Mail destination. */
  DNS_T_MF		= 4,	/* Mail forwarder. */
  DNS_T_CNAME		= 5,	/* Canonical name. */
  DNS_T_SOA		= 6,	/* Start of authority zone. */
  DNS_T_MB		= 7,	/* Mailbox domain name. */
  DNS_T_MG		= 8,	/* Mail group member. */
  DNS_T_MR		= 9,	/* Mail rename name. */
  DNS_T_NULL		= 10,	/* Null resource record. */
  DNS_T_WKS		= 11,	/* Well known service. */
  DNS_T_PTR		= 12,	/* Domain name pointer. */
  DNS_T_HINFO		= 13,	/* Host information. */
  DNS_T_MINFO		= 14,	/* Mailbox information. */
  DNS_T_MX		= 15,	/* Mail routing information. */
  DNS_T_TXT		= 16,	/* Text strings. */
  DNS_T_RP		= 17,	/* Responsible person. */
  DNS_T_AFSDB		= 18,	/* AFS cell database. */
  DNS_T_X25		= 19,	/* X_25 calling address. */
  DNS_T_ISDN		= 20,	/* ISDN calling address. */
  DNS_T_RT		= 21,	/* Router. */
  DNS_T_NSAP		= 22,	/* NSAP address. */
  DNS_T_NSAP_PTR	= 23,	/* Reverse NSAP lookup (deprecated). */
  DNS_T_SIG		= 24,	/* Security signature. */
  DNS_T_KEY		= 25,	/* Security key. */
  DNS_T_PX		= 26,	/* X.400 mail mapping. */
  DNS_T_GPOS		= 27,	/* Geographical position (withdrawn). */
  DNS_T_AAAA		= 28,	/* Ip6 Address. */
  DNS_T_LOC		= 29,	/* Location Information. */
  DNS_T_NXT		= 30,	/* Next domain (security). */
  DNS_T_EID		= 31,	/* Endpoint identifier. */
  DNS_T_NIMLOC		= 32,	/* Nimrod Locator. */
  DNS_T_SRV		= 33,	/* Server Selection. */
  DNS_T_ATMA		= 34,	/* ATM Address */
  DNS_T_NAPTR		= 35,	/* Naming Authority PoinTeR */
  DNS_T_KX		= 36,	/* Key Exchange */
  DNS_T_CERT		= 37,	/* Certification record */
  DNS_T_A6		= 38,	/* IPv6 address (deprecates AAAA) */
  DNS_T_DNAME		= 39,	/* Non-terminal DNAME (for IPv6) */
  DNS_T_SINK		= 40,	/* Kitchen sink (experimentatl) */
  DNS_T_OPT		= 41,	/* EDNS0 option (meta-RR) */
  DNS_T_TSIG		= 250,	/* Transaction signature. */
  DNS_T_IXFR		= 251,	/* Incremental zone transfer. */
  DNS_T_AXFR		= 252,	/* Transfer zone of authority. */
  DNS_T_MAILB		= 253,	/* Transfer mailbox records. */
  DNS_T_MAILA		= 254,	/* Transfer mail agent records. */
  DNS_T_ANY		= 255,	/* Wildcard match. */
  DNS_T_ZXFR		= 256,	/* BIND-specific, nonstandard. */
  DNS_T_MAX		= 65536
};

/**************************************************************************/
/**************** Domain Names (DNs) **************************************/

/* return length of the DN */
unsigned dns_dnlen(const unsigned char *dn);

/* return #of labels in a DN */
unsigned dns_dnlabels(const unsigned char *dn);

/* lower- and uppercase single DN char */
#define DNS_DNLC(c) ((c) >= 'A' && (c) <= 'Z' ? (c) - 'A' + 'a' : (c))
#define DNS_DNUC(c) ((c) >= 'a' && (c) <= 'z' ? (c) - 'a' + 'A' : (c))

/* compare the DNs, return dnlen of equal or 0 if not */
unsigned dns_dnequal(const unsigned char *dn1, const unsigned char *dn2);

/* copy one DN to another, size checking */
unsigned
dns_dntodn(const unsigned char *sdn, unsigned char *ddn, unsigned ddnsiz);

/* convert asciiz string of length namelen (0 to use strlen) to DN */
int
dns_ptodn(const char *name, unsigned namelen,
          unsigned char *dn, unsigned dnsiz,
          int *isabs);

/* simpler form of dns_ptodn() */
#define dns_sptodn(name,dn,dnsiz) dns_ptodn((name),0,(dn),(dnsiz),0)

extern const unsigned char dns_inaddr_arpa_dn[14];
#define DNS_A4RSIZE	30
int dns_a4todn(const struct in_addr *addr, const unsigned char *tdn,
               unsigned char *dn, unsigned dnsiz);
int dns_a4ptodn(const struct in_addr *addr, const char *tname,
                unsigned char *dn, unsigned dnsiz);
unsigned char *
dns_a4todn_(const struct in_addr *addr, unsigned char *dn, unsigned char *dne);

extern const unsigned char dns_ip6_arpa_dn[10];
#define DNS_A6RSIZE	74
int dns_a6todn(const struct in6_addr *addr, const unsigned char *tdn,
               unsigned char *dn, unsigned dnsiz);
int dns_a6ptodn(const struct in6_addr *addr, const char *tname,
               unsigned char *dn, unsigned dnsiz);
unsigned char *
dns_a6todn_(const struct in6_addr *addr, unsigned char *dn, unsigned char *dne);

/* convert DN into asciiz string */
int dns_dntop(const unsigned char *dn, char *name, unsigned namesiz);

/* convert DN into asciiz string, using static buffer (NOT thread-safe!) */
const char *dns_dntosp(const unsigned char *dn);

/* return buffer size (incl. null byte) required for asciiz form of a DN */
unsigned dns_dntop_size(const unsigned char *dn);

/**************************************************************************/
/**************** DNS raw packet layout ***********************************/

enum dns_rcode {	/* reply codes */
  DNS_R_NOERROR		= 0,	/* ok, no error */
  DNS_R_FORMERR		= 1,	/* format error */
  DNS_R_SERVFAIL	= 2,	/* server failed */
  DNS_R_NXDOMAIN	= 3,	/* domain does not exists */
  DNS_R_NOTIMPL		= 4,	/* not implemented */
  DNS_R_REFUSED		= 5,	/* query refused */
  /* these are for BIND_UPDATE */
  DNS_R_YXDOMAIN	= 6,	/* Name exists */
  DNS_R_YXRRSET		= 7,	/* RRset exists */
  DNS_R_NXRRSET		= 8,	/* RRset does not exist */
  DNS_R_NOTAUTH		= 9,	/* Not authoritative for zone */
  DNS_R_NOTZONE		= 10,	/* Zone of record different from zone section */
  /*ns_r_max = 11,*/
  /* The following are TSIG extended errors */
  DNS_R_BADSIG		= 16,
  DNS_R_BADKEY		= 17,
  DNS_R_BADTIME		= 18
};

static inline unsigned dns_get16(const unsigned char *s) {
  return ((unsigned)s[0]<<8) | s[1];
}
static inline unsigned dns_get32(const unsigned char *s) {
  return ((unsigned)s[0]<<24) | ((unsigned)s[1]<<16)
        | ((unsigned)s[2]<<8) | s[3];
}
static inline unsigned char *dns_put16(unsigned char *d, unsigned n) {
  *d++ = (n >> 8) & 255; *d++ = n & 255; return d;
}
static inline unsigned char *dns_put32(unsigned char *d, unsigned n) {
  *d++ = (n >> 24) & 255; *d++ = (n >> 16) & 255;
  *d++ = (n >>  8) & 255; *d++ = n & 255;
  return d;
}

/* DNS Header layout */
enum {
 /* bytes 0:1 - query ID */
  DNS_H_QID1	= 0,
  DNS_H_QID2	= 1,
  DNS_H_QID	= DNS_H_QID1,
#define dns_qid(pkt)	dns_get16((pkt)+DNS_H_QID)
 /* byte 2: flags1 */
  DNS_H_F1	= 2,
  DNS_HF1_QR	= 0x80,	/* query response flag */
#define dns_qr(pkt)	((pkt)[DNS_H_F1]&DNS_HF1_QR)
  DNS_HF1_OPCODE = 0x78, /* opcode, 0 = query */
#define dns_opcode(pkt)	(((pkt)[DNS_H_F1]&DNS_HF1_OPCODE)>>3)
  DNS_HF1_AA	= 0x04,	/* auth answer */
#define dns_aa(pkt)	((pkt)[DNS_H_F1]&DNS_HF1_AA)
  DNS_HF1_TC	= 0x02,	/* truncation flag */
#define dns_tc(pkt)	((pkt)[DNS_H_F1]&DNS_HF1_TC)
  DNS_HF1_RD	= 0x01,	/* recursion desired (may be set in query) */
#define dns_rd(pkt)	((pkt)[DNS_H_F1]&DNS_HF1_RD)
 /* byte 3: flags2 */
  DNS_H_F2	= 3,
  DNS_HF2_RA	= 0x80,	/* recursion available */
#define dns_ra(pkt)	((pkt)[DNS_H_F2]&DNS_HF2_RA)
  DNS_HF2_Z	= 0x70,	/* reserved */
  DNS_HF2_RCODE	= 0x0f,	/* response code, DNS_R_XXX above */
#define dns_rcode(pkt)	((pkt)[DNS_H_F2]&DNS_HF2_RCODE)
 /* bytes 4:5: qdcount, numqueries */
  DNS_H_QDCNT1	= 4,
  DNS_H_QDCNT2	= 5,
  DNS_H_QDCNT	= DNS_H_QDCNT1,
#define dns_numqd(pkt)	dns_get16((pkt)+4)
 /* bytes 6:7: ancount, numanswers */
  DNS_H_ANCNT1	= 6,
  DNS_H_ANCNT2	= 7,
  DNS_H_ANCNT	= DNS_H_ANCNT1,
#define dns_numan(pkt)	dns_get16((pkt)+6)
 /* bytes 8:9: nscount, numauthority */
  DNS_H_NSCNT1	= 8,
  DNS_H_NSCNT2	= 9,
  DNS_H_NSCNT	= DNS_H_NSCNT1,
#define dns_numns(pkt)	dns_get16((pkt)+8)
 /* bytes 10:11: arcount, numadditional */
  DNS_H_ARCNT1	= 10,
  DNS_H_ARCNT2	= 11,
  DNS_H_ARCNT	= DNS_H_ARCNT1,
#define dns_numar(pkt)	dns_get16((pkt)+10)
#define dns_payload(pkt) ((pkt)+DNS_HSIZE)
};

/* packet buffer: start at pkt, end before pkte, current pos *curp.
 * extract a DN and set *curp to the next byte after DN in packet.
 * return -1 on error, 0 if dnsiz is too small, or dnlen on ok.
 */
int
dns_getdn(const unsigned char *pkt,
          const unsigned char **curp,
          const unsigned char *pkte,
          unsigned char *dn, unsigned dnsiz);

/* skip the DN at position cur in packet ending before pkte,
 * return pointer to the next byte after the DN or NULL on error */
const unsigned char *
dns_skipdn(const unsigned char *pkte, const unsigned char *cur);

struct dns_rr {		/* DNS Resource Record */
  unsigned char dnsrr_dn[DNS_MAXDN];		/* the DN of the RR */
  enum dns_class dnsrr_cls;			/* Class */
  enum dns_type  dnsrr_typ;			/* Type */
  unsigned dnsrr_ttl;				/* Time-To-Live (TTL) */
  unsigned dnsrr_dsz;				/* data size */
  const unsigned char *dnsrr_dptr;		/* pointer to start of data */
  const unsigned char *dnsrr_dend;		/* past end of data */
};

struct dns_parse {	/* RR/packet parsing state */
  const unsigned char *dnsp_pkt;	/* start of the packet */
  const unsigned char *dnsp_end;	/* end of the packet */
  const unsigned char *dnsp_cur;	/* current packet position */
  int dnsp_rrl;				/* number of RRs left to go */
  int dnsp_nrr;				/* RR count so far */
  unsigned dnsp_ttl;			/* TTL value so far */
  const unsigned char *dnsp_qdn;	/* the RR DN we're looking for */
  enum dns_class dnsp_qcls;		/* RR class we're looking for or 0 */
  enum dns_type  dnsp_qtyp;		/* RR type we're looking for or 0 */
  unsigned char dnsp_dnbuf[DNS_MAXDN];
};

/* initialize the parse structure */
int dns_initparse(struct dns_parse *p, int qcls, int qtyp,
                  const unsigned char *pkt, const unsigned char *pkte);

/* search next RR, <0=error, 0=no more RRs, >0 = found. */
int dns_nextrr(struct dns_parse *p, struct dns_rr *rr);

/* equivalent to dns_initparse() followed by dns_nextrr() */
int dns_firstrr(struct dns_parse *p, struct dns_rr *rr, int qcls, int qtyp,
                const unsigned char *pkt, const unsigned char *pkte);
void dns_rewind(struct dns_parse *p);


/**************************************************************************/
/**************** Resolver Context ****************************************/

/* default resolver context */
extern struct dns_ctx dns_defctx;

/* initialize default resolver context and open it if do_open is true.
 * <0 on failure. */
int dns_init(int do_open);

/* return new resolver context with the same settings as copy */
struct dns_ctx *dns_new(const struct dns_ctx *copy);

/* free resolver context; all queries are dropped */
void dns_free(struct dns_ctx *ctx);

/* set nameserver list for a resolver context */
int dns_set_serv(struct dns_ctx *ctx, const char *serv[]);

/* set search list for a resolver context */
int dns_set_srch(struct dns_ctx *ctx, const char *srch[]);

/* set options for a resolver context */
int dns_set_opts(struct dns_ctx *ctx, const char *opts);

enum dns_opt {		/* options */
  DNS_OPT_FLAGS,	/* flags, DNS_F_XXX */
  DNS_OPT_TIMEOUT,	/* timeout in secounds */
  DNS_OPT_NTRIES,	/* number of retries */
  DNS_OPT_NDOTS,	/* ndots */
  DNS_OPT_UDPSIZE,	/* EDNS0 UDP size */
  DNS_OPT_PORT,		/* port to use */
};

/* set or get (if val<0) an option */
int dns_set_opt(struct dns_ctx *ctx, enum dns_opt opt, int val);

enum dns_flags {
  DNS_NOSRCH	= 0x00010000,	/* do not perform search */
  DNS_NORD	= 0x00020000,	/* request no recursion */
  DNS_AAONLY	= 0x00040000,	/* set AA flag in queries */
  DNS_PASSALL	= 0x00080000,	/* pass all replies to application */
};

/* set the debug function pointer */
void dns_set_dbgfn(struct dns_ctx *ctx, void (*fn)(const unsigned char*,int));

/* open and return UDP socket */
int dns_open(struct dns_ctx *ctx);

/* return UDP socket or -1 if not open */
int dns_sock(const struct dns_ctx *ctx);

/* close the UDP socket */
void dns_close(struct dns_ctx *ctx);

/* return true if any request queued */
int dns_active(const struct dns_ctx *ctx);

/* return status of the last operation */
int dns_status(const struct dns_ctx *ctx);
void dns_setstatus(struct dns_ctx *ctx, int status);

/* handle I/O event on UDP socket */
void dns_ioevent(struct dns_ctx *ctx, time_t now);

/* process any timeouts, return time in secounds to the
 * next timeout (or -1 if none) but not greather than maxwait */
int dns_timeouts(struct dns_ctx *ctx, int maxwait, time_t now);

/* define timer requesting routine to use */
typedef int dns_utm_fn(void *arg, struct dns_query *q, int timeout);
void dns_set_tmcbck(struct dns_ctx *ctx, dns_utm_fn *utmfn, void *arg);
/* routine to call as timer callback */
void dns_tmevent(struct dns_query *q, time_t now);

/**************************************************************************/
/**************** Making Queries ******************************************/

/* query callback routine */
typedef void dns_query_fn(struct dns_ctx *ctx, void *result, void *data);

/* query parse routine: raw DNS => application structure */
typedef int
dns_parse_fn(const unsigned char *pkt, const unsigned char *pkte, void **res);

enum dns_status {
  DNS_E_NOERROR		= 0,	/* ok, not an error */
  DNS_E_TEMPFAIL	= -1,	/* timeout, SERVFAIL or similar */
  DNS_E_PROTOCOL	= -2,	/* got garbled reply */
  DNS_E_NXDOMAIN	= -3,	/* domain does not exists */
  DNS_E_NODATA		= -4,	/* domain exists but no data of reqd type */
  DNS_E_NOMEM		= -5,	/* out of memory while processing */
  DNS_E_BADQUERY	= -6	/* the query is malformed */
};

/* submit generic DN query */
struct dns_query *
dns_submit_dn(struct dns_ctx *ctx,
              const unsigned char *dn, int qcls, int qtyp, int flags,
              dns_parse_fn *parse, dns_query_fn *cbck, void *data, time_t now);
/* submit generic name query */
struct dns_query *
dns_submit_p(struct dns_ctx *ctx,
             const char *name, int qcls, int qtyp, int flags,
             dns_parse_fn *parse, dns_query_fn *cbck, void *data, time_t now);

/* cancel the given async query in progress */
int dns_cancel(struct dns_ctx *ctx, struct dns_query *q);

/* immediately resolve a generic query, return the answer
 * and place completion status into *statusp */
void *
dns_resolve_dn(struct dns_ctx *ctx,
               const unsigned char *qdn, int qcls, int qtyp, int flags,
               dns_parse_fn *parse);
void *
dns_resolve_p(struct dns_ctx *ctx,
              const char *qname, int qcls, int qtyp, int flags,
              dns_parse_fn *parse);
void *dns_resolve(struct dns_ctx *ctx, struct dns_query *q);


/* Specific RR handlers */

#define dns_rr_common(prefix)						\
  char *prefix##_cname;		/* canonical name */			\
  char *prefix##_qname;		/* original query name */		\
  unsigned prefix##_ttl;	/* TTL value */				\
  int prefix##_nrr		/* number of records */

struct dns_rr_null {		/* NULL RRset, aka RRset template */
  dns_rr_common(dnsn);
};

int dns_stdrr_size(const struct dns_parse *p);
void *
dns_stdrr_finish(struct dns_rr_null *ret, char *cp, const struct dns_parse *p);

struct dns_rr_a4 {		/* the A RRset */
  dns_rr_common(dnsa4);
  struct in_addr *dnsa4_addr;	/* array of addresses, naddr elements */
};

dns_parse_fn dns_parse_a4;	/* A RR parsing routine */
typedef void			/* A query callback routine */
dns_query_a4_fn(struct dns_ctx *ctx, struct dns_rr_a4 *result, void *data);

/* submit A IN query */
struct dns_query *
dns_submit_a4(struct dns_ctx *ctx, const char *name, int flags,
              dns_query_a4_fn *cbck, void *data, time_t now);

/* resolve A IN query */
struct dns_rr_a4 *
dns_resolve_a4(struct dns_ctx *ctx, const char *name, int flags);


struct dns_rr_a6 {		/* the AAAA RRset */
  dns_rr_common(dnsa6);
  struct in6_addr *dnsa6_addr;	/* array of addresses, naddr elements */
};

dns_parse_fn dns_parse_a6;	/* A RR parsing routine */
typedef void			/* A query callback routine */
dns_query_a6_fn(struct dns_ctx *ctx, struct dns_rr_a6 *result, void *data);

/* submit AAAA IN query */
struct dns_query *
dns_submit_a6(struct dns_ctx *ctx, const char *name, int flags,
              dns_query_a6_fn *cbck, void *data, time_t now);

/* resolve AAAA IN query */
struct dns_rr_a6 *
dns_resolve_a6(struct dns_ctx *ctx, const char *name, int flags);


struct dns_rr_ptr {		/* the PTR RRset */
  dns_rr_common(dnsptr);
  char **dnsptr_ptr;		/* array of PTRs */
};

dns_parse_fn dns_parse_ptr;	/* PTR RR parsing routine */
typedef void			/* PTR query callback */
dns_query_ptr_fn(struct dns_ctx *ctx, struct dns_rr_ptr *result, void *data);
/* submit PTR IN in-addr.arpa query */
struct dns_query *
dns_submit_a4ptr(struct dns_ctx *ctx, const struct in_addr *addr,
                 dns_query_ptr_fn *cbck, void *data, time_t now);
/* resolve PTR IN in-addr.arpa query */
struct dns_rr_ptr *
dns_resolve_a4ptr(struct dns_ctx *ctx, const struct in_addr *addr);

/* the same as above, but for ip6.arpa */
struct dns_query *
dns_submit_a6ptr(struct dns_ctx *ctx, const struct in6_addr *addr,
                 dns_query_ptr_fn *cbck, void *data, time_t now);
struct dns_rr_ptr *
dns_resolve_a6ptr(struct dns_ctx *ctx, const struct in6_addr *addr);


struct dns_mx {		/* single MX RR */
  int priority;		/* MX priority */
  char *name;		/* MX name */
};
struct dns_rr_mx {		/* the MX RRset */
  dns_rr_common(dnsmx);
  struct dns_mx *dnsmx_mx;	/* array of MXes */
};
dns_parse_fn dns_parse_mx;	/* MX RR parsing routine */
typedef void			/* MX RR callback */
dns_query_mx_fn(struct dns_ctx *ctx, struct dns_rr_mx *result, void *data);
/* submit MX IN query */
struct dns_query *
dns_submit_mx(struct dns_ctx *ctx, const char *name, int flags,
              dns_query_mx_fn *cbck, void *data, time_t now);
/* resolve MX IN query */
struct dns_rr_mx *
dns_resolve_mx(struct dns_ctx *ctx, const char *name, int flags);


struct dns_txt {	/* single TXT record */
  int len;		/* length of the text */
  unsigned char *txt;	/* pointer to text buffer. May contain nulls. */
};
struct dns_rr_txt {		/* the TXT RRset */
  dns_rr_common(dnstxt);
  struct dns_txt *dnstxt_txt;	/* array of TXT records */
};
dns_parse_fn dns_parse_txt;	/* TXT RR parsing routine */
typedef void			/* TXT RR callback */
dns_query_txt_fn(struct dns_ctx *ctx, struct dns_rr_txt *result, void *data);
/* submit TXT query */
struct dns_query *
dns_submit_txt(struct dns_ctx *ctx, const char *name, int qcls, int flags,
               dns_query_txt_fn *cbck, void *data, time_t now);
/* resolve TXT query */
struct dns_rr_txt *
dns_resolve_txt(struct dns_ctx *ctx, const char *name, int qcls, int flags);

struct dns_query *
dns_submit_a4dnsbl(struct dns_ctx *ctx,
                   const struct in_addr *addr, const char *dnsbl,
                   dns_query_a4_fn *cbck, void *data, time_t now);
struct dns_query *
dns_submit_a4dnsbl_txt(struct dns_ctx *ctx,
                       const struct in_addr *addr, const char *dnsbl,
                       dns_query_txt_fn *cbck, void *data, time_t now);
struct dns_rr_a4 *
dns_resolve_a4dnsbl(struct dns_ctx *ctx,
                    const struct in_addr *addr, const char *dnsbl);
struct dns_rr_txt *
dns_resolve_a4dnsbl_txt(struct dns_ctx *ctx,
                        const struct in_addr *addr, const char *dnsbl);

struct dns_query *
dns_submit_a6dnsbl(struct dns_ctx *ctx,
                   const struct in6_addr *addr, const char *dnsbl,
                   dns_query_a4_fn *cbck, void *data, time_t now);
struct dns_query *
dns_submit_a6dnsbl_txt(struct dns_ctx *ctx,
                       const struct in6_addr *addr, const char *dnsbl,
                       dns_query_txt_fn *cbck, void *data, time_t now);
struct dns_rr_a4 *
dns_resolve_a6dnsbl(struct dns_ctx *ctx,
                    const struct in6_addr *addr, const char *dnsbl);
struct dns_rr_txt *
dns_resolve_a6dnsbl_txt(struct dns_ctx *ctx,
                        const struct in6_addr *addr, const char *dnsbl);

struct dns_query *
dns_submit_rhsbl(struct dns_ctx *ctx,
                 const char *name, const char *rhsbl,
                 dns_query_a4_fn *cbck, void *data, time_t now);
struct dns_query *
dns_submit_rhsbl_txt(struct dns_ctx *ctx,
                     const char *name, const char *rhsbl,
                     dns_query_txt_fn *cbck, void *data, time_t now);
struct dns_rr_a4 *
dns_resolve_rhsbl(struct dns_ctx *ctx, const char *name, const char *rhsbl);
struct dns_rr_txt *
dns_resolve_rhsbl_txt(struct dns_ctx *ctx, const char *name, const char *rhsbl);

/**************************************************************************/
/**************** Names, Names ********************************************/

struct dns_nameval {
  int val;
  const char *name;
};

extern const struct dns_nameval dns_classtab[];
extern const struct dns_nameval dns_typetab[];
extern const struct dns_nameval dns_rcodetab[];
int dns_findname(const struct dns_nameval *nv, const char *name);
#define dns_findclassname(class) dns_findname(dns_classtab, (class))
#define dns_findtypename(type) dns_findname(dns_typetab, (type))
#define dns_findrcodename(rcode) dns_findname(dns_rcodetab, (rcode))

const char *dns_classname(enum dns_class class);
const char *dns_typename(enum dns_type type);
const char *dns_rcodename(enum dns_rcode rcode);

const char *dns_strerror(int errnum);

#endif	/* include guard */
