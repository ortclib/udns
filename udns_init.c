/* udns_init.c
   resolver initialisation stuff

   Copyright (C) 2006  Michael Tokarev <mjt@corpit.ru>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "udns.h"
#include "platform.h"

#ifdef WINDOWS
# include <winsock2.h>          /* includes <windows.h> */

#ifdef HAVE_IPHLPAPI_H
# include <iphlpapi.h>		/* for dns server addresses etc */
#endif /* HAVE_IPHLPAPI_H */

# include <tchar.h>
#else
# include <sys/types.h>
# include <unistd.h>
# include <fcntl.h>
#endif	/* !WINDOWS */

#ifdef HAVE_RES_INIT
#include <resolv.h>
#endif /* HAVE_RES_INIT */

#include <stdlib.h>
#include <string.h>

#define ISSPACE(x) (x == ' ' || x == '\t' || x == '\r' || x == '\n')

static const char space[] = " \t\r\n";

static void dns_set_serv_internal(struct dns_ctx *ctx, char *serv) {
  dns_add_serv(ctx, NULL);
#ifdef WINDOWS
  char *nextToken = NULL;
  for (serv = strtok_s(serv, space, &nextToken); serv; serv = strtok_s(serv, space, &nextToken))
#else
  for (serv = strtok(serv, space); serv; serv = strtok(NULL, space))
#endif //UDNS_WINRT
    dns_add_serv(ctx, serv);
}

static void dns_set_srch_internal(struct dns_ctx *ctx, char *srch) {
  dns_add_srch(ctx, NULL);
#ifdef WINDOWS
  char *nextToken = NULL;
  for (srch = strtok_s(srch, space, &nextToken); srch; srch = strtok_s(srch, space, &nextToken))
#else
  for (srch = strtok(srch, space); srch; srch = strtok(NULL, space))
#endif //UDNS_WINRT
    dns_add_srch(ctx, srch);
}

#ifdef HAVE_IPHLPAPI_H
/* Apparently, some systems does not have proper headers for IPHLPAIP to work.
 * The best is to upgrade headers, but here's another, ugly workaround for
 * this: compile with -DNO_IPHLPAPI.
 */

typedef DWORD (WINAPI *GetAdaptersAddressesFunc)(
  ULONG Family, DWORD Flags, PVOID Reserved,
  PIP_ADAPTER_ADDRESSES pAdapterAddresses,
  PULONG pOutBufLen);

static int dns_initns_iphlpapi(struct dns_ctx *ctx) {
  HANDLE h_iphlpapi;
  GetAdaptersAddressesFunc pfnGetAdAddrs;
  PIP_ADAPTER_ADDRESSES pAddr, pAddrBuf;
  PIP_ADAPTER_DNS_SERVER_ADDRESS pDnsAddr;
  ULONG ulOutBufLen;
  DWORD dwRetVal;
  int ret = -1;

  h_iphlpapi = LoadLibrary(_T("iphlpapi.dll"));
  if (!h_iphlpapi)
    return -1;
  pfnGetAdAddrs = (GetAdaptersAddressesFunc)
    GetProcAddress((HMODULE)h_iphlpapi, "GetAdaptersAddresses");
  if (!pfnGetAdAddrs) goto freelib;
  ulOutBufLen = 0;
  dwRetVal = pfnGetAdAddrs(AF_UNSPEC, 0, NULL, NULL, &ulOutBufLen);
  if (dwRetVal != ERROR_BUFFER_OVERFLOW) goto freelib;
  pAddrBuf = (PIP_ADAPTER_ADDRESSES)(malloc(ulOutBufLen));
  if (!pAddrBuf) goto freelib;
  dwRetVal = pfnGetAdAddrs(AF_UNSPEC, 0, NULL, pAddrBuf, &ulOutBufLen);
  if (dwRetVal != ERROR_SUCCESS) goto freemem;
  for (pAddr = pAddrBuf; pAddr; pAddr = pAddr->Next)
    for (pDnsAddr = pAddr->FirstDnsServerAddress;
	 pDnsAddr;
	 pDnsAddr = pDnsAddr->Next)
      dns_add_serv_s(ctx, pDnsAddr->Address.lpSockaddr);
  ret = 0;
freemem:
  free(pAddrBuf);
freelib:
  FreeLibrary((HMODULE)h_iphlpapi);
  return ret;
}

#else /* HAVE_IPHLPAPI_H */

#define dns_initns_iphlpapi(ctx) (-1)

#endif /* HAVE_IPHLPAPI_H */

#ifdef HAVE_REGKEY

static int dns_initns_registry(struct dns_ctx *ctx) {
  LONG res;
  HKEY hk;
  DWORD type = REG_EXPAND_SZ | REG_SZ;
  DWORD len;
  char valBuf[1024];

#define REGKEY_WINNT "SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
#define REGKEY_WIN9x "SYSTEM\\CurrentControlSet\\Services\\VxD\\MSTCP"
  res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T(REGKEY_WINNT), 0, KEY_QUERY_VALUE, &hk);
  if (res != ERROR_SUCCESS)
    res = RegOpenKeyEx(HKEY_LOCAL_MACHINE, _T(REGKEY_WIN9x),
                       0, KEY_QUERY_VALUE, &hk);
  if (res != ERROR_SUCCESS)
    return -1;
  len = sizeof(valBuf) - 1;
  res = RegQueryValueEx(hk, _T("NameServer"), NULL, &type, (BYTE*)valBuf, &len);
  if (res != ERROR_SUCCESS || !len || !valBuf[0]) {
    len = sizeof(valBuf) - 1;
    res = RegQueryValueEx(hk, _T("DhcpNameServer"), NULL, &type,
                          (BYTE*)valBuf, &len);
  }
  RegCloseKey(hk);
  if (res != ERROR_SUCCESS || !len || !valBuf[0])
    return -1;
  valBuf[len] = '\0';
  /* nameservers are stored as a whitespace-seperate list:
   * "192.168.1.1 123.21.32.12" */
  dns_set_serv_internal(ctx, valBuf);
  return 0;
}
#else /* HAVE_REGKEY */

#define dns_initns_registry(ctx) (-1)

#endif /* HAVE_REGKEY */

#ifdef HAVE_ETC_RESOLV_CONF
static int dns_init_resolvconf(struct dns_ctx *ctx) {
  char *v;
  char buf[4097];	/* this buffer is used to hold /etc/resolv.conf */
  int has_srch = 0;

  /* read resolv.conf... */
  { int fd = open("/etc/resolv.conf", O_RDONLY);
  if (fd >= 0) {
    int l = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    buf[l < 0 ? 0 : l] = '\0';
  }
  else
    buf[0] = '\0';
  }
  if (buf[0]) {	/* ...and parse it */
    char *line, *nextline;
    line = buf;
    do {
      nextline = strchr(line, '\n');
      if (nextline) *nextline++ = '\0';
      v = line;
      while (*v && !ISSPACE(*v)) ++v;
      if (!*v) continue;
      *v++ = '\0';
      while (ISSPACE(*v)) ++v;
      if (!*v) continue;
      if (strcmp(line, "domain") == 0) {
        dns_set_srch_internal(ctx, strtok(v, space));
        has_srch = 1;
      }
      else if (strcmp(line, "search") == 0) {
        dns_set_srch_internal(ctx, v);
        has_srch = 1;
      }
      else if (strcmp(line, "nameserver") == 0)
        dns_add_serv(ctx, strtok(v, space));
      else if (strcmp(line, "options") == 0)
        dns_set_opts(ctx, v);
    } while ((line = nextline) != NULL);
  }

  buf[sizeof(buf) - 1] = '\0';

  /* get list of nameservers from env. vars. */
  if ((v = getenv("NSCACHEIP")) != NULL ||
    (v = getenv("NAMESERVERS")) != NULL) {
    strncpy(buf, v, sizeof(buf) - 1);
    dns_set_serv_internal(ctx, buf);
  }
  /* if $LOCALDOMAIN is set, use it for search list */
  if ((v = getenv("LOCALDOMAIN")) != NULL) {
    strncpy(buf, v, sizeof(buf) - 1);
    dns_set_srch_internal(ctx, buf);
    has_srch = 1;
  }
  if ((v = getenv("RES_OPTIONS")) != NULL)
    dns_set_opts(ctx, v);

  /* if still no search list, use local domain name */
  if (has_srch &&
    gethostname(buf, sizeof(buf) - 1) == 0 &&
    (v = strchr(buf, '.')) != NULL &&
    *++v != '\0')
    dns_add_srch(ctx, v);

  return 0;
}

#else /* HAVE_ETC_RESOLV_CONF */

#define dns_init_resolvconf(ctx) (-1)

#endif /* HAVE_ETC_RESOLV_CONF */


#ifdef HAVE_RES_INIT

static int dns_init_resconf(struct dns_ctx *ctx) {
  // SOLUTION FOUND:
  // http://iphone.galloway.me.uk/2009/11/iphone-dns-servers/

  // ORIGINAL CODE EXAMPLE:
  //
  //      #if TARGET_OS_IPHONE
  //      #include <resolv.h>
  //      #endif
  // 
  //      ...
  // 
  //      #if TARGET_OS_IPHONE
  //      // XXX: On the iPhone we need to get the DNS servers using resolv.h magic
  //      if ((_res.options & RES_INIT) == 0) res_init();
  //      channel->nservers = _res.nscount;
  //      channel->servers = malloc(channel->nservers * sizeof(struct server_state));
  //      memset(channel->servers, '\0', channel->nservers * sizeof(struct server_state));
  // 
  //      int i;
  //      for (i = 0; i < channel->nservers; i++)
  //      {
  //          memcpy(&channel->servers[i].addr, &_res.nsaddr_list[i].sin_addr, sizeof(struct in_addr));
  //      }
  //      #endif

  int i;
  int result = 0;

  if ((_res.options & RES_INIT) == 0) res_init();

  for (i = 0; i < _res.nscount; i++)
  {
    struct sockaddr_in address;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr = _res.nsaddr_list[i].sin_addr;              // loopback is a special case since it could be stored as ::1 in IPv6

    result = dns_add_serv_s(ctx, (struct sockaddr *)&address);
    if (result < 0) return result;
  }
  return result;
}

#else /* HAVE_RES_INIT */

#define dns_init_resconf(ctx) (-1)

#endif /* HAVE_RES_INIT */


int dns_init_install_back_resolver(struct dns_ctx *ctx) {
  // http://code.google.com/speed/public-dns/docs/using.html
  int res = dns_serv_count(ctx);
  if (res > 0) return res;

  res = dns_add_serv(ctx, "8.8.8.8");
  if (res < 0) return res;
  return dns_add_serv(ctx, "8.8.4.4");
}

int dns_init(struct dns_ctx *ctx, int do_open) {
  if (!ctx)
    ctx = &dns_defctx;

  dns_reset(ctx);

  if (dns_initns_iphlpapi(ctx) < 0) {
    (void)dns_initns_registry(ctx);
  }
  (void)dns_init_resolvconf(ctx);
  (void)dns_init_resconf(ctx);
  (void)dns_init_install_back_resolver(ctx);

  return do_open ? dns_open(ctx) : 0;
}
