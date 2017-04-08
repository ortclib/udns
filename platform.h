
#pragma once

#ifndef HAVE_CONFIG_H

#ifdef _WIN32

#ifdef __cplusplus_winrt
#undef UDNS_WINRT
#define UDNS_WINRT
#endif //__cplusplus_winrt

/* these are expected to exist */
#define HAVE_IPv6 1
#define HAVE_IPHLPAPI_H 1
#define HAVE_REGKEY 1
#define HAVE_FOPEN_S 1
#define HAVE_DUPENV_S 1
#define HAVE_STRTOK_S 1
#define HAVE_SPRINTF_S 1
#define HAVE_STRERROR_S 1
#define HAVE_GMTIME_S 1
#define HAVE_DHCPREQUESTPARAMS 1
#ifdef HAVE_IPv6
#define HAVE_DHCPV6REQUESTPARAMS 1
#endif //HAVE_IPv6
#define HAVE_WSALOOKUPSERVICE 1
#define HAVE_SVCGUID_H 1

#define HAVE_POLL 1

/* these are not expected to exist */
#undef HAVE_ETC_RESOLV_CONF
#undef HAVE_RES_INIT
#undef HAVE_GETOPT
#undef HAVE_INET_PTON_NTOP
#undef HAVE_POLL

#ifdef UDNS_WINRT

/* these are not allowed */
#undef HAVE_IPHLPAPI_H
#undef HAVE_REGKEY
#undef HAVE_RES_INIT
#undef HAVE_ETC_RESOLV_CONF
#undef HAVE_DUPENV_S

#ifdef UDNS_WINRT_PHONE
#undef HAVE_SVCGUID_H
#undef HAVE_DHCPREQUESTPARAMS
#undef HAVE_DHCPV6REQUESTPARAMS
#endif //(WINAPI_FAMILY == WINAPI_FAMILY_PHONE_APP)

#elif defined(WIN32_RX64)
#undef HAVE_IPHLPAPI_H
#undef HAVE_REGKEY
#undef HAVE_SVCGUID_H
#endif //UDNS_WINRT

#else /* _WIN32 */

/* expected to exist */
#define HAVE_GETOPT 1
#define HAVE_INET_PTON_NTOP 1
#define HAVE_IPv6 1
#define HAVE_ETC_RESOLV_CONF 1
#define HAVE_RES_INIT 1
#define HAVE_POLL 1

/* not expected to exist */
#undef HAVE_IPHLPAPI_H
#undef HAVE_WSALOOKUPSERVICE
#undef HAVE_REGKEY
#undef HAVE_FOPEN_S
#undef HAVE_DUPENV_S
#undef HAVE_STRTOK_S
#undef HAVE_SPRINTF_S
#undef HAVE_STRERROR_S
#undef HAVE_GMTIME_S

#endif /* _WIN32 */

#else /* ndef HAVE_CONFIG_H */

#include "config.h"

#endif /* ndef HAVE_CONFIG_H */

#ifdef _WIN32
# ifndef WINDOWS
#  define WINDOWS
# endif /* ndef WINDOWS */
#endif /* _WIN32 */

#ifdef NO_IPHLPAPI
#undef HAVE_IPHLPAPI_H
#endif /* NO_IPHLPAPI */
