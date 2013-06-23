# $Id: Makefile,v 1.25 2005/04/06 00:01:15 mjt Exp $
# libudns Makefile
#
# Copyright (C) 2005  Michael Tokarev <mjt@corpit.ru>
# This file is part of UDNS library, an async DNS stub resolver.
#
# This library is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation; either
# version 2.1 of the License, or (at your option) any later version.
#
# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library, in file named COPYING.LGPL; if not,
# write to the Free Software Foundation, Inc., 59 Temple Place,
# Suite 330, Boston, MA  02111-1307  USA

UDNS_VERS   = 0.0.5
UDNS_SRCS   = udns_dn.c udns_dntosp.c udns_parse.c udns_resolver.c udns_misc.c \
	udns_rr_a.c udns_rr_ptr.c udns_rr_mx.c udns_rr_txt.c udns_bl.c \
	udns_codes.c
UDNS_USRCS  = dnsget.c rblcheck.c ex-dig.c
UDNS_DIST   = COPYING.LGPL udns.h udns.3 $(UDNS_SRCS) $(UDNS_USRCS) \
	Makefile TODO

UDNS_OBJS   = $(UDNS_SRCS:.c=.o) $(UDNS_GEN:.c=.o)
UDNS_LIB    = libudns.a

UDNS_SOVER  = 0
UDNS_SOBJS  = $(UDNS_OBJS:.o=.lo)
UDNS_SOLIB  = libudns.so
UDNS_SOLIBV = $(UDNS_SOLIB).$(UDNS_SOVER)

UDNS_LIBS   = $(UDNS_LIB) $(UDNS_SOLIBV) $(UDNS_SOLIB)

UDNS_UTILS   = $(UDNS_USRCS:.c=)
UDNS_SOUTILS = $(UDNS_USRCS:.c=.shared)

UDNS_PFX = udns-$(UDNS_VERS)

CFLAGS = -Wall -W -Wmissing-prototypes -O2 -DHAVE_POLL
CC = gcc
AWK = awk
PICFLAGS = -fPIC

all: static

.SUFFIXES: .c .o .lo .shared

static: $(UDNS_LIB) $(UDNS_UTILS)
$(UDNS_LIB): $(UDNS_OBJS)
	-rm -f $@
	$(AR) rv $@ $(UDNS_OBJS)
.c.o:
	$(CC) $(CFLAGS) -c $<

$(UDNS_OBJS) $(UDNS_SOBJS): udns.h
$(UDNS_UTILS): udns.h $(UDNS_LIB)
.c:
	$(CC) $(CFLAGS) -o $@ $< $(UDNS_LIB)

shared: $(UDNS_SOLIB) $(UDNS_SOUTILS)

$(UDNS_SOLIB): $(UDNS_SOLIBV)
	rm -f $@
	ln -s $< $@
$(UDNS_SOLIBV): $(UDNS_SOBJS)
	$(CC) -shared -Wl,--soname,$@ -o $@ $(UDNS_SOBJS)
.c.lo:
	$(CC) $(CFLAGS) $(PICFLAGS) -o $@ -c $<

$(UDNS_SOUTILS): udns.h $(UDNS_SOLIB)
.c.shared:
	$(CC) $(CFLAGS) -o $@ $< $(UDNS_SOLIB)

udns_codes.c:	udns.h Makefile
	@echo Generating $@
	@set -e; exec >$@.tmp; \
	set T type C class R rcode; \
	echo "/* Automatically generated. */"; \
	echo "#include \"udns.h\""; \
	while [ "$$1" ]; do \
	 echo; \
	 echo "const struct dns_nameval dns_$${2}tab[] = {"; \
	 $(AWK) "/^  DNS_$${1}_[A-Z0-9_]+[ 	]*=/ \
	  { printf \" {%s,\\\"%s\\\"},\\n\", \$$1, substr(\$$1,7) }" \
	  $< ; \
	 echo " {0,0}};"; \
	 echo "const char *dns_$${2}name(enum dns_$${2} code) {"; \
	 echo " static char nm[20];"; \
	 echo " switch(code) {"; \
	 $(AWK) "BEGIN{i=0} \
	   /^  DNS_$${1}_[A-Z0-9_]+[ 	]*=/ \
	   {printf \" case %s: return dns_$${2}tab[%d].name;\\n\",\$$1,i++}\
	   " $< ; \
	 echo " }"; \
	 echo " return _dns_format_code(nm,\"$$2\",code);"; \
	 echo "}"; \
	 shift 2; \
	done
	@mv $@.tmp $@

udns.3.html: udns.3
	groff -man -Thtml $< > $@.tmp
	mv $@.tmp $@

dist: $(UDNS_PFX).tar.gz
$(UDNS_PFX).tar.gz: $(UDNS_DIST)
	mkdir $(UDNS_PFX)
	ln $(UDNS_DIST) $(UDNS_PFX)
	tar cvfz $@ $(UDNS_PFX)
	rm -rf $(UDNS_PFX)

clean:
	rm -f $(UDNS_OBJS) $(UDNS_SOBJS)
distclean: clean
	rm -f $(UDNS_LIBS) udns.3.html $(UDNS_UTILS) $(UDNS_SOUTILS)
