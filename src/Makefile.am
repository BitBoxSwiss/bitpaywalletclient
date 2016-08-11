DIST_SUBDIRS = univalue libbtc

AM_LDFLAGS = $(LIBTOOL_LDFLAGS) $(HARDENED_LDFLAGS)
AM_CXXFLAGS = $(HARDENED_CXXFLAGS)
AM_CPPFLAGS = $(HARDENED_CPPFLAGS)
EXTRA_LIBRARIES =

if EMBEDDED_UNIVALUE
LIBUNIVALUE = univalue/libunivalue.la

$(LIBUNIVALUE): $(wildcard univalue/lib/*) $(wildcard univalue/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)
else
LIBUNIVALUE = $(UNIVALUE_LIBS)
endif

LIBBTC = libbtc/libbtc.la

$(LIBBTC): $(wildcard libbtc/src/*) $(wildcard libbtc/include/*)
	$(AM_V_at)$(MAKE) $(AM_MAKEFLAGS) -C $(@D) $(@F)

LIBBITPAYWALLETCLIENT=libbitpaywalletclient.la

lib_LTLIBRARIES = $(LIBBITPAYWALLETCLIENT)

.PHONY: FORCE check-symbols check-security

LIBBITPAYWALLETCLIENT_H = utils.h bitpaywalletclient.h
libbitpaywalletclient_la_SOURCES = $(LIBBITPAYWALLETCLIENT_H) utils.cpp bitpaywalletclient.cpp

libbitpaywalletclient_la_LDFLAGS = $(AM_LDFLAGS) -no-undefined $(RELDFLAGS)
libbitpaywalletclient_la_LIBADD = $(LIBUNIVALUE) $(LIBBTC) $(LIBCURL)
libbitpaywalletclient_la_CPPFLAGS = $(AM_CPPFLAGS) $(UNIVALUE_CFLAGS) -I$(srcdir)/libbtc/include -I$(srcdir)/../include
libbitpaywalletclient_la_CXXFLAGS = $(AM_CXXFLAGS) $(PIE_FLAGS)

instdir=$(prefix)/bin
inst_PROGRAMS = bitpaywalletclient
bitpaywalletclient_LDADD = $(LIBUNIVALUE) $(LIBBTC) $(LIBCURL) libbitpaywalletclient.la
bitpaywalletclient_SOURCES = \
    clitool.cpp
bitpaywalletclient_CFLAGS = $(libbtc_la_CFLAGS)
bitpaywalletclient_CPPFLAGS = $(AM_CPPFLAGS) $(UNIVALUE_CFLAGS) -I$(srcdir)/libbtc/include -I$(srcdir)/../include
bitpaywalletclient_LDFLAGS = -static

clean-local:
	-$(MAKE) -C libbtc clean
	-$(MAKE) -C univalue clean
