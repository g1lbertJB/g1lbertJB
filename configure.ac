dnl Process this file with autoconf to produce a configure script.

AC_PREREQ(2.59)
AC_INIT(pris0nbarake, 1.0)
AC_CONFIG_MACRO_DIR([m4])

AC_CANONICAL_SYSTEM
AM_INIT_AUTOMAKE()

AM_PROG_CC_C_O
AC_PROG_LIBTOOL

AC_CONFIG_HEADERS(config.h)

AC_PROG_CXX

ACCFLAGS="-I\$(top_srcdir)/include"
ACSHAREDLIBS=""
ACLDFLAGS=""

LIBXML2_STATIC=""
OPENSSL_STATIC=""

PKG_CHECK_MODULES(libimobiledevice, libimobiledevice-1.0 >= 1.1.0)
PKG_CHECK_MODULES(libplist, libplist-2.0 >= 0.15)
PKG_CHECK_MODULES(libzip, libzip >= 0.8)
PKG_CHECK_MODULES(zlib, zlib)
PKG_CHECK_MODULES(openssl, openssl >= 0.9.8)

GLOBAL_CFLAGS=$ACCFLAGS
AC_SUBST(GLOBAL_CFLAGS)

AC_SUBST(GLOBAL_LIBS)

GLOBAL_LDFLAGS="$ACLDFLAGS"
AC_SUBST(GLOBAL_LDFLAGS)

AC_CONFIG_FILES(Makefile src/Makefile)
AC_OUTPUT

