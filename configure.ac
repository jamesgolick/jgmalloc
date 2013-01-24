AC_PREREQ(2.59)
AC_COPYRIGHT([Copyright (c) 2013 James "Gangster" Golick])
AC_INIT([libjgmalloc], [trunk])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR(src)
AM_CONFIG_HEADER(config.h)

AC_CANONICAL_SYSTEM
AC_LANG(C)

AM_INIT_AUTOMAKE([foreign])

AC_GNU_SOURCE
AC_PROG_CC
AC_PROG_CC_STDC
if test "x$ac_cv_prog_cc_c99" = xno; then
	AC_MSG_ERROR([Could not find a C99 compatible compiler])
fi
AC_PROG_CPP

AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_MAKE_SET

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([sys/stdlib.h])

AC_CONFIG_FILES([
	Makefile
	src/Makefile
])
AC_OUTPUT
