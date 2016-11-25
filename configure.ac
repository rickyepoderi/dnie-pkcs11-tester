#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([dnie-pkcs11-tester], [0.1], [https://github.com/rickyepoderi/dnie-pkcs11-tester])
AC_CONFIG_SRCDIR([dnie-pkcs11-tester.c])
AM_INIT_AUTOMAKE
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC_C99

# Use the C language and compiler for the following checks
AC_LANG([C])

# Checks for libraries.
AC_CHECK_LIB([crypto], [d2i_X509], [], [AC_MSG_FAILURE([could not find crypto])])

AC_ARG_WITH([pkcs11], 
  [AS_HELP_STRING([--with-pkcs11], [pkcs11 library to use @<:@default=/usr/lib/pkcs11/opensc-pkcs11.so@:>@])],
  [PKCS11LIB="$withval"],
  [AC_MSG_FAILURE(["Please specify pkcs11 library with --with-pkcs11=/path/to/pkcs11.so"])]
)
#PKCS11LIB=/usr/lib/x86_64-linux-gnu/pkcs11/opensc-pkcs11.so
AC_DEFINE_UNQUOTED([PKCS11LIB], ["${PKCS11LIB}"], [pkcs11 lib])
AC_SUBST([PKCS11LIB])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h termios.h unistd.h stdio.h stdarg.h getopt.h sys/wait.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_CHECK_FUNCS([strstr strtoul])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
