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
AC_SEARCH_LIBS([dlopen], [dl dld], [], [
  AC_MSG_FAILURE([unable to find the dlopen() function])
])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h termios.h unistd.h stdio.h stdarg.h getopt.h sys/wait.h dlfcn.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_CHECK_FUNCS([strstr strtoul])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
