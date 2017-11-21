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

# check for dlpopen library
AC_SEARCH_LIBS([dlopen], [dl dld], [], [
  AC_MSG_FAILURE([unable to find the dlopen() function])
])

# Checks for crypto
AC_ARG_WITH([ssl],
             AC_HELP_STRING([--with-ssl],
                            [Specify custom path for openssl libraries (default auto-detect)]),
             [ac_cv_use_ssl=$withval], [ac_cv_use_ssl=no])
if test "x$ac_cv_use_ssl" != xno; then
    AC_MSG_NOTICE([Using custom openssl information...])
    OPENSSL_PCDIR="$ac_cv_use_ssl/lib/pkgconfig"
    AC_PATH_TOOL([PKGCONFIG], [pkg-config], [no], [$PATH:/usr/bin:/usr/local/bin])
    itexists=`PKG_CONFIG_LIBDIR=$OPENSSL_PCDIR $PKGCONFIG --exists libcrypto >/dev/null 2>&1 && echo 1`
    if test -z "$itexists"; then
        CRYPTO_LDFLAGS="-L$ac_cv_use_ssl/lib"
        CRYPTO_CPPFLAGS="-I$ac_cv_use_ssl/include"
        AC_MSG_NOTICE([No pkg-config information found. Using hardcoded $CRYPTO_CPPFLAGS and $CRYPTO_LDFLAGS])
    else
        CRYPTO_LDFLAGS=`PKG_CONFIG_LIBDIR=$OPENSSL_PCDIR $PKGCONFIG --libs-only-L libcrypto 2>/dev/null`
        CRYPTO_CPPFLAGS=`PKG_CONFIG_LIBDIR=$OPENSSL_PCDIR $PKGCONFIG --cflags-only-I libcrypto 2>/dev/null`
        AC_MSG_NOTICE([pkg-config information found. Using returned $CRYPTO_CPPFLAGS and $CRYPTO_LDFLAGS])
    fi
    LDFLAGS="$LDFLAGS $CRYPTO_LDFLAGS"
    CPPFLAGS="$CPPFLAGS $CRYPTO_CPPFLAGS"
fi
AC_CHECK_LIB([crypto], [d2i_X509], [], [AC_MSG_FAILURE([could not find crypto])])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdlib.h string.h termios.h unistd.h stdio.h stdarg.h getopt.h openssl/x509.h sys/wait.h dlfcn.h],
                 [],[AC_MSG_FAILURE([could not find include files])])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_FORK
AC_CHECK_FUNCS([strstr strtoul])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
