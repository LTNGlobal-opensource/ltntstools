#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([ltntstools], [1.0], [stoth@ltnglobal.com])
AM_INIT_AUTOMAKE
AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_HOST
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AC_PROG_CXX
#CFLAGS+=" -DKL_USERSPACE "
AC_PROG_RANLIB
AC_PROG_LIBTOOL

AC_C_INLINE

AM_CONDITIONAL(LINUX, test `uname -s` = "Linux")
AM_CONDITIONAL(APPLE, test `uname -s` = "Darwin")

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h unistd.h])
AC_CHECK_HEADERS([pcap.h],
                 [break],
                 [AC_MSG_ERROR([libpcap headers not found or not usable])])
AC_CHECK_HEADERS([zlib.h],
                 [break],
                 [AC_MSG_ERROR([zlib-dev headers not found or not usable])])
#AC_CHECK_HEADERS([dvbpsi/dvbpsi.h],
#                 [break],
#                 [AC_MSG_ERROR([libdvbpsi headers not found or not usable])])

# Check for curses (optional)
AC_CHECK_HEADERS([curses.h], HEADER_LIBCURSES="yes")
if test "x$HEADER_LIBCURSES" == "xyes" ; then
    LDFLAGS+=" -lcurses "
fi
AM_CONDITIONAL(LIBCURSES, test x"$HEADER_LIBCURSES" == x"yes")

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_UINT16_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_CHECK_FUNCS([memset strrchr])

# Add debug support
AC_ARG_ENABLE(debug,
  AS_HELP_STRING(
    [--enable-debug],
    [enable debugging, default: no]),
    [case "${enableval}" in
      yes) debug=true ;;
      no)  debug=false ;;
      *)   AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
    esac],
    [debug=false])
AM_CONDITIONAL(DEBUG, test x"$debug" = x"true")
AM_COND_IF(DEBUG,
    AC_DEFINE(DEBUG, 1, [Define to 0 if this is a release build]),
    AC_DEFINE(DEBUG, 0, [Define to 1 or higher if this is a debug build]))

# Add Dektec DTAPI
AC_ARG_ENABLE(dtapi,
  AS_HELP_STRING(
    [--enable-dtapi],
    [enable dektec dtapi, default: yes]),
    [case "${enableval}" in
      yes) dtapi=true ;;
      no)  dtapi=false ;;
      *)   AC_MSG_ERROR([bad value ${enableval} for --enable-dtapi]) ;;
    esac],
    [dtapi=true])
AM_CONDITIONAL(DTAPI, test x"$dtapi" = x"true")
AM_COND_IF(DTAPI,
    AC_DEFINE(HAVE_DTAPI, 1, [Define to 1 if dtapi support included]),)

# Add NBA Tissot Timing protocol library support
AC_ARG_ENABLE(ntt,
  AS_HELP_STRING(
    [--enable-ntt],
    [enable NBA Tissot timing protocol, default: no]),
    [case "${enableval}" in
      yes) ntt=true ;;
      no)  ntt=false ;;
      *)   AC_MSG_ERROR([bad value ${enableval} for --enable-ntt]) ;;
    esac],
    [ntt=false])
AM_CONDITIONAL(NTT, test x"$ntt" = x"true")
AM_COND_IF(NTT,
    AC_DEFINE(HAVE_NTT, 1, [Define to 1 if NBA Tissot Timing support included]),)

AC_CONFIG_FILES([Makefile src/Makefile])
AC_OUTPUT
