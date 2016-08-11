dnl require autoconf 2.60 (AS_ECHO/AS_ECHO_N)
AC_PREREQ([2.60])
define(_CLIENT_VERSION_MAJOR, 0)
define(_CLIENT_VERSION_MINOR, 1)
define(_CLIENT_VERSION_REVISION, 99)
define(_CLIENT_VERSION_BUILD, 0)
define(_CLIENT_VERSION_IS_RELEASE, false)
define(_COPYRIGHT_YEAR, 2016)
define(_COPYRIGHT_HOLDERS,[The %s developers])
define(_COPYRIGHT_HOLDERS_SUBSTITUTION,[[Bitpay Wallet Client]])
AC_INIT([BitpayWalletClient],[_CLIENT_VERSION_MAJOR._CLIENT_VERSION_MINOR._CLIENT_VERSION_REVISION],[https://github.com/jonasschnelli/bitpaywalletclient/issues],[bitpaywalletclient])
AC_CONFIG_SRCDIR([src/bitpaywalletclient.cpp])
AC_CONFIG_HEADERS([src/config/bitpaywalletclient-config.h])
AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([build-aux/m4])

AC_CANONICAL_HOST

AH_TOP([#ifndef BITPAYWALLETCLIENT_CONFIG_H])
AH_TOP([#define BITPAYWALLETCLIENT_CONFIG_H])
AH_BOTTOM([#endif //BITPAYWALLETCLIENT_CONFIG_H])

dnl Automake init set-up and checks
AM_INIT_AUTOMAKE([no-define subdir-objects foreign])

dnl faketime messes with timestamps and causes configure to be re-run.
dnl --disable-maintainer-mode can be used to bypass this.
AM_MAINTAINER_MODE([enable])

dnl make the compilation flags quiet unless V=1 is used
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

dnl Compiler checks (here before libtool).
if test "x${CXXFLAGS+set}" = "xset"; then
  CXXFLAGS_overridden=yes
else
  CXXFLAGS_overridden=no
fi
AC_PROG_CXX
m4_ifdef([AC_PROG_OBJCXX],[AC_PROG_OBJCXX])

dnl By default, libtool for mingw refuses to link static libs into a dll for
dnl fear of mixing pic/non-pic objects, and import/export complications. Since
dnl we have those under control, re-enable that functionality.
case $host in
  *mingw*)
     lt_cv_deplibs_check_method="pass_all"
  ;;
esac
dnl Require C++11 compiler (no GNU extensions)
AX_CXX_COMPILE_STDCXX([11], [noext], [mandatory])
dnl Libtool init checks.
LT_INIT([pic-only])

dnl Check/return PATH for base programs.
AC_PATH_TOOL(AR, ar)
AC_PATH_TOOL(RANLIB, ranlib)
AC_PATH_TOOL(STRIP, strip)
AC_PATH_PROG([GIT], [git])

# Enable debug
AC_ARG_ENABLE([debug],
    [AS_HELP_STRING([--enable-debug],
                    [use debug compiler flags and macros (default is no)])],
    [enable_debug=$enableval],
    [enable_debug=no])

AC_LANG_PUSH([C++])
AX_CHECK_COMPILE_FLAG([-Werror],[CXXFLAG_WERROR="-Werror"],[CXXFLAG_WERROR=""])

if test "x$enable_debug" = xyes; then
    CPPFLAGS="$CPPFLAGS -DDEBUG -DDEBUG_LOCKORDER"
    if test "x$GCC" = xyes; then
        CFLAGS="$CFLAGS -g3 -O0"
    fi

    if test "x$GXX" = xyes; then
        CXXFLAGS="$CXXFLAGS -g3 -O0"
    fi
fi

if test "x$CXXFLAGS_overridden" = "xno"; then
  AX_CHECK_COMPILE_FLAG([-Wall],[CXXFLAGS="$CXXFLAGS -Wall"],,[[$CXXFLAG_WERROR]])
  AX_CHECK_COMPILE_FLAG([-Wextra],[CXXFLAGS="$CXXFLAGS -Wextra"],,[[$CXXFLAG_WERROR]])
  AX_CHECK_COMPILE_FLAG([-Wformat],[CXXFLAGS="$CXXFLAGS -Wformat"],,[[$CXXFLAG_WERROR]])
  AX_CHECK_COMPILE_FLAG([-Wformat-security],[CXXFLAGS="$CXXFLAGS -Wformat-security"],,[[$CXXFLAG_WERROR]])

  ## Some compilers (gcc) ignore unknown -Wno-* options, but warn about all
  ## unknown options if any other warning is produced. Test the -Wfoo case, and
  ## set the -Wno-foo case if it works.
  AX_CHECK_COMPILE_FLAG([-Wunused-parameter],[CXXFLAGS="$CXXFLAGS -Wno-unused-parameter"],,[[$CXXFLAG_WERROR]])
  AX_CHECK_COMPILE_FLAG([-Wself-assign],[CXXFLAGS="$CXXFLAGS -Wno-self-assign"],,[[$CXXFLAG_WERROR]])
  AX_CHECK_COMPILE_FLAG([-Wunused-local-typedef],[CXXFLAGS="$CXXFLAGS -Wno-unused-local-typedef"],,[[$CXXFLAG_WERROR]])
  AX_CHECK_COMPILE_FLAG([-Wdeprecated-register],[CXXFLAGS="$CXXFLAGS -Wno-deprecated-register"],,[[$CXXFLAG_WERROR]])
fi
CPPFLAGS="$CPPFLAGS -DHAVE_BUILD_INFO -D__STDC_FORMAT_MACROS"

dnl Check for endianness
AC_C_BIGENDIAN

if test x$TARGET_OS != xwindows; then
  # All windows code is PIC, forcing it on just adds useless compile warnings
  AX_CHECK_COMPILE_FLAG([-fPIC],[PIC_FLAGS="-fPIC"])
fi

if test x$use_hardening != xno; then
  AX_CHECK_COMPILE_FLAG([-Wstack-protector],[HARDENED_CXXFLAGS="$HARDENED_CXXFLAGS -Wstack-protector"])
  AX_CHECK_COMPILE_FLAG([-fstack-protector-all],[HARDENED_CXXFLAGS="$HARDENED_CXXFLAGS -fstack-protector-all"])

  AX_CHECK_PREPROC_FLAG([-D_FORTIFY_SOURCE=2],[
    AX_CHECK_PREPROC_FLAG([-U_FORTIFY_SOURCE],[
      HARDENED_CPPFLAGS="$HARDENED_CPPFLAGS -U_FORTIFY_SOURCE"
    ])
    HARDENED_CPPFLAGS="$HARDENED_CPPFLAGS -D_FORTIFY_SOURCE=2"
  ])

  AX_CHECK_LINK_FLAG([[-Wl,--dynamicbase]], [HARDENED_LDFLAGS="$HARDENED_LDFLAGS -Wl,--dynamicbase"])
  AX_CHECK_LINK_FLAG([[-Wl,--nxcompat]], [HARDENED_LDFLAGS="$HARDENED_LDFLAGS -Wl,--nxcompat"])
  AX_CHECK_LINK_FLAG([[-Wl,-z,relro]], [HARDENED_LDFLAGS="$HARDENED_LDFLAGS -Wl,-z,relro"])
  AX_CHECK_LINK_FLAG([[-Wl,-z,now]], [HARDENED_LDFLAGS="$HARDENED_LDFLAGS -Wl,-z,now"])

  if test x$TARGET_OS != xwindows; then
    AX_CHECK_COMPILE_FLAG([-fPIE],[PIE_FLAGS="-fPIE"])
    AX_CHECK_LINK_FLAG([[-pie]], [HARDENED_LDFLAGS="$HARDENED_LDFLAGS -pie"])
  fi

  case $host in
    *mingw*)
       AC_CHECK_LIB([ssp],      [main],, AC_MSG_ERROR(lib missing))
    ;;
  esac
fi

dnl this flag screws up non-darwin gcc even when the check fails. special-case it.
if test x$TARGET_OS = xdarwin; then
  AX_CHECK_LINK_FLAG([[-Wl,-dead_strip]], [LDFLAGS="$LDFLAGS -Wl,-dead_strip"])
fi

AC_CHECK_HEADERS([endian.h sys/endian.h byteswap.h stdio.h stdlib.h unistd.h strings.h sys/types.h sys/stat.h sys/select.h sys/prctl.h])

AC_CHECK_DECLS([strnlen])

AC_MSG_CHECKING([for visibility attribute])
AC_LINK_IFELSE([AC_LANG_SOURCE([
  int foo_def( void ) __attribute__((visibility("default")));
  int main(){}
  ])],
  [
    AC_DEFINE(HAVE_VISIBILITY_ATTRIBUTE,1,[Define if the visibility attribute is supported.])
    AC_MSG_RESULT(yes)
  ],
  [
    AC_MSG_RESULT(no)
    if test x$use_reduce_exports = xyes; then
      AC_MSG_ERROR([Cannot find a working visibility attribute. Use --disable-reduce-exports.])
    fi
  ]
)

if test x$use_reduce_exports = xyes; then
  AX_CHECK_COMPILE_FLAG([-fvisibility=hidden],[RE_CXXFLAGS="-fvisibility=hidden"],
  [AC_MSG_ERROR([Cannot set default symbol visibility. Use --disable-reduce-exports.])])
fi

if test x$use_reduce_exports = xyes; then
    CXXFLAGS="$CXXFLAGS $RE_CXXFLAGS"
    AX_CHECK_LINK_FLAG([[-Wl,--exclude-libs,ALL]], [RELDFLAGS="-Wl,--exclude-libs,ALL"])
fi

dnl check curl
LIBCURL_CHECK_CONFIG(, 7.21.0, , [AC_MSG_ERROR([Missing required libcurl >= 7.21.0])])

dnl univalue check

if test x$system_univalue != xno ; then
  found_univalue=no
  if test x$use_pkgconfig = xyes; then
    : #NOP
    m4_ifdef(
      [PKG_CHECK_MODULES],
      [
        PKG_CHECK_MODULES([UNIVALUE],[libunivalue],[found_univalue=yes],[true])
      ]
    )
  else
    AC_CHECK_HEADER([univalue.h],[
      AC_CHECK_LIB([univalue],  [main],[
        UNIVALUE_LIBS=-lunivalue
        found_univalue=yes
      ],[true])
    ],[true])
  fi

  if test x$found_univalue = xyes ; then
    system_univalue=yes
  elif test x$system_univalue = xyes ; then
    AC_MSG_ERROR([univalue not found])
  else
    system_univalue=no
  fi
fi

if test x$system_univalue = xno ; then
  UNIVALUE_CFLAGS='-I$(srcdir)/univalue/include'
  UNIVALUE_LIBS='univalue/libunivalue.la'
fi
AM_CONDITIONAL([EMBEDDED_UNIVALUE],[test x$system_univalue = xno])
AC_SUBST(UNIVALUE_CFLAGS)
AC_SUBST(UNIVALUE_LIBS)

AC_LANG_POP

if test "x$use_ccache" != "xno"; then
  AC_MSG_CHECKING(if ccache should be used)
  if test x$CCACHE = x; then
    if test "x$use_ccache" = "xyes"; then
      AC_MSG_ERROR([ccache not found.]);
    else
      use_ccache=no
    fi
  else
    use_ccache=yes
    CC="$ac_cv_path_CCACHE $CC"
    CXX="$ac_cv_path_CCACHE $CXX"
  fi
  AC_MSG_RESULT($use_ccache)
fi
if test "x$use_ccache" = "xyes"; then
    AX_CHECK_PREPROC_FLAG([-Qunused-arguments],[CPPFLAGS="-Qunused-arguments $CPPFLAGS"])
fi

AC_MSG_CHECKING([whether to reduce exports])
if test x$use_reduce_exports = xyes; then
  AC_MSG_RESULT([yes])
else
  AC_MSG_RESULT([no])
fi

AM_CONDITIONAL([TARGET_DARWIN], [test x$TARGET_OS = xdarwin])
AM_CONDITIONAL([BUILD_DARWIN], [test x$BUILD_OS = xdarwin])
AM_CONDITIONAL([TARGET_WINDOWS], [test x$TARGET_OS = xwindows])
AM_CONDITIONAL([ENABLE_TESTS],[test x$BUILD_TEST = xyes])
AM_CONDITIONAL([HARDEN],[test x$use_hardening = xyes])

AC_DEFINE(CLIENT_VERSION_MAJOR, _CLIENT_VERSION_MAJOR, [Major version])
AC_DEFINE(CLIENT_VERSION_MINOR, _CLIENT_VERSION_MINOR, [Minor version])
AC_DEFINE(CLIENT_VERSION_REVISION, _CLIENT_VERSION_REVISION, [Build revision])
AC_DEFINE(CLIENT_VERSION_BUILD, _CLIENT_VERSION_BUILD, [Version Build])
AC_DEFINE(CLIENT_VERSION_IS_RELEASE, _CLIENT_VERSION_IS_RELEASE, [Version is release])
AC_DEFINE(COPYRIGHT_YEAR, _COPYRIGHT_YEAR, [Copyright year])
AC_DEFINE(COPYRIGHT_HOLDERS, "_COPYRIGHT_HOLDERS", [Copyright holder(s) before %s replacement])
AC_DEFINE(COPYRIGHT_HOLDERS_SUBSTITUTION, "_COPYRIGHT_HOLDERS_SUBSTITUTION", [Replacement for %s in copyright holders string])
define(_COPYRIGHT_HOLDERS_FINAL, [patsubst(_COPYRIGHT_HOLDERS, [%s], [_COPYRIGHT_HOLDERS_SUBSTITUTION])])
AC_DEFINE(COPYRIGHT_HOLDERS_FINAL, "_COPYRIGHT_HOLDERS_FINAL", [Copyright holder(s)])
AC_SUBST(CLIENT_VERSION_MAJOR, _CLIENT_VERSION_MAJOR)
AC_SUBST(CLIENT_VERSION_MINOR, _CLIENT_VERSION_MINOR)
AC_SUBST(CLIENT_VERSION_REVISION, _CLIENT_VERSION_REVISION)
AC_SUBST(CLIENT_VERSION_BUILD, _CLIENT_VERSION_BUILD)
AC_SUBST(CLIENT_VERSION_IS_RELEASE, _CLIENT_VERSION_IS_RELEASE)
AC_SUBST(COPYRIGHT_YEAR, _COPYRIGHT_YEAR)
AC_SUBST(COPYRIGHT_HOLDERS, "_COPYRIGHT_HOLDERS")
AC_SUBST(COPYRIGHT_HOLDERS_SUBSTITUTION, "_COPYRIGHT_HOLDERS_SUBSTITUTION")
AC_SUBST(COPYRIGHT_HOLDERS_FINAL, "_COPYRIGHT_HOLDERS_FINAL")

AC_SUBST(RELDFLAGS)
AC_SUBST(HARDENED_CXXFLAGS)
AC_SUBST(HARDENED_CPPFLAGS)
AC_SUBST(HARDENED_LDFLAGS)
AC_SUBST(PIC_FLAGS)
AC_SUBST(PIE_FLAGS)
AC_SUBST(LIBTOOL_APP_LDFLAGS)
AC_CONFIG_FILES([Makefile src/Makefile])

CPPFLAGS_TEMP="$CPPFLAGS"
unset CPPFLAGS
CPPFLAGS="$CPPFLAGS_TEMP"

LDFLAGS_TEMP="$LDFLAGS"
unset LDFLAGS
LDFLAGS="$LDFLAGS_TEMP"

LIBS_TEMP="$LIBS"
unset LIBS
LIBS="$LIBS_TEMP"

PKGCONFIG_PATH_TEMP="$PKG_CONFIG_PATH"
unset PKG_CONFIG_PATH
PKG_CONFIG_PATH="$PKGCONFIG_PATH_TEMP"

PKGCONFIG_LIBDIR_TEMP="$PKG_CONFIG_LIBDIR"
unset PKG_CONFIG_LIBDIR
PKG_CONFIG_LIBDIR="$PKGCONFIG_LIBDIR_TEMP"

if test x$system_univalue = xno; then
  AC_CONFIG_SUBDIRS([src/univalue])
fi

ac_configure_args="${ac_configure_args} --disable-shared --with-pic --with-bignum=no --enable-module-recovery"
AC_CONFIG_SUBDIRS([src/libbtc])

AC_OUTPUT

dnl Taken from https://wiki.debian.org/RpathIssue
case $host in
   *-*-linux-gnu)
     AC_MSG_RESULT([Fixing libtool for -rpath problems.])
     sed < libtool > libtool-2 \
     's/^hardcode_libdir_flag_spec.*$'/'hardcode_libdir_flag_spec=" -D__LIBTOOL_IS_A_FOOL__ "/'
     mv libtool-2 libtool
     chmod 755 libtool
   ;;
esac

dnl Replace the BUILDDIR path with the correct Windows path if compiling on Native Windows
case ${OS} in
   *Windows*)
     sed  's/BUILDDIR="\/\([[a-z]]\)/BUILDDIR="\1:/'  qa/pull-tester/tests_config.py > qa/pull-tester/tests_config-2.py
     mv qa/pull-tester/tests_config-2.py qa/pull-tester/tests_config.py
   ;;
esac
