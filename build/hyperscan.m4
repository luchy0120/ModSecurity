dnl Check for hyperscan Libraries
dnl CHECK_HYPERSCAN(ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND])
dnl Sets:
dnl  HS_CFLAGS
dnl  HS_LIBS

HS_CFLAGS=""
HS_LDADD=""


AC_DEFUN([CHECK_HYPERSCAN],
[dnl

AC_ARG_WITH(
      hyperscan-includes,
      [AC_HELP_STRING([--with-hyperscan-includes=PATH],[Path to libhs include directory])],
      [test_paths="${with_hyperscan-includes}"],
      [test_paths="/usr/local/include/hs /usr/local/include"])

AC_MSG_CHECKING([for hs include directory])
for x in ${test_paths}; do
    dnl # Check whether ch.h exists
    if test -e "${x}/ch.h"; then
        HS_CFLAGS="-I${x}"
        AC_MSG_RESULT([yes])
        break
    fi
done

if test -z "${HS_CFLAGS}"; then
      AC_MSG_RESULT([no])
fi

AC_ARG_WITH(
      hyperscan-libraries, 
      [AC_HELP_STRING([--with-hyperscan-libraries=PATH],[Path to libhs library directory])],
      [test_paths="${with_hyperscan-libraries}"],
      [test_paths="/usr/local/lib"])

AC_MSG_CHECKING([for hs libarary directory])
for x in ${test_paths}; do
    dnl # Check whether libchimera exists
    if test -e "${x}/libchimera.a"; then
        HS_LDADD="-L${x} -lchimera"
        AC_MSG_RESULT([yes])
        break
    fi
done

if test -z "${HS_LDADD}"; then
    AC_MSG_RESULT([no])
fi

if test -z "${HS_CFLAGS}" -o -z "${HS_LDADD}"; then
    dnl # At last, we try pkg-config
    PKG_CHECK_MODULES([CH],[libch >= 4.7.0],[HS_LDADD=CH_LIBS])
fi

AC_SUBST(HS_CFLAGS)
AC_SUBST(HS_LDADD)

if test -z "${HS_CFLAGS}" -o -z "${HS_LDADD}"; then
    AC_MSG_NOTICE([*** hyperscan-chimera library not found.])
    ifelse([$2], , AC_MSG_ERROR([hyperscan-chimera library is required]), $2)
else
    ifelse([$1], , , $1)
    HS_LDADD="${HS_LDADD} -lhs -lpcre"
    AC_MSG_NOTICE([hs CFLAGS: $HS_CFLAGS])
    AC_MSG_NOTICE([hs LDADD: $HS_LDADD])
fi

])
