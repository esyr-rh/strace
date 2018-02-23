# ===========================================================================
#   http://www.gnu.org/software/autoconf-archive/ax_prog_cc_for_build.html
# ===========================================================================
#
# SYNOPSIS
#
#   AX_PROG_CC_FOR_BUILD
#
# DESCRIPTION
#
#   This macro searches for a C compiler that generates native executables,
#   that is a C compiler that surely is not a cross-compiler. This can be
#   useful if you have to generate source code at compile-time like for
#   example GCC does.
#
#   The macro sets the CC_FOR_BUILD and CPP_FOR_BUILD macros to anything
#   needed to compile or link (CC_FOR_BUILD) and preprocess (CPP_FOR_BUILD).
#   The value of these variables can be overridden by the user by specifying
#   a compiler with an environment variable (like you do for standard CC).
#
#   It also sets BUILD_EXEEXT and BUILD_OBJEXT to the executable and object
#   file extensions for the build platform, and GCC_FOR_BUILD to `yes' if
#   the compiler we found is GCC. All these variables but GCC_FOR_BUILD are
#   substituted in the Makefile.
#
# LICENSE
#
#   Copyright (c) 2008 Paolo Bonzini <bonzini@gnu.org>
#   Copyright (c) 2008-2017 The strace developers.
#
#   Copying and distribution of this file, with or without modification, are
#   permitted in any medium without royalty provided the copyright notice
#   and this notice are preserved. This file is offered as-is, without any
#   warranty.

#serial 8
#modified for strace project

AU_ALIAS([AC_PROG_CC_FOR_BUILD], [AX_PROG_CC_FOR_BUILD])
AC_DEFUN([AX_PROG_CC_FOR_BUILD], [dnl
AX_PROG_CC_FOR(build,$@)dnl
])

AC_DEFUN([AX_PROG_CC_FOR], [dnl
AC_REQUIRE([AC_PROG_CC])dnl
AC_REQUIRE([AC_PROG_CPP])dnl
AC_REQUIRE([AC_EXEEXT])dnl
AC_REQUIRE([AC_CANONICAL_HOST])dnl

m4_define([forupper], m4_toupper([$1]))

dnl Use the standard macros, but make them use other variable names
dnl
pushdef([ac_cv_prog_CPP], ac_cv_$1_prog_CPP)dnl
pushdef([ac_cv_prog_gcc], ac_cv_$1_prog_gcc)dnl
pushdef([ac_cv_prog_cc_works], ac_cv_$1_prog_cc_works)dnl
pushdef([ac_cv_prog_cc_cross], ac_cv_$1_prog_cc_cross)dnl
pushdef([ac_cv_prog_cc_g], ac_cv_$1_prog_cc_g)dnl
pushdef([ac_cv_prog_cc_stdc], ac_cv_$1_prog_cc_stdc)dnl
pushdef([ac_cv_prog_cc_c11], ac_cv_$1_prog_cc_c11)dnl
pushdef([ac_cv_prog_cc_c99], ac_cv_$1_prog_cc_c99)dnl
pushdef([ac_cv_prog_cc_c89], ac_cv_$1_prog_cc_c89)dnl
pushdef([ac_cv_exeext], ac_cv_$1_exeext)dnl
pushdef([ac_cv_objext], ac_cv_$1_objext)dnl
pushdef([ac_exeext], ac_$1_exeext)dnl
pushdef([ac_objext], ac_$1_objext)dnl
pushdef([CC], [CC_FOR_]forupper)dnl
pushdef([CPP], [CPP_FOR_]forupper)dnl
pushdef([CFLAGS], [CFLAGS_FOR_]forupper)dnl
pushdef([CPPFLAGS], [CPPFLAGS_FOR_]forupper)dnl
pushdef([LDFLAGS], [LDFLAGS_FOR_]forupper)dnl
pushdef([WARN_CFLAGS], [WARN_CFLAGS_FOR_]forupper)dnl
pushdef([host], $1)dnl
pushdef([host_alias], $1_alias)dnl
pushdef([host_cpu], $1_cpu)dnl
pushdef([host_vendor], $1_vendor)dnl
pushdef([host_os], $1_os)dnl
pushdef([ac_cv_host], ac_cv_$1)dnl
pushdef([ac_cv_host_alias], ac_cv_$1_alias)dnl
pushdef([ac_cv_host_cpu], ac_cv_$1_cpu)dnl
pushdef([ac_cv_host_vendor], ac_cv_$1_vendor)dnl
pushdef([ac_cv_host_os], ac_cv_$1_os)dnl
pushdef([am_cv_prog_cc_c_o], am_cv_$1_prog_cc_c_o)dnl
pushdef([am_cv_CC_dependencies_compiler_type], am_cv_$1_CC_dependencies_compiler_type)dnl
pushdef([gl_unknown_warnings_are_errors], gl_$1_unknown_warnings_are_errors)dnl

st_SAVE_VAR([ac_c_decl_warn_flag])
st_SAVE_VAR([ac_c_preproc_warn_flag])
st_SAVE_VAR([ac_c_werror_flag])
st_SAVE_VAR([ac_compile])
st_SAVE_VAR([ac_compiler_gnu])
st_SAVE_VAR([ac_cpp])
st_SAVE_VAR([ac_cv_c_compiler_gnu])
st_SAVE_VAR([ac_cv_c_decl_report])
st_SAVE_VAR([ac_link])
st_SAVE_VAR([ac_tool_prefix])
st_SAVE_VAR([cross_compiling])
cross_compiling=no

AC_MSG_NOTICE([looking for a C compiler that generates executables for ]$1)
AC_PROG_CC
AC_PROG_CPP
AC_EXEEXT

st_WARN_CFLAGS

st_RESTORE_VAR([cross_compiling])
st_RESTORE_VAR([ac_tool_prefix])
st_RESTORE_VAR([ac_link])
st_RESTORE_VAR([ac_cv_c_decl_report])
st_RESTORE_VAR([ac_cv_c_compiler_gnu])
st_RESTORE_VAR([ac_cpp])
st_RESTORE_VAR([ac_compiler_gnu])
st_RESTORE_VAR([ac_compile])
st_RESTORE_VAR([ac_c_werror_flag])
st_RESTORE_VAR([ac_c_preproc_warn_flag])
st_RESTORE_VAR([ac_c_decl_warn_flag])

dnl Restore the old definitions
dnl
popdef([gl_unknown_warnings_are_errors])dnl
popdef([am_cv_CC_dependencies_compiler_type])dnl
popdef([am_cv_prog_cc_c_o])dnl
popdef([ac_cv_host_os])dnl
popdef([ac_cv_host_vendor])dnl
popdef([ac_cv_host_cpu])dnl
popdef([ac_cv_host_alias])dnl
popdef([ac_cv_host])dnl
popdef([host_os])dnl
popdef([host_vendor])dnl
popdef([host_cpu])dnl
popdef([host_alias])dnl
popdef([host])dnl
popdef([WARN_CFLAGS])dnl
popdef([LDFLAGS])dnl
popdef([CPPFLAGS])dnl
popdef([CFLAGS])dnl
popdef([CPP])dnl
popdef([CC])dnl
popdef([ac_objext])dnl
popdef([ac_exeext])dnl
popdef([ac_cv_objext])dnl
popdef([ac_cv_exeext])dnl
popdef([ac_cv_prog_cc_c89])dnl
popdef([ac_cv_prog_cc_c99])dnl
popdef([ac_cv_prog_cc_c11])dnl
popdef([ac_cv_prog_cc_stdc])dnl
popdef([ac_cv_prog_cc_g])dnl
popdef([ac_cv_prog_cc_cross])dnl
popdef([ac_cv_prog_cc_works])dnl
popdef([ac_cv_prog_gcc])dnl
popdef([ac_cv_prog_CPP])dnl

dnl Finally, set Makefile variables
dnl
forupper[_EXEEXT]=$ac_$1_exeext
forupper[_OBJEXT]=$ac_$1_objext
AC_SUBST(forupper[_EXEEXT])dnl
AC_SUBST(forupper[_OBJEXT])dnl
AC_SUBST([CFLAGS_FOR_]forupper)dnl
AC_SUBST([CPPFLAGS_FOR_]forupper)dnl
AC_SUBST([LDFLAGS_FOR_]forupper)dnl
AC_SUBST([WARN_CFLAGS_FOR_]forupper)dnl
])
