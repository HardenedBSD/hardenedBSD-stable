# $FreeBSD$
#
# You must include bsd.test.mk instead of this file from your Makefile.
#
# Logic to build and install ATF test programs; i.e. test programs linked
# against the ATF libraries.

.if !target(__<bsd.test.mk>__)
.error atf.test.mk cannot be included directly.
.endif

# List of C, C++ and shell test programs to build.
#
# Programs listed here are built using PROGS, PROGS_CXX and SCRIPTS,
# respectively, from bsd.prog.mk.  However, the build rules are tweaked to
# require the ATF libraries.
#
# Test programs registered in this manner are set to be installed into TESTSDIR
# (which should be overriden by the Makefile) and are not required to provide a
# manpage.
ATF_TESTS_C?=
ATF_TESTS_CXX?=
ATF_TESTS_SH?=

# Path to the prefix of the installed ATF tools, if any.
#
# If atf-run and atf-report are installed from ports, we automatically define a
# realregress target below to run the tests using these tools.  The tools are
# searched for in the hierarchy specified by this variable.
ATF_PREFIX?= /usr/local

# C compiler passed to ATF tests that need to build code.
ATF_BUILD_CC?= ${DESTDIR}/usr/bin/cc
TESTS_ENV+= ATF_BUILD_CC=${ATF_BUILD_CC}

# C preprocessor passed to ATF tests that need to build code.
ATF_BUILD_CPP?= ${DESTDIR}/usr/bin/cpp
TESTS_ENV+= ATF_BUILD_CPP=${ATF_BUILD_CPP}

# C++ compiler passed to ATF tests that need to build code.
ATF_BUILD_CXX?= ${DESTDIR}/usr/bin/c++
TESTS_ENV+= ATF_BUILD_CXX=${ATF_BUILD_CXX}

# Shell interpreter used to run atf-sh(1) based tests.
ATF_SHELL?= ${DESTDIR}/bin/sh
TESTS_ENV+= ATF_SHELL=${ATF_SHELL}

.if !empty(ATF_TESTS_C)
PROGS+= ${ATF_TESTS_C}
_TESTS+= ${ATF_TESTS_C}
.for _T in ${ATF_TESTS_C}
BINDIR.${_T}= ${TESTSDIR}
MAN.${_T}?= # empty
SRCS.${_T}?= ${_T}.c
DPADD.${_T}+= ${LIBATF_C}
LDADD.${_T}+= -latf-c
USEPRIVATELIB+= atf-c
TEST_INTERFACE.${_T}= atf
.endfor
.endif

.if !empty(ATF_TESTS_CXX)
PROGS_CXX+= ${ATF_TESTS_CXX}
_TESTS+= ${ATF_TESTS_CXX}
.for _T in ${ATF_TESTS_CXX}
BINDIR.${_T}= ${TESTSDIR}
MAN.${_T}?= # empty
SRCS.${_T}?= ${_T}${CXX_SUFFIX:U.cc}
DPADD.${_T}+= ${LIBATF_CXX} ${LIBATF_C}
LDADD.${_T}+= -latf-c++ -latf-c
USEPRIVATELIB+= atf-c++
TEST_INTERFACE.${_T}= atf
.endfor
.endif

.if !empty(ATF_TESTS_SH)
SCRIPTS+= ${ATF_TESTS_SH}
_TESTS+= ${ATF_TESTS_SH}
.for _T in ${ATF_TESTS_SH}
SCRIPTSDIR_${_T}= ${TESTSDIR}
TEST_INTERFACE.${_T}= atf
CLEANFILES+= ${_T} ${_T}.tmp
# TODO(jmmv): It seems to me that this SED and SRC functionality should
# exist in bsd.prog.mk along the support for SCRIPTS.  Move it there if
# this proves to be useful within the tests.
ATF_TESTS_SH_SED_${_T}?= # empty
ATF_TESTS_SH_SRC_${_T}?= ${_T}.sh
${_T}: ${ATF_TESTS_SH_SRC_${_T}}
	echo '#! /usr/libexec/atf-sh' > ${.TARGET}.tmp
.if empty(ATF_TESTS_SH_SED_${_T})
	cat ${.ALLSRC:N*Makefile*} >>${.TARGET}.tmp
.else
	cat ${.ALLSRC:N*Makefile*} \
	    | sed ${ATF_TESTS_SH_SED_${_T}} >>${.TARGET}.tmp
.endif
	chmod +x ${.TARGET}.tmp
	mv ${.TARGET}.tmp ${.TARGET}
.endfor
.endif
