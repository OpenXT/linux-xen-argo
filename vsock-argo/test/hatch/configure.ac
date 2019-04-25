#
# Autoconf initialisation.
#
AC_INIT(hatch, 1.0)
AC_PREREQ(2.13)
AC_CONFIG_HEADERS(src/config.h)
AC_CONFIG_SRCDIR(src/project.h)
AM_INIT_AUTOMAKE([foreign -Wall -Werror])

#
# Version management.
# +1    : 0     Interface changes breaking retro-compatibility.
# 0     : +1    Internal changes without lost of retro-compatibility.
#
VERSION_MAJOR=0
VERSION_MINOR=1
AC_DEFINE_UNQUOTED([VERSION_MAJOR], [$VERSION_MAJOR], [major version number])
AC_DEFINE_UNQUOTED([VERSION_MINOR], [$VERSION_MINOR], [minor version number])

#
# Standard checks.
#
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AM_PROG_AR

# Compiler capabilities.
AC_C_INLINE
AC_C_CONST

# Required headers.
AC_CHECK_HEADERS([sys/ioctl.h sys/socket.h linux/socket.h])
AC_CHECK_HEADERS([linux/vm_sockets.h], [],
                 AC_MSG_ERROR("VSock support not available"),
                 [#include <sys/ioctl.h>
                  #include <sys/socket.h>
                  #include <linux/socket.h>
                  ])

# Output files.
AC_OUTPUT([Makefile
           src/Makefile
           ])
