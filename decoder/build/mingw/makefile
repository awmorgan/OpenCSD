# OpenCSD - main MinGW makefile for libraries and tests (static builds only)
#
# command line options
# DEBUG=1 	    create a debug build
#

# MinGW/Clang flags for Windows
export PLATFORM_CFLAGS := -D_LIB
export PLATFORM_CXXFLAGS := -D_LIB
export PLATFORM_LDFLAGS :=

export SONAME_FLAG :=
export SHARED_LIB_SUFFIX := so

# Disable shared library builds for MinGW
export DISABLE_SHARED_LIBS := 1

# For applications using the C API static library
export CPPFLAGS := -DOCSD_USE_STATIC_C_API

# set OCSD_ROOT relative to the main mingw makefile
ifeq ($(OCSD_ROOT),)
OCSD_ROOT := $(shell echo $(dir $(abspath $(lastword $(MAKEFILE_LIST)))) | sed 's,/build/mingw.*,,')
export OCSD_ROOT
endif

# include the common unix makefile
include $(OCSD_ROOT)/build/unix_common/makefile.common
