## $Id
AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libknxnetip.a

libknxnetip_a_SOURCES = \
knxnetip.c 

SUBDIRS = user_interface 

libknxnetip_a_LIBADD = \
user_interface/knx_ui_snort.o \
user_interface/knx_ui_config.o \
knxnetip.o


INCLUDES = @INCLUDES@
