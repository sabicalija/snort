
AUTOMAKE_OPTIONS=foreign no-dependencies

noinst_LIBRARIES = libknxnetip.a

SUBDIRS = user_interface anomaly_detection




 
libknxnetip_a_SOURCES = \
knxnetip.c knxnetip.h





libknxnetip_a_LIBADD = \
user_interface/knx_ui_snort.o \
user_interface/knx_ui_config.o \
knxnetip.o \
anomaly_detection/knx_ad.o














INCLUDES = @INCLUDES@
