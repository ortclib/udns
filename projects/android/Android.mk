LOCAL_PATH := $(call my-dir)/../../

include $(CLEAR_VARS)

LOCAL_ARM_MODE := arm

LOCAL_CFLAGS	:= -Wall \
-W \
-std=gnu++11 \
-O2 \
-pipe \
-fPIC \
-D_ANDROID \
-DHAVE_CONFIG_H \

LOCAL_MODULE    := udns_android

LOCAL_C_INCLUDES:= \
		$(LOCAL_PATH) \

LOCAL_SRC_FILES := dnsget.c \
getopt.c \
inet_XtoX.c \
udns_bl.c \
udns_codes.c \
udns_dn.c \
udns_dntosp.c \
udns_init.c \
udns_jran.c \
udns_misc.c \
udns_parse.c \
udns_resolver.c \
udns_rr_a.c \
udns_rr_mx.c \
udns_rr_naptr.c \
udns_rr_ptr.c \
udns_rr_srv.c \
udns_rr_txt.c \
udns_XtoX.c \

include $(BUILD_STATIC_LIBRARY)

