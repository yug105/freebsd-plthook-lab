LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := target
LOCAL_SRC_FILES := libtarget.c
include $(BUILD_SHARED_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := claimcheck
LOCAL_SRC_FILES := claimcheck.c
LOCAL_SHARED_LIBRARIES := target
LOCAL_LDLIBS := -ldl
include $(BUILD_EXECUTABLE)

