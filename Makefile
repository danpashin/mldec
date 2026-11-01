TARGET := iphone:clang:latest:7.0
ARCHS = arm64
FINALPACKAGE = 1

include $(THEOS)/makefiles/common.mk

TOOL_NAME = mldec
${TOOL_NAME}_FILES = main.m MLModelCryptor.swift
${TOOL_NAME}_CFLAGS = -fobjc-arc -Wno-unused-variable
${TOOL_NAME}_LDFLAGS = -Wl,-no_warn_duplicate_libraries ./CoreML.tbd
${TOOL_NAME}_CODESIGN_FLAGS = -Sentitlements.plist
${TOOL_NAME}_INSTALL_PATH = /usr/local/bin

include $(THEOS_MAKE_PATH)/tool.mk
