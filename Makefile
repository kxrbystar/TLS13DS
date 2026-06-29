#---------------------------------------------------------------------------------
# tls13-3ds - standalone TLS 1.2/1.3 client wrapper for Nintendo 3DS
#---------------------------------------------------------------------------------

ifeq ($(strip $(DEVKITARM)),)
$(error "Please set DEVKITARM in your environment. export DEVKITARM=<path to>/devkitARM")
endif

ifeq ($(strip $(DEVKITPRO)),)
$(error "Please set DEVKITPRO in your environment. export DEVKITPRO=<path to>/devkitPro")
endif

PREFIX       ?= $(DEVKITPRO)/portlibs/3ds
BUILD        := build
TARGET       := libtls13_3ds.a
EXAMPLE_ELF  := $(BUILD)/https_get.elf
EXAMPLE_3DSX := $(BUILD)/https_get.3dsx

CC      := $(DEVKITARM)/bin/arm-none-eabi-gcc
CXX     := $(DEVKITARM)/bin/arm-none-eabi-g++
AR      := $(DEVKITARM)/bin/arm-none-eabi-ar

ARCH    := -march=armv6k -mtune=mpcore -mfloat-abi=hard -mtp=soft
COMMON  := -g -Og -mword-relocations -ffunction-sections -fdata-sections \
           $(ARCH) -D__3DS__ \
           -I. \
           -Iinclude \
           -ImbedTLS/mbedtls-3.6.6/include \
           -I$(DEVKITPRO)/libctru/include \
           -DMBEDTLS_CONFIG_FILE='"mbedTLS/3ds_mbedtls_config.h"'
CFLAGS  := $(COMMON) -std=gnu11 -Wall -Wextra
CXXFLAGS:= $(COMMON) -std=gnu++20 -fno-rtti -fno-exceptions -Wall -Wextra
LDFLAGS := -specs=3dsx.specs -g $(ARCH)

LIB_OBJS := \
	$(BUILD)/tls13_3ds.o \
	$(BUILD)/3ds_hw_poll.o

MBEDTLS_LIB := mbedTLS/lib3/lib/libmbedtls36.a

.PHONY: all mbedtls example install clean

all: $(TARGET)

$(TARGET): $(LIB_OBJS)
	$(AR) rcs $@ $^

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/tls13_3ds.o: source/tls13_3ds.cpp include/tls13_3ds.h | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/3ds_hw_poll.o: mbedTLS/3ds_hw_poll.c | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

mbedtls:
	NO_INSTALL=1 ./mbedTLS/build_3ds.sh

example: $(EXAMPLE_3DSX)

$(EXAMPLE_3DSX): $(EXAMPLE_ELF)
	3dsxtool $< $@

$(EXAMPLE_ELF): examples/https_get/source/main.cpp $(TARGET) $(MBEDTLS_LIB) | $(BUILD)
	$(CXX) $(CXXFLAGS) $< $(TARGET) $(MBEDTLS_LIB) \
		-L$(DEVKITPRO)/libctru/lib -lctru -lm \
		$(LDFLAGS) -Wl,-Map,$(BUILD)/https_get.map -o $@

install: $(TARGET)
	mkdir -p $(PREFIX)/include $(PREFIX)/lib
	cp include/tls13_3ds.h $(PREFIX)/include/
	cp $(TARGET) $(PREFIX)/lib/

clean:
	rm -rf $(BUILD) $(TARGET)
