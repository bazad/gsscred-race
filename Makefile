TARGET = gsscred-race

DEBUG      ?= 0
ARCH       ?= x86_64
SDK        ?= macosx
SIGNING_ID ?= -

SYSROOT  := $(shell xcrun --sdk $(SDK) --show-sdk-path)
ifeq ($(SYSROOT),)
$(error Could not find SDK "$(SDK)")
endif
CLANG    := $(shell xcrun --sdk $(SDK) --find clang)
CC       := $(CLANG) -isysroot $(SYSROOT) -arch $(ARCH)
CODESIGN := codesign

CFLAGS = -O2 -Wall -Werror

ifneq ($(DEBUG),0)
DEFINES += -DDEBUG=$(DEBUG)
endif

SOURCE_DIR = gsscred_race

FRAMEWORKS = -framework Foundation

SOURCES = gsscred_race.c \
	  log.c \
	  main.c \
	  payload.c \
	  $(ARCH_SOURCES)

HEADERS = apple_private.h \
	  log.h \
	  gsscred_race.h \
	  payload.h \
	  $(ARCH_HEADERS)

ARCH_arm64_SOURCES = arm64_payload.c \
		     gadgets.c \
		     payload_strategy_1.c

ARCH_arm64_HEADERS = arm64_payload.h \
		     gadgets.h

ARCH_SOURCES = $(ARCH_$(ARCH)_SOURCES:%=$(ARCH)/%)
ARCH_HEADERS = $(ARCH_$(ARCH)_HEADERS:%=$(ARCH)/%)

SOURCES := $(SOURCES:%=$(SOURCE_DIR)/%)
HEADERS := $(HEADERS:%=$(SOURCE_DIR)/%)

CFLAGS += -I$(SOURCE_DIR)

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(FRAMEWORKS) $(DEFINES) -o $@ $(SOURCES)
	$(CODESIGN) -s '$(SIGNING_ID)' $@

clean:
	rm -f -- $(TARGET)
