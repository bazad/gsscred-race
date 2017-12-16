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

ifneq ($(ARCH),x86_64)
CFLAGS += -Iinclude
endif

ifneq ($(DEBUG),0)
DEFINES += -DDEBUG=$(DEBUG)
endif

FRAMEWORKS = -framework Foundation

SOURCES = gsscred_race/gsscred_race.c \
	  gsscred_race/main.c

HEADERS =

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) $(FRAMEWORKS) $(DEFINES) -o $@ $(SOURCES)
	$(CODESIGN) -s '$(SIGNING_ID)' $@

clean:
	rm -f -- $(TARGET)
