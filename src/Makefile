# make -C $KDIR ARCH=arm64 M=$(pwd) modules
# For ddk: ddk build android14-6.1  (KDIR set by container)

KDIR ?= /lib/modules/$(shell uname -r)/build
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))

obj-m += hymofs_lkm.o
hymofs_lkm-objs := hymofs_core.o hymofs_tracepoint.o hymofs_ftrace.o

ccflags-y += -gz=none

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

all:
	$(MAKE) -C $(KDIR) M=$(MDIR) ARCH=arm64 modules

clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean 2>/dev/null || true
	rm -rf .tmp_versions
	@find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '*.md' ! -name '.gitignore' -exec rm -f {} + 2>/dev/null || true
.PHONY: all clean
