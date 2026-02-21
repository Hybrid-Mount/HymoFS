obj-m += hymofs_lkm.o

ccflags-y += -gz=none
ccflags-y += $(call cc-option,-fno-sanitize=cfi)
ccflags-y += -DHYMOFS_USE_SYSCALL_TRACEPOINT=0
ccflags-$(call cc-option,-fno-sanitize=cfi) += -fno-sanitize=cfi
ccflags-$(call cc-option,-fno-sanitize=kcfi) += -fno-sanitize=kcfi
ccflags-y += -Wno-unknown-sanitizers

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
	rm -rf .tmp_versions
	@find . -maxdepth 1 -type f ! -name '*.c' ! -name '*.h' ! -name 'Makefile' ! -name '*.md' ! -name '.gitignore' -exec rm -f {} + 2>/dev/null || true

.PHONY: all clean