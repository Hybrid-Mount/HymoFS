obj-m += hymofs_lkm.o

ccflags-y += -gz=none
ccflags-y += -DHYMOFS_USE_SYSCALL_TRACEPOINT=0
ccflags-y += $(call cc-option,-fno-sanitize=cfi)
ccflags-y += $(call cc-option,-fno-sanitize=kcfi)
ccflags-y += -Wno-unknown-sanitizers

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

.PHONY: all clean