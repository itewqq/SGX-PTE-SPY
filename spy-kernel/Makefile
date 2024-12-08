# CC=clang-15
# CXX=$(CC)++

KSRC ?= host
ifeq ($(KSRC), host)
	KERN_DIR=/lib/modules/$(shell uname -r)/build/
else
	KERN_DIR=/home/qsp/Kernel/src/linux-6.1.46/
endif

obj-m += pte_spy.o

pte_spy-y := pte_utils.o pte_attack.o pte_spy_mod.o

ext:
	make CC=$(CC) -C $(KERN_DIR) M=$(PWD) modules
host:
	make CC=$(CC) -C $(KERN_DIR) M=$(PWD) modules
clean:
	make CC=$(CC) -C $(KERN_DIR) M=$(PWD) clean
	$(shell sudo rmmod pte_spy)
help:
	make CC=$(CC) -C $(KERN_DIR) M=$(PWD) help
install: 
	$(shell sudo insmod pte_spy.ko)
remake: clean host install;
