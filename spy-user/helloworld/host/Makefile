# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

include ../config.mk

CFLAGS=$(shell pkg-config oehost-$(COMPILER) --cflags)
LDFLAGS=$(shell pkg-config oehost-$(COMPILER) --libs)
INCDIR=$(shell pkg-config oehost-$(COMPILER) --variable=includedir)

# for ../../sgx_attacker.c
KERN_DIR=/lib/modules/$(shell uname -r)/build/
CFLAGS_HOST = -isystem /usr/lib/gcc/x86_64-linux-gnu/7/include  -I$(KERN_DIR)/arch/x86/include -I$(KERN_DIR)/arch/x86/include/generated  -I$(KERN_DIR)/include -I$(KERN_DIR)/arch/x86/include/uapi -I$(KERN_DIR)/arch/x86/include/generated/uapi -I$(KERN_DIR)/include/uapi -I$(KERN_DIR)/include/generated/uapi

build:
	@ echo "Compilers used: $(CC), $(CXX)"
	oeedger8r ../helloworld.edl --untrusted \
		--search-path $(INCDIR) \
		--search-path $(INCDIR)/openenclave/edl/sgx
	$(CC) -g -c $(CFLAGS) ../../sgx_attacker.c
	$(CC) -g -c $(CFLAGS) host.c
	$(CC) -g -c $(CFLAGS) helloworld_u.c
	$(CC) -o helloworld_host helloworld_u.o host.o sgx_attacker.o $(LDFLAGS)

clean:
	rm -f helloworld_host host.o helloworld_u.o helloworld_u.c helloworld_u.h helloworld_args.h
