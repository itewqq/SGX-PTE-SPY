#ifndef PTE_ATTACK_H
#define PTE_ATTACK_H

#include "common.h"
#include <linux/mm.h>

/* IO functions */
#define GSGX_IOCTL_SPY_START        _IOR('p', 0x04, struct gsgx_spy_info)
#define GSGX_IOCTL_SPY_STOP         _IOR('p', 0x05, void*)
#define GSGX_IOCTL_SPY_WAIT         _IOR('p', 0x06, void*)
#define GSGX_IOCTL_SPY_INIT         _IOR('p', 0x07, void*)


long gsgx_ioctl_spy_init(struct file *filep, unsigned int cmd,
                    unsigned long arg);

long gsgx_ioctl_spy_stop(struct file *filep, unsigned int cmd,
                    unsigned long arg);

long gsgx_ioctl_spy_wait(struct file *filep, unsigned int cmd,
                    unsigned long arg);

long gsgx_ioctl_spy_start(struct file *filep, unsigned int cmd,
                    unsigned long arg);

void gsgx_attacker_setup(void);

void gsgx_attacker_teardown(void);



void ipi_handler(void);
void victim_ipi_init(void *info);
void victim_ipi_final(void *info);
void victim_ipi_handler(void *info);

void gsgx_spy_thread(struct gsgx_spy_info *arg);
#if CONFIG_EDBGRD_RIP
    /*
     * Symbols exported by patched linux-sgx-driver LKM.
     */
    extern int isgx_vma_access(struct vm_area_struct *vma, unsigned long addr,
                    void *buf, int len, int write);
    extern unsigned long isgx_get_enclave_base(struct vm_area_struct *vma);
    extern unsigned long isgx_get_enclave_ssaframesize(
        struct vm_area_struct *vma);

    uint64_t edbgrd_ssa(unsigned long tcs_address, int ssa_field_offset);
#endif



#endif
