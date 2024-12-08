#ifndef COMMON_H
#define COMMON_H


#include "config.h"

#include <linux/sched.h>
#include <linux/fs_struct.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <asm/uaccess.h>
#include <asm/irq.h>
#include <asm/apic.h>
#include <asm/apicdef.h>
#include <asm/pgtable_64_types.h>

struct gsgx_spy_info
{
    uint64_t ipi_cpu_nb;
    uint64_t cur_tcs;
    uint64_t aep;
};

struct victim_ipi_init_info {
    int victim_cpu;
    uint64_t cur_tcs;
    uint64_t erip_base;
    uint64_t aep;
};

/* Precompiler macros. */

#define RET_WARN_ON( cond, rv )                                             \
    WARN_ON(cond);                                                          \
    if (cond) return rv                                                     \


#define ACCESS_MASK             0x20
#define DIRTY_MASK              0x40
#define ACCESSED(pte_pt)        (pte_pt && (*pte_pt & ACCESS_MASK) != 0)
#define DIRTY(pte_pt)           (pte_pt && (*pte_pt & DIRTY_MASK) != 0)

#define CLEAR_AD(pte_pt)        \
    if (pte_pt) (*pte_pt = *pte_pt & (~ACCESS_MASK) & (~DIRTY_MASK))

#define PRINT_AD(pte_pt)   \
    printk("\t--> A/D PTE(%s) is %d/%d\n", #pte_pt, \
    ACCESSED(pte_pt), DIRTY(pte_pt))

/* NOTE: incorrect GPRSGX size in Intel manual vol. 3D June 2016 p.38-7 */
#define SGX_TCS_OSSA_OFFSET         16
#define SGX_GPRSGX_SIZE             184
#define SGX_GPRSGX_RIP_OFFSET       136
#define SGX_GPRSGX_RAX_OFFSET       0

#if CONFIG_DISABLE_CACHE
    /*
     * Set CR0.CD bit to disable caching on current CPU.
     */
    #define CR0_DISABLE_CACHE                                               \
        asm volatile (                                                      \
            "mov %%cr0, %%rax\n\t"                                          \
            "or $(1 << 30),%%rax\n\t" /* set CD but not NW bit */           \
            "movq %%rax, %%cr0\n\t"                                         \
            "wbinvd\n\t"               /* flush */                          \
            "or $(1 << 29),%%rax\n\t"  /* now set the NW bit */             \
            "movq %%rax, %%cr0\n\t"                                         \
            ::: "%rax","%rcx","%rdx");

    /*
     * Clear CR0.CD/NW bit to re-enable caching on current CPU.
     */
    #define CR0_ENABLE_CACHE                                                \
        asm volatile (                                                      \
            "mov %%cr0, %%rax\n\t"                                          \
            "and $~(1 << 30), %%rax\n\t"                                    \
            "and $~(1 << 29), %%rax\n\t"                                    \
            "movq %%rax, %%cr0\n\t"                                         \
            ::: "%rax");                                                    
#else
    #define CR0_DISABLE_CACHE
    #define CR0_ENABLE_CACHE
#endif

#endif
