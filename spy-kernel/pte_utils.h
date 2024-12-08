#ifndef PTE_UTILS_H
#define PTE_UTILS_H

typedef struct spy_pte {
    uint64_t *pte_pt;
    uint64_t cacheline;
    struct spy_pte *nxt;
} spy_pte_t;

typedef struct spy_pte_set {
    uint64_t *monitor_pte_pt;
    spy_pte_t *head;
    uint64_t erip_base;
    int restrict_cacheline;
} spy_pte_set_t;

spy_pte_set_t *build_pte_set(void);
pte_t *get_pte_adrs(uint64_t address);
uint64_t test_pte_set(spy_pte_set_t *set);
void clear_pte_set(spy_pte_set_t *set);
void free_pte_set(spy_pte_set_t *set);

void gsgx_flush(void* p);
unsigned long gsgx_reload(void* p);

#endif
