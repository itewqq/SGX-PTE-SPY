#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/highmem.h>
#include <linux/miscdevice.h>
#include <linux/module.h>
#include <linux/vmalloc.h>
#include <linux/security.h>
#include <asm/tlbflush.h>

#include "common.h"
#include "pte_attack.h"

#define DRV_DESCRIPTION "SGX PTE SPY Driver"
#define DRV_VERSION "1.0"
#define PTE_SPY_MINOR	MISC_DYNAMIC_MINOR

typedef long (*ioctl_t)(struct file *filep, unsigned int cmd, unsigned long arg);

long pte_spy_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
	char data[256];
	ioctl_t handler = NULL;
	long ret;
    unsigned long buf_len = _IOC_SIZE(cmd);

	switch (cmd) {
        case GSGX_IOCTL_SPY_START:
            handler = gsgx_ioctl_spy_start;
            break;
        case GSGX_IOCTL_SPY_STOP:
            handler = gsgx_ioctl_spy_stop;
            break;
	    case GSGX_IOCTL_SPY_WAIT:
            handler = gsgx_ioctl_spy_wait;
            break;
	    case GSGX_IOCTL_SPY_INIT:
            handler = gsgx_ioctl_spy_init;
            break;
	default:
			return -EINVAL;
	}
	buf_len = buf_len < 256 ? buf_len : 256;
	if (copy_from_user(data, (void __user *) arg, buf_len))
		return -EFAULT;

	ret = handler(filep, cmd, (unsigned long) ((void *) data));

	if (!ret && (cmd & IOC_OUT)) {
		if (copy_to_user((void __user *) arg, data, buf_len))
			return -EFAULT;
	}

	return ret;
}


static const struct file_operations pte_spy_fops = {
	.owner		= THIS_MODULE,
	.unlocked_ioctl	= pte_spy_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= pte_spy_ioctl,
#endif
};

static struct miscdevice pte_spy_dev = {
	.minor	= PTE_SPY_MINOR,
	.name	= "pte_spy",
	.fops	= &pte_spy_fops,
	.mode	= S_IRUGO | S_IWUGO,
};

static int pte_spy_setup(void){
    unsigned cpu;
    int ret;

    ret = misc_register(&pte_spy_dev);
	if (ret) {
		pr_err("pte_spy: misc_register() failed\n");
		pte_spy_dev.this_device = NULL;
		return ret;
	}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 0, 0)
	for_each_online_cpu(cpu) {
		// per_cpu(cpu_tlbstate.cr4, cpu) |= X86_CR4_FSGSBASE;
		/*
			itewqq: the struct cpu_tlbstate is not exported in recent kernel code. 
					use cr4_set_bits instead
		*/
		cr4_set_bits(X86_CR4_FSGSBASE);
	}
#endif

	return 0;
}

static void pte_spy_teardown(void)
{
    gsgx_attacker_teardown();

	if (pte_spy_dev.this_device)
		misc_deregister(&pte_spy_dev);
}

static int __init pte_spy_init(void)
{
	int ret;

	ret = pte_spy_setup();
	if (ret) {
		pr_err("pte_spy: pte_spy_init failed\n");
		pte_spy_teardown();
		return ret;
	}

    gsgx_attacker_setup();

	return 0;
}

static void __exit pte_spy_exit(void)
{
	pte_spy_teardown();
}

module_init(pte_spy_init);
module_exit(pte_spy_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ITEWQQ");
MODULE_DESCRIPTION("kernel module for sgx-pte attack");
MODULE_VERSION("6");

