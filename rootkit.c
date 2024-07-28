#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>  
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>

#define ARG_LEN 128
#define MAX_ARG_COUNT 32

MODULE_LICENSE("GPL");
MODULE_AUTHOR("cxponxtu");
MODULE_DESCRIPTION("execve hookup");
MODULE_VERSION("1.0");

unsigned long *__sys_call_table = NULL;
static struct kprobe kln = {.symbol_name = "kallsyms_lookup_name"};
typedef unsigned long (*klnt)(const char *name);

typedef asmlinkage unsigned long (*regis)(const struct pt_regs *reg);
static regis org_execve_reg;


static klnt get_kln_addr(void)
{   
    klnt kln_addr;
    register_kprobe(&kln);
    kln_addr = (klnt)kln.addr;
    unregister_kprobe(&kln);
    return kln_addr;
}

static inline void asm_cr0_write_protection (int arg)
{
    unsigned long value;
    if(arg == 0)
    {
        value = read_cr0() & ~0x00010000;
        printk(KERN_INFO "Disabling write protection\n");
    }
    else if (arg == 1)
    {
        value = read_cr0() | 0x00010000; 
        printk(KERN_INFO "Enabling write protection\n");
    }
    
    unsigned long __force_order;
    asm volatile ("mov %0, %%cr0" : "+r"(value), "+m"(__force_order));
    printk(KERN_INFO "Writing CR0 register is done\n");
}

static unsigned long execve_mod_reg(const struct pt_regs *reg)
{
    int i,arg_count = 0;
    char filename[ARG_LEN];
    char n_filename[ARG_LEN] = "/usr/bin/";

    char __user *u_filename = (char __user *)reg->di;
    char __user **u_args = (char __user **)reg->si;
    const char *hidden_prefix = "/hidden";
    size_t hidden_prefix_len = strlen(hidden_prefix);

    if(strncpy_from_user(filename, u_filename, ARG_LEN) < 0)
    {
        printk(KERN_INFO "Error copying filename from user\n");
        return org_execve_reg(reg);
    }
    filename[ARG_LEN-1] = '\0';

    for ( i = 0; i < MAX_ARG_COUNT; i++)
    {
        char __user *buff;
        if(get_user(buff, &u_args[i]) < 0)
        {
            break;
        }
        if(buff == NULL)
        {
            break;
        }
        arg_count++;
    }
    
    if ((strncmp(filename, hidden_prefix, hidden_prefix_len) == 0) && (strlen(filename) == hidden_prefix_len ))
    {
        for (i = 0; i < arg_count - 1; i++)
        {
            u_args[i] = u_args[i + 1];
        }
        u_args[arg_count - 1] = NULL;
        arg_count--;
        strcat(n_filename, u_args[0]);

        if(copy_to_user(u_filename, n_filename, strlen(n_filename)+1) < 0)
        {
            printk(KERN_INFO "Error copying filename to user\n");
            return org_execve_reg(reg);
        }

    }

    return org_execve_reg(reg);

}


static void hook_execve(void)
{
    org_execve_reg = (regis)__sys_call_table[__NR_execve];
    __sys_call_table[__NR_execve] = (unsigned long)execve_mod_reg;
}


static int __init start(void)
{
    printk(KERN_INFO "Module loading\n");
    
    klnt kallsyms_lookup_name = get_kln_addr();
    __sys_call_table = (unsigned long *)kallsyms_lookup_name("sys_call_table");

    printk(KERN_INFO "Syscall table at %px\n", __sys_call_table);

    asm_cr0_write_protection(0);
    hook_execve();
    asm_cr0_write_protection(1);

    printk(KERN_INFO "Module loaded successfully\n");
    return 0;
}

static void __exit end(void)
{
    asm_cr0_write_protection(0);
    __sys_call_table[__NR_execve] = (unsigned long)org_execve_reg;
    asm_cr0_write_protection(1);
    
    printk(KERN_INFO "Module unloaded\n");
}

module_init(start);
module_exit(end);