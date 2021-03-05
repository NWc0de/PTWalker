/*
 * The procReport kernel module iterates through currently running 
 * processes and generates a report of their memory usage in both
 * /var/log/syslog as well as to a procReport file in /proc.
 *
 * For each process with PID > 650 the following attributes are reported:
 *
 * 1. Process ID
 * 2. Process name
 * 3. Number of contigously allocated pages
 * 4. Number of non-contiguously allocated pages 
 * 5. Total number allocated pages
 *
 * Spencer Little - mrlittle@uw.edu
 */

#include "procReport.h"

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/string.h>

/*
 * Add docs 
 *
 */
int proc_init (void) {
    struct task_struct *p;
    p_data *root;
    p_data *p_info = root; // can I do *root = *p_info
    rcu_read_lock();
    for_each_process(p) {
        if (p->pid <= 650) {
            continue;
        }
        struct vm_area_struct *vma = 0;
        unsigned long vpage = 0, pc = 0;
        char buf[TASK_COMM_LEN];
        p_info = kzalloc(sizeof(p_data), GFP_KERNEL);
        p_info->name = kzalloc(TASK_COMM_LEN, GFP_KERNEL);
        p_info->pid = p->pid;
        get_task_comm(buf, p);
        strncpy(p_info->name, buf, TASK_COMM_LEN);
        if (p->mm && p->mm->mmap) {
            for (vma = p->mm->mmap; vma; vma = vma->vm_next) {
                for (vpage = vma->vm_start; vpage < vma->vm_end; vpage += PAGE_SIZE) {
                    pc++;
                }
            }
        }
        p_info->tp = pc;
        p_info = p_info->next;
        printk(KERN_INFO "%s pages : %lu, PID : %lu\n", p_info->name, p_info->tp, p_info->pid); 
    }
    rcu_read_unlock();
  return 0;
}

void proc_cleanup(void) {
  printk(KERN_INFO "helloModule: performing cleanup of module\n");
}

MODULE_LICENSE("GPL");
module_init(proc_init);
module_exit(proc_cleanup);

