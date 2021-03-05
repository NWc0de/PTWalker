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

#include <linux/memblock.h>
#include <linux/module.h>
#include <linux/mm_types.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/string.h>

unsigned long vp_translate(unsigned long, struct mm_struct*);

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
        unsigned long vpage = 0, pc = 0, cc = 0, lppage = 0;
        char buf[TASK_COMM_LEN];
        p_info = kzalloc(sizeof(p_data), GFP_KERNEL);
        p_info->name = kzalloc(TASK_COMM_LEN, GFP_KERNEL);
        p_info->pid = p->pid;
        get_task_comm(buf, p);
        strncpy(p_info->name, buf, TASK_COMM_LEN);
        if (p->mm && p->mm->mmap) {
            for (vma = p->mm->mmap; vma; vma = vma->vm_next) {
                for (vpage = vma->vm_start; vpage < vma->vm_end; vpage += PAGE_SIZE) {
                    unsigned long phys_page = vp_translate(vpage, p->mm);
                    pc++;
                    if (phys_page == (lppage + PAGE_SIZE)) {
                        cc++;
                    }
                    lppage = phys_page;
                }
            }
        }
        int test = 0;
        if (p->mm)
            test = p->mm->total_vm;
        p_info->tp = pc;
        p_info->cp = cc;
        p_info->ncp = pc - cc;
        printk(KERN_INFO "NAME: %s, PAGES: %lu, REALPAGES %lu, PID: %lu, CP: %lu, NCP: %lu\n", p_info->name, p_info->tp, test, p_info->pid, p_info->cp, p_info->ncp); // verify with p->total_vm
        p_info = p_info->next;
    }
    rcu_read_unlock();
  return 0;
}

/*
 * Translates a virtual address to a physical address. Provided by
 * Dr. Hu (assn 3 documentation). 
 *
 * param: vpage (unsigned long): the virtual address of the page 
 *                               retrieved from the vm_start field 
 *                               of vm_area_struct 
 *
 * param: mm (struct mm_struct*): a pointer the mm_struct structure
 *                                that the vm_area_struct containing
 *                                vpage belongs too
 *
 * return: addr (unsigned long): the physical address that vpage maps too
 *                                or 0 if the page is unmapped/untranslatable
 */
unsigned long vp_translate(unsigned long vpage, struct mm_struct *mm) {
    pgd_t *pgd;
    p4d_t *p4d;
    pud_t *pud;
    pmd_t *pmd;
    pte_t *pte;
    struct page *page;
    unsigned long addr;
    pgd = pgd_offset(mm, vpage);
    if (pgd_none(*pgd) || pgd_bad(*pgd))
        return NO_MAPPING;
    p4d = p4d_offset(pgd, vpage);
    if (p4d_none(*p4d) || p4d_bad(*p4d))
        return NO_MAPPING;
    pud = pud_offset(p4d, vpage);
    if (pud_none(*pud) || pud_bad(*pud))
        return NO_MAPPING;
    pmd = pmd_offset(pud, vpage);
    if (pmd_none(*pmd) || pmd_bad(*pmd))
        return NO_MAPPING;
    if (!(pte = pte_offset_map(pmd, vpage)))
        return NO_MAPPING;
    if (!(page = pte_page(*pte)))
        return NO_MAPPING;
    addr = page_to_phys(page);
    pte_unmap(pte);           
    if (addr == UNMAPPED)
        return NO_MAPPING;
    return addr;
}

void proc_cleanup(void) {
    // free mem, etc.
  printk(KERN_INFO "helloModule: performing cleanup of module\n");
}

MODULE_LICENSE("GPL");
module_init(proc_init);
module_exit(proc_cleanup);

