/*
 * The procReport kernel module iterates through currently running 
 * processes and generates a report of their memory usage in both
 * /var/log/syslog and to /proc/proc_report.
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
#include <linux/mm.h>
#include <linux/proc_fs.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/seq_file.h>
#include <linux/slab.h>
#include <linux/string.h>

p_data *ROOT;
p_data **PTABLE;
int PROC_CNT = 0;
int TOTAL_PAGES = 0;
int TOTAL_CPAGES = 0;

static const struct seq_operations ct_seq_ops = {
    .start = ct_seq_start,
    .next  = ct_seq_next,
    .stop  = ct_seq_stop,
    .show  = ct_seq_show,
};

static const struct proc_ops ct_file_ops = {
    .proc_open    = ct_open,
    .proc_read    = seq_read,
    .proc_lseek  = seq_lseek,
    .proc_release = seq_release
};

/*
 *  
 *
 */
int pr_init (void) {
    struct proc_dir_entry *ent;
    int i;
    ROOT = get_proc_data();
    p_data *curr = ROOT;
    PTABLE = kzalloc(sizeof(p_data*) * PROC_CNT, GFP_KERNEL);
    for (i = 0; i < PROC_CNT; i++) {  // translate the linked list to an array for quick access for the iterator
        PTABLE[i] = curr;
        printk(KERN_INFO "b4 curr value %lu\n", curr); // verify with p->total_vm
        curr = curr->next;
        printk(KERN_INFO "after curr value %lu\n", curr); // verify with p->total_vm
    }
    ent = proc_create("proc_report", 660, NULL, &ct_file_ops);
  return 0;
}

static void *ct_seq_start(struct seq_file *s, loff_t *pos) {
    loff_t *spos = kmalloc(sizeof(loff_t), GFP_KERNEL);
    if (!spos || *pos >= PROC_CNT)
        return NULL;
    *spos = *pos;
    return spos;
}

static void *ct_seq_next(struct seq_file *s, void *v, loff_t *pos) {
    loff_t *spos = v;
    if (*spos == PROC_CNT - 1)
        return NULL;
    *pos = ++*spos;
    return spos;
}

static void ct_seq_stop(struct seq_file *s, void *v) {
    kfree(v);
}

static int ct_seq_show(struct seq_file *s, void *v) {
    loff_t *spos = v;
    if (*spos == 0) {
        seq_printf(s, "PROCESS REPORT:\n");
        seq_printf(s, "proc_id,proc_name,contig_pages,noncontig_pages,total_pages:\n");
    }
    p_data *p_info = PTABLE[*spos];
    seq_printf(s, "%lu,%s,%lu,%lu,%lu\n", p_info->pid, p_info->name, p_info->cp, p_info->ncp, p_info->tp);
    if (*spos == PROC_CNT - 1) {
        seq_printf(s, "TOTALS:,,%lu,%lu,%lu\n", TOTAL_CPAGES, TOTAL_PAGES - TOTAL_CPAGES, TOTAL_PAGES);
    }
    return 0;
}

static int ct_open(struct inode *inode, struct file *file) {
        return seq_open(file, &ct_seq_ops);
}

/*
 * Walks the page table and retrieves the following data points for each process with PID > 650:
 *
 * 1. Process ID
 * 2. Process name
 * 3. Number of contigously allocated pages
 * 4. Number of non-contiguously allocated pages 
 * 5. Total number allocated pages
 *
 * return: root (p_data): a pointer to the head of a linked list containing process_data struct
 *                        for each process with PID > 650 or NULL if no processes were identified.
 *
 *
 */
p_data *get_proc_data(void) {
    struct task_struct *p;
    p_data *root = kzalloc(sizeof(p_data), GFP_KERNEL);
    p_data *p_info = root, *last = NULL; 
    rcu_read_lock();
    for_each_process(p) {
        if (p->pid <= 650)
            continue;
        struct vm_area_struct *vma = 0;
        unsigned long vpage = 0, pc = 0, cc = 0, lppage = 0;
        char buf[TASK_COMM_LEN];
        p_info->name = kzalloc(TASK_COMM_LEN, GFP_KERNEL);
        p_info->pid = p->pid;
        get_task_comm(buf, p);
        strncpy(p_info->name, buf, TASK_COMM_LEN);
        if (p->mm && p->mm->mmap) {
            for (vma = p->mm->mmap; vma; vma = vma->vm_next) {
                for (vpage = vma->vm_start; vpage < vma->vm_end; vpage += PAGE_SIZE) {
                    unsigned long phys_page = vp_translate(vpage, p->mm);
                    if (phys_page == NO_MAPPING) {  // page is not allocated, skip
                        continue;
                    }
                    pc++;
                    if (phys_page == (lppage + PAGE_SIZE)) {  // current page = last page + page size, +1 contiguous page
                        cc++;
                    }
                    lppage = phys_page;
                }
            }
        }
        TOTAL_PAGES += pc;
        TOTAL_CPAGES += cc;
        p_info->tp = pc;
        p_info->cp = cc;
        p_info->ncp = pc - cc;
        printk(KERN_INFO "[FROM FUNC]NAME: %s, PAGES: %lu, PID: %lu, CP: %lu, NCP: %lu\n", p_info->name, p_info->tp, p_info->pid, p_info->cp, p_info->ncp); // verify with p->total_vm
        last = p_info;
        p_info->next = kzalloc(sizeof(p_data), GFP_KERNEL);
        p_info = p_info->next;
        PROC_CNT++;
    }
    rcu_read_unlock();
    if (PROC_CNT > 0) {  // free the last allocated p_data struct
        last->next = NULL;
        kfree(p_info);
    }
    return root;
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

void pr_cleanup(void) {
    // free mem, etc.
  printk(KERN_INFO "helloModule: performing cleanup of module\n");
}

MODULE_LICENSE("GPL");
module_init(pr_init);
module_exit(pr_cleanup);

