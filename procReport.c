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
 * To display the procfile the seq_file iterator is used. More details can be found in the Linux source
 * at Documentation/filesystems/seq_file.rst.
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
struct proc_dir_entry *PROC_ENT;
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
    .proc_lseek   = seq_lseek,
    .proc_release = seq_release
};

/*
 * Initializes the proc report module. Converts the linked list
 * return by get_proc_data() to an array, initializes the proc 
 * file with proc_create and prints the proc data to the syslog.
 *
 */
int pr_init(void) {
    int i;
    ROOT = get_proc_data();
    PTABLE = kzalloc(sizeof(p_data*) * PROC_CNT, GFP_KERNEL);
    p_data *curr = ROOT;
    for (i = 0; i < PROC_CNT; i++) {  // translate the linked list to an array for quick access for the seq iterator
        PTABLE[i] = curr;
        curr = curr->next;
    }
    PROC_ENT = proc_create("proc_report", 0666, NULL, &ct_file_ops);
    log_proc_data();
  return 0;
}

/*
 * Writes the process data in PTABLE to the syslog in CSV format.
 *
 */
void log_proc_data(void) {
    printk(KERN_INFO "PROCESS REPORT:\n");
    printk(KERN_INFO "proc_id,proc_name,contig_pages,noncontig_pages,total_pages\n");
    int i;
    for (i = 0; i < PROC_CNT; i++) {
        p_data *p_info = PTABLE[i];
        printk(KERN_INFO "%d,%s,%d,%d,%d\n", p_info->pid, p_info->name, p_info->cp, p_info->ncp, p_info->tp);
    }
    printk(KERN_INFO "TOTALS,,%d,%d,%d\n", TOTAL_CPAGES, TOTAL_PAGES - TOTAL_CPAGES, TOTAL_PAGES);
}

/*
 * Initializes the seq iterator used to track UM read()
 * positions in the virtual file. In this case the iterator
 * is simply an integer corresponding an index into PTABLE.
 *
 * Adapted from Documentation/filesystems/seq_file.rst.
 *
 * param: s (seq_file*): a pointer to the seq_file struct containing
 *                       info on this virtual file
 * param: pos (loff_t*): a pointer to an offset into the virtual file
 *
 * return: the newly initialized offset
 *                       
 */
static void *ct_seq_start(struct seq_file *s, loff_t *pos) {
    loff_t *spos = kmalloc(sizeof(loff_t), GFP_KERNEL);
    if (!spos || *pos >= PROC_CNT)  // EOF requested, return NULL
        return NULL;
    *spos = *pos;
    return spos;
}

/*
 * Increments the seq iterator by one.
 *
 * Adapted from Documentation/filesystems/seq_file.rst.
 *
 * param: s (seq_file*): a pointer to the seq_file struct containing
 *                       info on this virtual file
 * param: pos (loff_t*): (OUT) a pointer to an offset into the virtual file
 * param: v (void*): the current value of the iterator
 *
 * return: the new iterator
 *                       
 */
static void *ct_seq_next(struct seq_file *s, void *v, loff_t *pos) {
    loff_t *spos = v;
    *pos = ++*spos;
    if (*spos == PROC_CNT) // EOF reached, return NULL
        return NULL;
    return spos;
}

/*
 * Frees the allocated iterator.
 *
 * Adapted from Documentation/filesystems/seq_file.rst.
 *
 * param: s (seq_file*): a pointer to the seq_file struct containing
 *                       info on this virtual file
 * param: pos (loff_t*): (OUT) a pointer to an offset into the virtual file
 *                       
 */
static void ct_seq_stop(struct seq_file *s, void *v) {
    kfree(v);
}

/*
 * Displays a single line of the virtual file based on the offset value
 * v. In this case, a single line of the virtual file is a line of the CSV
 * containing data from PTABLE[*v]. If the offset requested is the first or
 * last additional lines are printed.
 *
 * ADapted from Documentation/filesystems/seq_file.rst.
 *
 * param: s (seq_file*): a pointer to the seq_file struct containing
 *                       info on this virtual file
 * param: pos (loff_t*): (OUT) a pointer to an offset into the virtual file
 *                       
 */
static int ct_seq_show(struct seq_file *s, void *v) {
    loff_t *spos = v;
    if (*spos == 0) {
        seq_printf(s, "PROCESS REPORT:\n");
        seq_printf(s, "proc_id,proc_name,contig_pages,noncontig_pages,total_pages\n");
    }
    p_data *p_info = PTABLE[*spos];
    seq_printf(s, "%d,%s,%d,%d,%d\n", p_info->pid, p_info->name, p_info->cp, p_info->ncp, p_info->tp);
    if (*spos == PROC_CNT - 1) {
        seq_printf(s, "TOTALS,,%d,%d,%d\n", TOTAL_CPAGES, TOTAL_PAGES - TOTAL_CPAGES, TOTAL_PAGES);
    }
    return 0;
}

/*
 * Initializes the seq iterator by calling seq_open.
 *
 * See Documentation/filesystems/seq_file.rst for more details.                       
 */
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
        last = p_info;
        p_info->next = kzalloc(sizeof(p_data), GFP_KERNEL);
        p_info = p_info->next;
        PROC_CNT++;
    }
    rcu_read_unlock();
    if (PROC_CNT > 0) {  // free the last unnecessarily allocated p_data struct
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

/*
 * Frees all memory allocated for the linked list and PTABLE and removes
 * the proc file entry.
 *
 */
void pr_cleanup(void) {
    p_data *curr = ROOT, *free;
    int i;
    proc_remove(PROC_ENT);
    for (i = 0; i < PROC_CNT; i++) { 
        free = curr;
        curr = curr->next;
        kfree(free->name);
        kfree(free);
    }
    kfree(PTABLE);
}

MODULE_LICENSE("GPL");
module_init(pr_init);
module_exit(pr_cleanup);
