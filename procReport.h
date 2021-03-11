/*
 * The procReport header file. Contains definition of the struct
 * used to aggregate process data.
 *
 * Spencer Little - mrlittle@uw.edu
 */

#include <linux/mm_types.h>
#include <linux/types.h>

#define NO_MAPPING 0
#define UNMAPPED 70368744173568

typedef struct process_data {
    pid_t pid;
    char *name;
    int tp;
    int cp;
    int ncp;
    struct process_data *next;
} p_data;

p_data *get_proc_data(void);
static ssize_t read_procdata(struct file*, char __user*, size_t, loff_t*);
unsigned long vp_translate(unsigned long, struct mm_struct*);
void log_proc_data(void);

static void *ct_seq_start(struct seq_file*, loff_t*);
static void *ct_seq_next(struct seq_file*, void*, loff_t*);
static void ct_seq_stop(struct seq_file*, void*);
static int ct_seq_show(struct seq_file*, void*);
static int ct_open(struct inode*, struct file*);