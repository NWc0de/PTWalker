/*
 * The procReport header file. Contains definition of the struct
 * used to aggregate process data.
 *
 * Spencer Little - mrlittle@uw.edu
 */

#include <linux/types.h>

typedef struct process_data {
    pid_t pid;
    char *name;
    int tp;
    int cp;
    int ncp;
    struct process_data *next;
} p_data;