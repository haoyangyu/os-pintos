#include <stdio.h>
#include <syscall-nr.h>
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/process.h"

#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

struct child_process *get_child_process_by_id(tid_t pid);

#endif /* userprog/syscall.h */
