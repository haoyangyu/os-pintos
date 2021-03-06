#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/synch.h"
/* File descriptor for system calls. */
struct file_desc
{
  int fd;
  struct file *file;
  struct list_elem elem; 
};

enum loading_status
  {
     SUCCESS,     
     FAIL,
     UNLOADED
  };

/* States in a thread's life cycle. */
enum thread_status
  {
    THREAD_RUNNING,     /* Running thread. */
    THREAD_READY,       /* Not running but ready to run. */
    THREAD_BLOCKED,     /* Waiting for an event to trigger. */
    THREAD_DYING        /* About to be destroyed. */
  };

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
typedef int pid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* A kernel thread or user process.

   Each thread structure is stored in its own 4 kB page.  The
   thread structure itself sits at the very bottom of the page
   (at offset 0).  The rest of the page is reserved for the
   thread's kernel stack, which grows downward from the top of
   the page (at offset 4 kB).  Here's an illustration:

        4 kB +---------------------------------+
             |          kernel stack           |
             |                |                |
             |                |                |
             |                V                |
             |         grows downward          |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             |                                 |
             +---------------------------------+
             |              magic              |
             |                :                |
             |                :                |
             |               name              |
             |              status             |
        0 kB +---------------------------------+

   The upshot of this is twofold:

      1. First, `struct thread' must not be allowed to grow too
         big.  If it does, then there will not be enough room for
         the kernel stack.  Our base `struct thread' is only a
         few bytes in size.  It probably should stay well under 1
         kB.

      2. Second, kernel stacks must not be allowed to grow too
         large.  If a stack overflows, it will corrupt the thread
         state.  Thus, kernel functions should not allocate large
         structures or arrays as non-static local variables.  Use
         dynamic allocation with malloc() or palloc_get_page()
         instead.

   The first symptom of either of these problems will probably be
   an assertion failure in thread_current(), which checks that
   the `magic' member of the running thread's `struct thread' is
   set to THREAD_MAGIC.  Stack overflow will normally change this
   value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
   the run queue (thread.c), or it can be an element in a
   semaphore wait list (synch.c).  It can be used these two ways
   only because they are mutually exclusive: only a thread in the
   ready state is on the run queue, whereas only a thread in the
   blocked state is on a semaphore wait list. */
struct thread
  {
    /* For Alarm Clock Proj. */
    int64_t sleep_ticks;                /* Ticks a thread sleeps, used for timer_sleep(). */ 

    /* For Priority Scheduling Proj. */
    int initial_priority;		/* Inital priority before donation. */
    bool donated;			/* Check a thread's priority is donated or not. */
    struct list locks;       	  	/* A list for locks, which is sorted in descending order by the highest thread priority in its semaphore's waiters list, keep track of all locks a thread holds. */
    struct lock *wait_on_lock;	        /* The lock that the thread is waiting on. */ 

    /* For Advanced Scheduler Proj. */
    int nice;   /*The niceness value of multilevel feedback queue*/
    int recent_cpu;  /*The recent cpu is an estimate of the CPU time the thread has used recently */
    
    /* For system call. */
    struct list fd_list;
    
    /* Owned by thread.c. */
    tid_t tid;                          /* Thread identifier. */
    enum thread_status status;          /* Thread state. */
    char name[16];                      /* Name (for debugging purposes). */
    uint8_t *stack;                     /* Saved stack pointer. */
    int priority;                       /* Priority. */
    struct list_elem allelem;           /* List element for all threads list. */

    /* Shared between thread.c and synch.c. */
    struct list_elem elem;              /* List element. */

    /* For Process Termination Messages. */
    int return_value;

#ifdef USERPROG
    /* Owned by userprog/process.c. */
    uint32_t *pagedir;                  /* Page directory. */

    tid_t parent;

    enum loading_status loading;

    struct lock child_process_lock;

    struct list children;

#endif

    /* Owned by thread.c. */
    unsigned magic;                     /* Detects stack overflow. */
  };

struct child_process
  {
    bool waited;
    bool exited;
    int exit_status;
    tid_t child_id;
    struct list_elem elem;
  };
/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

void thread_sleep(int64_t ticks);

/* Performs some operation on thread t, given auxiliary data AUX. */
typedef void thread_action_func (struct thread *t, void *aux);
void thread_foreach (thread_action_func *, void *);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

/* For Alarm Clock Proj. */
bool compare_sleep_ticks (const struct list_elem *a,
			  const struct list_elem *b,
			  void *aux);  

bool compare_thread_priority (const struct list_elem *a,
		              const struct list_elem *b,
		              void *aux);  

/* For Priority Scheduling Proj. */
#define FAKE_PRIORITY -1
#define MAX_LOCK_LEVEL 8

void thread_yield_current (struct thread *cur);

void thread_given_priority(struct thread *cur, int new_priority, bool is_donated);

void thread_wake_up(void);

/* For Advanced Scheduling Proj*/
int get_number_of_ready_threads(void);

void update_priority_value_thread_mlfqs(struct thread *t, void *aux);

void update_recent_cpu_value_thread_mlfqs(struct thread *t, void *aux);

void update_BSD_value_thread_mlfqs(void);

void thread_priority_preemption_test(void);

void before_schedule_update_priority(void);

void increase_recent_cpu_value_thread_mlfqs(struct thread *t, void *aux);
/* For System Call Proj */
struct thread *get_thread(tid_t tid);
#endif /* threads/thread.h */
