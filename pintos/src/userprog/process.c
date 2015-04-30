#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "userprog/syscall.h"
#include "userprog/process.h"

static thread_func start_process NO_RETURN;
static bool load (struct args_struct *args_struct_ptr, void (**eip) (void), void **esp);

struct lock unilock;
//For argument parsing
static void argument_tokenize (struct args_struct *args_struct_ptr);
//Utility function for pushing args into stack
static bool push_byte_to_stack (uint8_t val, void **esp);
static bool push_word_to_stack (uint32_t val, void **esp);
//Have a function for pushing args into stack 
static bool push_args_to_stack (struct args_struct *args_struct_ptr, void **esp);
//Set the USER_STACK_VADDR as the address of the baseline address of the valid stack
//Set it as a constant, in running procedure, use USER_STACK_VADDR to make sure does not have stackoverflow
const uint8_t *USER_STACK_VADDR = (uint8_t *) PHYS_BASE - PGSIZE; 
struct lock filesys_lock;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t
process_execute (const char *arguments) 
{
  //lock_init(&unilock);
  struct args_struct *args_struct_ptr;
  tid_t tid = TID_ERROR;
  printf("execute!\n");

  /* Make a copy of args.
     Otherwise there's a race between the caller and load(). */
  args_struct_ptr = palloc_get_page (0);
  if (args_struct_ptr == NULL)
    return TID_ERROR;
  strlcpy (args_struct_ptr-> args, arguments, ARGS_SIZE);

  //Use argument_tokenize to parse the arguments
  argument_tokenize(args_struct_ptr);
  printf("argument_tokenization finished!\n");
  if (args_struct_ptr->argc == BAD_ARGS){
    palloc_free_page (args_struct_ptr);
    return TID_ERROR;
  }
  printf("before thread create!\n");
  //Need to make the execution in order, because the new thread may be scheduled before this funciton returns.
  lock_acquire(&unilock);
  /* Create a new thread to execute FILE_NAME. */
  printf("%s\n",args_struct_ptr->argv[0]);
  struct file *file = filesys_open(args_struct_ptr->argv[0]);
  if (file == NULL)
    printf("no such file!\n");
  else
    printf("find the file!!!!\n");
  tid = thread_create (args_struct_ptr->argv[0], PRI_DEFAULT, start_process, args_struct_ptr);
  lock_release(&unilock);
  
  printf("thread_create_finished!\n");

  if (tid == TID_ERROR)
    palloc_free_page (args_struct_ptr); 
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *arguments_)
{

  struct args_struct * args_struct_ptr = (struct args_struct *) arguments_;

  struct intr_frame if_;
  bool success = false;
  
  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  // Implement set up stack in load function, when loading, naturally set up the stack for future use.
  printf("start_process_begun\n");
  success = load (args_struct_ptr, &if_.eip, &if_.esp);

  /* If load failed, quit. */
  //palloc_free_page (args_struct_ptr);
  if (!success) 
    thread_exit ();

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid) 
{/*
  if (child_tid == -1) 
    return -1;
  else 
  {
    struct thread *current = thread_current();
    int status;
    struct child_process *child = get_child_process_by_id(child_tid);
    if (child == NULL) 
      return -1;
    lock_acquire(&current->child_process_lock);
    while (get_child_process_by_id(child_tid) != NULL)
      barrier();
    if (child->waited || !child->exited) {
      lock_release(&current->child_process_lock);
      return -1; 	
    }
    status = child->exit_status;
    child->waited = true;
    lock_release(&current->child_process_lock);
    return status;
  }*/
  //printf("wait!\n");
  return -1;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  printf("process_exit_begun!\n");
  struct thread *cur = thread_current ();
  uint32_t *pd;

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */

  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);

      /*Print the process termination messages*/
      printf("%s: exit(%d)\n",cur->name,cur->return_value);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (struct args_struct *args_struct_ptr, void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (struct args_struct *args_struct_ptr, void (**eip) (void), void **esp) 
{
  lock_init(&filesys_lock);
  printf("Load_Begun!\n");
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  //Get file name
  char *file_name = args_struct_ptr->argv[0];

  printf("file name: %s\n",file_name);

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    return success;
  process_activate ();

  printf("before open executable file!\n");
  /* Open executable file. */
  lock_acquire (&filesys_lock);
  file = filesys_open (file_name);
 
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }
   printf("before read and verify exeutable headers!\n");
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }
  printf("before read program headers!\n");
  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }
  printf("Before setup stack!!\n");
  /* Set up stack. */
  if (!setup_stack (args_struct_ptr,esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  lock_release (&filesys_lock);
  printf("load complete!\n");
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

//argument_tokenize is for parsing the filename into different tokens. 
static void argument_tokenize (struct args_struct *args_struct_ptr){
  char * save_ptr;
  char * token;
  unsigned argc_value = 0;
  char ** arg_variable = args_struct_ptr->argv;
  for (token = strtok_r(args_struct_ptr->args,ARGS_DELI, &save_ptr); token != NULL; token = strtok_r (NULL, ARGS_DELI, &save_ptr)){
    arg_variable[argc_value]=token;
    argc_value +=1;
    //Check the count of the arguments cannot equal or larger than the THRESHOLD of the argument variables size
    //Return the argc_value to -1
    if(argc_value>=ARGV_SIZE){
      printf("Enter too many arguments\n");
      argc_value = BAD_ARGS;
      break;
    }
  }
  //Return the argc with the arguments number, or -1 if the arguments are too many 
  args_struct_ptr->argc = argc_value;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}



/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (struct args_struct *args_struct_ptr,void **esp){
  uint8_t *kpage;
  bool success_for_stack_page_allocation = false;
  bool success_for_setup_stack = false;
  
  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL){
      success_for_stack_page_allocation = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success_for_stack_page_allocation){
        *esp = PHYS_BASE;
        //If the minimal stack created successfully
        success_for_setup_stack= push_args_to_stack(args_struct_ptr, esp);
      }else{
        palloc_free_page (kpage);
      } 
    }
   return (success_for_stack_page_allocation && success_for_setup_stack);
}

//Push the arguments into stack
static bool 
push_args_to_stack (struct args_struct *args_struct_ptr, void **esp){
  //Return the value in args_struct
  unsigned argc_value;
  argc_value = args_struct_ptr -> argc;
  char ** arg_variable;
  arg_variable = args_struct_ptr -> argv;

//For old C declaration
  int i;
  int j;
  size_t length;

  //Place arguments into the stack
  //Reverse access the arguments stored in argv
  for (i = argc_value - 1; i >= 0; --i){
    //Get length of each argument
      length = strlen (arg_variable[i]);
      for (j = length; j >= 0; j--){
        //Check the esp is between USER_STACK_VADDR and PHYS_BASE or not
        if (!push_byte_to_stack ((uint8_t) arg_variable[i][j], esp))
          return false;
      }
      //Update the each argument starting address
      arg_variable[i] = *esp;
      //*esp = argc_value[i];
    }

  //Word-align esp.
  for (i = (uintptr_t) *esp % sizeof (uint32_t); i > 0; --i){
    //Check the esp is between USER_STACK_VADDR and PHYS_BASE or not
    if (!push_byte_to_stack (NULL, esp))
      return false;
  }

  //Place the pointers to arguments into the stack 
  for (i = argc_value - 1; i >= 0; --i){
    if (!push_word_to_stack ((uint32_t) arg_variable[i], esp))
      return false;
  }
  arg_variable = *esp;

  // Place argv, argc and dummy return pointer into stack
  return push_word_to_stack ((uint32_t) arg_variable, esp)
         && push_word_to_stack ((uint32_t) argc_value, esp)
         && push_word_to_stack (NULL, esp);

}
/* Push a byte of data onto the stack. 
  In the meantime, check the esp is between USER_STACK_VADDR and PHYS_BASE or not 
*/
static bool
push_byte_to_stack (uint8_t val, void **esp)
{
  *esp -= sizeof(uint8_t);
  if (*esp<USER_STACK_VADDR)
    return false;
  *((uint8_t *) (*esp)) = val;
  return true;
}

/* Push a word of data onto the stack.
  In the meantime, check the esp is between USER_STACK_VADDR and PHYS_BASE or not
 */
static bool
push_word_to_stack (uint32_t val, void **esp)
{
  *esp -= sizeof(uint32_t);
  if (*esp<USER_STACK_VADDR)
    return false;
  *((uint32_t *) (*esp)) = val;
  return true;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
