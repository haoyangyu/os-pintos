#include <stdio.h>
#include <syscall-nr.h>
#include "devices/shutdown.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/malloc.h"
#include "threads/interrupt.h"
#include "threads/vaddr.h"
#include "threads/thread.h"
#include "userprog/pagedir.h"
#include "userprog/syscall.h"

static struct lock file_lock;    /* Lock for file system access. */

static void syscall_handler (struct intr_frame *);

struct child_process *get_child_process_by_id(tid_t pid);

void modify_child_process(struct thread *parent, tid_t pid, int status);

struct child_process *get_child_process_by_id(tid_t pid)
{
  struct thread *current=thread_current();
  struct list_elem *e;
  for (e = list_tail(&current->children); e != list_head(&current->children); e = list_prev(e))
  {
    struct child_process *child = list_entry(e, struct child_process, elem);
    if (child->child_id == pid)
      return child;
  }  
  return NULL;
}

void modify_child_process(struct thread *parent, tid_t pid, int status)
{
  struct list_elem *e;
  for (e = list_tail(&parent->children); e != list_head(&parent->children); e = list_prev(e))
  {
    struct child_process *child = list_entry(e, struct child_process, elem);
    if (child->child_id == pid) 
    {
      lock_acquire(&parent->child_process_lock);
      child->exited = true;
      child->exit_status = status;
      lock_release(&parent->child_process_lock);
      break;
    }
  }  
  return;
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&file_lock);
}

bool not_valid(const void *pointer)
{
  if (!is_user_vaddr(pointer) || pagedir_get_page(thread_current()->pagedir,pointer) == NULL || pointer == NULL) 
    return true; 
  else 
    return false;
}
void 
halt (void)
{
  shutdown_power_off();
}


void 
exit (int status)
{
  struct thread *current = thread_current(); 	
  printf("%s: exit(%d)\n", current->name, status);
  struct thread *parent = get_thread(current->parent);
  if (parent != NULL) modify_child_process(parent,current->tid,status);
  thread_exit ();
}

pid_t exec (const char *cmd_line)
{
  if (not_valid(cmd_line))
  {
    exit(-1);
  }
  struct thread *current = thread_current ();
  tid_t tid = process_execute (cmd_line);
  lock_acquire (&current->child_process_lock);
  while (current->loading != SUCCESS && current->loading != FAIL) barrier();
  lock_release (&current->child_process_lock);
  if (current->loading == FAIL) return -1; else return tid;
}

int 
wait (pid_t pid)
{
  return process_wait (pid);
}

bool
create(const char *file, unsigned initial_size)
{
  if ( not_valid(file))
    exit (-1);
  
  bool result = filesys_create (file, initial_size);
  return result;
}

bool
remove (const char *file)
{
  if ( not_valid (file))
    exit (-1);
  
  bool result = false;

  /* In case the file is opened. First check its existence. */
  struct file *f = filesys_open (file);
  if (f)
  {
    file_close (f);
    result = filesys_remove (file);
  }
  
  return result;
}

int 
open (const char *file)
{
  //YHY: For fixing the declaration 
  int last_fd;

  if ( not_valid (file))
    exit (-1);
  
  int prev_fd;
  struct file *f;
  struct file_desc *new_fd;
  struct list_elem *e;

  lock_acquire (&file_lock);

  f = filesys_open (file);
  if (f == NULL)
    return -1;

  struct list* fd_list = &thread_current()->fd_list;
  
  new_fd = malloc (sizeof (struct file_desc));
  if (new_fd == NULL)
  {
    file_close (f);
    return -1;
  }

  if (list_empty (fd_list))
    last_fd = 1;
  else
  {
    e = list_begin (fd_list);
    last_fd = list_entry (e, struct file_desc, elem)->fd;
  }
  
  new_fd->fd = last_fd + 1;
  new_fd->file = f;
  list_push_front (fd_list, &new_fd->elem);
  lock_release (&file_lock);

  return new_fd->fd;
}

int
filesize (int fd)
{
  struct file_desc *file_d;
  struct list *fd_list;
  struct list_elem *e;
  int size = -1;

  lock_acquire (&file_lock);

  fd_list = &thread_current()->fd_list;
  for (e = list_begin (fd_list); e != list_end (fd_list); 
       e = list_next (e))
  {
    file_d = list_entry (e, struct file_desc, elem);
    if (file_d->fd == fd)
    {
      size = file_length (file_d->file);
      break;
    }
  }

  lock_release (&file_lock);
  return size;
}

int 
read (int fd, void *buffer, unsigned size)
{
  if ( not_valid (buffer) || not_valid (buffer + size)
       || fd == STDOUT_FILENO)
    exit(-1);

  int count = 0;
  
  /* Read from keyboard. */
  if (fd == STDIN_FILENO)
    {
      while (count < size)
        {
           *((uint8_t *) (buffer + count)) = input_getc ();
          count++;
        }
      return size;
    }

  /* Read from file. */

  struct file_desc *file_d;
  struct list *fd_list;
  struct list_elem *e;

  lock_acquire (&file_lock);

  fd_list = &thread_current()->fd_list;
  for (e = list_begin (fd_list); e != list_end (fd_list); 
       e = list_next (e))
  {
    file_d = list_entry (e, struct file_desc, elem);
    if (file_d->fd == fd)
    {
      count = file_read (file_d->file, buffer, size);
      break;
    }
  }

  lock_release (&file_lock);

  return count;
}

int 
write (int fd, const void *buffer, unsigned size)
{
  int count = 0;

  /* Write to the console. */
  if (fd == STDOUT_FILENO)
  {
    putbuf (buffer, size);
    /* putbuf has no return, return size. */
    return size;
  }

  if ( not_valid(buffer))
    exit(-1);

  /* Write to a file. */
  struct file_desc *file_d;
  struct list *fd_list;
  struct list_elem *e;

  lock_acquire (&file_lock);

  fd_list = &thread_current()->fd_list;
  for (e = list_begin (fd_list); e != list_end (fd_list); 
       e = list_next (e))
  {
    file_d = list_entry (e, struct file_desc, elem);
    if (file_d->fd == fd)
    {
      count = file_write (file_d->file, buffer, size); 
      break;   
    }
  }

  lock_release (&file_lock);

  return count;
}

void 
seek (int fd, unsigned position)
{
  struct file_desc *file_d;
  struct list *fd_list;
  struct list_elem *e;

  lock_acquire (&file_lock);

  fd_list = &thread_current()->fd_list;
  for (e = list_begin (fd_list); e != list_end (fd_list); 
       e = list_next (e))
  {
    file_d = list_entry (e, struct file_desc, elem);
    if (file_d->fd == fd)
    {
      file_seek (file_d->file, position); 
      break;   
    }
  }

  lock_release (&file_lock);
}

unsigned 
tell (int fd)
{
  unsigned pos = 0;
  struct file_desc *file_d;
  struct list *fd_list;
  struct list_elem *e;

  lock_acquire (&file_lock);

  fd_list = &thread_current()->fd_list;
  for (e = list_begin (fd_list); e != list_end (fd_list); 
       e = list_next (e))
  {
    file_d = list_entry (e, struct file_desc, elem);
    if (file_d->fd == fd)
    {
      pos = file_tell (file_d->file); 
      break;   
    }
  }

  lock_release (&file_lock);

  return pos;
}

void 
close (int fd)
{
  struct file_desc *file_d;
  struct list *fd_list;
  struct list_elem *e;

  lock_acquire (&file_lock);

  fd_list = &thread_current()->fd_list;
  for (e = list_begin (fd_list); e != list_end (fd_list); 
       e = list_next (e))
  {
    file_d = list_entry (e, struct file_desc, elem);
    if (file_d->fd == fd)
    {
      file_close (file_d->file);
      list_remove (e);
      free (file_d); 
      break;   
    }
  }

  lock_release (&file_lock);
}

static void
syscall_handler (struct intr_frame *f /* UNUSED */) 
{
  uint32_t *pointer = f->esp;
  if (not_valid(pointer)) 
  {
    exit(-1);
    return;
  }
  switch (*pointer) 
  {
    case SYS_HALT:
      halt();
      break;
    case SYS_EXIT:
      exit(*(pointer+1));
      break;
    case SYS_EXEC:
      f->eax = exec((char *)(*(pointer+1)));
      break;
    case SYS_WAIT:
      f->eax = wait(*(pointer+1));
      break;
    case SYS_CREATE:
      f->eax = create((char *)(*(pointer+1)), *(pointer+2));
      break;
    case SYS_REMOVE:
      f->eax = remove((char *)(*(pointer+1)));
      break;
    case SYS_OPEN:
      f->eax = open ((char *)(*(pointer+1)));
      break;
    case SYS_FILESIZE:
      f->eax = filesize(*(pointer+1));
      break;
    case SYS_READ: 
      f->eax = read((char *)(*(pointer+1)), (void *)(*(pointer+2)), *(pointer+3));
      break;
    case SYS_WRITE:
      f->eax = write((char *)(*(pointer+1)), (void *)(*(pointer+2)), *(pointer+3));
      break;
    case SYS_TELL:
      f->eax = tell(*(pointer+1));
      break;
    case SYS_SEEK:
     // f->eax = seek(*(pointer+1), *(pointer+2));
      break;
    case SYS_CLOSE:
     // f->eax = close(*(pointer+1));
      break;
    default:
      break;  
  }  
  thread_exit ();
}


