#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
//This for author contribution test

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* For specify the size of arguments string array */
#define ARGS_SIZE 1024 
/* For specify how many arguments variable can the process has*/
#define ARGV_SIZE 256 
/* For arguments delimter*/
#define ARGS_DELI " "
/* The size of a word. */
#define WORD_SIZE 4
/* Error definitions. */
#define BAD_EXIT -1
#define BAD_WAIT -1
#define BAD_ARGS -1

//Form a struct that holds the arguments of ARGUMENTS structure
struct args_struct{
	char args[ARGS_SIZE];
	char *argv[ARGV_SIZE];
	unsigned argc;
};

#endif /* userprog/process.h */

