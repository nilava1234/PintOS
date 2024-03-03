#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/interrupt.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "string.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "process.h"
#include "user/syscall.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"

// max number of file descriptor addresses a one page can handle
#define FD_MAX_ENTRIES (PGSIZE / sizeof(void*))

void syscall_init (void);
static void syscall_handler (struct intr_frame *f UNUSED);
void parse_args (char* my_esp, char* arg0, char* arg1, char* arg2,
 int arg0_size, int arg1_size, int arg2_size);
void halt (void);
void exit (int status);
pid_t exec (const char *cmd_line);
int wait (pid_t pid);
bool create (const char *file, unsigned initial_size);
bool remove (const char *file);
int open (const char *filename);
int filesize (int fd);
int read (int fd, void *buffer, unsigned size);
int write (int fd, const void *buffer, unsigned size);
void seek (int fd, unsigned position);
unsigned tell (int fd);
void close (int fd);
struct file* get_file (int fd);
int insert_file_to_current_thread (struct file* file);
void is_valid_pointer (const void* ptr);
bool chdir (const char *dir);
bool mkdir (const char *dir);
bool readdir (int fd, char *name);
bool isdir (int fd);
int inumber (int fd);
struct lock* get_filelock ();

static struct lock file_lock;

#endif /* userprog/syscall.h */
