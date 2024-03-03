#include "userprog/process.h"
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

static thread_func start_process NO_RETURN;
static bool load (const char *cmdline, void (**eip) (void), void **esp);

/* Makes sure the child has loaded */
static struct semaphore load_sync;

char** parse_arguments (const char *file_name, int *num_of_args);
char* push_args_to_stack (char *sp, char **args, int num_of_args);
struct thread* find_child (tid_t tid);

/* Searches for the given process's tid through the current thread's children
   list. */
struct thread* find_child (tid_t tid){
  struct thread* t = thread_current ();
  struct list_elem* child = list_begin (&t->children_records);
  if (child == NULL) return NULL;
  for (child = list_begin (&t->children_records);
       child != list_end (&t->children_records);
       child = list_next (child))
  {
    struct thread* child_thread = list_entry (child, struct thread, child_elem);
    if (child_thread->tid == tid){
      return child_thread;
    }
  }
  return NULL;
}

/*
  - Parses through the arguments in file_name and puts them in a char* array.
  - Sets num_of_args to the number of arguments in file_name.
  - Returns the char* array.
  
  WARNING:
  - Returns NULL if calloc() fails or if the number of arguments
    is zero or exceeds MAX_NUM_OF_ARGS.
*/
char** parse_arguments (const char *file_name, int *num_of_args){
  // Diem Drives here
  // allocate space to store args
  char** args_array = palloc_get_page (0);
  if (args_array == NULL) return NULL; // handle palloc failure

  char* dummy; // dummy pointer for strtok
  char* delimiters = " \t\n\v\f";
  int index = 0;
  
  // get first arg
  char* arg = strtok_r (file_name, delimiters, &dummy);
  
  // read new args and add them to the args_array
  while (arg != NULL){
    // Alyssa Drives here
    args_array[index] = arg;
    index++;

    // gets the next argument
    arg = strtok_r (NULL, delimiters, &dummy);
  }

  // handles when no arguments are passed
  if (index == 0){
    palloc_free_page (args_array);
    return NULL;
  }

  *num_of_args = index;
  return args_array;
}

/*
  - Parses through the arguments in args and puts them in the given sp pointer.
  WARNING:
  - Return Address needs fixing, it is currently set to zero.
*/
char* push_args_to_stack (char *sp, char **args, int num_of_args){
  // Abdo Drives here
  int WORD_LENGTH = sizeof(char*); // size of a pointer
  int total_data_length = 0;

  // an array to store addresses of args data
  char ***data_addresses = palloc_get_page (0);
  if (data_addresses == NULL) return NULL;

  // add args data to stack
  for (int i = num_of_args - 1; i >= 0; i--){
    // Nilava drives here
    int data_length = strlen (args[i]) + 1; // + 1 for the null terminator
    sp = sp - data_length;
    if ((char*) PHYS_BASE - sp > PGSIZE) return NULL;
    data_addresses[i] = sp;
    memcpy (sp, args[i], data_length); 
    total_data_length += data_length;
  }

  // aligns sp to multiples of WORD_LENGTH
  int alignment_amount = WORD_LENGTH - (total_data_length % WORD_LENGTH);
  sp = sp - alignment_amount;
  if ((char*) PHYS_BASE - sp > PGSIZE) return NULL;
  memset (sp, '\0', alignment_amount);
  
  // ensure argv[argc] == '\0', as required by assignment
  sp = sp - WORD_LENGTH;
  if ((char*) PHYS_BASE - sp > PGSIZE) return NULL;
  memset (sp, '\0', WORD_LENGTH);

  // Abdo Drives Here
  // adds args pointers to the stack
  for (int i = num_of_args - 1; i >= 0; i--){
    //printf("SET STACK -> addrress: %p \n", (char *) data_addresses[i]); 
    sp = sp - WORD_LENGTH;
    if ((char*) PHYS_BASE - sp > PGSIZE) return NULL;
    memcpy (sp, &data_addresses[i], WORD_LENGTH);
  }

  // adds argv pointer, points to args[0]
  data_addresses[num_of_args] = sp;
  sp = sp - WORD_LENGTH;
  if ((char*) PHYS_BASE - sp > PGSIZE) return NULL;
  memcpy (sp, &data_addresses[num_of_args], WORD_LENGTH);

  // adds argc pointer, creates a space for one int
  sp = sp - sizeof(int);
  if ((char*) PHYS_BASE - sp > PGSIZE) return NULL;
  memcpy (sp, &num_of_args, sizeof(int));

  // adds return address pointer
  // TODO: Verify if return address = 0 or something else
  sp = sp - WORD_LENGTH;
  if ((char*) PHYS_BASE - sp > PGSIZE) return NULL;
  memset (sp, '\0', WORD_LENGTH);
  palloc_free_page ((void*) data_addresses);
  return sp;
}

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */
tid_t process_execute (const char *file_name)
{
  lock_acquire (get_filelock ());
  tid_t tid;
  sema_init (&load_sync, 0);


  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  char *fn_copy = palloc_get_page (0);
  if (fn_copy == NULL){
    tid = TID_ERROR;
    goto done_exec; 
  }

  char *fn_copy2= palloc_get_page (0);
  if (fn_copy2 == NULL){
    palloc_free_page (fn_copy);
    tid = TID_ERROR;
    goto done_exec;
  }
  
  strlcpy (fn_copy, file_name, PGSIZE);
  strlcpy (fn_copy2, file_name, PGSIZE); 

  
  int num_of_args = 0;
  char** args = parse_arguments (fn_copy, &num_of_args);
  if (args == NULL){ 
    palloc_free_page (fn_copy);
    palloc_free_page (fn_copy2);
    tid = TID_ERROR;
    goto done_exec;
  } 

  
  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (args[0], PRI_DEFAULT, start_process, fn_copy2);
  if (tid == TID_ERROR) {
    palloc_free_page (fn_copy);
    palloc_free_page (fn_copy2);
    goto done_exec;
  }
  sema_down (&load_sync);
  if (find_child(tid) == NULL) tid = TID_ERROR;

  done_exec:
  lock_release (get_filelock ());
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process (void *file_name_)
{
  char *file_name = file_name_;
  struct intr_frame if_;
  bool success;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  /* Initialize thread's cwd if uninitialized. */
  if (thread_current ()->cwd == NULL) {
    thread_current ()->cwd = dir_open_root ();
  }

  /* If load failed, quit. */
  palloc_free_page (file_name);
  sema_up (&load_sync);
  if (!success) {
    list_remove (&thread_current ()->child_elem);
    thread_exit ();
  }
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
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
int process_wait (tid_t tid)
{
  if(tid == NULL)
  {
    return -1;
  }
  struct thread* t = thread_current ();
  struct thread* child = find_child (tid);
  if(child == NULL){
    return -1;
  }

  sema_down (&child->parent_sema);
  int status = child->my_status;
  sema_up (&child->my_sema);
  list_remove (&child->child_elem);
  return status;
}

/* Free the current process's resources. */
void process_exit (void)
{
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
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void process_activate (void)
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
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack (void **esp, char **args, int num_of_args);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load (const char *file_name, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  // Abdo Drives
  int num_of_args = 0;
  char** args = parse_arguments (file_name, &num_of_args);


  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    goto done;
  process_activate ();

  /* Open executable file. */
  //lock_acquire(get_filelock());
  file = filesys_open (args[0]);
  if (file == NULL)
    {
      printf ("load: %s: open failed\n", args[0]);
      goto done;
    }
  file_deny_write(file);
  t->file_descriptors[2] = file;
  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 ||
      ehdr.e_machine != 3 || ehdr.e_version != 1 ||
      ehdr.e_phentsize != sizeof (struct Elf32_Phdr) || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", args[0]);
      goto done;
    }

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
                    zero_bytes =
                        (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE) -
                         read_bytes);
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
  //lock_release(get_filelock());

  /* Set up stack. */
  if (!setup_stack (esp, args, num_of_args))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;
  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
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
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable)
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
static bool setup_stack (void **esp, char **args, int num_of_args)
{
  uint8_t *kpage;
  bool success = false;

  if (args == NULL) return false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL)
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success){
        *esp = PHYS_BASE;
        // Abdo Drives here
        *esp = (void*) push_args_to_stack ((char*) *esp, args, num_of_args);
        if (*esp == NULL){
          success = false;
          palloc_free_page (kpage);
        }
      } else {
        palloc_free_page (kpage);
      }
    }
  //hex_dump(*esp, *esp, ((char *) PHYS_BASE) - ((char *) *esp), true);
  return success;
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
static bool install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL &&
          pagedir_set_page (t->pagedir, upage, kpage, writable));
}
