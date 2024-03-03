#include "userprog/syscall.h"



/* A gettor function for the file_lock to be called from process.c. */
struct lock* get_filelock () { return &file_lock; }

/* 
  Frees all the children associated with the given children_list. By Free, 
  we're calling sema up on the child's parent_sema, so it can exit.
*/
void free_children (struct list* children_list)
{
  while (!list_empty (children_list))
  {
    struct list_elem *child = list_pop_front (children_list);
    struct thread* child_thread = list_entry (child, struct thread, child_elem);
    sema_up (&child_thread->parent_sema);
  }
  return;
}

/* It Parses through the stack pointer and fills the given arguments. */
void parse_args (char* my_esp, char* arg0, char* arg1, char* arg2,
 int arg0_size, int arg1_size, int arg2_size)
{
  // Abdo Drove Here
  char* args_size = my_esp + arg0_size + arg1_size + arg2_size;
  is_valid_pointer (args_size);
  if (arg0 == NULL || arg0_size == 0) return;
  memcpy  (arg0, my_esp, arg0_size);
  my_esp += arg0_size;
  if (arg1 == NULL || arg1_size == 0) return;
  memcpy (arg1, my_esp, arg1_size);
  my_esp += arg1_size;
  if (arg2 == NULL || arg2_size == 0) return;
  memcpy (arg2, my_esp, arg2_size);
  my_esp += arg2_size;
  return;
}

void syscall_init (void)
{
  lock_init (&file_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void syscall_handler (struct intr_frame *f UNUSED)
{
  // Diem Drove Here
  char** my_esp = f->esp;
  is_valid_pointer ((char*) my_esp + sizeof(int));
  int sys_number = *my_esp;
  my_esp = (char**) (((char*) my_esp) + sizeof(sys_number));
  is_valid_pointer (my_esp);

  char* file;
  void* buffer;
  int fd;
  unsigned size;

  // Both Abdo and Nil Drove here
  switch (sys_number){
    case SYS_HALT:
    halt ();
    break;

    case SYS_EXIT:
    int status;
    parse_args (my_esp, &status, NULL, NULL, sizeof(int), 0, 0);
    exit (status);
    break;

    case SYS_EXEC:
    char* cmd_line;
    parse_args (my_esp, &cmd_line, NULL, NULL, sizeof(char*), 0, 0);
    is_valid_pointer (cmd_line);
    f->eax = exec (cmd_line);
    break;

    case SYS_WAIT:
    pid_t pid;
    parse_args (my_esp, &pid, NULL, NULL, sizeof(pid_t), 0, 0);
    f->eax = wait (pid);
    break;

    case SYS_CREATE:
    lock_acquire (&file_lock);
    unsigned initial_size;
    parse_args (my_esp, &file, &initial_size, NULL, sizeof(char*), sizeof(unsigned), 0);
    is_valid_pointer (file);
    f->eax = create (file, initial_size);
    lock_release (&file_lock);
    break;

    case SYS_REMOVE:
    lock_acquire (&file_lock);
    parse_args (my_esp, &file, NULL, NULL, sizeof(char*), 0, 0);
    is_valid_pointer (file);
    f->eax = remove (file);
    lock_release (&file_lock);
    break;

    case SYS_OPEN:
    lock_acquire (&file_lock);
    char* filename;
    parse_args (my_esp, &filename, NULL, NULL, sizeof(char*), 0, 0);
    is_valid_pointer (filename);
    f->eax = open (filename);
    lock_release (&file_lock);
    break;

    case SYS_FILESIZE:
    lock_acquire (&file_lock);
    parse_args (my_esp, &fd, NULL, NULL, sizeof(int), 0, 0);
    f->eax = filesize (fd);
    lock_release (&file_lock);
    break;

    case SYS_READ:
    lock_acquire (&file_lock);
    parse_args (my_esp, &fd, &buffer, &size, sizeof(fd), sizeof(buffer), sizeof(size));
    is_valid_pointer (buffer);
    f->eax = read (fd, buffer, size);
    lock_release (&file_lock);
    break;

    case SYS_WRITE:
    lock_acquire (&file_lock);
    parse_args (my_esp, &fd, &buffer, &size, sizeof(fd), sizeof(buffer), sizeof(size));
    is_valid_pointer (buffer);
    f->eax = write (fd, buffer, size);
    lock_release (&file_lock);
    break;

    case SYS_SEEK:
    lock_acquire (&file_lock);
    unsigned position;
    parse_args (my_esp, &fd, &position, NULL, sizeof(fd), sizeof(position), 0);
    seek (fd, position);
    lock_release (&file_lock);
    break;

    case SYS_TELL:
    lock_acquire (&file_lock);
    parse_args (my_esp, &fd, NULL, NULL, sizeof(fd), 0, 0);
    f->eax = tell (fd);
    lock_release (&file_lock);
    break;

    case SYS_CHDIR:
    lock_acquire (&file_lock);
    char* path;
    parse_args (my_esp, &path, NULL, NULL, sizeof(path), 0, 0);
    f->eax = chdir (path);
    lock_release (&file_lock);
    break;

    case SYS_MKDIR:
    lock_acquire (&file_lock);
    char* path2;
    parse_args (my_esp, &path2, NULL, NULL, sizeof(path), 0, 0);
    f->eax = mkdir (path);
    lock_release (&file_lock);
    break;

    case SYS_READDIR:
    lock_acquire (&file_lock);
    char* path3;
    parse_args (my_esp, &fd, &path3, sizeof(fd), sizeof(path), 0, 0);
    f->eax = readdir (fd, path3);
    lock_release (&file_lock);
    break;

    case SYS_ISDIR:
    lock_acquire (&file_lock);
    parse_args (my_esp, &fd, NULL, sizeof(fd), 0, 0, 0);
    f->eax = isdir (fd);
    lock_release (&file_lock);
    break;

    case SYS_INUMBER:
    lock_acquire (&file_lock);
    parse_args (my_esp, &fd, NULL, sizeof(fd), 0, 0, 0);
    f->eax = inumber (fd);
    lock_release (&file_lock);
    break;

    case SYS_CLOSE:
    lock_acquire (&file_lock);
    parse_args (my_esp, &fd, NULL, NULL, sizeof(fd), 0, 0);
    close (fd);
    lock_release (&file_lock);
    break;

    default:
    exit (-1);
    break;
  }
}

/**
 * Returns the directory containing the given file path or 
 * NULL if the given file path is invalid. 
 */
struct dir* get_dir_from_path (char *path_orig) {
  if (path_orig == NULL) return NULL;

  // copy the given file path
  char* path = malloc (strlen (path_orig)); 
  char* path2 = malloc (strlen (path_orig)); 
  strlcpy (path, path_orig, strlen (path_orig));
  strlcpy (path2, path_orig, strlen (path_orig));
  
  // determine the beginning directory
  struct dir* dir;
  if (is_absolute_path (path)) {
    dir = dir_open_root ();
  } else {
    dir = thread_current ()->cwd;
  }

  char* dummy; // dummy pointer for strtok_r
  char* delimiter = "/";
  
  // gets the first directory name
  char* dir_name = strtok_r (path, delimiter, &dummy);

  // store last directory name in prev
  char* prev = NULL;
  while (dir_name != NULL){
    prev = dir_name;
    dir_name = strtok_r (NULL, delimiter, &dummy);
  }
  free(path);

  // navigate directories until we reach prev
  char* dir_name2 = strtok_r (path2, delimiter, &dummy);
  while (path2 != NULL) {

    struct inode* inode;
    bool found_entry = dir_lookup (dir, dir_name2, &inode);
    
    // only accept directory entries
    if (!found_entry || !inode->data.is_dir) {
      free (path2);
      return NULL;
    }

    // set the current directory
    dir_close (dir);
    dir = dir_open (inode);

    // stop if we reached last directory
    if (strcmp (dir_name2, prev) == 0) {
      free (path2);
      return dir;
    }

    // get the next token
    dir_name2 = strtok_r (NULL, delimiter, &dummy);
  }
  free (path2);
  return NULL;
}

/**
 * Returns the directory in the path_orig path or return NULL if name exist
 * in any directory along the path.
*/
struct dir* add_dir_from_path (char *path_orig, char* name) {
  if (path_orig == NULL) return NULL;

  // copy the given file path
  char* path = malloc (strlen (path_orig));
  strlcpy (path, path_orig, strlen (path_orig));
  
  // determine the beginning directory
  struct dir* dir;
  if (is_absolute_path (path)) {
    dir = dir_open_root ();
  } else {
    dir = thread_current ()->cwd;
  }

  char* dummy; // dummy pointer for strtok_r
  char* delimiter = "/";
  
  // gets the first directory name
  char* dir_name = strtok_r (path, delimiter, &dummy);

  // parse each token in the path
  while (path != NULL) {

    struct inode* inode;
    bool found_entry = dir_lookup (dir, dir_name, &inode);
    
    // current directory name matches the given name
    if (strcmp (dir_name, name) == 0) {
      free (path);
      if (found_entry) {
        return NULL;
      }
      return dir;
    }

    // no directory with the given name found
    if (!found_entry || !inode->data.is_dir) {
      free (path);
      return NULL;
    }

    // set the current directory
    dir_close (dir);
    dir = dir_open (inode);

    // get the next token
    dir_name = strtok_r (NULL, delimiter, &dummy);
  }
  free (path);
  return NULL;
}

/**
 * Changes the current working directory for the current thread to the
 * given directory in path.
*/
bool chdir (const char *path)
{
  struct dir *dir = get_dir_from_path (path);
  if(dir == NULL) return false;
  thread_current()->cwd = dir;
  return true;
}

/**
 * Creates a directory in the given dir_path, where the last directory
 * name is the new directory name.
*/
bool mkdir (const char *dir_path)
{
  char* path = strlcpy (path, dir_path, strlen (dir_path));
  char* dummy; // dummy pointer for strtok_r
  char* delimiter = "/";
  
  // gets the first directory name
  char* dir_name = strtok_r (path, delimiter, &dummy);
  char* prev = NULL;

  // parse each token in the path
  while (dir_name != NULL){
    prev = dir_name;
    dir_name = strtok_r (NULL, delimiter, &dummy);
  }

  struct dir* dir = add_dir_from_path (dir_path, prev);

  if (dir == NULL) return false;

  block_sector_t sector;
  if (!free_map_allocate (1, &sector)) return NULL;
  if (!dir_create (sector, 1) || !dir_add (dir, prev, sector)){
    free_map_release (sector, 1);
    return false;
  }
  return true;
}

/**
 * returns stores the next directory name in name from the directory in fd.
*/
bool readdir (int fd, char *name)
{
  struct file *file = get_file (fd);
  if (file == NULL || !isdir(fd)) return false;
  struct dir *dir = dir_open (file->inode);
  bool result = dir_readdir (dir, name);
  dir_close (dir);
  return result;
}

/**
 * returns if the file associated with fd is a directory or not.
*/
bool isdir (int fd)
{
  struct file *file = get_file (fd);
  if (file == NULL) return false;
  return (bool)file->inode->data.is_dir;
}

/**
 * returns the inode sector number of the given file.
*/
int inumber (int fd)
{
  struct file *file = get_file (fd);
  if (file == NULL) return false;
  return file->inode->sector;
}


/*
* halt
*/
void halt (void)
{
  // Alyssa Drives Here
  shutdown_power_off ();
}


/*
* exit
*/
void exit (int status)
{
  // Diem Drives Here
  struct thread* t = thread_current ();
  if (lock_held_by_current_thread(&file_lock)){
    lock_release(&file_lock);
  }
  t->my_status = status;
  printf ("%s: exit(%d)\n", t->name, t->my_status);
  lock_acquire(&file_lock);
  file_close (t->file_descriptors[2]);
  lock_release(&file_lock);
  sema_up (&t->parent_sema);
  sema_down (&t->my_sema);
  free_children (&t->children_records);
  thread_exit ();
  return;
}


/*
* exec
*/
pid_t exec (const char *cmd_line)
{
  // Alyssa Drives Here
  pid_t pid = process_execute (cmd_line);
  return pid;
}


/*
* wait
*/
int wait (pid_t pid)
{
  if (pid == TID_ERROR) return -1;
  return process_wait ((tid_t) pid);
}


/*
* create
*/
bool create (const char *file, unsigned initial_size)
{
  if (file[0] == '\0'){
    exit (-1);
  }

  if (strlen (file) >= 511){
    return false;
  }
  bool status = filesys_create (file, initial_size);
  return status;
}


/*
* remove
*/
bool remove (const char *file)
{
  if (file[0] == '\0'){
    exit (-1);
  }
  return filesys_remove (file);
}


/*
* open
*/
int open (const char *filename)
{
  struct file* file = filesys_open (filename);
  if (file == NULL) return -1;
  return insert_file_to_current_thread (file);
}

/*
* get the file size
*/
int filesize (int fd)
{
  struct file* file = get_file (fd);
  if (file == NULL) return -1;
  return file_length (file);
}


/*
* read size bytes from file descriptor fd 
*/
int read (int fd, void *buffer, unsigned size)
{

  if (fd == 0){ // stdin
    unsigned chars_read = size;
    while (chars_read-- <= 0){
      input_getc ();
    }
    return size;
  }

  struct file* file = get_file (fd);
  if (file == NULL){
    return -1;
  }


  int bytes_read = file_read (file, buffer, size);
  return bytes_read;
}


/*
* write size bytes
*/
int write (int fd, const void *buffer, unsigned size)
{
  // Abdo Drives Here

  if (fd == 1){ // stdout
    putbuf (buffer, size);
    return size;
  }

  struct file* file = get_file (fd);
  if (file == NULL){
    return -1;
  }
  
  int bytes_written = file_write (file, buffer, size);
  return bytes_written;
}


/*
* seek
*/
void seek (int fd, unsigned position)
{
  // Nil Drives Here
  struct file* file = get_file (fd);
  if (file == NULL || position < 0){

    return;
  }
  file_seek (file, position);
  return;
}


/*
* tell
*/
unsigned tell (int fd)
{
  // Abdo Drives Here
  struct file* file = get_file (fd);
  if (file == NULL){
    return -1;
  }
  int next = file_tell (file);
  return next;
}


/*
* close
*/
void close (int fd)
{
  // Diem Drives Here
  struct file* file = get_file (fd);
  if (file != NULL){
    file_close (file);
    thread_current ()->file_descriptors[fd] = NULL;
  }
}


/*
* get the corresponding file from a file descriptor
*/
struct file* get_file (int fd)
{
  // Abdo Drives here
  if (fd > FD_MAX_ENTRIES || fd <= 2){
    return NULL;
  }
  return thread_current () ->file_descriptors[fd];
}


/*
* insert file to current thread
*/
int insert_file_to_current_thread (struct file* file) {
  // Alyssa Drives Here
  struct file** file_descriptors = thread_current ()->file_descriptors;
  // start with 3 because 0, 1, 2 are reserved for stdin, stdout,
  // and the thread's executable file
  int index = 3;
  while (index < FD_MAX_ENTRIES && file_descriptors[index] != NULL){
    index++;
  }

  // handles when file descriptor full
  if (index >= FD_MAX_ENTRIES) return -1;

  file_descriptors[index] = file;
  return index;
}

/*
* helper to check validity of memory pointer passed in by user
* call at beginning of all syscalls to make sure user memory
* is being appropriately accessed
*/
void is_valid_pointer (const void* ptr)
{
  // Alyssa Drives Here
  //possible invalid cases: ptr is null ptr, ptr is kernel addr (>= phys base),
  //or ptr is to unmapped mem
  struct thread *cur = thread_current ();
  uint32_t pd = cur->pagedir;
  if (ptr == NULL || !is_user_vaddr (ptr) ||
     pagedir_get_page (pd, ptr) == NULL){
    exit (-1);
  }
}