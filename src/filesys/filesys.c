#include "filesys/filesys.h"

/* Partition that contains the file system. */
struct block *fs_device;

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init (bool format)
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();

  if (format)
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done (void) { free_map_close (); }

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create (const char *name, off_t initial_size)
{
  block_sector_t inode_sector = 0;

  // handle edge case
  if (name == NULL) return false;

  struct dir *dir = dir_from_path (name);

  bool success = (dir != NULL && free_map_allocate (1, &inode_sector) &&
                  inode_create (inode_sector, initial_size, 0) &&
                  dir_add (dir, name, inode_sector));
  if (!success && inode_sector != 0)
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file *filesys_open (const char *name)
{
  struct dir *dir = dir_from_path (name);
  struct inode *inode = NULL;

  if (dir != NULL)
    dir_lookup (dir, name, &inode);
  dir_close (dir);

  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove (const char *name)
{
  struct dir *dir = dir_from_path (name);
  bool success = dir != NULL && dir_remove (dir, name);
  dir_close (dir);

  return success;
}

/* Formats the file system. */
static void do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}

/* Determine if a given filename path is absolute or not. */
bool is_absolute_path (char *path) {
  if (path == NULL) return false;
  return path[0] == '/';
}

/**
 * Returns the directory containing the given file path or 
 * NULL if the given file path is invalid. 
 */
struct dir* dir_from_path (char *path_orig) {
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

  // handle when path is absolute
  if (dir_name == NULL){
    strtok_r (NULL, delimiter, &dummy);
  }

  // parse each token in the path
  while (true){
    struct inode* inode;
    bool found_entry = dir_lookup (dir, dir_name, &inode);
    
    // no entry with the given name found
    if (!found_entry) {
      free (path);
      return NULL;
    }

    // current entry isn't a directory
    if (!inode->data.is_dir) {

      // is this entry the last token in path?
      char* next_token = strtok_r (NULL, delimiter, &dummy);

      // no -> path is incorrect
      if (next_token != NULL) {
        dir_close (dir);
        free (path);
        return NULL;
      } 
      
      // yes -> path is correct
      else {
        free (path);
        return dir;
      }
    }
    
    // set the current directory
    dir_close (dir);
    dir = dir_open (inode);

    // get the next token
    dir_name = strtok_r (NULL, delimiter, &dummy);
  }
}
