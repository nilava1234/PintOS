#include "filesys/inode.h"

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector (const struct inode *inode, off_t pos)
{
  ASSERT (inode != NULL);
  if (pos >= inode->data.length) return -1;

  int lvl_1_index = (pos / BLOCK_SECTOR_SIZE) / TABLE_ENTRIES_CNT;
  int lvl_2_index = (pos / BLOCK_SECTOR_SIZE) % TABLE_ENTRIES_CNT;

  uint32_t* lvl_1_ptr = malloc (BLOCK_SECTOR_SIZE);
  uint32_t* lvl_2_ptr = malloc (BLOCK_SECTOR_SIZE);

  block_read (fs_device, inode->data.table, lvl_1_ptr);
  block_read (fs_device, lvl_1_ptr[lvl_1_index], lvl_2_ptr);

  block_sector_t block = lvl_2_ptr[lvl_2_index];
  free (lvl_1_ptr);
  free (lvl_2_ptr);
  return block;
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init (void) { list_init (&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create (block_sector_t sector, off_t length, uint32_t is_dir)
{
  struct inode_disk *disk_inode = NULL;
  bool success = true;

  ASSERT (length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);//CHECK: Why?
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      static char zeros[BLOCK_SECTOR_SIZE];

      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;
      disk_inode->is_dir = is_dir;
      if (is_dir){
        disk_inode->itself_dir = disk_inode;
        disk_inode->parent_dir = dir_reopen (thread_current ()->cwd->inode);
        // TODO: fix parent_dir, parent_dir != parent_process_cwd
      }

      success = success & free_map_allocate (1, &disk_inode->table); // TODO: handle when it returns false.
      block_sector_t table_data[TABLE_ENTRIES_CNT];
      memcpy (zeros, table_data, BLOCK_SECTOR_SIZE); // TODO: verify memcpy

      int sectors_copy = sectors;
      // for each entry in the lvl1 table
      for (int lvl1_i = 0; lvl1_i < TABLE_ENTRIES_CNT; lvl1_i++)//COMMENT: more detail
      {

        if (table_data[lvl1_i] == NULL){
          success = success & free_map_allocate (1, &table_data[lvl1_i]);
        }

        block_sector_t table_2_data[TABLE_ENTRIES_CNT];
        memcpy (zeros, table_2_data, BLOCK_SECTOR_SIZE);
        // CHECK: does table_1 save the pointer??? I dont think so
        // for each entry in the lvl2 table
        for (int lvl2_i = 0; lvl2_i < TABLE_ENTRIES_CNT; lvl2_i++)
        {
          if (table_2_data[lvl2_i] == NULL) {
            success = success & free_map_allocate (1, &table_2_data[lvl2_i]);
          }
          sectors_copy--;
          if (sectors_copy == 0) break;
        }

        block_write (fs_device, table_data[lvl1_i], table_2_data);
        if (sectors_copy == 0) break;
      }


      block_write (fs_device, disk_inode->table, table_data);
      block_write (fs_device, sector, disk_inode);
      free (disk_inode);
    }
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e))
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector)
        {
          inode_reopen (inode);
          return inode;
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close (struct inode *inode)
{
  /* Ignore null pointer. */
  if (inode == NULL) return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt > 0) return;

  // removes inode from the active inodes list
  list_remove (&inode->elem);

  /* Deallocate blocks if removed. */
  if(inode->removed)
  {
    block_sector_t inode_table[TABLE_ENTRIES_CNT];
    block_read (fs_device, inode->data.table, &inode_table);

    //Traverse through the first table
    for(int lvl1 = 0; lvl1 < TABLE_ENTRIES_CNT; lvl1++)
    { 
      // traverse through the 2nd table
      block_sector_t lvl2_data[TABLE_ENTRIES_CNT];
      block_read (fs_device, inode_table[lvl1], &lvl2_data);

      // CHECK: should we stop early or check all entries?
      if (lvl2_data[lvl1] == NULL) break;

      for (int lvl2 = 0; lvl2 < TABLE_ENTRIES_CNT; lvl2++)
      {
        if (lvl2_data[lvl2] != NULL){
          free_map_release (lvl2_data[lvl2], 1);
        }
      }
      
    }
    free_map_release (inode->sector, 1);
  }

  free (inode);
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove (struct inode *inode)
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at (struct inode *inode, void *buffer_, off_t size,
                     off_t offset)
{
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0)
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  return bytes_read;
}

/**
 * expands the inode to the given pos by allocating blocks.
*/
bool expand_inode (struct inode* inode, off_t pos) {
  ASSERT (pos >= inode->data.length);

  if (pos + inode->data.length > fs_device->size * BLOCK_SECTOR_SIZE) {
    return false;
  }
  inode->data.length += pos;

  int lvl_1_index = pos / (BLOCK_SECTOR_SIZE);
  int lvl_2_index = pos % (BLOCK_SECTOR_SIZE);

  uint32_t* lvl_1_ptr = malloc (BLOCK_SECTOR_SIZE);
  uint32_t* lvl_2_ptr = malloc (BLOCK_SECTOR_SIZE);

  block_read (fs_device, inode->data.table, lvl_1_ptr);

  // lock_acquire ();
  for (int entry = 0; entry <= lvl_1_index; entry++){
    if (lvl_1_ptr[entry] == NULL) {
      free_map_allocate (1, &lvl_1_ptr[entry]);
      // printf ("allocated: %ld\n", lvl_1_ptr[entry]);
    }
  }

  block_read (fs_device, lvl_1_ptr[lvl_1_index], lvl_2_ptr);

  for (int entry = 0; entry <= lvl_2_index; entry++){
    if (lvl_2_ptr[entry] == NULL) {
      free_map_allocate (1, &lvl_2_ptr[entry]);
    }
  }
  // lock_release ();
  block_sector_t block = lvl_2_ptr[lvl_2_index];
  free (lvl_1_ptr);
  free (lvl_2_ptr);
  return true;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                      off_t offset)
{
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt)
    return 0;

  // check length here
  if (offset + size >= inode_length (inode)) {
    // lock_acquire (&inode->lock);
    expand_inode (inode, offset + size);
    // lock_release (&inode->lock);
  }

  while (size > 0)
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else
        {
          /* We need a bounce buffer. */
          if (bounce == NULL)
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left)
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write (struct inode *inode)
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write (struct inode *inode)
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length (const struct inode *inode) { return inode->data.length; }
