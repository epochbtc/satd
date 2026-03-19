use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

const MAX_FILE_SIZE: u64 = 128 * 1024 * 1024; // 128 MB

/// Position of a block within the flat file set.
#[derive(Debug, Clone, Copy)]
pub struct FlatFilePos {
    pub file_number: u32,
    pub data_pos: u32,
}

/// Manages sequential block storage in blk*.dat files.
pub struct FlatFileManager {
    blocks_dir: PathBuf,
    current_file: u32,
    current_pos: u64,
}

impl FlatFileManager {
    pub fn new(blocks_dir: &Path) -> std::io::Result<Self> {
        std::fs::create_dir_all(blocks_dir)?;

        // Find the latest file and its size
        let mut file_num = 0u32;
        loop {
            let path = blocks_dir.join(format!("blk{:05}.dat", file_num + 1));
            if path.exists() {
                file_num += 1;
            } else {
                break;
            }
        }

        let current_pos = {
            let path = blocks_dir.join(format!("blk{:05}.dat", file_num));
            if path.exists() {
                std::fs::metadata(&path)?.len()
            } else {
                0
            }
        };

        Ok(Self {
            blocks_dir: blocks_dir.to_path_buf(),
            current_file: file_num,
            current_pos,
        })
    }

    /// Get the blocks directory path.
    pub fn blocks_dir(&self) -> &Path {
        &self.blocks_dir
    }

    fn file_path(&self, file_number: u32) -> PathBuf {
        self.blocks_dir
            .join(format!("blk{:05}.dat", file_number))
    }

    /// Write a block to the flat files. Returns the position where it was stored.
    pub fn write_block(
        &mut self,
        block_data: &[u8],
        network_magic: [u8; 4],
    ) -> std::io::Result<FlatFilePos> {
        // Total size: 4 (magic) + 4 (size) + block_data.len()
        let record_size = 8 + block_data.len() as u64;

        // Roll over to next file if current would exceed max
        if self.current_pos > 0 && self.current_pos + record_size > MAX_FILE_SIZE {
            self.current_file += 1;
            self.current_pos = 0;
        }

        let pos = FlatFilePos {
            file_number: self.current_file,
            data_pos: self.current_pos as u32,
        };

        let path = self.file_path(self.current_file);
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        file.write_all(&network_magic)?;
        file.write_all(&(block_data.len() as u32).to_le_bytes())?;
        file.write_all(block_data)?;

        self.current_pos += record_size;

        Ok(pos)
    }

    /// Check whether a given flat file exists on disk.
    pub fn file_exists(&self, file_number: u32) -> bool {
        self.file_path(file_number).exists()
    }

    /// Delete a flat file from disk.
    pub fn delete_file(&self, file_number: u32) -> std::io::Result<()> {
        let path = self.file_path(file_number);
        if path.exists() {
            std::fs::remove_file(&path)?;
        }
        Ok(())
    }

    /// Read a block from the flat files at the given position.
    pub fn read_block(&self, pos: &FlatFilePos) -> std::io::Result<Vec<u8>> {
        let path = self.file_path(pos.file_number);
        let mut file = File::open(&path)?;
        file.seek(SeekFrom::Start(pos.data_pos as u64))?;

        // Read magic (4 bytes) + size (4 bytes)
        let mut header = [0u8; 8];
        file.read_exact(&mut header)?;
        let size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;

        let mut data = vec![0u8; size];
        file.read_exact(&mut data)?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_and_read_block() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda]; // regtest
        let block_data = b"fake block data for testing";

        let pos = mgr.write_block(block_data, magic).unwrap();
        assert_eq!(pos.file_number, 0);
        assert_eq!(pos.data_pos, 0);

        let read_back = mgr.read_block(&pos).unwrap();
        assert_eq!(read_back, block_data);

        // Write another block
        let pos2 = mgr.write_block(b"second block", magic).unwrap();
        assert_eq!(pos2.file_number, 0);
        assert!(pos2.data_pos > 0);

        let read_back2 = mgr.read_block(&pos2).unwrap();
        assert_eq!(read_back2, b"second block");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_multiple_blocks_same_file() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-multi-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda];

        let pos1 = mgr.write_block(b"block one", magic).unwrap();
        let pos2 = mgr.write_block(b"block two", magic).unwrap();
        let pos3 = mgr.write_block(b"block three", magic).unwrap();

        // All three should be in file 0
        assert_eq!(pos1.file_number, 0);
        assert_eq!(pos2.file_number, 0);
        assert_eq!(pos3.file_number, 0);

        // Positions should be strictly increasing
        assert!(pos2.data_pos > pos1.data_pos);
        assert!(pos3.data_pos > pos2.data_pos);

        // All blocks should be readable
        assert_eq!(mgr.read_block(&pos1).unwrap(), b"block one");
        assert_eq!(mgr.read_block(&pos2).unwrap(), b"block two");
        assert_eq!(mgr.read_block(&pos3).unwrap(), b"block three");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_read_nonexistent() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-noexist-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mgr = FlatFileManager::new(&dir).unwrap();
        let pos = FlatFilePos {
            file_number: 99,
            data_pos: 0,
        };
        // Reading from a file that doesn't exist should return an error
        assert!(mgr.read_block(&pos).is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_file_exists_and_delete() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-del-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda];

        // Before writing, file 0 doesn't exist
        assert!(!mgr.file_exists(0));

        mgr.write_block(b"data", magic).unwrap();

        // After writing, file 0 exists
        assert!(mgr.file_exists(0));

        // Delete it
        mgr.delete_file(0).unwrap();
        assert!(!mgr.file_exists(0));

        // Deleting a non-existent file should not error
        assert!(mgr.delete_file(99).is_ok());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_resume_from_existing() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let magic = [0xfa, 0xbf, 0xb5, 0xda];

        // First manager: write one block
        let pos1 = {
            let mut mgr = FlatFileManager::new(&dir).unwrap();
            mgr.write_block(b"first block", magic).unwrap()
        };
        // mgr is dropped here

        // Second manager: should resume from where the first left off
        let mut mgr2 = FlatFileManager::new(&dir).unwrap();
        let pos2 = mgr2.write_block(b"second block", magic).unwrap();

        // Both should be in file 0 and the second should not overwrite the first
        assert_eq!(pos1.file_number, 0);
        assert_eq!(pos2.file_number, 0);
        assert!(pos2.data_pos > pos1.data_pos);

        // Both blocks should be readable
        assert_eq!(mgr2.read_block(&pos1).unwrap(), b"first block");
        assert_eq!(mgr2.read_block(&pos2).unwrap(), b"second block");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn test_multiple_reads_same_file() {
        let dir = std::env::temp_dir().join(format!("satd-flatfile-mread-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        let mut mgr = FlatFileManager::new(&dir).unwrap();
        let magic = [0xfa, 0xbf, 0xb5, 0xda];

        let data_a = vec![0xAA; 1024]; // 1 KB block
        let data_b = vec![0xBB; 2048]; // 2 KB block

        let pos_a = mgr.write_block(&data_a, magic).unwrap();
        let pos_b = mgr.write_block(&data_b, magic).unwrap();

        // Read both multiple times — should be consistent
        for _ in 0..3 {
            assert_eq!(mgr.read_block(&pos_a).unwrap(), data_a);
            assert_eq!(mgr.read_block(&pos_b).unwrap(), data_b);
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
