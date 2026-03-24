use std::fs;
use std::path::Path;

use super::VaultError;

/// Write a note file, creating parent directories as needed.
pub fn write_note(vault_root: &Path, relative_path: &str, content: &str) -> Result<(), VaultError> {
    let full_path = vault_root.join(relative_path);
    if let Some(parent) = full_path.parent() {
        fs::create_dir_all(parent).map_err(|e| VaultError::DirError {
            path: parent.display().to_string(),
            source: e,
        })?;
    }
    fs::write(&full_path, content).map_err(|e| VaultError::WriteError {
        path: full_path.display().to_string(),
        source: e,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_test_dir(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("portreaper_test_{name}_{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    #[test]
    fn write_note_creates_file_with_parent_directories() {
        let dir = make_test_dir("write_note_creates");
        let result = write_note(&dir, "subdir/nested/note.md", "hello");
        assert!(result.is_ok(), "write_note failed: {:?}", result.err());
        let expected = dir.join("subdir/nested/note.md");
        assert!(expected.exists(), "expected file does not exist");
        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_note_content_matches_what_was_written() {
        let dir = make_test_dir("write_note_content");
        let content = "# Test Note\n\nSome content here.";
        write_note(&dir, "note.md", content).expect("write_note");
        let read_back = fs::read_to_string(dir.join("note.md")).expect("read_to_string");
        assert_eq!(read_back, content);
        // Cleanup
        let _ = fs::remove_dir_all(&dir);
    }
}
