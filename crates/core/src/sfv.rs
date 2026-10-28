//! Check archive volumes against an `.sfv` (Simple File Verification) file
//! next to the archive before extraction starts, and stop before modifying
//! anything if a volume is missing or damaged.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use crate::archive::storage::{Reads, Storage};

/// An entry parsed from an `.sfv` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SfvEntry {
    pub(crate) file_name: String,
    pub(crate) crc32: u32,
}

/// Parses the contents of an `.sfv` file.
///
/// Lines starting with `;` and blank lines are ignored.
/// Data lines take the format `<filename> <crc32>`, where the CRC-32 is an 8-character
/// hex string at the end of the line.
pub(crate) fn parse_sfv(content: &str) -> Vec<SfvEntry> {
    let mut entries = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with(';') {
            continue;
        }
        let Some((name_part, crc_part)) = trimmed.rsplit_once([' ', '\t']) else {
            continue;
        };
        let crc_str = crc_part.trim();
        let Ok(crc32) = u32::from_str_radix(crc_str, 16) else {
            continue;
        };
        let name_str = name_part.trim().trim_matches('"');
        if name_str.is_empty() {
            continue;
        }
        let file_name = Path::new(name_str)
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| name_str.to_string());

        entries.push(SfvEntry { file_name, crc32 });
    }
    entries
}

/// Computes the CRC-32 of a file by reading it in 128 KiB chunks.
pub(crate) fn file_crc32(path: &Path, reads: &Reads, cancelled: &dyn Fn() -> bool) -> Result<u32> {
    let mut file = File::open(path).with_context(|| {
        format!(
            "opening {} to verify CRC-32. Nothing was modified",
            path.display()
        )
    })?;
    let mut hasher = crc32fast::Hasher::new();
    let mut buf = [0u8; 128 * 1024];
    loop {
        if cancelled() {
            bail!("SFV verification cancelled. Nothing was modified");
        }
        let n = file
            .read(&mut buf)
            .with_context(|| format!("reading {}. Nothing was modified", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        reads
            .done
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
    }
    Ok(hasher.finalize())
}

/// Locates a matching `.sfv` file next to the archive, if one exists.
pub(crate) fn find_sfv(storage: &Storage) -> Option<(PathBuf, Vec<SfvEntry>)> {
    let primary = storage.primary();
    let parts = storage.parts();
    let dir = primary.parent().unwrap_or(Path::new("."));

    // Only consider SFV paths derived from this archive's name. A folder-wide
    // scan could mistake an unrelated set's manifest for this one.
    let mut candidates = Vec::new();
    if let Some(name) = primary.file_name() {
        candidates.push(dir.join(format!("{}.sfv", name.to_string_lossy())));
    }
    candidates.push(primary.with_extension("sfv"));

    if let Some(stem) = primary.file_name().and_then(|n| n.to_str())
        && let Some((base, _)) = stem.rsplit_once('.')
    {
        candidates.push(dir.join(format!("{base}.sfv")));
        if let Some((root, _)) = base.rsplit_once('.') {
            candidates.push(dir.join(format!("{root}.sfv")));
        }
    }

    // Try explicit candidates first.
    for path in &candidates {
        if path.is_file()
            && let Ok(bytes) = fs::read(path)
        {
            let content = String::from_utf8_lossy(&bytes);
            let entries = parse_sfv(&content);
            if entries_match_archive(&entries, parts) {
                return Some((path.clone(), entries));
            }
        }
    }

    None
}

fn entries_match_archive(entries: &[SfvEntry], parts: &[crate::archive::storage::Part]) -> bool {
    entries.iter().any(|entry| {
        parts.iter().any(|part| {
            part.path.file_name().is_some_and(|name| {
                name.to_string_lossy()
                    .eq_ignore_ascii_case(&entry.file_name)
            })
        })
    })
}

/// Checks the archive's volumes against an `.sfv` file next to it, if present.
///
/// Returns `Ok(Some(sfv_path))` if an `.sfv` file was found and verified,
/// `Ok(None)` if no `.sfv` file exists next to the archive, or an error if a volume
/// fails its CRC-32 check or is missing.
pub(crate) fn check_volumes(storage: &Storage) -> Result<Option<PathBuf>> {
    check_volumes_cancellable(storage, &|| false)
}

/// Checks each chunk for cancellation before reading it.
pub(crate) fn check_volumes_cancellable(
    storage: &Storage,
    cancelled: &dyn Fn() -> bool,
) -> Result<Option<PathBuf>> {
    if storage.sfv_checked() {
        return Ok(None);
    }

    let Some((sfv_path, entries)) = find_sfv(storage) else {
        return Ok(None);
    };

    let dir = storage.primary().parent().unwrap_or(Path::new("."));
    let sfv_display = sfv_path
        .file_name()
        .unwrap_or(sfv_path.as_os_str())
        .to_string_lossy();

    // Check if any volume listed in the SFV for this set is missing on disk.
    let primary_name = storage
        .primary()
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    for entry in &entries {
        if same_volume_set(&primary_name, &entry.file_name)
            && !storage.parts().iter().any(|part| {
                part.path
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().eq_ignore_ascii_case(&entry.file_name))
            })
        {
            let volume_path = dir.join(&entry.file_name);
            if !volume_path.exists() {
                bail!(
                    "{} listed in {} is missing. Nothing was modified",
                    entry.file_name,
                    sfv_display
                );
            }
        }
    }

    for part in storage.parts() {
        let name = part.path.file_name().unwrap_or_default().to_string_lossy();
        if !entries
            .iter()
            .any(|entry| entry.file_name.eq_ignore_ascii_case(&name))
        {
            bail!("{name} has no checksum in {sfv_display}. Nothing was modified");
        }
    }
    let total = storage.parts().iter().map(|part| part.len).sum();
    storage.expect_reads(total);
    let reads = storage.reads();

    // Verify CRC-32 for each volume of the archive present on disk.
    for part in storage.parts() {
        let part_name = part
            .path
            .file_name()
            .map(|n| n.to_string_lossy())
            .unwrap_or_default();

        if let Some(entry) = entries
            .iter()
            .find(|e| e.file_name.eq_ignore_ascii_case(&part_name))
        {
            let computed = file_crc32(&part.path, &reads, cancelled)?;
            if computed != entry.crc32 {
                bail!(
                    "{} does not match its CRC-32 in {} (expected {:08x}, computed {:08x}). Nothing was modified",
                    part_name,
                    sfv_display,
                    entry.crc32,
                    computed
                );
            }
        }
    }

    storage.mark_sfv_checked();
    Ok(Some(sfv_path))
}

// Recognise numbered volumes, not arbitrary files sharing an archive prefix.
fn same_volume_set(primary: &str, candidate: &str) -> bool {
    let primary = primary.to_ascii_lowercase();
    let candidate = candidate.to_ascii_lowercase();
    if primary == candidate {
        return true;
    }
    let Some((stem, ext)) = primary.rsplit_once('.') else {
        return false;
    };
    if ext.len() == 3 && ext.bytes().all(|b| b.is_ascii_digit()) {
        return candidate.rsplit_once('.').is_some_and(|(s, e)| {
            s == stem && e.len() == 3 && e.bytes().all(|b| b.is_ascii_digit())
        });
    }
    if ext == "rar" {
        if let Some((base, digits)) = stem.rsplit_once(".part")
            && !digits.is_empty()
            && digits.bytes().all(|b| b.is_ascii_digit())
        {
            return candidate
                .strip_suffix(".rar")
                .and_then(|s| s.rsplit_once(".part"))
                .is_some_and(|(s, n)| {
                    s == base && !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit())
                });
        }
        return candidate.rsplit_once('.').is_some_and(|(s, e)| {
            let b = e.as_bytes();
            s == stem
                && b.len() == 3
                && (b'r'..=b'z').contains(&b[0])
                && b[1..].iter().all(u8::is_ascii_digit)
        });
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::Ordering;

    #[test]
    fn parses_sfv_lines_and_ignores_comments() {
        let content = "\
; Generated by WIN-SFV32 v1.0
; (compatible: Total Commander)
;
game.7z.001 94E5D4B2
game.7z.002 4F3D612A
\"My Game.7z.003\" a1b2c3d4
";
        let entries = parse_sfv(content);
        assert_eq!(entries.len(), 3);
        assert_eq!(
            entries[0],
            SfvEntry {
                file_name: "game.7z.001".into(),
                crc32: 0x94E5D4B2,
            }
        );
        assert_eq!(
            entries[1],
            SfvEntry {
                file_name: "game.7z.002".into(),
                crc32: 0x4F3D612A,
            }
        );
        assert_eq!(
            entries[2],
            SfvEntry {
                file_name: "My Game.7z.003".into(),
                crc32: 0xA1B2C3D4,
            }
        );
    }

    #[test]
    fn computes_crc32_matching_expected() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("test.bin");
        fs::write(&file, b"123456789").unwrap();
        // Standard check value for ASCII "123456789" is 0xCBF43926
        let reads = Reads::default();
        let crc = file_crc32(&file, &reads, &|| false).unwrap();
        assert_eq!(crc, 0xCBF43926);
        assert_eq!(reads.done.load(Ordering::Relaxed), 9);
    }

    #[test]
    fn ignores_unrelated_sfv_files_in_the_archive_directory() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("game.7z.001");
        fs::write(&archive, b"volume bytes").unwrap();
        fs::write(
            dir.path().join("other-set.sfv"),
            format!("game.7z.001 {:08X}\n", crc32fast::hash(b"volume bytes")),
        )
        .unwrap();
        let storage = Storage::open(&archive, false).unwrap();

        assert!(find_sfv(&storage).is_none());
    }

    #[test]
    fn volume_check_counts_bytes_for_progress() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("game.7z.001");
        let bytes = b"volume bytes";
        fs::write(&archive, bytes).unwrap();
        fs::write(
            dir.path().join("game.7z.sfv"),
            format!("game.7z.001 {:08X}\n", crc32fast::hash(bytes)),
        )
        .unwrap();
        let storage = Storage::open(&archive, false).unwrap();

        check_volumes(&storage).unwrap();

        assert_eq!(storage.reads().fraction(), Some(1.0));
    }
    #[test]
    fn incomplete_manifest_is_refused_before_reading() {
        let dir = tempfile::tempdir().unwrap();
        let first = dir.path().join("game.7z.001");
        fs::write(&first, b"one").unwrap();
        fs::write(first.with_extension("002"), b"two").unwrap();
        fs::write(
            dir.path().join("game.7z.sfv"),
            format!("game.7z.001 {:08X}\n", crc32fast::hash(b"one")),
        )
        .unwrap();
        let storage = Storage::open(&first, false).unwrap();
        let error = check_volumes(&storage).unwrap_err().to_string();
        assert!(error.contains("game.7z.002 has no checksum"));
        assert!(!storage.sfv_checked());
        assert_eq!(storage.reads().done.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unrelated_entries_with_same_prefix_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("game.zip");
        fs::write(&archive, b"archive").unwrap();
        fs::write(
            dir.path().join("game.sfv"),
            format!(
                "game.zip {:08X}\ngame-notes.txt 12345678\n",
                crc32fast::hash(b"archive")
            ),
        )
        .unwrap();
        let storage = Storage::open(&archive, false).unwrap();
        assert!(check_volumes(&storage).unwrap().is_some());
        assert!(storage.sfv_checked());
    }

    #[test]
    fn cancellation_between_chunks_does_not_mark_verified() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("game.zip");
        let bytes = vec![42; 256 * 1024];
        fs::write(&archive, &bytes).unwrap();
        fs::write(
            dir.path().join("game.sfv"),
            format!("game.zip {:08X}\n", crc32fast::hash(&bytes)),
        )
        .unwrap();
        let storage = Storage::open(&archive, false).unwrap();
        let reads = storage.reads();
        let error = check_volumes_cancellable(&storage, &|| reads.done.load(Ordering::Relaxed) > 0)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("cancelled. Nothing was modified")
        );
        assert_eq!(reads.done.load(Ordering::Relaxed), 128 * 1024);
        assert!(!storage.sfv_checked());
        assert_eq!(fs::read(&archive).unwrap(), bytes);
        assert!(check_volumes(&storage).unwrap().is_some());
    }

    #[test]
    fn volume_names_match_only_the_same_set() {
        for (first, next) in [
            ("game.7z.001", "game.7z.003"),
            ("game.part01.rar", "game.part02.rar"),
            ("game.rar", "game.r00"),
        ] {
            assert!(same_volume_set(first, next));
        }
        for (first, other) in [
            ("game.zip", "game-notes.txt"),
            ("game.7z.001", "game.7z.notes"),
            ("game.rar", "game-extra.r00"),
        ] {
            assert!(!same_volume_set(first, other));
        }
    }
}
