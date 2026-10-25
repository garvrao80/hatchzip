//! Check archive volumes against an `.sfv` (Simple File Verification) file
//! next to the archive before extraction starts, and stop before modifying
//! anything if a volume is missing or damaged.

use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};

use crate::archive::storage::{Reads, Storage};

/// An entry parsed from an `.sfv` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfvEntry {
    pub file_name: String,
    pub crc32: u32,
}

/// Parses the contents of an `.sfv` file.
///
/// Lines starting with `;` and blank lines are ignored.
/// Data lines take the format `<filename> <crc32>`, where the CRC-32 is an 8-character
/// hex string at the end of the line.
pub fn parse_sfv(content: &str) -> Vec<SfvEntry> {
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
pub fn file_crc32(path: &Path, reads: &Reads) -> Result<u32> {
    let mut file =
        File::open(path).with_context(|| format!("opening {} to verify CRC-32", path.display()))?;
    let mut hasher = crc32fast::Hasher::new();
    let mut buf = [0u8; 128 * 1024];
    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("reading {}", path.display()))?;
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
pub fn find_sfv(storage: &Storage) -> Option<(PathBuf, Vec<SfvEntry>)> {
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
pub fn check_volumes(storage: &Storage) -> Result<Option<PathBuf>> {
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
    // Determine common stem of the archive set.
    let primary_name = storage
        .primary()
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let prefix = if let Some((stem, _)) = primary_name.rsplit_once('.') {
        stem
    } else {
        &primary_name
    };

    for entry in &entries {
        if entry.file_name.starts_with(prefix) {
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

    let total = storage
        .parts()
        .iter()
        .filter(|part| {
            part.path.file_name().is_some_and(|name| {
                entries.iter().any(|entry| {
                    name.to_string_lossy()
                        .eq_ignore_ascii_case(&entry.file_name)
                })
            })
        })
        .map(|part| part.len)
        .sum();
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
            let computed = file_crc32(&part.path, &reads)
                .map_err(|e| anyhow!("{e:#}. Nothing was modified"))?;
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
        let crc = file_crc32(&file, &reads).unwrap();
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
}
