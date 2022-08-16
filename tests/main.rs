#![cfg(test)]
extern crate asset_archive;
extern crate rand;

use std::io::{Read, Cursor};

use asset_archive::{Archive, Compression, CompressionMethod, Entry, Table};
use rand::Rng;
use rand::distributions::Standard;



#[test]
fn read_write() {
  let mut rng = rand::thread_rng();

  let file1_length = rng.gen_range(20..256);
  let file1_contents = (&mut rng).sample_iter(Standard)
    .take(file1_length).collect::<Vec<u8>>();

  let file2_length = rng.gen_range(20..256);
  let file2_contents = (&mut rng).sample_iter(Standard)
    .take(file2_length).collect::<Vec<u8>>();

  let file3_length = rng.gen_range(20..256);
  let file3_contents = (&mut rng).sample_iter(Standard)
    .take(file3_length).collect::<Vec<u8>>();

  let entries = [
    ("file1.txt", &file1_contents[..]),
    ("file2.txt", &file2_contents[..]),
    ("folder/empty.txt", &[]),
    ("folder/file3.txt", &file3_contents[..]),
  ];

  let (archive_contents, original_archive) = {
    let mut buffer = Vec::new();
    let original_archive = Archive::create(&mut buffer, entries)
      .expect("failed to create archive");
    (buffer, original_archive)
  };

  let archive = Archive::new(Cursor::new(&archive_contents))
    .expect("failed to parse archive");
  assert_eq!(original_archive, archive);

  for (path, expected_contents) in entries {
    let entry = archive.entry(path).expect("failed to get entry");
    assert_eq!(entry.size, entry.uncompressed_size);
    assert_eq!(entry.compression_method, CompressionMethod::Store);

    let contents = &archive_contents[entry.range()];
    assert_eq!(contents, expected_contents, "contents mismatch");

    let mut contents_buffer = Vec::new();
    let bytes_read = entry
      .reader(Cursor::new(&archive_contents)).expect("failed to create reader entry")
      .read_to_end(&mut contents_buffer).expect("failed to read entry");
    assert_eq!(bytes_read as u64, entry.uncompressed_size);
    assert_eq!(contents_buffer, expected_contents, "contents mismatch");
  };
}

#[test]
fn read_write_compression() {
  let entries: [(&str, Compression, &[u8]); 4] = [
    ("file1.txt", Compression::Deflate(4), &[b'1'; 128]),
    ("file2.txt", Compression::Deflate(4), &[b'2'; 128]),
    ("folder/empty.txt", Compression::BZip2(7), &[]),
    ("folder/file3.txt", Compression::BZip2(7), &[b'3'; 128]),
  ];

  let (archive_contents, original_archive) = {
    let mut buffer = Vec::new();
    let original_archive = Archive::create(&mut buffer, entries)
      .expect("failed to create archive");
    (buffer, original_archive)
  };

  let archive = Archive::new(Cursor::new(&archive_contents))
    .expect("failed to parse archive");
  assert_eq!(original_archive, archive);

  for (path, compression, expected_contents) in entries {
    let entry = archive.entry(path).expect("failed to get entry");
    assert_eq!(entry.compression_method, compression.into());

    let mut contents_buffer = Vec::new();
    let bytes_read = entry
      .reader(Cursor::new(&archive_contents)).expect("failed to create reader entry")
      .read_to_end(&mut contents_buffer).expect("failed to read entry");
    assert_eq!(bytes_read as u64, entry.uncompressed_size);
    assert_eq!(contents_buffer, expected_contents, "contents mismatch");
  };
}

#[test]
fn prevent_zip_bomb() {
  let entry = Entry {
    offset: 4,
    size: 1024,
    uncompressed_size: 1024,
    compression_method: CompressionMethod::Store,
    path: "file.txt".to_owned()
  };

  let malicious_contents = std::iter::repeat(entry.clone())
    .take(16).enumerate()
    .map(|(i, entry)| (i.to_string(), entry))
    .collect();
  let malicious_table = Table { contents: malicious_contents };

  assert!(!malicious_table.validate_entry_windows());

  let safe_contents = std::iter::once(("safe.txt".to_owned(), entry)).collect();
  let safe_table = Table { contents: safe_contents };

  assert!(safe_table.validate_entry_windows());
}
