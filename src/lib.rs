//! # Asset-Archive
//!
//! A fairly generic file archive format with file compression support.
//!
//! This crate's API may differ slightly from other similar crates in that
//! the [`Archive`] does not wrap a reader, as it is really just a list
//! of entries. Instead of wrapping a reader, [`Archive`] only requires
//! you give it the reader when you're either instantiating an archive
//! or when you're trying to read the contents of an entry.
//!
//! This has a few benefits - since the reader and archive wrapper are
//! separate, you don't need access to the [`Archive`] to inspect its
//! entries.
//!
//! # Example
//! ```no_run
//! use std::fs::File;
//! use std::path::Path;
//! use asset_archive::Archive;
//!
//! let mut my_file = File::open("my_archive.arc").unwrap();
//! let my_archive = Archive::new(&mut my_file).unwrap();
//! for entry in my_archive.iter() {
//!   println!("entry: {}", entry.path);
//!   let path = Path::new("./my_archive/").join(&entry.path);
//!   let mut reader = entry.reader(&mut my_file).unwrap();
//!   let mut out_file = File::create(&path).unwrap();
//!   std::io::copy(&mut reader, &mut out_file).unwrap();
//! }
//! ```

use std::error::Error;
use std::path::{Path, PathBuf};
use std::iter::FusedIterator;
use std::convert::Infallible;
use std::collections::BTreeMap;
use std::collections::btree_map::Values as BTreeMapValues;
use std::collections::btree_map::IntoValues as BTreeMapIntoValues;
use std::io::{self, Read, Seek, SeekFrom, Write};

use bincode::Error as BincodeError;
use bincode::config::Options;
use byteorder::{BE, ReadBytesExt, WriteBytesExt};
use bzip2::Compression as BzCompression;
use bzip2::write::BzEncoder;
use bzip2::read::BzDecoder;
use flate2::Compression as DeflateCompression;
use flate2::write::DeflateEncoder;
use flate2::read::DeflateDecoder;
use serde::{Serialize, Deserialize};
use thiserror::Error;



pub const MAGIC_BYTES: [u8; 4] = [0xf5, b'a', b'r', b'c'];

/*
Archive Format
- 4 magic bytes at the beginning identifying the file type
- (the archive body of variable length)
- (the entry table, encoded in big-endian bincode)
- 8 bytes, a big-endian 64-bit int identifying the start of the entry table
- EOF
*/

/// A wrapper with all of the information necessary to extract
/// any desired file(s) from an archive's reader or byte buffer.
#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Archive {
  table: Table
}

impl Archive {
  /// Reads an archive's information from a reader.
  pub fn new<R: Read + Seek>(mut reader: R) -> ArchiveResult<Self> {
    let mut magic_bytes = [0x00; 4];
    reader.read_exact(&mut magic_bytes)?;
    if magic_bytes != MAGIC_BYTES {
      return Err(ArchiveError::MagicBytes(magic_bytes));
    };

    let table_end = reader.seek(SeekFrom::End(-8))?;
    let table_start = reader.read_u64::<BE>()?;
    debug_assert!(table_start < table_end);
    reader.seek(SeekFrom::Start(table_start))?;
    let table_reader = reader.by_ref().take(table_end - table_start);
    let table: Table = bincode::options().with_big_endian()
      .deserialize_from(table_reader)?;

    Ok(Archive { table })
  }

  /// Reads an archive's information from a byte slice.
  pub fn new_from_bytes(bytes: &[u8]) -> ArchiveResult<Self> {
    #[inline]
    fn unexpected_eof() -> io::Error {
      io::Error::new(io::ErrorKind::UnexpectedEof, "failed to fill whole buffer")
    }

    match (&bytes[0..4]).try_into() {
      Ok(MAGIC_BYTES) => (),
      Ok(magic_bytes) => return Err(ArchiveError::MagicBytes(magic_bytes)),
      Err(_) => return Err(unexpected_eof().into())
    };

    let table_end = bytes.len() - 8;
    let table_start = match (&bytes[table_end..]).try_into() {
      Ok(table_start) => u64::from_be_bytes(table_start) as usize,
      Err(_) => return Err(unexpected_eof().into())
    };

    debug_assert!(table_start < table_end);
    let table_bytes = &bytes[table_start..table_end];
    let table: Table = bincode::options().with_big_endian()
      .deserialize(table_bytes)?;

    Ok(Archive { table })
  }

  /// Serializes an archive into the given writer, filling it with the given entries.
  pub fn try_create<W, U, E, I>(mut writer: W, entries: I) -> ArchiveResult<Self, U>
  where
    W: Write,
    U: Error,
    E: EntryWritable,
    I: IntoIterator<Item = ArchiveResult<E, U>>
  {
    writer.write_all(&MAGIC_BYTES)?;
    let mut offset = 4;

    let mut table = Table::new();
    for entry in entries {
      let mut entry = entry?;
      let compression = entry.compression();
      let path = convert_path_with_error(entry.path())
        .map_err(ArchiveError::with_user_error)?;

      let (uncompressed_size, size) = copy_with_compression(entry.contents(), writer.by_ref(), compression)?;

      table.insert(Entry {
        offset,
        size,
        uncompressed_size,
        compression_method: compression.into(),
        path
      });

      offset += size;
    };

    bincode::options().with_big_endian()
      .serialize_into(writer.by_ref(), &table)?;

    writer.write_u64::<BE>(offset)?;

    Ok(Archive { table })
  }

  /// Serializes an archive into the given writer, filling it with the given entries.
  ///
  /// # Example
  /// ```ignore
  /// Archive::create(File::create("archive.arc"), [
  ///   ("file1.txt", file1_contents),
  ///   ("file2.txt", file2_contents),
  ///   ("file3.txt", file3_contents)
  /// ])?;
  /// ```
  pub fn create<W, E, I>(writer: W, entries: I) -> ArchiveResult<Self>
  where
    W: Write,
    E: EntryWritable,
    I: IntoIterator<Item = E>
  {
    Archive::try_create::<W, Infallible, E, _>(writer, entries.into_iter().map(Ok))
  }

  /// Takes a reader and writer, and uses the given modifier function to determine how each entry will be modified.
  /// Returning `None` results in the entry being removed.
  ///
  /// Take care to ensure that the reader and writer are separate or do not refer to the same file, otherwise they
  /// will interfere with each other.
  pub fn modify<R, W, U, E, F>(self, mut reader: R, writer: W, mut f: F) -> ArchiveResult<Self, U>
  where
    R: Read + Seek,
    W: Write,
    U: Error,
    E: EntryWritable,
    F: FnMut(&mut R, Entry) -> ArchiveResult<Option<E>, U>
  {
    Archive::try_create(writer, {
      self.into_iter().filter_map(|entry| {
        f(&mut reader, entry).transpose()
      })
    })
  }

  /// Similar to `modify`, but takes one reader/writer combo, and buffers the contents of it
  /// in memory before constructing the new archive and writing it back.
  pub fn modify_buffered<RW, U, E, F>(self, mut rw: RW, mut f: F) -> ArchiveResult<Self, U>
  where
    RW: Read + Write + Seek,
    U: Error,
    E: EntryWritable,
    F: FnMut(&[u8], Entry) -> ArchiveResult<Option<E>, U>
  {
    let mut buffer = Vec::new();
    rw.read_to_end(&mut buffer)?;
    rw.seek(SeekFrom::Start(0))?;
    Archive::try_create(rw, {
      self.into_iter().filter_map(|entry| {
        f(&buffer, entry).transpose()
      })
    })
  }

  #[inline]
  pub fn entry<P: AsRef<Path>>(&self, path: P) -> Option<&Entry> {
    self.table.get(path)
  }

  #[inline]
  pub fn into_table(self) -> Table {
    self.table
  }

  #[inline]
  pub fn iter(&self) -> ArchiveEntriesIter {
    self.into_iter()
  }
}

impl IntoIterator for Archive {
  type Item = Entry;
  type IntoIter = ArchiveEntriesIntoIter;

  #[inline]
  fn into_iter(self) -> Self::IntoIter {
    ArchiveEntriesIntoIter {
      inner: self.table.contents.into_values()
    }
  }
}

impl<'a> IntoIterator for &'a Archive {
  type Item = &'a Entry;
  type IntoIter = ArchiveEntriesIter<'a>;

  #[inline]
  fn into_iter(self) -> Self::IntoIter {
    ArchiveEntriesIter {
      inner: self.table.contents.values()
    }
  }
}

#[repr(transparent)]
#[derive(Debug)]
pub struct ArchiveEntriesIntoIter {
  inner: BTreeMapIntoValues<String, Entry>
}

impl<'a> Iterator for ArchiveEntriesIntoIter {
  type Item = Entry;

  #[inline]
  fn next(&mut self) -> Option<Self::Item> {
    self.inner.next()
  }

  #[inline]
  fn size_hint(&self) -> (usize, Option<usize>) {
    self.inner.size_hint()
  }

  #[inline]
  fn last(self) -> Option<Self::Item> {
    self.inner.last()
  }
}

impl<'a> DoubleEndedIterator for ArchiveEntriesIntoIter {
  #[inline]
  fn next_back(&mut self) -> Option<Self::Item> {
    self.inner.next_back()
  }
}

impl ExactSizeIterator for ArchiveEntriesIntoIter {
  #[inline]
  fn len(&self) -> usize {
    self.inner.len()
  }
}

impl FusedIterator for ArchiveEntriesIntoIter {}

#[repr(transparent)]
#[derive(Debug, Clone)]
pub struct ArchiveEntriesIter<'a> {
  inner: BTreeMapValues<'a, String, Entry>
}

impl<'a> Iterator for ArchiveEntriesIter<'a> {
  type Item = &'a Entry;

  #[inline]
  fn next(&mut self) -> Option<Self::Item> {
    self.inner.next()
  }

  #[inline]
  fn size_hint(&self) -> (usize, Option<usize>) {
    self.inner.size_hint()
  }

  #[inline]
  fn last(self) -> Option<Self::Item> {
    self.inner.last()
  }
}

impl<'a> DoubleEndedIterator for ArchiveEntriesIter<'a> {
  #[inline]
  fn next_back(&mut self) -> Option<Self::Item> {
    self.inner.next_back()
  }
}

impl ExactSizeIterator for ArchiveEntriesIter<'_> {
  #[inline]
  fn len(&self) -> usize {
    self.inner.len()
  }
}

impl FusedIterator for ArchiveEntriesIter<'_> {}



/// The raw representation of the archive's internal table.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Table {
  pub contents: BTreeMap<String, Entry>
}

impl Table {
  #[inline]
  pub fn new() -> Self {
    Table::default()
  }

  pub fn get<P: AsRef<Path>>(&self, path: P) -> Option<&Entry> {
    let mut path = convert_path(path.as_ref()).ok()?;
    path.make_ascii_lowercase();
    self.contents.get(&path)
  }

  pub fn insert(&mut self, entry: Entry) {
    let path = entry.path.to_ascii_lowercase();
    self.contents.insert(path, entry);
  }
}

/// The raw representation of a file entry within the archive's table.
/// Contains all of the information necessary to obtain the contents of an entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
  pub offset: u64,
  pub size: u64,
  pub uncompressed_size: u64,
  pub compression_method: CompressionMethod,
  pub path: String
}

impl Entry {
  /// Takes a reader of the archive's contents and produces a reader this entry's raw contents.
  #[inline]
  pub fn reader_raw<R: Read + Seek>(&self, mut reader: R) -> ArchiveResult<impl Read> {
    reader.seek(SeekFrom::Start(self.offset))?;
    Ok(reader.take(self.size))
  }

  /// Takes a reader of the archive's contents and produces a reader of
  /// only this entry's contents, performing decompression if necessary.
  pub fn reader<'r, R: Read + Seek + 'r>(&self, reader: R) -> ArchiveResult<Box<dyn Read + 'r>> {
    Ok(self.compression_method.create_decompressing_reader(self.reader_raw(reader)?))
  }

  /// Takes a byte slice of the archive's contents and produces a reader of
  /// only this entry's contents, performing decompression if necessary.
  pub fn reader_from_bytes<'r>(&self, bytes: &'r [u8]) -> Box<dyn Read + 'r> {
    self.compression_method.create_decompressing_reader(&bytes[self.range()])
  }

  /// A range that when used to index a byte slice of the archive's
  /// contents, will produce a subslice of this archive's raw contents.
  #[inline]
  pub fn range(&self) -> std::ops::Range<usize> {
    self.offset as usize..(self.offset + self.size) as usize
  }
}

/// Indicates which compression algorithm to use when decompressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum CompressionMethod {
  Store,
  Deflate,
  BZip2
}

impl CompressionMethod {
  #[inline]
  pub fn with_level(self, level: u32) -> Compression {
    match self {
      CompressionMethod::Store => Compression::Store,
      CompressionMethod::Deflate => Compression::Deflate(level),
      CompressionMethod::BZip2 => Compression::BZip2(level)
    }
  }

  pub fn create_decompressing_reader<'r, R: Read + 'r>(self, reader: R) -> Box<dyn Read + 'r> {
    match self {
      CompressionMethod::Store => Box::new(reader),
      CompressionMethod::Deflate => Box::new(DeflateDecoder::new(reader)),
      CompressionMethod::BZip2 => Box::new(BzDecoder::new(reader))
    }
  }
}

impl Default for CompressionMethod {
  #[inline]
  fn default() -> CompressionMethod {
    CompressionMethod::Store
  }
}

impl From<Compression> for CompressionMethod {
  #[inline]
  fn from(compression: Compression) -> CompressionMethod {
    match compression {
      Compression::Store => CompressionMethod::Store,
      Compression::Deflate(_) => CompressionMethod::Deflate,
      Compression::BZip2(_) => CompressionMethod::BZip2
    }
  }
}

/// Indicates which compression algorithm and what compression level to use when compressing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Compression {
  /// No Compression.
  Store,
  /// Deflate compression. Level must be between 0 and 9.
  Deflate(u32),
  /// BZip2 compression. Level must be between 0 and 9.
  BZip2(u32)
}

impl From<CompressionMethod> for Compression {
  #[inline]
  fn from(method: CompressionMethod) -> Compression {
    match method {
      CompressionMethod::Store => Compression::Store,
      CompressionMethod::Deflate => Compression::Deflate(DeflateCompression::default().level()),
      CompressionMethod::BZip2 => Compression::BZip2(BzCompression::default().level())
    }
  }
}

impl Default for Compression {
  #[inline]
  fn default() -> Compression {
    Compression::Store
  }
}



/// Used to construct an entry and its data when writing an archive.
pub trait EntryWritable {
  fn path(&self) -> &Path;
  fn compression(&self) -> Compression;
  fn contents(&mut self) -> &mut dyn Read;
}

impl<P, C> EntryWritable for (P, Compression, C)
where P: AsRef<Path>, C: Read {
  #[inline]
  fn path(&self) -> &Path {
    self.0.as_ref()
  }

  #[inline]
  fn compression(&self) -> Compression {
    self.1
  }

  #[inline]
  fn contents(&mut self) -> &mut dyn Read {
    &mut self.2
  }
}

impl<P, C> EntryWritable for (P, C)
where P: AsRef<Path>, C: Read {
  #[inline]
  fn path(&self) -> &Path {
    self.0.as_ref()
  }

  #[inline]
  fn compression(&self) -> Compression {
    Compression::Store
  }

  #[inline]
  fn contents(&mut self) -> &mut dyn Read {
    &mut self.1
  }
}



/// An error produced when manupilating an archive.
#[derive(Debug, Error)]
pub enum ArchiveError<U: Error = Infallible> {
  #[error("incorrect magic bytes found")]
  MagicBytes([u8; 4]),
  #[error("{0} ({})", .1.display())]
  InvalidPath(PathError, PathBuf),
  #[error(transparent)]
  IoError(#[from] io::Error),
  #[error(transparent)]
  BincodeError(#[from] BincodeError),
  /// Some methods on [`Archive`][Archive] accept functions that return a user error type,
  /// which will be returned as a [`ArchiveError::UserError`][ArchiveError::UserError] variant.
  #[error(transparent)]
  UserError(U)
}

impl ArchiveError {
  pub fn with_user_error<U: Error>(self) -> ArchiveError<U> {
    match self {
      ArchiveError::MagicBytes(bytes) => ArchiveError::MagicBytes(bytes),
      ArchiveError::InvalidPath(desc, path) => ArchiveError::InvalidPath(desc, path),
      ArchiveError::IoError(error) => ArchiveError::IoError(error),
      ArchiveError::BincodeError(error) => ArchiveError::BincodeError(error),
      ArchiveError::UserError(x) => match x {},
    }
  }
}

impl<U: Error> ArchiveError<U> {
  pub fn separate(self) -> Result<ArchiveError, U> {
    match self {
      ArchiveError::MagicBytes(bytes) => Ok(ArchiveError::MagicBytes(bytes)),
      ArchiveError::InvalidPath(desc, path) => Ok(ArchiveError::InvalidPath(desc, path)),
      ArchiveError::IoError(error) => Ok(ArchiveError::IoError(error)),
      ArchiveError::BincodeError(error) => Ok(ArchiveError::BincodeError(error)),
      ArchiveError::UserError(user_error) => Err(user_error),
    }
  }
}

pub type ArchiveResult<T, U = Infallible> = Result<T, ArchiveError<U>>;



fn copy_with_compression(
  reader: &mut (impl Read + ?Sized),
  writer: &mut (impl Write + ?Sized),
  compression: Compression
) -> io::Result<(u64, u64)> {
  match compression {
    Compression::Store => {
      let size = io::copy(reader, writer)?;
      Ok((size, size))
    },
    Compression::Deflate(level) => {
      let compression = DeflateCompression::new(level);
      let mut writer = DeflateEncoder::new(writer, compression);
      let uncompressed_size = io::copy(reader, &mut writer)?;
      writer.try_finish()?;

      Ok((uncompressed_size, writer.total_out()))
    },
    Compression::BZip2(level) => {
      let compression = BzCompression::new(level);
      let mut writer = BzEncoder::new(writer, compression);
      let uncompressed_size = io::copy(reader, &mut writer)?;
      writer.try_finish()?;

      Ok((uncompressed_size, writer.total_out()))
    }
  }
}



/// Tests whether or not the given path is valid for usage in archives.
///
/// Valid paths meet the following criteria:
/// - Contains no 'parent dir' (`..`) components.
/// - Consists of only ASCII characters between Space (0x20) and Tilde (0x7e),
///   and does not contain any characters that are invalid for Windows paths.
///   (`<`, `>`, `:`, `"`, `|`, `?`, `*`)
/// - Contains no `.` path components.
/// - Is not an empty path or a path to the root directory.
///
/// When creating archives, the following aspects will be normalized:
/// - Any prefix, 'root dir', or 'current dir' components will be removed.
/// - Any trailing separators will be removed.
/// - All separators will be converted to `/`.
pub fn is_valid_path<P: AsRef<Path>>(path: P) -> bool {
  use std::path::Component;

  let mut segments = 0;
  for c in path.as_ref().components() {
    match c {
      Component::RootDir => (),
      Component::Prefix(_) => (),
      Component::CurDir => (),
      Component::ParentDir => return false,
      Component::Normal(s) => {
        let s = match s.to_str() {
          Some(".") | None => return false,
          Some(s) => s
        };

        for ch in s.chars() {
          if !is_valid_path_char(ch) {
            return false;
          };
        };

        segments += 1;
      }
    };
  };

  segments > 0
}

/// Performs all of the following normalizations to the given path, returning a string:
///
/// - Any prefix, 'root dir', or 'current dir' components will be removed.
/// - Any trailing separators will be removed.
/// - All separators will be converted to `/`.
///
/// This function will return an error if the path is invalid according to
/// [`is_valid_path`][is_valid_path].
#[inline]
pub fn normaize_path<P: AsRef<Path>>(path: P) -> Result<String, PathError> {
  convert_path(path.as_ref())
}



#[derive(Debug, Error)]
pub enum PathError {
  #[error("illegal `ParentDir` component")]
  IllegalParrentDirComponent,
  #[error("path contains non-unicode characters")]
  NonUnicodeCharacters,
  #[error("illegal path character: {0}")]
  IllegalCharacter(char),
  #[error("illegal path segment: {0:?}")]
  IllegalPathSegment(String),
  #[error("path is empty")]
  EmptyPath
}

impl PathError {
  #[inline]
  pub fn into_archive_error(self, path: impl Into<PathBuf>) -> ArchiveError {
    ArchiveError::InvalidPath(self, path.into())
  }
}

fn is_valid_path_char(ch: char) -> bool {
  match ch {
    // Disallow any characters prohibited on windows
    '<' | '>' | ':' | '"' | '/' | '\\' | '|' | '?' | '*' => false,
    // Allow any ASCII chars between space (0x20) and tilde (0x7e)
    '\x20'..='\x7e' => true,
    // No other chars are allowed
    _ => false
  }
}

#[inline]
fn convert_path_with_error(path: &Path) -> ArchiveResult<String> {
  match convert_path(path) {
    Ok(valid_path) => Ok(valid_path),
    Err(error) => Err(ArchiveError::InvalidPath(error, path.to_owned()))
  }
}

fn convert_path(path: &Path) -> Result<String, PathError> {
  use std::path::Component;

  let mut buf = String::new();
  let mut has_trailing_slash = false;
  for c in path.components() {
    match c {
      // No prefixes or root '/' chars in archive paths
      Component::RootDir => (),
      Component::Prefix(_) => (),
      // CurDir (`.`) will be treated just like a root directory component
      Component::CurDir => (),
      // ParentDir (`..`) makes no sense in an archive absolute path
      Component::ParentDir => return Err(PathError::IllegalParrentDirComponent),
      Component::Normal(s) => {
        let s = s.to_str().ok_or(PathError::NonUnicodeCharacters)?;

        if s == "." {
          return Err(PathError::IllegalPathSegment(s.to_owned()))
        };

        for ch in s.chars() {
          if is_valid_path_char(ch) {
            buf.push(ch);
          } else {
            return Err(PathError::IllegalCharacter(ch));
          };
        };

        buf.push('/');
        has_trailing_slash = true;
      }
    };
  };

  if buf.is_empty() {
    return Err(PathError::EmptyPath);
  };

  if has_trailing_slash {
    buf.pop();
  };

  debug_assert!(!buf.starts_with('/'));
  debug_assert!(!buf.ends_with('/'));
  debug_assert!(!buf.contains("//"));

  Ok(buf)
}
