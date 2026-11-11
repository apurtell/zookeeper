// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Readers for the symbol tables of built libraries.
//!
//! The readers cover Mach-O (thin and universal), ELF (32-bit and 64-bit,
//! both byte orders) and `ar` archives of either. They use only safe std
//! code, so they run on any host and read cross-built targets. They read
//! symbol facts only: names, kinds, sizes, binding, visibility, the
//! writability of the section, and the library identity.

use std::collections::{BTreeMap, BTreeSet};

use crate::util::Error;

/// The kind of a defined symbol.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum SymKind {
    /// Code.
    Func,
    /// A data object.
    Data,
    /// An absolute or other symbol.
    Other,
}

impl SymKind {
    /// Returns the golden table spelling.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Func => "func",
            Self::Data => "data",
            Self::Other => "other",
        }
    }
}

/// The file format of a binary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Format {
    /// Mach-O.
    MachO,
    /// ELF.
    Elf,
}

/// One defined global symbol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Symbol {
    /// The C name. The Mach-O leading underscore is removed.
    pub(crate) name: String,
    /// The kind.
    pub(crate) kind: SymKind,
    /// True when the symbol is in a writable section.
    pub(crate) writable: bool,
    /// The recorded size. Mach-O records no size.
    pub(crate) size: Option<u64>,
    /// The distance to the next symbol or to the end of the section. It is
    /// an upper bound of the object size. Only Mach-O has it.
    pub(crate) span: Option<u64>,
    /// The address or the section offset.
    pub(crate) addr: u64,
    /// True for a weak definition.
    pub(crate) weak: bool,
    /// The ELF visibility: 0 default, 1 internal, 2 hidden, 3 protected.
    pub(crate) visibility: u8,
    /// The alignment of the section that holds the symbol, in bytes.
    pub(crate) section_align: u64,
    /// The file offset of the symbol contents, for an object file.
    pub(crate) file_off: Option<u64>,
}

/// The symbol facts of one binary.
#[derive(Clone, Debug)]
pub(crate) struct Binary {
    /// The format.
    pub(crate) format: Format,
    /// True for a shared library.
    pub(crate) shared: bool,
    /// The exported (shared) or global (object) defined symbols, by name.
    pub(crate) symbols: BTreeMap<String, Symbol>,
    /// The undefined symbol references.
    pub(crate) undefined: BTreeSet<String>,
    /// The needed libraries: `DT_NEEDED` or `LC_LOAD_DYLIB`.
    pub(crate) needed: Vec<String>,
    /// The identity: `DT_SONAME` or the `LC_ID_DYLIB` path.
    pub(crate) soname: Option<String>,
    /// The Mach-O current and compatibility versions, as `a.b.c`.
    pub(crate) dylib_versions: Option<(String, String)>,
    /// The Mach-O export trie names, when the binary has a trie.
    pub(crate) trie: Option<BTreeSet<String>>,
    /// The Mach-O minimum OS version, as `a.b.c`.
    pub(crate) minos: Option<String>,
    /// True for a 64-bit file.
    pub(crate) is64: bool,
    /// The Mach-O two-level namespace flag.
    pub(crate) twolevel: Option<bool>,
}

/// A bounds-checked view of the file bytes. `wide` selects the 64-bit
/// layout of the ELF structures that have a word-sized field. The Mach-O
/// and universal readers do not use `wide`, so its value has no effect there.
#[derive(Clone, Copy)]
struct R<'a> {
    b: &'a [u8],
    le: bool,
    wide: bool,
}

impl<'a> R<'a> {
    fn slice(&self, off: u64, len: u64) -> Result<&'a [u8], Error> {
        let start = usize::try_from(off).map_err(|_| trunc())?;
        let len = usize::try_from(len).map_err(|_| trunc())?;
        let end = start.checked_add(len).ok_or_else(trunc)?;
        self.b.get(start..end).ok_or_else(trunc)
    }

    /// Reads the `N` bytes at `base + off`, most significant byte first.
    fn field<const N: usize>(&self, base: u64, off: u64) -> Result<[u8; N], Error> {
        let s = self.slice(add(base, off)?, N as u64)?;
        let mut a = [0_u8; N];
        a.copy_from_slice(s);
        if self.le {
            a.reverse();
        }
        Ok(a)
    }

    fn u8(&self, base: u64, off: u64) -> Result<u8, Error> {
        Ok(u8::from_be_bytes(self.field(base, off)?))
    }

    fn u16(&self, base: u64, off: u64) -> Result<u16, Error> {
        Ok(u16::from_be_bytes(self.field(base, off)?))
    }

    fn u32(&self, base: u64, off: u64) -> Result<u32, Error> {
        Ok(u32::from_be_bytes(self.field(base, off)?))
    }

    fn u64(&self, base: u64, off: u64) -> Result<u64, Error> {
        Ok(u64::from_be_bytes(self.field(base, off)?))
    }

    /// Reads a 32-bit field as a 64-bit value.
    fn w32(&self, base: u64, off: u64) -> Result<u64, Error> {
        self.u32(base, off).map(u64::from)
    }

    /// Reads a word: 64 bits in the wide layout, else 32 bits.
    fn word(&self, base: u64, off: u64) -> Result<u64, Error> {
        if self.wide {
            self.u64(base, off)
        } else {
            self.w32(base, off)
        }
    }

    /// Reads a NUL-terminated string at `off` in the table of `size` bytes
    /// at `base`.
    fn cstr(&self, base: u64, size: u64, off: u64) -> Result<String, Error> {
        let at = add(base, off)?;
        let avail = u64::try_from(self.b.len())
            .map_err(|_| trunc())?
            .saturating_sub(at);
        let s = self.slice(at, size.saturating_sub(off).min(avail))?;
        Ok(until(s, 0))
    }
}

fn trunc() -> Error {
    Error::msg("truncated or malformed binary".to_owned())
}

/// Adds two file offsets.
fn add(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_add(b).ok_or_else(trunc)
}

/// Multiplies two file offsets.
fn mul(a: u64, b: u64) -> Result<u64, Error> {
    a.checked_mul(b).ok_or_else(trunc)
}

/// Returns the text of `s` before the first `stop` byte.
fn until(s: &[u8], stop: u8) -> String {
    String::from_utf8_lossy(s.split(|c| *c == stop).next().unwrap_or_default()).into_owned()
}

/// Returns `name` without one leading underscore.
fn strip_underscore(name: String) -> String {
    name.strip_prefix('_').map_or(name.clone(), str::to_owned)
}

/// Parses a shared library or an object file. `arch` selects the slice of
/// a universal Mach-O file: `aarch64`/`arm64` or `x86_64`.
pub(crate) fn parse(b: &[u8], arch: Option<&str>) -> Result<Binary, Error> {
    match b.get(..4) {
        Some([0xcf, 0xfa, 0xed, 0xfe]) => macho(R {
            b,
            le: true,
            wide: true,
        }),
        Some([0xca, 0xfe, 0xba, 0xbe]) => fat(b, arch),
        Some([0x7f, b'E', b'L', b'F']) => elf(b),
        _ => Err(Error::msg(
            "not a 64-bit Mach-O, universal or ELF file".to_owned(),
        )),
    }
}

/// Selects one slice of a universal Mach-O file.
fn fat(b: &[u8], arch: Option<&str>) -> Result<Binary, Error> {
    let r = R {
        b,
        le: false,
        wide: false,
    };
    let want: u32 = match arch.unwrap_or(std::env::consts::ARCH) {
        "aarch64" | "arm64" => 0x0100_000c,
        "x86_64" => 0x0100_0007,
        other => return Err(Error::msg(format!("unknown architecture {other}"))),
    };
    for i in 0..r.w32(4, 0)? {
        let at = add(8, mul(i, 20)?)?;
        if r.u32(at, 0)? == want {
            let off = r.w32(at, 8)?;
            let size = r.w32(at, 12)?;
            return parse(r.slice(off, size)?, arch);
        }
    }
    Err(Error::msg(
        "the universal file has no slice for the architecture".to_owned(),
    ))
}

/// Formats a packed Mach-O version `xxxx.yy.zz`.
fn macho_version(v: u32) -> String {
    format!("{}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff)
}

impl Binary {
    /// Makes the facts of a binary with no symbols and no identity yet.
    fn new(format: Format, shared: bool, is64: bool, twolevel: Option<bool>) -> Self {
        Self {
            format,
            shared,
            symbols: BTreeMap::new(),
            undefined: BTreeSet::new(),
            needed: Vec::new(),
            soname: None,
            dylib_versions: None,
            trie: None,
            minos: None,
            is64,
            twolevel,
        }
    }
}

/// A Mach-O section.
struct Section {
    addr: u64,
    size: u64,
    offset: u64,
    align: u64,
    code: bool,
    writable: bool,
}

impl Section {
    /// Returns the end address.
    fn end(&self) -> u64 {
        self.addr.saturating_add(self.size)
    }
}

/// Parses a thin 64-bit little-endian Mach-O file.
fn macho(r: R<'_>) -> Result<Binary, Error> {
    const LC_SEGMENT_64: u32 = 0x19;
    const LC_SYMTAB: u32 = 0x2;
    const LC_ID_DYLIB: u32 = 0xd;
    const LC_LOAD_DYLIB: u32 = 0xc;
    const LC_LOAD_WEAK_DYLIB: u32 = 0x8000_0018;
    const LC_REEXPORT_DYLIB: u32 = 0x8000_001f;
    const LC_DYLD_INFO: u32 = 0x22;
    const LC_DYLD_INFO_ONLY: u32 = 0x8000_0022;
    const LC_DYLD_EXPORTS_TRIE: u32 = 0x8000_0033;
    const LC_BUILD_VERSION: u32 = 0x32;
    const MH_DYLIB: u32 = 6;

    const MH_TWOLEVEL: u32 = 0x80;
    let filetype = r.u32(12, 0)?;
    let ncmds = r.u32(16, 0)?;
    let hflags = r.u32(24, 0)?;
    let mut sections: Vec<Section> = Vec::new();
    let mut symtab = None;
    let mut trie_at = None;
    let mut bin = Binary::new(
        Format::MachO,
        filetype == MH_DYLIB,
        true,
        Some(hflags & MH_TWOLEVEL != 0),
    );
    let mut at: u64 = 32;
    for _ in 0..ncmds {
        let cmd = r.u32(at, 0)?;
        let size = r.w32(at, 4)?;
        match cmd {
            LC_SEGMENT_64 => macho_segment(r, at, &mut sections)?,
            LC_SYMTAB => {
                symtab = Some([
                    r.w32(at, 8)?,
                    r.w32(at, 12)?,
                    r.w32(at, 16)?,
                    r.w32(at, 20)?,
                ]);
            }
            LC_ID_DYLIB => {
                bin.soname = Some(dylib_name(r, at, size)?);
                bin.dylib_versions =
                    Some((macho_version(r.u32(at, 16)?), macho_version(r.u32(at, 20)?)));
            }
            LC_LOAD_DYLIB | LC_LOAD_WEAK_DYLIB | LC_REEXPORT_DYLIB => {
                bin.needed.push(dylib_name(r, at, size)?);
            }
            LC_DYLD_INFO | LC_DYLD_INFO_ONLY => trie_at = Some((r.w32(at, 40)?, r.w32(at, 44)?)),
            LC_DYLD_EXPORTS_TRIE => trie_at = Some((r.w32(at, 8)?, r.w32(at, 12)?)),
            LC_BUILD_VERSION => bin.minos = Some(macho_version(r.u32(at, 12)?)),
            _ => {}
        }
        at = add(at, size)?;
    }
    if let Some(tab) = symtab {
        macho_symbols(r, &sections, tab, &mut bin)?;
    }
    if let Some((off, size)) = trie_at.filter(|(_, size)| *size > 0) {
        bin.trie = Some(export_trie(r.slice(off, size)?)?);
    }
    Ok(bin)
}

/// Reads the sections of one `LC_SEGMENT_64` command at `at`.
fn macho_segment(r: R<'_>, at: u64, sections: &mut Vec<Section>) -> Result<(), Error> {
    let initprot = r.u32(at, 60)?;
    let nsects = r.w32(at, 64)?;
    let flags = r.u32(at, 68)?;
    // SG_READ_ONLY marks __DATA_CONST, which dyld makes read-only.
    let writable = initprot & 2 != 0 && flags & 0x10 == 0;
    for i in 0..nsects {
        let s = add(add(at, 72)?, mul(i, 80)?)?;
        let sflags = r.u32(s, 64)?;
        let align_log = r.u32(s, 52)?;
        sections.push(Section {
            addr: r.u64(s, 32)?,
            size: r.u64(s, 40)?,
            offset: r.w32(s, 48)?,
            align: 1_u64.checked_shl(align_log).unwrap_or(0),
            code: sflags & 0x8000_0400 != 0,
            writable,
        });
    }
    Ok(())
}

/// Reads the path of a dylib load command of `size` bytes at `at`.
fn dylib_name(r: R<'_>, at: u64, size: u64) -> Result<String, Error> {
    r.cstr(at, size, r.w32(at, 8)?)
}

/// Returns the distance from `addr` to the next section symbol in
/// `addrs`, or to the end of the section that holds `addr`.
fn macho_span(sections: &[Section], addrs: &[u64], addr: u64) -> Option<u64> {
    let sec = sections.iter().find(|s| addr >= s.addr && addr < s.end())?;
    let end = sec.end();
    let next = addrs
        .iter()
        .copied()
        .find(|a| *a > addr && *a < end)
        .unwrap_or(end);
    Some(next.saturating_sub(addr))
}

/// Reads the Mach-O symbol table `[symoff, nsyms, stroff, strsize]` into
/// `bin`.
fn macho_symbols(
    r: R<'_>,
    sections: &[Section],
    tab: [u64; 4],
    bin: &mut Binary,
) -> Result<(), Error> {
    const N_STAB: u8 = 0xe0;
    const N_PEXT: u8 = 0x10;
    const N_TYPE: u8 = 0x0e;
    const N_EXT: u8 = 0x01;
    const N_UNDF: u8 = 0x0;
    const N_SECT: u8 = 0xe;
    const N_WEAK_DEF: u16 = 0x80;
    let [symoff, nsyms, stroff, strsize] = tab;
    // The address of every section symbol gives the span of each object.
    let mut addrs: Vec<u64> = Vec::new();
    let mut defs = Vec::new();
    for i in 0..nsyms {
        let e = add(symoff, mul(i, 16)?)?;
        let strx = r.w32(e, 0)?;
        let ntype = r.u8(e, 4)?;
        let nsect = r.u8(e, 5)?;
        let ndesc = r.u16(e, 6)?;
        let value = r.u64(e, 8)?;
        if ntype & N_STAB != 0 {
            continue;
        }
        let name = strip_underscore(r.cstr(stroff, strsize, strx)?);
        let ty = ntype & N_TYPE;
        if ty == N_SECT {
            addrs.push(value);
        }
        if ntype & N_EXT == 0 || ntype & N_PEXT != 0 {
            continue;
        }
        let common = ty == N_UNDF && value != 0 && !bin.shared;
        if ty == N_UNDF && !common {
            bin.undefined.insert(name);
            continue;
        }
        let sec = usize::from(nsect)
            .checked_sub(1)
            .and_then(|k| sections.get(k))
            .filter(|_| ty == N_SECT);
        // A common symbol is a tentative data definition.
        let (kind, writable) = match sec {
            _ if common => (SymKind::Data, true),
            Some(s) if s.code => (SymKind::Func, s.writable),
            Some(s) => (SymKind::Data, s.writable),
            None => (SymKind::Other, false),
        };
        defs.push(Symbol {
            name,
            kind,
            writable,
            size: None,
            span: if common {
                Some(value)
            } else {
                (ty != N_SECT).then_some(0)
            },
            addr: value,
            weak: !common && ndesc & N_WEAK_DEF != 0,
            visibility: 0,
            section_align: sec.map_or(1, |s| s.align),
            file_off: sec
                .filter(|s| !bin.shared && s.offset != 0)
                .map(|s| s.offset.saturating_add(value.saturating_sub(s.addr))),
        });
    }
    addrs.sort_unstable();
    addrs.dedup();
    for mut s in defs {
        s.span = s.span.or_else(|| macho_span(sections, &addrs, s.addr));
        bin.symbols.insert(s.name.clone(), s);
    }
    Ok(())
}

/// Reads a ULEB128 value at `*pos` and moves `*pos` after it.
fn uleb(b: &[u8], pos: &mut usize) -> Result<u64, Error> {
    let mut v: u64 = 0;
    let mut shift = 0_u32;
    loop {
        let byte = *b.get(*pos).ok_or_else(trunc)?;
        *pos = pos.checked_add(1).ok_or_else(trunc)?;
        if shift >= 64 {
            return Err(trunc());
        }
        v |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(v);
        }
        shift = shift.saturating_add(7);
    }
}

/// Returns the names in a Mach-O export trie, without the leading underscore.
fn export_trie(t: &[u8]) -> Result<BTreeSet<String>, Error> {
    let mut out = BTreeSet::new();
    let mut stack: Vec<(usize, Vec<u8>)> = vec![(0, Vec::new())];
    let mut visited = BTreeSet::new();
    while let Some((node, prefix)) = stack.pop() {
        if !visited.insert(node) {
            return Err(Error::msg("export trie has a cycle".to_owned()));
        }
        let mut pos = node;
        let term = usize::try_from(uleb(t, &mut pos)?).map_err(|_| trunc())?;
        if term > 0 {
            out.insert(strip_underscore(
                String::from_utf8_lossy(&prefix).into_owned(),
            ));
        }
        pos = pos.checked_add(term).ok_or_else(trunc)?;
        let n = *t.get(pos).ok_or_else(trunc)?;
        pos = pos.checked_add(1).ok_or_else(trunc)?;
        for _ in 0..n {
            let rest = t.get(pos..).ok_or_else(trunc)?;
            let len = rest.iter().position(|c| *c == 0).ok_or_else(trunc)?;
            let mut edge = prefix.clone();
            edge.extend_from_slice(rest.get(..len).ok_or_else(trunc)?);
            pos = pos
                .checked_add(len)
                .and_then(|p| p.checked_add(1))
                .ok_or_else(trunc)?;
            let child = usize::try_from(uleb(t, &mut pos)?).map_err(|_| trunc())?;
            stack.push((child, edge));
        }
    }
    Ok(out)
}

/// An ELF section header.
struct Shdr {
    ty: u32,
    flags: u64,
    offset: u64,
    size: u64,
    link: u32,
    align: u64,
    entsize: u64,
}

impl Shdr {
    /// Returns the section that `link` names: the string table of a symbol
    /// table or of a dynamic section.
    fn linked<'s>(&self, shdrs: &'s [Shdr]) -> Result<&'s Shdr, Error> {
        shdrs
            .get(usize::try_from(self.link).map_err(|_| trunc())?)
            .ok_or_else(trunc)
    }
}

/// Parses an ELF shared library or relocatable object.
fn elf(b: &[u8]) -> Result<Binary, Error> {
    const ET_REL: u16 = 1;
    const ET_DYN: u16 = 3;
    const SHT_SYMTAB: u32 = 2;
    const SHT_DYNSYM: u32 = 11;
    const SHT_DYNAMIC: u32 = 6;
    let wide = match b.get(4) {
        Some(1) => false,
        Some(2) => true,
        _ => return Err(Error::msg("bad ELF class".to_owned())),
    };
    let r = R {
        b,
        le: b.get(5) == Some(&1),
        wide,
    };
    let etype = r.u16(16, 0)?;
    // The offsets of e_shoff, e_shentsize and e_shnum.
    let [shoff, shentsize, shnum] = if wide {
        [0x28, 0x3a, 0x3c]
    } else {
        [0x20, 0x2e, 0x30]
    };
    let shdrs = elf_shdrs(r, r.word(0, shoff)?, r.u16(0, shentsize)?, r.u16(0, shnum)?)?;
    let shared = etype == ET_DYN;
    if !shared && etype != ET_REL {
        return Err(Error::msg(format!(
            "ELF type {etype} is not a shared library or an object"
        )));
    }
    let mut bin = Binary::new(Format::Elf, shared, wide, None);
    let want = if shared { SHT_DYNSYM } else { SHT_SYMTAB };
    for sh in shdrs.iter().filter(|s| s.ty == want) {
        elf_symbols(r, &shdrs, sh, &mut bin)?;
    }
    for sh in shdrs.iter().filter(|s| s.ty == SHT_DYNAMIC) {
        elf_dynamic(r, &shdrs, sh, &mut bin)?;
    }
    Ok(bin)
}

/// Reads the ELF section headers.
fn elf_shdrs(r: R<'_>, shoff: u64, shentsize: u16, shnum: u16) -> Result<Vec<Shdr>, Error> {
    // The offsets of sh_flags, sh_offset, sh_size, sh_link, sh_addralign
    // and sh_entsize.
    let [flags, offset, size, link, align, entsize] = if r.wide {
        [8, 24, 32, 40, 48, 56]
    } else {
        [8, 16, 20, 24, 32, 36]
    };
    let mut shdrs = Vec::new();
    for i in 0..u64::from(shnum) {
        let s = add(shoff, mul(i, u64::from(shentsize))?)?;
        shdrs.push(Shdr {
            ty: r.u32(s, 4)?,
            flags: r.word(s, flags)?,
            offset: r.word(s, offset)?,
            size: r.word(s, size)?,
            link: r.u32(s, link)?,
            align: r.word(s, align)?,
            entsize: r.word(s, entsize)?,
        });
    }
    Ok(shdrs)
}

/// Reads one ELF symbol table into `bin`.
fn elf_symbols(r: R<'_>, shdrs: &[Shdr], sh: &Shdr, bin: &mut Binary) -> Result<(), Error> {
    let shared = bin.shared;
    let strtab = sh.linked(shdrs)?;
    // The entry size and the offsets of st_info, st_other, st_shndx,
    // st_value and st_size.
    let [ent, info_at, other_at, shndx_at, value_at, size_at] = if r.wide {
        [24, 4, 5, 6, 8, 16]
    } else {
        [16, 12, 13, 14, 4, 8]
    };
    let ent = if sh.entsize == 0 { ent } else { sh.entsize };
    let n = sh.size.checked_div(ent).unwrap_or(0);
    for i in 1..n {
        let e = add(sh.offset, mul(i, ent)?)?;
        let name = r.w32(e, 0)?;
        let info = r.u8(e, info_at)?;
        let other = r.u8(e, other_at)?;
        let shndx = r.u16(e, shndx_at)?;
        let value = r.word(e, value_at)?;
        let size = r.word(e, size_at)?;
        let bind = info >> 4;
        if bind == 0 {
            continue;
        }
        let name = r.cstr(strtab.offset, strtab.size, name)?;
        if name.is_empty() {
            continue;
        }
        let vis = other & 3;
        if shndx == 0 {
            bin.undefined.insert(name);
            continue;
        }
        if shared && (vis == 1 || vis == 2) {
            continue;
        }
        let kind = match info & 0xf {
            2 | 10 => SymKind::Func,
            1 | 6 => SymKind::Data,
            _ if shndx == 0xfff2 => SymKind::Data,
            _ => SymKind::Other,
        };
        let sec = shdrs.get(usize::from(shndx)).filter(|_| shndx < 0xff00);
        let writable = sec.is_some_and(|s| s.flags & 1 != 0);
        // SHT_NOBITS sections have no file contents.
        let file_off = sec
            .filter(|s| !shared && s.ty != 8)
            .map(|s| s.offset.saturating_add(value));
        bin.symbols.insert(
            name.clone(),
            Symbol {
                name,
                kind,
                writable: writable || shndx == 0xfff2,
                size: Some(size),
                span: None,
                addr: value,
                weak: bind == 2,
                visibility: vis,
                section_align: sec.map_or(1, |s| s.align.max(1)),
                file_off,
            },
        );
    }
    Ok(())
}

/// Reads one ELF dynamic section into `bin`.
fn elf_dynamic(r: R<'_>, shdrs: &[Shdr], sh: &Shdr, bin: &mut Binary) -> Result<(), Error> {
    let strtab = sh.linked(shdrs)?;
    let (ent, val_at) = if r.wide { (16, 8) } else { (8, 4) };
    for i in 0..sh.size.checked_div(ent).unwrap_or(0) {
        let e = add(sh.offset, mul(i, ent)?)?;
        let tag = r.word(e, 0)?;
        let val = r.word(e, val_at)?;
        match tag {
            0 => break,
            1 => bin.needed.push(r.cstr(strtab.offset, strtab.size, val)?),
            14 => bin.soname = Some(r.cstr(strtab.offset, strtab.size, val)?),
            _ => {}
        }
    }
    Ok(())
}

/// Returns `len` bytes of `b` at `at`.
fn take(b: &[u8], at: usize, len: usize) -> Result<&[u8], Error> {
    at.checked_add(len)
        .and_then(|end| b.get(at..end))
        .ok_or_else(trunc)
}

/// Parses an `ar` archive and returns its object members by name.
pub(crate) fn parse_archive(b: &[u8], arch: Option<&str>) -> Result<Vec<(String, Binary)>, Error> {
    let body = b
        .strip_prefix(b"!<arch>\n")
        .ok_or_else(|| Error::msg("not an ar archive".to_owned()))?;
    let mut out = Vec::new();
    let mut long_names: &[u8] = &[];
    let mut pos = 0_usize;
    while pos < body.len() {
        let hdr = take(body, pos, 60)?;
        let field = |a: usize, z: usize| {
            String::from_utf8_lossy(hdr.get(a..z).unwrap_or_default())
                .trim()
                .to_owned()
        };
        let raw_name = field(0, 16);
        let size: usize = field(48, 58).parse().map_err(|_| trunc())?;
        let data_at = pos.checked_add(60).ok_or_else(trunc)?;
        let data = take(body, data_at, size)?;
        pos = data_at.checked_add(size).ok_or_else(trunc)?;
        // Members start at even offsets.
        pos = pos.saturating_add(pos % 2);
        let (name, content) = if let Some(n) = raw_name.strip_prefix("#1/") {
            // BSD: the name of `n` bytes starts the data.
            let n: usize = n.parse().map_err(|_| trunc())?;
            let (nm, content) = data.split_at_checked(n).ok_or_else(trunc)?;
            (until(nm, 0), content)
        } else if raw_name == "//" {
            long_names = data;
            continue;
        } else if let Some(idx) = raw_name
            .strip_prefix('/')
            .and_then(|s| s.parse::<usize>().ok())
        {
            // GNU: the name is at an offset in the `//` member.
            let rest = long_names.get(idx..).ok_or_else(trunc)?;
            (until(rest, b'\n').trim_end_matches('/').to_owned(), data)
        } else {
            (raw_name.trim_end_matches('/').to_owned(), data)
        };
        if name.is_empty() || name.starts_with("__.SYMDEF") || name == "/SYM64" {
            continue;
        }
        let obj =
            parse(content, arch).map_err(|e| Error::msg(format!("archive member {name}: {e}")))?;
        out.push((name, obj));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put(v: &mut [u8], at: usize, bytes: &[u8]) {
        if let Some(d) = v.get_mut(at..at.saturating_add(bytes.len())) {
            d.copy_from_slice(bytes);
        }
    }

    /// Builds an ELF64 LE shared library with a .dynsym of three symbols.
    fn tiny_elf() -> Vec<u8> {
        let mut v = vec![0_u8; 0x400];
        put(&mut v, 0, &[0x7f, b'E', b'L', b'F', 2, 1, 1]);
        put(&mut v, 16, &3_u16.to_le_bytes());
        put(&mut v, 0x28, &0x100_u64.to_le_bytes());
        put(&mut v, 0x3a, &64_u16.to_le_bytes());
        put(&mut v, 0x3c, &4_u16.to_le_bytes());
        // Section 1: .dynsym at 0x300, 4 entries; section 2: .dynstr at 0x380;
        // section 3: a writable data section.
        let sh = |v: &mut Vec<u8>,
                  i: usize,
                  ty: u32,
                  flags: u64,
                  off: u64,
                  size: u64,
                  link: u32,
                  ent: u64| {
            let s = 0x100_usize.saturating_add(i.saturating_mul(64));
            put(v, s.saturating_add(4), &ty.to_le_bytes());
            put(v, s.saturating_add(8), &flags.to_le_bytes());
            put(v, s.saturating_add(24), &off.to_le_bytes());
            put(v, s.saturating_add(32), &size.to_le_bytes());
            put(v, s.saturating_add(40), &link.to_le_bytes());
            put(v, s.saturating_add(56), &ent.to_le_bytes());
        };
        sh(&mut v, 1, 11, 2, 0x300, 96, 2, 24);
        sh(&mut v, 2, 3, 2, 0x380, 32, 0, 0);
        sh(&mut v, 3, 1, 3, 0, 0, 0, 0);
        put(&mut v, 0x380, b"\0zoo_get\0logLevel\0hidden_fn\0");
        let sym =
            |v: &mut Vec<u8>, i: usize, name: u32, info: u8, other: u8, shndx: u16, size: u64| {
                let e = 0x300_usize.saturating_add(i.saturating_mul(24));
                put(v, e, &name.to_le_bytes());
                put(v, e.saturating_add(4), &[info, other]);
                put(v, e.saturating_add(6), &shndx.to_le_bytes());
                put(v, e.saturating_add(16), &size.to_le_bytes());
            };
        sym(&mut v, 1, 1, 0x12, 0, 3, 40);
        sym(&mut v, 2, 9, 0x11, 0, 3, 4);
        sym(&mut v, 3, 18, 0x12, 2, 3, 8);
        v
    }

    #[test]
    fn elf_dynsym() {
        let b = parse(&tiny_elf(), None);
        let b = b.ok();
        let names: Vec<String> = b.iter().flat_map(|b| b.symbols.keys().cloned()).collect();
        assert_eq!(names, vec!["logLevel".to_owned(), "zoo_get".to_owned()]);
        let ll = b.as_ref().and_then(|b| b.symbols.get("logLevel"));
        assert_eq!(
            ll.map(|s| (s.kind, s.size, s.writable)),
            Some((SymKind::Data, Some(4), true))
        );
    }

    #[test]
    fn trie_walk() {
        // The root has no terminal and one edge "_a" to node 6. Node 6 has a
        // terminal and one edge "b" to node 13. Node 13 has a terminal.
        let t: Vec<u8> = vec![0, 1, b'_', b'a', 0, 6, 2, 0, 1, 1, b'b', 0, 13, 2, 0, 2, 0];
        let names = export_trie(&t).ok();
        let want: BTreeSet<String> = ["a".to_owned(), "ab".to_owned()].into_iter().collect();
        assert_eq!(names, Some(want));
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(b"nope", None).is_err());
        assert!(parse(&[0xcf, 0xfa, 0xed, 0xfe, 0, 0], None).is_err());
        assert!(parse_archive(b"!<arch>\nshort", None).is_err());
    }
}
