use std::error::Error;

use object::elf;
use object::write::elf::Sym;
use object::write::elf::{SectionIndex, SymbolIndex, Writer};
use object::write::StringId;
use object::{Architecture, Endianness};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::mem;

use super::*;

mod blocks;
mod dynamics;
mod section;
mod segments;
mod statics;
mod utils;

pub use blocks::*;
pub use dynamics::*;
pub use section::*;
pub use segments::*;
pub use statics::*;
pub use utils::*;

#[derive(Debug, Clone)]
pub struct ProgramHeaderEntry {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

pub(crate) struct Library {
    pub(crate) name: String,
    pub(crate) string_id: Option<StringId>,
}

struct Dynamic {
    tag: u32,
    // Ignored if `string` is set.
    val: u64,
    string: Option<object::write::StringId>,
}

#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub enum AllocSegment {
    RO,
    RW,
    RX,
    #[default]
    None,
}

impl AllocSegment {
    pub fn section_header_flags(&self) -> u32 {
        match self {
            AllocSegment::RO => elf::SHF_ALLOC,
            AllocSegment::RW => elf::SHF_ALLOC | elf::SHF_WRITE,
            AllocSegment::RX => elf::SHF_ALLOC | elf::SHF_EXECINSTR,
            AllocSegment::None => 0,
        }
    }
    pub fn program_header_flags(&self) -> u32 {
        match self {
            AllocSegment::RO => elf::PF_R,
            AllocSegment::RW => elf::PF_R | elf::PF_W,
            AllocSegment::RX => elf::PF_R | elf::PF_X,
            AllocSegment::None => 0,
        }
    }
}

#[derive(Default)]
pub struct TrackSection {
    pub size: Option<usize>,
    pub addr: Option<u64>,
    pub section_index: Option<SectionIndex>,
}

impl TrackSection {
    /*
        fn new() -> Self {
            Self { size: 0, addr: 0, section_index: None }
        }
    */
}

pub enum SymbolPointer {
    RX(usize),
    RO(usize),
    RW(usize),
    Bss(usize),
    Got(usize),
    GotPlt(usize),
}

#[derive(Debug)]
pub struct DynamicSymbol {
    pub symbol_index: SymbolIndex,
    pub sym: Sym,
}

#[derive(Debug, Clone)]
pub enum ResolvePointer {
    Resolved(u64),
    Section(String, u64),
    Got(usize),
    GotPlt(usize),
    Plt(usize),
    PltGot(usize),
}

impl fmt::Display for ResolvePointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolved(p) => write!(f, "Abs({:#0x})", p),
            Self::Section(name, p) => write!(f, "Section({},{:#0x})", name, p),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl ResolvePointer {
    pub fn relocate(self, base: u64) -> Self {
        match self {
            Self::Section(section_name, offset) => Self::Section(section_name, offset + base),
            Self::Resolved(address) => Self::Resolved(address + base),
            _ => unimplemented!("{:?}", self),
        }
    }

    pub fn resolve(&self, data: &Data) -> Option<u64> {
        //eprintln!("X: {:?}", self);
        //eprintln!("X: {:?}", &data.addr);
        match self {
            Self::Resolved(x) => Some(*x),
            Self::Section(section_name, offset) => {
                if let Some(base) = data
                    .addr
                    .get(&AddressKey::Section(section_name.to_string()))
                {
                    Some(base + offset)
                } else {
                    None
                }
            }

            Self::Got(index) => {
                if let Some(base) = data.addr_get_by_name(".got") {
                    let size = std::mem::size_of::<usize>() as u64;
                    Some(base + (*index as u64) * size)
                } else {
                    None
                }
            }

            Self::GotPlt(index) => {
                if let Some(base) = data.addr_get_by_name(".got.plt") {
                    let size = std::mem::size_of::<usize>() as u64;
                    // first 3 entries in the got.plt are already used
                    Some(base + (*index as u64 + 3) * size)
                } else {
                    None
                }
            }

            Self::Plt(index) => {
                if let Some(base) = data.addr_get_by_name(".plt") {
                    // each entry in small model is 0x10 in size
                    let size = 0x10;
                    // skip the stub (+1)
                    Some(base + (*index as u64 + 1) * size)
                } else {
                    None
                }
            }

            Self::PltGot(index) => {
                if let Some(base) = data.addr_get_by_name(".plt.got") {
                    // each entry in small model is 0x8 in size
                    let size = 0x08;
                    Some(base + (*index as u64 * size))
                } else {
                    None
                }
            }
        }
    }
}

#[derive(Eq, Hash, PartialEq, Debug)]
pub enum AddressKey {
    SectionIndex(SectionIndex),
    Section(String),
    PltGot(String),
}

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub enum DebugFlag {
    Relocations,
    Symbols,
    Disassemble,
    HashTables,
}

pub struct Data {
    arch: Architecture,
    interp: String,
    is_64: bool,
    pub(crate) libs: Vec<Library>,
    base: usize,
    pub dynamics: Dynamics,
    pub statics: Statics,
    debug: HashSet<DebugFlag>,
    pub ph: Vec<ProgramHeaderEntry>,

    pub addr: HashMap<AddressKey, u64>,
    pub pointers: HashMap<String, ResolvePointer>,
    pub section_index: HashMap<String, SectionIndex>,
    pub(crate) segments: SegmentTracker,
    dynstr: TrackSection,
    dynsym: TrackSection,
    reladyn: TrackSection,
    relaplt: TrackSection,
    hash: TrackSection,
    symtab: TrackSection,
    section_dynamic: TrackSection,

    add_section_headers: bool,
    add_symbols: bool,
}

impl Data {
    pub fn new(lib_names: Vec<String>) -> Self {
        let libs = lib_names
            .iter()
            .map(|name| Library {
                name: name.clone(),
                string_id: None,
            })
            .collect();
        let base = 0x80000;
        Self {
            arch: Architecture::X86_64,
            is_64: true,
            // default gnu loader
            interp: "/lib64/ld-linux-x86-64.so.2".to_string(),
            libs,
            base,
            ph: vec![],
            addr: HashMap::new(),
            section_index: HashMap::new(),
            segments: SegmentTracker::new(base as u64),
            dynstr: TrackSection::default(),
            dynsym: TrackSection::default(),
            reladyn: TrackSection::default(),
            relaplt: TrackSection::default(),
            hash: TrackSection::default(),
            symtab: TrackSection::default(),
            section_dynamic: TrackSection::default(),
            pointers: HashMap::new(),

            add_section_headers: true,
            add_symbols: true,
            debug: HashSet::new(),

            // Tables
            dynamics: Dynamics::new(),
            statics: Statics::new(),
        }
    }

    pub fn debug_enabled(&self, f: &DebugFlag) -> bool {
        self.debug.contains(f)
    }

    pub fn interp(mut self, interp: String) -> Self {
        self.interp = interp;
        self
    }

    pub fn is_64(&self) -> bool {
        use object::AddressSize;
        match self.arch.address_size().unwrap() {
            AddressSize::U8 | AddressSize::U16 | AddressSize::U32 => false,
            AddressSize::U64 => true,
            _ => unimplemented!(),
        }
    }

    fn is_dynamic(&self) -> bool {
        self.libs.len() > 0
    }

    pub fn pointer_set(&mut self, name: String, p: u64) {
        self.pointers.insert(name, ResolvePointer::Resolved(p));
    }

    pub fn pointer_get(&self, name: &str) -> u64 {
        self.pointers
            .get(name)
            .expect(&format!("Pointer not found: {}", name))
            .resolve(self)
            .expect(&format!("Pointer unresolved: {}", name))
    }

    pub fn addr_get_by_name(&self, name: &str) -> Option<u64> {
        self.addr
            .get(&AddressKey::Section(name.to_string()))
            .cloned()
    }

    pub fn addr_get_by_index(&self, index: SectionIndex) -> Option<u64> {
        self.addr.get(&AddressKey::SectionIndex(index)).cloned()
    }

    pub fn addr_get(&self, name: &str) -> u64 {
        *self
            .addr
            .get(&AddressKey::Section(name.to_string()))
            .expect(&format!("Address not found: {}", name))
    }

    pub fn addr_set(&mut self, name: &str, value: u64) {
        self.addr
            .insert(AddressKey::Section(name.to_string()), value);
    }

    pub fn section_index_get(&self, name: &str) -> SectionIndex {
        *self
            .section_index
            .get(name)
            .expect(&format!("Section Index not found: {}", name))
    }

    pub fn section_index_set(&mut self, name: &str, section_index: SectionIndex) {
        self.section_index.insert(name.to_string(), section_index);
    }

    fn gen_dynamic(&self) -> Vec<Dynamic> {
        let mut out = vec![];
        for lib in self.libs.iter() {
            out.push(Dynamic {
                tag: elf::DT_NEEDED,
                val: 0,
                string: lib.string_id,
            });
        }
        out.push(Dynamic {
            tag: elf::DT_HASH,
            val: self.hash.addr.unwrap(),
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_STRTAB,
            val: self.dynstr.addr.unwrap(),
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_SYMTAB,
            val: self.dynsym.addr.unwrap(),
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_STRSZ,
            val: self.dynstr.size.unwrap() as u64,
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_SYMENT,
            val: self.symbol_size() as u64,
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_DEBUG,
            val: 0,
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_PLTGOT,
            val: *self
                .addr
                .get(&AddressKey::Section(".got.plt".to_string()))
                .unwrap_or(&0),
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_PLTRELSZ,
            val: self.relaplt.size.unwrap() as u64,
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_PLTREL,
            val: 7,
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_JMPREL,
            val: self.addr_get(".rela.plt"),
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_RELA,
            val: self.addr_get(".rela.dyn"),
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_RELASZ,
            val: self.reladyn.size.unwrap() as u64,
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_RELAENT,
            val: self.rel_size(true) as u64,
            string: None,
        });
        out.push(Dynamic {
            tag: elf::DT_NULL,
            val: 0,
            string: None,
        });
        out
    }

    pub fn symbol_size(&self) -> usize {
        if self.is_64 {
            mem::size_of::<elf::Sym64<Endianness>>()
        } else {
            mem::size_of::<elf::Sym32<Endianness>>()
        }
    }

    pub fn rel_size(&self, is_rela: bool) -> usize {
        if self.is_64 {
            if is_rela {
                mem::size_of::<elf::Rela64<Endianness>>()
            } else {
                mem::size_of::<elf::Rel64<Endianness>>()
            }
        } else {
            if is_rela {
                mem::size_of::<elf::Rela32<Endianness>>()
            } else {
                mem::size_of::<elf::Rel32<Endianness>>()
            }
        }
    }
}

pub fn write_file_main<Elf: object::read::elf::FileHeader<Endian = Endianness>>(
    data: &mut Data,
    block: &mut ReadBlock,
    w: &mut Writer,
) -> std::result::Result<(), Box<dyn Error>> {
    block.build_strings(data, w);
    let mut blocks = Blocks::new(data, w);
    blocks.build(data, w, block);
    Ok(())
}

/// align size
pub fn size_align(n: usize, align: usize) -> usize {
    return (n + (align - 1)) & !(align - 1);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use test_log::test;

    #[test]
    fn write_empty_main() {
        let mut b = Link::new();
        b.add_obj_file("test", Path::new("../tmp/empty_main.o"))
            .unwrap();
        //b.write(Path::new("../tmp/out.exe")).unwrap();
    }
}
