pub(crate) mod block_section;
pub(crate) mod blocks;
pub(crate) mod config;
pub(crate) mod data;
pub(crate) mod disassemble;
pub(crate) mod dynamics;
pub(crate) mod reader;
pub(crate) mod relocations;
pub(crate) mod segments;
pub(crate) mod statics;
pub(crate) mod target;
pub(crate) mod utils;

pub use block_section::*;
pub use blocks::*;
pub use config::*;
pub use data::*;
pub use disassemble::*;
pub use dynamics::*;
pub use reader::*;
pub use relocations::*;
pub use segments::*;
pub use statics::*;
pub use target::*;
pub use utils::*;

use object::elf;
use object::write::elf::Sym;
use object::write::elf::{SectionIndex, SymbolIndex, Writer};
use object::write::StringId;
use object::Endianness;
use object::SymbolKind;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::path::Path;

use crate::format::*;

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
    //pub(crate) name: String,
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

/*
pub enum SymbolPointer {
    RX(usize),
    RO(usize),
    RW(usize),
    Bss(usize),
    Got(usize),
    GotPlt(usize),
}
*/

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

fn gen_dynamic(data: &Data, config: &AOTConfig) -> Vec<Dynamic> {
    let mut out = vec![];
    for lib in data.libs.iter() {
        out.push(Dynamic {
            tag: elf::DT_NEEDED,
            val: 0,
            string: lib.string_id,
        });
    }
    out.push(Dynamic {
        tag: elf::DT_HASH,
        val: data.hash.addr.unwrap(),
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_STRTAB,
        val: data.dynstr.addr.unwrap(),
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_SYMTAB,
        val: data.dynsym.addr.unwrap(),
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_STRSZ,
        val: data.dynstr.size.unwrap() as u64,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_SYMENT,
        val: config.symbol_size() as u64,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_DEBUG,
        val: 0,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_PLTGOT,
        val: *data
            .addr
            .get(&AddressKey::Section(".got.plt".to_string()))
            .unwrap_or(&0),
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_PLTRELSZ,
        val: data.relaplt.size.unwrap() as u64,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_PLTREL,
        val: 7,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_JMPREL,
        val: data.addr_get(".rela.plt"),
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_RELA,
        val: data.addr_get(".rela.dyn"),
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_RELASZ,
        val: data.reladyn.size.unwrap() as u64,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_RELAENT,
        val: config.rel_size(true) as u64,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_NULL,
        val: 0,
        string: None,
    });
    out
}

#[cfg(test)]
mod tests {
    use test_log::test;

    #[test]
    fn write_empty_main() {}
}
