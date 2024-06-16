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

#[derive(Debug)]
pub struct DynamicSymbol {
    pub symbol_index: SymbolIndex,
    pub sym: Sym,
}
*/

#[cfg(test)]
mod tests {
    use test_log::test;

    #[test]
    fn write_empty_main() {}
}
