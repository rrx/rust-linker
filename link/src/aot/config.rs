use object::elf;
use object::{Architecture, Endianness};
use std::collections::HashSet;
use std::mem;

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
pub enum DebugFlag {
    Relocations,
    Symbols,
    Disassemble,
    HashTables,
}

#[derive(Debug, Clone)]
pub struct AOTConfig {
    pub arch: Architecture,
    pub add_section_headers: bool,
    pub add_symbols: bool,
    pub use_gnuhash: bool,
    pub debug: HashSet<DebugFlag>,
}

impl AOTConfig {
    pub fn new() -> Self {
        Self {
            arch: Architecture::X86_64,
            add_section_headers: true,
            add_symbols: true,
            use_gnuhash: false,
            debug: HashSet::new(),
        }
    }

    pub fn debug_add(&mut self, f: &DebugFlag) {
        self.debug.insert(f.clone());
    }

    pub fn is_64(&self) -> bool {
        use object::AddressSize;
        match self.arch.address_size().unwrap() {
            AddressSize::U8 | AddressSize::U16 | AddressSize::U32 => false,
            AddressSize::U64 => true,
            _ => unimplemented!(),
        }
    }

    pub fn symbol_size(&self) -> usize {
        if self.is_64() {
            mem::size_of::<elf::Sym64<Endianness>>()
        } else {
            mem::size_of::<elf::Sym32<Endianness>>()
        }
    }

    pub fn rel_size(&self, is_rela: bool) -> usize {
        if self.is_64() {
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
