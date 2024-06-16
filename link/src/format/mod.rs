pub(crate) mod disassemble;
pub(crate) mod relocations;

pub use disassemble::*;
pub use relocations::*;

use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub enum CodeSymbolDefinition {
    Extern,
    Defined,
    Local,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CodeSymbolKind {
    Text,
    Data,
    Section,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct CodeSymbol {
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) address: u64,
    pub(crate) kind: CodeSymbolKind,
    pub(crate) def: CodeSymbolDefinition,
    pub(crate) st_info: u8,
    pub(crate) st_other: u8,
}

impl fmt::Display for CodeSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Symbol addr: {:6}, size: {:6}, kind: {:?}, def: {:?}: {}",
            self.address, self.size, self.kind, self.def, self.name
        )
    }
}
