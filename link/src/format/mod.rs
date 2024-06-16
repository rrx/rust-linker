pub mod disassemble;
pub mod relocations;
pub use disassemble::*;
pub use relocations::*;

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
