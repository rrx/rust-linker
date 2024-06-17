pub(crate) mod blocks;
pub(crate) mod disassemble;
pub(crate) mod dynamic_linker;
pub(crate) mod libraries;
pub(crate) mod memory;
pub(crate) mod process_maps;
pub(crate) mod relocations;
pub(crate) mod segment;
pub(crate) mod table;
pub(crate) mod version;

pub use blocks::*;
pub use disassemble::*;
pub use dynamic_linker::*;
pub use libraries::*;
pub use memory::*;
pub use process_maps::*;
pub use relocations::*;
pub use segment::*;
pub use table::*;
pub use version::*;

use std::fmt;

#[derive(Debug)]
pub enum LinkError {
    NotFound,
    MissingSymbol,
    SymbolNotFound,
}
impl std::error::Error for LinkError {}
impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LinkError: {:?}", &self)
    }
}
