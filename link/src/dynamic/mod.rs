pub mod blocks;
pub mod disassemble;
pub mod dynamic_linker;
pub mod libraries;
pub mod memory;
pub mod process_maps;
pub mod relocations;
pub mod segment;
mod table;
pub mod version;

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
