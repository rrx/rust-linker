use super::*;
use crate::memory::*;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::sync::Arc;

pub type PatchSymbolPointers = im::HashMap<String, RelocationPointer>;
pub type LinkedSymbolPointers = im::HashMap<String, RelocationPointer>;

#[derive(Clone, Debug)]
pub struct LinkedBlock(pub Arc<PatchBlock>);
impl LinkedBlock {
    pub fn disassemble(&self) {
        let inner = &self.0.as_ref();
        inner.disassemble();
    }
}

#[derive(Debug)]
pub enum PatchBlockKind {
    Code,
    Data,
    DataRO,
}

#[derive(Debug)]
pub struct PatchBlock {
    pub(crate) kind: PatchBlockKind,
    pub(crate) name: String,
    pub(crate) block: Block,
    pub(crate) externs: HashMap<String, RelocationPointer>,
    pub(crate) symbols: HashMap<String, RelocationPointer>,
    pub(crate) internal: HashMap<String, RelocationPointer>,
    pub(crate) relocations: Vec<CodeRelocation>,
}
impl PatchBlock {
    pub fn patch(
        self,
        pointers: PatchSymbolPointers,
        got: TableVersion,
        plt: TableVersion,
    ) -> Result<LinkedBlock, Box<dyn Error>> {
        let block = match self.kind {
            PatchBlockKind::Code => patch_code(self, pointers, got, plt),
            PatchBlockKind::Data | PatchBlockKind::DataRO => patch_data(self, pointers, got, plt),
        };
        block.finalize()
    }

    pub fn finalize(self) -> Result<LinkedBlock, Box<dyn Error>> {
        match self.kind {
            PatchBlockKind::Code => Ok(LinkedBlock(Arc::new(self.make_executable()?))),
            PatchBlockKind::Data => Ok(LinkedBlock(Arc::new(self))),
            PatchBlockKind::DataRO => Ok(LinkedBlock(Arc::new(self))),
        }
    }

    pub fn make_readonly(mut self) -> io::Result<Self> {
        self.block = self.block.make_readonly_block()?;
        Ok(self)
    }

    pub fn make_executable(mut self) -> io::Result<Self> {
        self.block = self.block.make_exec_block()?;
        Ok(self)
    }
}
