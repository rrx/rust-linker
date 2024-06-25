use super::*;
use crate::format::*;
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

pub fn patch_code(
    block: PatchBlock,
    pointers: PatchSymbolPointers,
    _got: TableVersion,
    _plt: TableVersion,
) -> PatchBlock {
    log::debug!(
        "patching code {} at base {:#08x}",
        &block.name,
        block.block.as_ptr() as usize
    );

    for r in &block.relocations {
        let patch_base = block.block.as_ptr();
        let addr = pointers
            .get(&r.name)
            .expect(&format!("missing symbol: {}", &r.name))
            .as_ptr() as *const u8;
        log::debug!(
            "r ptr: {:#08x}:{:#08x}: {}",
            patch_base as usize,
            addr as usize,
            &r.name
        );

        r.patch_dynamic(patch_base as *mut u8, patch_base as *mut u8, addr);
    }

    block
}

pub fn patch_data(
    block: PatchBlock,
    pointers: PatchSymbolPointers,
    got: TableVersion,
    _plt: TableVersion,
) -> PatchBlock {
    log::debug!(
        "patching data {} at base {:#08x}",
        &block.name,
        block.block.as_ptr() as usize
    );

    for r in &block.relocations {
        let patch_base = block.block.as_ptr();
        let addr = match r.effect() {
            PatchEffect::AddToGot => got.get(&r.name).unwrap().as_ptr(),
            _ => {
                if let Some(p) = pointers.get(&r.name) {
                    p.as_ptr() as *const u8
                } else if let Some(p) = block.internal.get(&r.name) {
                    p.as_ptr() as *const u8
                } else {
                    unreachable!("symbol not found:{}", &r.name)
                }
            }
        };

        log::debug!(
            "r ptr: {:#08x}:{:#08x}:{:?}:{}",
            patch_base as usize,
            addr as usize,
            r.effect(),
            &r.name
        );

        r.patch_dynamic(patch_base as *mut u8, patch_base as *mut u8, addr);
    }
    block
}
