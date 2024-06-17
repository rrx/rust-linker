use super::*;
use crate::format::{disassemble_code, eprint_bytes};
use itertools::Itertools;
use std::collections::HashMap;

#[derive(PartialOrd, Ord, PartialEq, Eq)]
struct SymbolEntry {
    ptr: usize,
    name: String,
}

impl PatchBlock {
    pub fn disassemble(&self) {
        match self.kind {
            PatchBlockKind::Code => {
                let base = self.block.as_ptr() as u64;
                eprintln!(
                    "Code Block Disassemble: Base: {:#08x}, Name: {}",
                    base, &self.name
                );
                let mut pointers = HashMap::new();

                self.symbols
                    .iter()
                    .map(|(name, ptr)| SymbolEntry {
                        name: name.clone(),
                        ptr: ptr.as_ptr() as usize,
                    })
                    .sorted()
                    .for_each(|e| {
                        eprintln!(" {:#08x}: {}", e.ptr as usize, e.name);
                    });

                for (name, ptr) in self.symbols.iter() {
                    pointers.insert(name.clone(), ptr.as_ptr() as u64 - base);
                }
                for r in &self.relocations {
                    eprintln!(" {}", &r);
                }
                let size = self.block.size;
                let buf = &self.block.as_slice()[0..size];
                disassemble_code(buf, &pointers);
            }

            PatchBlockKind::Data | PatchBlockKind::DataRO => {
                let _base = self.block.as_ptr() as usize;
                eprint_bytes(&self.block.as_slice()[0..self.block.size]);
                let mut pointers = im::HashMap::new();
                let base = self.block.as_ptr() as usize;
                eprintln!(
                    "Data Block Disassemble: Base: {:#08x}, Name: {}",
                    base, &self.name
                );
                eprintln!("data_rw@{:#08x}+{:#x}", base, self.block.size);

                self.symbols
                    .iter()
                    .map(|(name, ptr)| SymbolEntry {
                        name: name.clone(),
                        ptr: ptr.as_ptr() as usize,
                    })
                    .sorted()
                    .for_each(|e| unsafe {
                        let value = std::ptr::read(e.ptr as *const u64);
                        eprintln!(
                            " {:#08x}, Offset: {:#08x}, Value: {:#08x} {}",
                            e.ptr as usize,
                            e.ptr as usize - base,
                            value,
                            &e.name
                        )
                    });

                for (name, ptr_ref) in &self.symbols {
                    let ptr = ptr_ref.as_ptr();
                    pointers.insert(ptr as usize - base, name.clone());
                }
                let size = self.block.size;
                let buf = &self.block.as_slice()[0..size];
                println!(" buf: {:?}", buf);
            }
        }
    }
}
