use super::*;
use crate::format::{disassemble_code, eprint_bytes};
use std::collections::HashMap;

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
                for (name, ptr) in &self.symbols {
                    eprintln!(" {:#08x}: {}", ptr.as_ptr() as usize, name);
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
                for (name, ptr_ref) in &self.symbols {
                    let ptr = ptr_ref.as_ptr();
                    pointers.insert(ptr as usize - base, name.clone());
                    unsafe {
                        let value = std::ptr::read(ptr as *const u64);
                        eprintln!(
                            " {:#08x}, Offset: {:#08x}, Value: {:#08x} {}",
                            ptr as usize,
                            ptr as usize - base,
                            value,
                            &name
                        )
                    }
                }
                let size = self.block.size;
                let buf = &self.block.as_slice()[0..size];
                println!(" buf: {:?}", buf);
            }
        }
    }
}
