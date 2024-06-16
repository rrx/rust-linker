use super::*;
use crate::format::*;
use crate::writer::*;
use binary_heap_plus::BinaryHeap;
use capstone::prelude::*;

impl GeneralSection {
    pub fn disassemble(&self, data: &Data) {
        eprintln!(
            "Disassemble: {}, {:#0x}, size: {:#0x}",
            self.name,
            self.offsets.address,
            self.size()
        );
        match self.offsets.alloc {
            AllocSegment::RX => self.disassemble_code(data, &self.bytes),
            _ => self.disassemble_data(data),
        }
    }

    fn disassemble_data(&self, _data: &Data) {
        print_bytes(self.bytes.as_slice(), self.offsets.address as usize);
    }

    pub fn disassemble_code(&self, data: &Data, buf: &[u8]) {
        let mut symbols = vec![];
        for (name, p) in data.pointers.iter() {
            let addr = p.resolve(data).unwrap();
            if addr >= self.offsets.address && addr <= (self.offsets.address + self.size as u64) {
                //eprintln!("b: {}, {:#0x}", name, addr);
                symbols.push((name, addr));
            }
        }

        //disassemble_code_with_symbols(self.bytes.as_slice(), &symbols, &self.relocations);
        let mut heap =
            BinaryHeap::from_vec_cmp(symbols.clone(), |a: &(&String, u64), b: &(&String, u64)| {
                b.1.cmp(&a.1)
            });

        let mut r_heap = BinaryHeap::from_vec_cmp(
            self.relocations.clone(),
            |a: &CodeRelocation, b: &CodeRelocation| b.offset.cmp(&a.offset),
        );

        let cs = capstone::Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Att)
            .detail(true)
            .build()
            .unwrap();
        let insts = cs.disasm_all(buf, 0).expect("disassemble");

        for instr in insts.as_ref() {
            let addr = instr.address();
            let abs_addr = instr.address() + self.offsets.address; // as u64;

            while r_heap.len() > 0 {
                let next_reloc_addr = r_heap.peek().unwrap().offset;
                if next_reloc_addr <= addr {
                    let r = r_heap.pop().unwrap();
                    eprintln!("    {}", r);
                    let p0 = if let Some(addr) = data.dynamics.lookup(&r) {
                        addr
                    } else {
                        data.pointers.get(&r.name).unwrap().clone()
                    };
                    let p = p0.resolve(data).unwrap();
                    eprintln!(
                        "    Base: {:#0x}, addr: {:#0x}, offset: {:#0x}, p: {:#0x}, p0: {}",
                        self.offsets.address, addr, r.offset, p, p0
                    );
                } else {
                    break;
                }
            }

            while heap.len() > 0 {
                let next_symbol_addr = heap.peek().unwrap().1;

                if next_symbol_addr <= abs_addr {
                    let symbol = heap.pop().unwrap();
                    eprintln!(" {}: {:#0x}", symbol.0, symbol.1,);
                } else {
                    break;
                }
            }

            eprintln!(
                "  {:#06x} {:#06x} {}\t\t{}",
                instr.address() + self.offsets.address,
                instr.address(),
                instr.mnemonic().expect("no mnmemonic found"),
                instr.op_str().expect("no op_str found")
            );
        }
    }
}
