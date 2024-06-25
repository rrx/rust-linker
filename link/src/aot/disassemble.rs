use super::*;
use crate::format::*;
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
        self.disassemble_code_start(
            data,
            buf,
            self.offsets.address as usize,
            self.offsets.size as usize,
        );
    }

    pub fn disassemble_code_start(&self, data: &Data, buf: &[u8], start: usize, size: usize) {
        let mut symbols = vec![];
        for (name, s) in data.symbols.iter() {
            if let Some(addr) = s.pointer.resolve(data) {
                if addr as usize >= start && addr as usize <= (start + size) {
                    //eprintln!("b: {}, {:#0x}", name, addr);
                    symbols.push((name, addr as usize));
                }
            }
        }

        let mut heap = BinaryHeap::from_vec_cmp(
            symbols.clone(),
            |a: &(&String, usize), b: &(&String, usize)| b.1.cmp(&a.1),
        );

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
        let insts = cs.disasm_all(buf, start as u64).expect("disassemble");

        for instr in insts.as_ref() {
            let addr = instr.address() as u64 - start as u64;
            let abs_addr = instr.address() as usize; // + start;

            // relocation heap
            while r_heap.len() > 0 {
                let next_reloc_addr = r_heap.peek().unwrap().offset;
                if next_reloc_addr <= addr {
                    let r = r_heap.pop().unwrap();
                    eprintln!("    {}", r);
                    let p0 = if let Some(addr) = data.dynamics.lookup(&r) {
                        addr
                    } else {
                        data.symbols.get(&r.name).unwrap().pointer.clone()
                    };
                    if let Some(p) = p0.resolve(data) {
                        eprintln!(
                            "    Base: {:#0x}, addr: {:#0x}, offset: {:#0x}, p: {:#0x}, p0: {}",
                            start, addr, r.offset, p, p0
                        );
                    }
                } else {
                    break;
                }
            }

            // symbol heap
            while heap.len() > 0 {
                let next_symbol_addr = heap.peek().unwrap().1;

                if next_symbol_addr <= abs_addr {
                    let symbol = heap.pop().unwrap();
                    eprintln!(" {}: {:#0x}", symbol.0, symbol.1,);
                } else {
                    break;
                }
            }

            let cfg = pretty_hex::HexConfig {
                title: false,
                ascii: false,
                width: 16,
                group: 2,
                chunk: 16,
                ..pretty_hex::HexConfig::default()
            };
            let s = pretty_hex::config_hex(&instr.bytes().to_vec(), cfg);

            eprintln!(
                "  {:#06x} {:#06x} {}\t\t{}\t{}",
                instr.address() as usize - start,
                instr.address(),
                instr.mnemonic().expect("no mnmemonic found"),
                instr.op_str().expect("no op_str found"),
                s
            );
        }
    }
}
