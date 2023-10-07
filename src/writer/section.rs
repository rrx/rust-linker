use object::elf;
use object::write::elf::{SectionIndex, Writer};
use object::write::StringId;
use std::collections::HashMap;

use super::*;

#[derive(Debug, Clone)]
pub struct ProgSymbol {
    pub name_id: Option<StringId>,
    pub section_index: Option<SectionIndex>,
    pub base: usize,
    pub s: CodeSymbol,
}

impl ProgSymbol {
    pub fn new_object(name: &str, section_index: Option<SectionIndex>) -> Self {
        Self {
            name_id: None,
            section_index,
            base: 0,
            s: CodeSymbol {
                name: name.to_string(),
                size: 0,
                address: 0,
                kind: CodeSymbolKind::Data,
                def: CodeSymbolDefinition::Defined,
                st_info: 0,
                st_other: 0,
            },
        }
    }

    pub fn get_symbol(&self) -> object::write::elf::Sym {
        let st_shndx = elf::SHN_ABS;
        let st_size = self.s.size;
        let addr = self.s.address;
        object::write::elf::Sym {
            name: self.name_id,
            section: self.section_index,
            st_info: self.s.st_info,
            st_other: self.s.st_other,
            st_shndx,
            st_value: addr,
            st_size,
        }
    }

    pub fn write_symbol(&self, _: &mut Writer) {
        //let sym = self.get_symbol();
        //w.write_symbol(&sym);
    }
}

pub struct ProgSectionBuilder {}

pub struct ProgSection {
    pub name: Option<String>,
    pub name_id: Option<StringId>,
    pub index: Option<SectionIndex>,
    pub kind: AllocSegment,
    pub base: usize,
    pub addr: usize,
    pub data_count: usize,
    pub file_offset: usize,     // file offset
    pub rel_file_offset: usize, // file offset
    pub mem_size: usize,        // might be different than file size
    pub symbols: HashMap<String, ProgSymbol>,
    pub externs: HashMap<String, ProgSymbol>,
    pub relocations: Vec<CodeRelocation>,
    pub bytes: Vec<u8>,
}

impl ProgSection {
    pub fn new(
        kind: AllocSegment,
        name: Option<String>,
        name_id: Option<StringId>,
        mem_size: usize,
    ) -> Self {
        Self {
            name,
            name_id,
            index: None,
            kind,
            addr: 0,
            base: 0,
            file_offset: 0,
            rel_file_offset: 0,
            mem_size,
            data_count: 0,
            symbols: HashMap::new(),
            externs: HashMap::new(),
            relocations: vec![],
            bytes: vec![],
        }
    }

    pub fn size(&self) -> usize {
        if self.bytes.len() == 0 {
            self.mem_size as usize
        } else {
            self.bytes.len()
        }
    }

    pub fn update_segment_base(&mut self, base: usize) {
        self.addr += base;
    }

    pub fn add_bytes(&mut self, bytes: &[u8]) {
        self.file_offset += bytes.len();
        self.mem_size += bytes.len();
        self.bytes.extend(bytes.to_vec());
    }

    pub fn append<'a>(&mut self, unlinked: &'a UnlinkedCodeSegment, w: &mut Writer<'a>) {
        self.bytes.extend(unlinked.bytes.clone());
        for r in &unlinked.relocations {
            let mut r = r.clone();
            eprintln!("relocation before: {}", &r);
            r.offset += self.data_count as u64;
            eprintln!("relocation after: {}", &r);
            self.relocations.push(r.clone());
        }

        for (name, symbol) in unlinked.externs.iter() {
            let name_id = Some(w.add_string(name.as_bytes()));
            let mut symbol = symbol.clone();
            symbol.address += self.base as u64 + self.addr as u64 + self.data_count as u64;
            let ps = ProgSymbol {
                name_id,
                section_index: None,
                base: 0,
                s: symbol,
            };
            eprintln!("symbol extern: {}, {:#0x}", &name, &ps.s.address);
            self.externs.insert(name.clone(), ps);
        }

        for (name, symbol) in unlinked.defined.iter() {
            let name_id = Some(w.add_string(name.as_bytes()));
            let mut symbol = symbol.clone();
            symbol.address += self.base as u64 + self.addr as u64 + self.data_count as u64;
            let ps = ProgSymbol {
                name_id,
                section_index: None,
                base: 0,
                s: symbol,
            };
            eprintln!("symbol: {}, {:#0x}", &name, &ps.s.address);
            self.symbols.insert(name.clone(), ps);
        }
        self.data_count += unlinked.bytes.len();
    }

    pub fn disassemble_code(&self) {
        let buf = &self.bytes.as_slice()[0..self.size()];
        use capstone::prelude::*;
        let cs = capstone::Capstone::new()
            .x86()
            .mode(arch::x86::ArchMode::Mode64)
            .syntax(arch::x86::ArchSyntax::Att)
            .detail(true)
            .build()
            .unwrap();
        let insts = cs.disasm_all(&buf, 0).expect("disassemble");
        for instr in insts.as_ref() {
            let addr = instr.address() as usize;
            eprintln!(
                "  {:#06x} {}\t\t{}",
                &addr,
                instr.mnemonic().expect("no mnmemonic found"),
                instr.op_str().expect("no op_str found")
            );
        }
    }

    pub fn unapplied_relocations(
        &self,
        symbols: &HashMap<String, ProgSymbol>,
        externs: &HashMap<String, ProgSymbol>,
    ) -> Vec<(ProgSymbol, CodeRelocation)> {
        let mut unapplied = vec![];
        for r in self.relocations.iter() {
            if let Some(symbol) = externs.get(&r.name) {
                if !symbols.contains_key(&r.name) && externs.contains_key(&r.name) {
                    unapplied.push((symbol.clone(), r.clone()));
                }
            }
        }
        unapplied
    }
}

/*
impl ElfBlock for ProgSection {
    fn alloc(&self) -> Option<AllocSegment> {
        Some(self.kind)
    }

    fn reserve_section_index(&mut self, _data: &mut Data, w: &mut Writer) {
        self.index = Some(w.reserve_section_index());
    }

    fn reserve(&mut self, _data: &mut Data, tracker: &mut SegmentTracker, w: &mut Writer) {
        let pos = w.reserved_len();
        let align_pos = size_align(pos, self.kind.align());
        w.reserve_until(align_pos);
        let start = w.reserved_len();

        w.reserve(self.bytes.len(), self.kind.align());
        let after = w.reserved_len();
        self.file_offset = start;

        // this will be updated later when segments are aligned
        let delta = after - pos;

        self.base = tracker.add_data(self.alloc().unwrap(), delta, self.file_offset);
        self.addr = self.base + self.file_offset;
        eprintln!(
            "reserve: {:?}, {:#0x}/{:#0x}/{:#0x}",
            self.alloc(),
            self.addr,
            self.file_offset,
            self.bytes.len()
        );
    }

    //fn update(&mut self, _data: &mut Data) {}

    fn write(&self, _data: &Data, _tracker: &mut SegmentTracker, w: &mut Writer) {
        let pos = w.len();
        let aligned_pos = size_align(pos, self.kind.align());
        w.pad_until(aligned_pos);
        let before = w.len();
        w.write(self.bytes.as_slice());
        let after = w.len();
        eprintln!(
            "write: {:?}, {:#0x}/{:#0x}/{:#0x}",
            self.alloc(),
            before,
            after,
            self.bytes.len()
        );
    }

    fn write_section_header(&self, _data: &Data, _tracker: &SegmentTracker, w: &mut Writer) {
        if let Some(name_id) = self.name_id {
            w.write_section_header(&object::write::elf::SectionHeader {
                name: Some(name_id),
                sh_type: elf::SHT_PROGBITS,
                sh_flags: self.kind.section_header_flags() as u64,
                sh_addr: self.addr as u64,
                sh_offset: self.file_offset as u64,
                sh_info: 0,
                sh_link: 0,
                sh_entsize: 0,
                sh_addralign: self.kind.align() as u64,
                sh_size: self.size() as u64,
            });
        }
    }
}
*/
