use super::*;
use object::elf;
use object::write::elf::{SectionIndex, SymbolIndex, Writer};
use object::write::StringId;
use std::collections::HashMap;

pub trait WriterEx {
    fn reserve_start_section(&mut self, offsets: &SectionOffset) -> usize;
    fn write_start_section(&mut self, offsets: &SectionOffset) -> usize;
}

impl<'a> WriterEx for Writer<'a> {
    fn reserve_start_section(&mut self, offsets: &SectionOffset) -> usize {
        let align = offsets.align as usize;
        let pos = self.reserved_len();
        let align_pos = size_align(pos, align);
        self.reserve_until(align_pos);

        log::debug!(
            "reserve: {:#0x}, {}, {:?}, base: {:#0x}, addr: {:#0x}, align: {:#0x}",
            self.reserved_len(),
            offsets.name,
            offsets.alloc,
            offsets.base,
            offsets.address,
            offsets.align,
        );

        self.reserved_len()
    }

    fn write_start_section(&mut self, offsets: &SectionOffset) -> usize {
        let pos = self.len();
        let aligned_pos = size_align(pos, offsets.align as usize);
        self.pad_until(aligned_pos);

        log::debug!(
            "write: {:#0x}/{:#0x}, {}, {:?}",
            self.len(),
            offsets.file_offset,
            offsets.name,
            offsets.alloc,
        );

        assert_eq!(self.len(), offsets.file_offset as usize);

        self.len()
    }
}

pub trait ElfBlock {
    fn name(&self) -> String;
    fn alloc(&self) -> AllocSegment {
        AllocSegment::None
    }
    fn program_header(&self) -> Vec<ProgramHeaderEntry> {
        vec![]
    }
    fn reserve_section_index(&mut self, _: &mut Data, _: &mut Writer) {}
    fn reserve(&mut self, _: &mut Data, _: &mut Writer) {}
    fn write(&self, _: &Data, _: &mut Writer) {}
    fn write_section_header(&self, _: &Data, _: &mut Writer) {}
}

pub struct FileHeader {
    offsets: SectionOffset,
}

impl Default for FileHeader {
    fn default() -> Self {
        Self {
            offsets: SectionOffset::new("fh".into(), AllocSegment::RO, 0x01),
        }
    }
}

impl ElfBlock for FileHeader {
    fn name(&self) -> String {
        self.offsets.name.clone()
    }

    fn alloc(&self) -> AllocSegment {
        self.offsets.alloc
    }

    fn reserve_section_index(&mut self, _data: &mut Data, w: &mut Writer) {
        let _null_section_index = w.reserve_null_section_index();
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        if w.reserved_len() > 0 {
            panic!("Must start with file header");
        }

        // Start reserving file ranges.
        w.reserve_file_header();
        let size = w.reserved_len();
        self.offsets.size = size as u64;
        let alloc = self.alloc();
        data.segments.add_offsets(alloc, &mut self.offsets); //, w);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize + self.offsets.size as usize,
            w.reserved_len()
        );
    }

    fn write(&self, data: &Data, w: &mut Writer) {
        let start = data
            .symbols
            .get("_start")
            .unwrap()
            .pointer
            .resolve(data)
            .unwrap();
        let e_entry = start;

        w.write_file_header(&object::write::elf::FileHeader {
            os_abi: 0x00,         // SysV
            abi_version: 0,       // ignored on linux
            e_type: elf::ET_EXEC, // ET_EXEC - Executable file
            e_machine: 0x3E,      // AMD x86-64
            e_entry,              // e_entry, normally points to _start
            e_flags: 0,           // e_flags
        })
        .unwrap();
    }

    fn write_section_header(&self, _: &Data, w: &mut Writer) {
        // null section header must be the first written
        w.write_null_section_header();
    }
}

pub struct ProgramHeader {
    //base: usize,
    offsets: SectionOffset,
    ph_count: usize,
}

impl Default for ProgramHeader {
    fn default() -> Self {
        Self {
            ph_count: 0,
            //base: 0,
            offsets: SectionOffset::new("ph".into(), AllocSegment::RO, 0x01),
        }
    }
}

impl ElfBlock for ProgramHeader {
    fn name(&self) -> String {
        self.offsets.name.clone()
    }

    fn alloc(&self) -> AllocSegment {
        self.offsets.alloc
    }

    fn program_header(&self) -> Vec<ProgramHeaderEntry> {
        vec![
            // program header
            ProgramHeaderEntry {
                p_type: elf::PT_PHDR,
                p_flags: elf::PF_R,
                p_offset: self.offsets.file_offset,
                p_vaddr: self.offsets.address,
                p_paddr: self.offsets.address,
                p_filesz: self.offsets.size as u64,
                p_memsz: self.offsets.size as u64,
                p_align: 8,
            },
        ]
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        self.ph_count = data.ph.len();
        let before = w.reserved_len();
        w.reserve_program_headers(self.ph_count as u32);
        let after = w.reserved_len();
        self.offsets.size = (after - before) as u64;

        let alloc = self.alloc();
        let size = self.offsets.size as usize;
        self.offsets.size = size as u64;
        data.segments.add_offsets(alloc, &mut self.offsets);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize + self.offsets.size as usize,
            w.reserved_len()
        );
    }

    fn write(&self, data: &Data, w: &mut Writer) {
        w.write_align_program_headers();

        for ph in data.ph.iter() {
            w.write_program_header(&object::write::elf::ProgramHeader {
                p_type: ph.p_type,
                p_flags: ph.p_flags,
                p_offset: ph.p_offset,
                p_vaddr: ph.p_vaddr,
                p_paddr: ph.p_paddr,
                p_filesz: ph.p_filesz,
                p_memsz: ph.p_memsz,
                p_align: ph.p_align,
            });
        }
        assert_eq!(data.ph.len(), self.ph_count);
    }
}

use std::ffi::CString;
pub struct InterpSection {
    alloc: AllocSegment,
    name_id: Option<StringId>,
    cstr: CString,
    offsets: SectionOffset,
}

impl InterpSection {
    pub fn new(interp: &str) -> Self {
        let interp = interp.as_bytes().to_vec();
        let cstr = std::ffi::CString::new(interp).unwrap();
        Self {
            alloc: AllocSegment::RO,
            cstr,
            name_id: None,
            offsets: SectionOffset::new("interp".into(), AllocSegment::RO, 0x01),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        self.cstr.as_bytes_with_nul()
    }
}

impl ElfBlock for InterpSection {
    fn name(&self) -> String {
        self.offsets.name.clone()
    }
    fn alloc(&self) -> AllocSegment {
        self.offsets.alloc
    }
    fn program_header(&self) -> Vec<ProgramHeaderEntry> {
        let size = self.as_slice().len() as u64;
        vec![ProgramHeaderEntry {
            p_type: elf::PT_INTERP,
            p_flags: self.alloc().program_header_flags(),
            p_offset: self.offsets.file_offset,
            p_vaddr: self.offsets.address,
            p_paddr: self.offsets.address,
            p_filesz: size,
            p_memsz: size,
            p_align: self.offsets.align as u64,
        }]
    }

    fn reserve_section_index(&mut self, _: &mut Data, w: &mut Writer) {
        self.name_id = Some(w.add_section_name(".interp".as_bytes()));
        let _index = w.reserve_section_index();
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        w.reserve_start_section(&self.offsets);
        let size = self.as_slice().len();
        self.offsets.size = size as u64;
        w.reserve(size, 1); //self.offsets.align as usize);
        data.segments.add_offsets(self.alloc(), &mut self.offsets);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize + self.offsets.size as usize,
            w.reserved_len()
        );
    }

    fn write(&self, _: &Data, w: &mut Writer) {
        w.write_start_section(&self.offsets);
        w.write(self.as_slice());
    }

    fn write_section_header(&self, _: &Data, w: &mut Writer) {
        if let Some(name_id) = self.name_id {
            w.write_section_header(&object::write::elf::SectionHeader {
                name: Some(name_id),
                sh_type: elf::SHT_PROGBITS,
                sh_flags: self.alloc.section_header_flags() as u64,
                sh_addr: self.offsets.address,
                sh_offset: self.offsets.file_offset,
                sh_info: 0,
                sh_link: 0,
                sh_entsize: 0,
                sh_addralign: self.offsets.align,
                sh_size: self.as_slice().len() as u64,
            });
        }
    }
}

pub struct DynamicSection {
    index: Option<SectionIndex>,
    offsets: SectionOffset,
    config: AOTConfig,
}
impl DynamicSection {
    pub fn new(config: &AOTConfig) -> Self {
        Self {
            index: None,
            offsets: SectionOffset::new("dynamic".into(), AllocSegment::RW, 0x08),
            config: config.clone(),
        }
    }
}

impl ElfBlock for DynamicSection {
    fn name(&self) -> String {
        self.offsets.name.clone()
    }
    fn alloc(&self) -> AllocSegment {
        self.offsets.alloc
    }

    fn program_header(&self) -> Vec<ProgramHeaderEntry> {
        //program DYNAMIC
        vec![ProgramHeaderEntry {
            p_type: elf::PT_DYNAMIC,
            p_flags: elf::PF_R | elf::PF_W,
            p_offset: self.offsets.file_offset as u64,
            p_vaddr: self.offsets.address,
            p_paddr: self.offsets.address,
            p_filesz: self.offsets.size as u64,
            p_memsz: self.offsets.size as u64,
            p_align: self.offsets.align as u64,
        }]
    }

    fn reserve_section_index(&mut self, data: &mut Data, w: &mut Writer) {
        let index = w.reserve_dynamic_section_index();
        data.section_dynamic.section_index = Some(index);
        data.section_index_set(".dynamic", index);
        self.index = Some(index);
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        let dynamic = gen_dynamic(data, &self.config);
        let file_offset = w.reserve_start_section(&self.offsets);
        w.reserve_dynamic(dynamic.len());
        let after = w.reserved_len();
        let size = after - file_offset;
        self.offsets.size = size as u64;

        data.segments.add_offsets(self.alloc(), &mut self.offsets);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize + self.offsets.size as usize,
            w.reserved_len()
        );
        data.section_dynamic.addr = Some(self.offsets.address);
        let pointer = ResolvePointer::Resolved(self.offsets.address);
        let symbol = ReadSymbol::from_pointer(".dynamic".to_string(), pointer);
        data.symbols.insert(symbol.name.clone(), symbol);
        data.addr_set(".dynamic", self.offsets.address);
    }

    fn write(&self, data: &Data, w: &mut Writer) {
        let dynamic = gen_dynamic(data, &self.config);
        w.write_start_section(&self.offsets);

        // write out dynamic symbols
        for d in dynamic.iter() {
            if let Some(string) = d.string {
                w.write_dynamic_string(d.tag, string);
            } else {
                w.write_dynamic(d.tag, d.val);
            }
        }
    }

    fn write_section_header(&self, _: &Data, w: &mut Writer) {
        w.write_dynamic_section_header(self.offsets.address);
    }
}

pub struct RelaDynSection {
    kind: GotSectionKind,
    name_id: Option<StringId>,
    count: usize,
    offsets: SectionOffset,
    is_rela: bool,
}

impl RelaDynSection {
    pub fn new(kind: GotSectionKind) -> Self {
        let name = format!("reladyn:{:?}", kind);
        Self {
            kind,
            name_id: None,
            count: 0,
            offsets: SectionOffset::new(name, AllocSegment::RO, 0x08),
            is_rela: true,
        }
    }
}

impl ElfBlock for RelaDynSection {
    fn name(&self) -> String {
        self.offsets.name.clone()
    }
    fn alloc(&self) -> AllocSegment {
        self.offsets.alloc
    }

    fn reserve_section_index(&mut self, _: &mut Data, w: &mut Writer) {
        let name = self.kind.rel_section_name();
        self.name_id = Some(w.add_section_name(name.as_bytes()));
        self.offsets.section_index = Some(w.reserve_section_index());
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        let relocations = data.dynamics.relocations(self.kind);

        self.count = relocations.len();
        let file_offset = w.reserve_start_section(&self.offsets);
        w.reserve_relocations(self.count, self.is_rela);

        let after = w.reserved_len();
        let size = after - file_offset;
        self.offsets.size = size as u64;

        data.segments.add_offsets(self.alloc(), &mut self.offsets);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize + self.offsets.size as usize,
            w.reserved_len()
        );
        match self.kind {
            GotSectionKind::GOT => {
                data.addr_set(".rela.dyn", self.offsets.address);
                data.reladyn.size = Some(w.rel_size(self.is_rela) * relocations.len());
            }
            GotSectionKind::GOTPLT => {
                data.addr_set(".rela.plt", self.offsets.address);
                data.relaplt.size = Some(w.rel_size(self.is_rela) * relocations.len());
            }
        }
    }

    fn write(&self, data: &Data, w: &mut Writer) {
        let relocations = data.dynamics.relocations(self.kind);
        w.write_start_section(&self.offsets);
        assert_eq!(self.count, relocations.len());

        // we are writing a relocation for the GOT entries
        for (index, (r, symbol)) in relocations.iter().enumerate() {
            let mut r_addend = 0;
            let mut r_sym = 0;

            // if relative, look up the pointer in statics
            if symbol.is_static() {
                let static_sym = data
                    .statics
                    .symbol_hash
                    .get(&symbol.name)
                    .expect(&format!("not found {}", &symbol.name));
                //r_sym = if let Some(symbol_index) = static_sym.symbol_index {
                //symbol_index.0
                //} else {
                //0
                //};
                //r_sym = 0;

                if let Some(p) = data.statics.symbol_get(&symbol.name) {
                    if let Some(addr) = p.resolve(data) {
                        r_addend = addr as i64;
                    }
                }
            } else {
                // we needed to fork object in order to access .0
                let (symbol_index, _sym) = data
                    .dynamics
                    .symbol_get(&symbol.name, data)
                    .expect(&format!("not found {}", &symbol.name));
                r_sym = symbol_index.0;
                r_addend = 0;
            }

            let r_type = match self.kind {
                GotSectionKind::GOT => {
                    if symbol.is_static() {
                        elf::R_X86_64_RELATIVE
                    } else if r.r.kind() == object::RelocationKind::Absolute {
                        elf::R_X86_64_64
                    } else {
                        elf::R_X86_64_GLOB_DAT
                    }
                }
                GotSectionKind::GOTPLT => elf::R_X86_64_JUMP_SLOT,
            };

            let r_offset = match self.kind {
                GotSectionKind::GOT => {
                    if r.r.kind() == object::RelocationKind::Absolute {
                        let addr = data.addr_get(&r.section_name);
                        addr as usize + r.offset as usize
                    } else {
                        let got_addr = data.addr_get(".got");
                        let got_index = data.dynamics.got_lookup.get(&symbol.name).unwrap();
                        got_addr as usize + got_index * std::mem::size_of::<usize>()
                    }
                }
                GotSectionKind::GOTPLT => {
                    let start = 3;
                    let plt_addr = data.addr_get(".got.plt");
                    plt_addr as usize + (index + start) * std::mem::size_of::<usize>()
                }
            };

            w.write_relocation(
                true,
                &object::write::elf::Rel {
                    r_offset: r_offset as u64,
                    r_sym,
                    r_type,
                    r_addend,
                },
            );
        }
    }

    fn write_section_header(&self, data: &Data, w: &mut Writer) {
        let relocations = data.dynamics.relocations(self.kind);

        let sh_addralign = self.offsets.align;

        let sh_info = match self.kind {
            GotSectionKind::GOT => SectionIndex::default().0,
            GotSectionKind::GOTPLT => data.section_index_get(".got.plt").0,
        };

        let sh_link = data.dynsym.section_index.unwrap().0;
        let sh_entsize = w.rel_size(self.is_rela) as u64;

        let sh_type = if self.is_rela {
            elf::SHT_RELA
        } else {
            elf::SHT_REL
        };

        w.write_section_header(&object::write::elf::SectionHeader {
            name: self.name_id,
            sh_type,
            sh_flags: self.kind.rel_flags().into(),
            sh_addr: self.offsets.address,
            sh_offset: self.offsets.file_offset,
            sh_info,
            sh_link,
            sh_entsize,
            sh_addralign,
            sh_size: sh_entsize * relocations.len() as u64,
        });
    }
}

pub struct StrTabSection {
    offsets: SectionOffset,
}
impl StrTabSection {
    pub fn new() -> Self {
        Self {
            offsets: SectionOffset::new("strtab".into(), AllocSegment::None, 1),
        }
    }
}

impl ElfBlock for StrTabSection {
    fn name(&self) -> String {
        return "strtab".to_string();
    }
    fn reserve_section_index(&mut self, data: &mut Data, w: &mut Writer) {
        let index = w.reserve_strtab_section_index();
        self.offsets.section_index = Some(index);
        data.section_index.insert(".strtab".to_string(), index);
    }

    fn reserve(&mut self, _: &mut Data, w: &mut Writer) {
        self.offsets.file_offset = w.reserve_start_section(&self.offsets) as u64;
        assert!(w.strtab_needed());
        w.reserve_strtab();
    }

    fn write(&self, _: &Data, w: &mut Writer) {
        w.write_start_section(&self.offsets);
        w.write_strtab();
    }

    fn write_section_header(&self, _: &Data, w: &mut Writer) {
        w.write_strtab_section_header();
    }
}

pub struct SymTabSection {
    count: usize,
    offsets: SectionOffset,
}
impl Default for SymTabSection {
    fn default() -> Self {
        Self {
            count: 0,
            offsets: SectionOffset::new("symtab".into(), AllocSegment::None, 0x10),
        }
    }
}

impl ElfBlock for SymTabSection {
    fn name(&self) -> String {
        self.offsets.name.clone()
    }

    fn reserve_section_index(&mut self, data: &mut Data, w: &mut Writer) {
        let index = w.reserve_symtab_section_index();
        self.offsets.section_index = Some(index);
        data.symtab.section_index = Some(index);

        if w.symtab_shndx_needed() {
            w.reserve_symtab_shndx_section_index();
        }
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        self.count = data.statics.symbol_count();
        let symbols = data.statics.gen_symbols(data);

        for (i, x) in symbols.iter().enumerate() {
            log::debug!("static: {}:{:?}", i, x);
        }

        assert_eq!(symbols.len(), self.count);
        assert_eq!(symbols.len() + 1, w.symbol_count() as usize);

        // reserve the symbols in the various sections
        self.offsets.file_offset = w.reserve_start_section(&self.offsets) as u64;

        w.reserve_symtab();

        if w.symtab_shndx_needed() {
            w.reserve_symtab_shndx();
        }
    }

    fn write(&self, data: &Data, w: &mut Writer) {
        assert_eq!(self.count + 1, w.symbol_count() as usize);
        w.write_start_section(&self.offsets);

        data.statics.symbols_write(data, w);

        if w.symtab_shndx_needed() {
            w.write_symtab_shndx();
        }
    }

    fn write_section_header(&self, data: &Data, w: &mut Writer) {
        let symbols = data.statics.gen_symbols(data);
        assert_eq!(symbols.len(), self.count);

        let mut num_locals = 0;

        symbols
            .iter()
            .filter(|s| s.st_info >> 4 == elf::STB_LOCAL)
            .for_each(|_s| {
                num_locals += 1;
            });

        // one greater than the symbol table index of the last
        // local symbol (binding STB_LOCAL)
        w.write_symtab_section_header(num_locals as u32 + 1);
        if w.symtab_shndx_needed() {
            w.write_symtab_shndx_section_header();
        }
    }
}

pub struct DynSymSection {
    offsets: SectionOffset,
    symbol_count: u32,
}
impl Default for DynSymSection {
    fn default() -> Self {
        Self {
            offsets: SectionOffset::new("dynsym".into(), AllocSegment::RO, 0x08),
            symbol_count: 0,
        }
    }
}

impl ElfBlock for DynSymSection {
    fn name(&self) -> String {
        self.offsets.name.clone()
    }

    fn alloc(&self) -> AllocSegment {
        self.offsets.alloc
    }

    fn reserve_section_index(&mut self, data: &mut Data, w: &mut Writer) {
        let index = w.reserve_dynsym_section_index();
        self.offsets.section_index = Some(index);
        data.dynsym.section_index = Some(index);
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        self.symbol_count = w.dynamic_symbol_count();
        let file_offset = w.reserve_start_section(&self.offsets);
        w.reserve_dynsym();
        let after = w.reserved_len();
        let size = after - file_offset;
        self.offsets.size = size as u64;
        data.segments.add_offsets(self.alloc(), &mut self.offsets);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize + self.offsets.size as usize,
            w.reserved_len()
        );
        data.dynsym.addr = Some(self.offsets.address);
        data.dynsym.size = Some(self.offsets.size as usize);
    }

    fn write(&self, data: &Data, w: &mut Writer) {
        assert_eq!(self.symbol_count, w.dynamic_symbol_count());
        assert_eq!(self.symbol_count as usize, data.dynamics.symbol_count() + 1);
        w.write_start_section(&self.offsets);
        data.dynamics.symbols_write(data, w);
    }

    fn write_section_header(&self, data: &Data, w: &mut Writer) {
        // find the number of local symbols, probably 1 (the null symbol)?
        let num_locals = data.dynamics.symbols_local_count();
        /*
         * http://www.skyfree.org/linux/references/ELF_Format.pdf
         * SHT_DYNSYM
         * sh_link: The section header index of the associated string table.
         * sh_info: One greater than the symbol table index of the last local symbol (binding STB_LOCAL).
         */
        w.write_dynsym_section_header(data.dynsym.addr.unwrap(), num_locals as u32);
    }
}

pub struct DynStrSection {
    offsets: SectionOffset,
}
impl Default for DynStrSection {
    fn default() -> Self {
        Self {
            offsets: SectionOffset::new("dynstr".into(), AllocSegment::RO, 0x01),
        }
    }
}
impl ElfBlock for DynStrSection {
    fn name(&self) -> String {
        self.offsets.name.clone()
    }

    fn alloc(&self) -> AllocSegment {
        self.offsets.alloc
    }

    fn reserve_section_index(&mut self, data: &mut Data, w: &mut Writer) {
        let index = w.reserve_dynstr_section_index();
        self.offsets.section_index = Some(index);
        data.dynstr.section_index = Some(index);
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        let file_offset = w.reserve_start_section(&self.offsets);
        w.reserve_dynstr();
        let after = w.reserved_len();
        let size = after - file_offset;
        self.offsets.size = size as u64;
        data.segments.add_offsets(self.alloc(), &mut self.offsets);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize + self.offsets.size as usize,
            w.reserved_len()
        );
        data.dynstr.addr = Some(self.offsets.address);
        data.dynstr.size = Some(self.offsets.size as usize);
    }

    fn write(&self, _: &Data, w: &mut Writer) {
        w.write_start_section(&self.offsets);
        w.write_dynstr();
    }

    fn write_section_header(&self, data: &Data, w: &mut Writer) {
        w.write_dynstr_section_header(data.dynstr.addr.unwrap());
    }
}

pub struct ShStrTabSection {
    offsets: SectionOffset,
}
impl Default for ShStrTabSection {
    fn default() -> Self {
        Self {
            offsets: SectionOffset::new("shstrtab".into(), AllocSegment::RO, 0x01),
        }
    }
}
impl ElfBlock for ShStrTabSection {
    fn name(&self) -> String {
        self.offsets.name.to_string()
    }

    fn alloc(&self) -> AllocSegment {
        self.offsets.alloc
    }

    fn reserve_section_index(&mut self, _data: &mut Data, w: &mut Writer) {
        let index = w.reserve_shstrtab_section_index();
        self.offsets.section_index = Some(index);
    }

    fn reserve(&mut self, _: &mut Data, w: &mut Writer) {
        self.offsets.file_offset = w.reserved_len() as u64;
        w.reserve_shstrtab();
    }

    fn write(&self, _: &Data, w: &mut Writer) {
        assert_eq!(w.len(), self.offsets.file_offset as usize);
        w.write_shstrtab();
    }

    fn write_section_header(&self, _: &Data, w: &mut Writer) {
        w.write_shstrtab_section_header();
    }
}

pub struct HashSection {
    bucket_count: u32,
    offsets: SectionOffset,
}

// ported from libbfd
fn sysv_hash(s: &[u8]) -> u32 {
    0xfffffff
        & s.iter()
            .map(|c| *c as u32)
            .fold(0u32, |mut h: u32, c: u32| {
                h = h.wrapping_mul(16) + c;
                h ^= h >> 24 & 0xf0;
                h
            })
}

/// See: https://flapenguin.me/elf-dt-hash
impl HashSection {
    pub fn new() -> Self {
        Self {
            bucket_count: 2,
            offsets: SectionOffset::new("hash".into(), AllocSegment::RO, 0x08),
        }
    }
}

impl ElfBlock for HashSection {
    fn name(&self) -> String {
        self.offsets.name.clone()
    }
    fn alloc(&self) -> AllocSegment {
        self.offsets.alloc
    }

    fn reserve_section_index(&mut self, _data: &mut Data, w: &mut Writer) {
        self.offsets.section_index = Some(w.reserve_hash_section_index());
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        let chain_count = data.dynamics.symbol_count() as u32;
        let file_offset = w.reserve_start_section(&self.offsets);
        w.reserve_hash(self.bucket_count, chain_count);

        let after = w.reserved_len();
        let size = after - file_offset;
        self.offsets.size = size as u64;
        data.segments.add_offsets(self.alloc(), &mut self.offsets);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize + self.offsets.size as usize,
            w.reserved_len()
        );
        data.hash.addr = Some(self.offsets.address);
    }

    fn write(&self, data: &Data, w: &mut Writer) {
        let chain_count = data.dynamics.symbol_count() as u32;
        w.write_start_section(&self.offsets);
        let mut h = HashMap::new();
        for (name, symbol_index, _p) in data.dynamics.symbols() {
            if let Some(index) = symbol_index {
                h.insert(index, name);
            }
        }

        w.write_hash(self.bucket_count, chain_count, |i| {
            if let Some(name) = h.get(&SymbolIndex(i)) {
                let hash = sysv_hash(name.as_bytes());
                Some(hash)
            } else {
                None
            }
        });
    }

    fn write_section_header(&self, _: &Data, w: &mut Writer) {
        w.write_hash_section_header(self.offsets.address);
    }
}

/// See: https://flapenguin.me/elf-dt-gnu-hash
pub struct GnuHashSection {
    bucket_count: u32,
    chain_count: u32,
    bloom_count: u32,
    offsets: SectionOffset,
}

impl GnuHashSection {
    pub fn new() -> Self {
        Self {
            bucket_count: 10,
            chain_count: 10,
            bloom_count: 10,
            offsets: SectionOffset::new("gnuhash".into(), AllocSegment::RO, 0x08),
        }
    }
}

impl ElfBlock for GnuHashSection {
    fn name(&self) -> String {
        self.offsets.name.clone()
    }
    fn alloc(&self) -> AllocSegment {
        self.offsets.alloc
    }

    fn reserve_section_index(&mut self, _data: &mut Data, w: &mut Writer) {
        self.offsets.section_index = Some(w.reserve_gnu_hash_section_index());
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        self.offsets.file_offset = w.reserve_start_section(&self.offsets) as u64;
        w.reserve_gnu_hash(self.bloom_count, self.bucket_count, self.chain_count);

        let after = w.reserved_len();
        let size = after - self.offsets.file_offset as usize;
        self.offsets.size = size as u64;
        data.segments.add_offsets(self.alloc(), &mut self.offsets);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize + self.offsets.size as usize,
            w.reserved_len()
        );
    }

    fn write(&self, _: &Data, w: &mut Writer) {
        w.write_start_section(&self.offsets);
        w.write_gnu_hash(
            0,
            0,
            self.bloom_count,
            self.bucket_count,
            self.chain_count,
            |x| x,
        );
    }

    fn write_section_header(&self, _: &Data, w: &mut Writer) {
        w.write_gnu_hash_section_header(self.offsets.address);
    }
}

#[derive(Debug, Clone, Copy)]
pub enum GotSectionKind {
    GOT,
    GOTPLT,
}

impl GotSectionKind {
    pub fn section_name(&self) -> &'static str {
        match self {
            Self::GOT => ".got",
            Self::GOTPLT => ".got.plt",
        }
    }

    pub fn rel_section_name(&self) -> &'static str {
        match self {
            Self::GOT => ".rela.dyn",
            Self::GOTPLT => ".rela.plt",
        }
    }

    pub fn rel_flags(&self) -> u32 {
        match self {
            Self::GOT => elf::SHF_ALLOC,
            Self::GOTPLT => elf::SHF_ALLOC | elf::SHF_INFO_LINK,
        }
    }

    pub fn start_index(&self) -> usize {
        match self {
            Self::GOT => 0,
            Self::GOTPLT => 3,
        }
    }

    fn write_entries(&self, data: &Data, w: &mut Writer) {
        match self {
            GotSectionKind::GOT => {
                let bytes = BuildGotSection::contents(data);
                w.write(bytes.as_slice());
            }
            GotSectionKind::GOTPLT => {
                let bytes = BuildGotPltSection::contents(data);
                w.write(bytes.as_slice());
            }
        }
    }
}

pub struct GotSection {
    kind: GotSectionKind,
    section: GeneralSection,
}
impl GotSection {
    pub fn new(kind: GotSectionKind, align: u64) -> Self {
        let name = kind.section_name();
        Self {
            kind,
            section: GeneralSection::new(AllocSegment::RW, name, align),
        }
    }
}

impl ElfBlock for GotSection {
    fn name(&self) -> String {
        self.section.name()
    }
    fn alloc(&self) -> AllocSegment {
        self.section.alloc()
    }

    fn reserve_section_index(&mut self, data: &mut Data, w: &mut Writer) {
        self.section.reserve_section_index(data, w);
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        // each entry in unapplied will be a GOT entry
        let unapplied = data.dynamics.relocations(self.kind);
        let name = self.kind.section_name();

        let len = unapplied.len() + self.kind.start_index();
        let size = len * std::mem::size_of::<usize>();
        let file_offset = w.reserve_start_section(&self.section.offsets);
        self.section.offsets.size = size as u64;
        w.reserve(size, 1);
        let after = w.reserved_len();
        assert_eq!(after - file_offset, size);
        data.segments
            .add_offsets(self.alloc(), &mut self.section.offsets);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize
                + self.section.offsets.size as usize,
            w.reserved_len()
        );
        // update section pointers
        data.addr_set(name, self.section.offsets.address);
    }

    fn write(&self, data: &Data, w: &mut Writer) {
        w.write_start_section(&self.section.offsets);
        self.kind.write_entries(data, w);
    }

    fn write_section_header(&self, _: &Data, w: &mut Writer) {
        let sh_flags = self.alloc().section_header_flags() as u64;
        let sh_addralign = self.section.offsets.align;

        let es = match self.kind {
            GotSectionKind::GOT => 0x08,
            GotSectionKind::GOTPLT => 0x08,
        };

        w.write_section_header(&object::write::elf::SectionHeader {
            name: self.section.name_id,
            sh_type: elf::SHT_PROGBITS,
            sh_flags,
            sh_addr: self.section.offsets.address,
            sh_offset: self.section.offsets.file_offset,
            sh_info: 0,
            sh_link: 0,
            sh_entsize: es,
            sh_addralign,
            sh_size: self.section.offsets.size,
        });
    }
}

pub struct PltSection {
    section: GeneralSection,
}

impl PltSection {
    pub fn new(name: &'static str) -> Self {
        Self {
            section: GeneralSection::new(AllocSegment::RX, name, 0x10),
        }
    }
}

impl ElfBlock for PltSection {
    fn name(&self) -> String {
        self.section.name()
    }
    fn alloc(&self) -> AllocSegment {
        self.section.alloc()
    }

    fn reserve_section_index(&mut self, data: &mut Data, w: &mut Writer) {
        self.section.reserve_section_index(data, w);
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        // length + 1, to account for the stub.  Each entry is 0x10 in size
        let size = BuildPltSection::size(data);
        self.section.bytes.resize(size, 0);
        let align = BuildPltSection::align(data);

        let file_offset = w.reserve_start_section(&self.section.offsets);
        self.section.offsets.size = size as u64;
        w.reserve(self.section.bytes.len(), align);
        let after = w.reserved_len();
        assert_eq!(size, after - file_offset);
        data.segments
            .add_offsets(self.alloc(), &mut self.section.offsets);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize
                + self.section.offsets.size as usize,
            w.reserved_len()
        );

        // update section pointers
        data.addr.insert(
            AddressKey::Section(self.name()),
            self.section.offsets.address,
        );
        data.addr.insert(
            AddressKey::SectionIndex(self.section.section_index.unwrap()),
            self.section.offsets.address,
        );
    }

    fn write(&self, data: &Data, w: &mut Writer) {
        w.write_start_section(&self.section.offsets);
        let stub = BuildPltSection::contents(data, self.section.offsets.address as usize);
        w.write(stub.as_slice());
    }

    fn write_section_header(&self, _data: &Data, w: &mut Writer) {
        w.write_section_header(&object::write::elf::SectionHeader {
            name: self.section.name_id,
            sh_type: object::elf::SHT_PROGBITS,
            sh_flags: self.section.offsets.alloc.section_header_flags() as u64,
            sh_addr: self.section.offsets.address,
            sh_offset: self.section.offsets.file_offset,
            sh_info: 0,
            sh_link: 0,
            sh_entsize: 0x10, // entity size for .plt is 0x10
            sh_addralign: self.section.offsets.align,
            sh_size: self.section.offsets.size as u64,
        });
    }
}

pub struct PltGotSection {
    section: GeneralSection,
    entry_size: usize,
}

impl PltGotSection {
    pub fn new(name: &'static str) -> Self {
        Self {
            section: GeneralSection::new(AllocSegment::RX, name, 0x08),
            entry_size: 0x08,
        }
    }
}

impl ElfBlock for PltGotSection {
    fn name(&self) -> String {
        self.section.name()
    }

    fn alloc(&self) -> AllocSegment {
        self.section.alloc()
    }

    fn reserve_section_index(&mut self, data: &mut Data, w: &mut Writer) {
        self.section.reserve_section_index(data, w);
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        let pltgot = data.dynamics.pltgot_objects();
        let size = (pltgot.len()) * self.entry_size;
        let file_offset = w.reserve_start_section(&self.section.offsets);
        self.section.offsets.size = size as u64;
        w.reserve(size, 1);
        let after = w.reserved_len();
        assert_eq!(size, after - file_offset);

        data.segments
            .add_offsets(self.alloc(), &mut self.section.offsets);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize
                + self.section.offsets.size as usize,
            w.reserved_len()
        );

        // update section pointers
        let address = self.section.offsets.address;
        data.addr.insert(AddressKey::Section(self.name()), address);
        data.addr.insert(
            AddressKey::SectionIndex(self.section.section_index.unwrap()),
            address,
        );
    }

    fn write(&self, data: &Data, w: &mut Writer) {
        w.write_start_section(&self.section.offsets);
        let bytes = BuildPltGotSection::contents(data, self.section.offsets.address as usize);
        w.write(&bytes);
    }

    fn write_section_header(&self, _data: &Data, w: &mut Writer) {
        w.write_section_header(&object::write::elf::SectionHeader {
            name: self.section.name_id,
            sh_type: object::elf::SHT_PROGBITS,
            sh_flags: self.section.offsets.alloc.section_header_flags() as u64,
            sh_addr: self.section.offsets.address,
            sh_offset: self.section.offsets.file_offset,
            sh_info: 0,
            sh_link: 0,
            sh_entsize: BuildPltGotSection::entry_size() as u64,
            sh_addralign: self.section.offsets.align,
            sh_size: self.section.offsets.size as u64,
        });
    }
}

struct Dynamic {
    tag: u32,
    // Ignored if `string` is set.
    val: u64,
    string: Option<object::write::StringId>,
}

fn gen_dynamic(data: &Data, config: &AOTConfig) -> Vec<Dynamic> {
    let mut out = vec![];
    for lib in data.libs.iter() {
        out.push(Dynamic {
            tag: elf::DT_NEEDED,
            val: 0,
            string: lib.string_id,
        });
    }
    out.push(Dynamic {
        tag: elf::DT_HASH,
        val: data.hash.addr.unwrap(),
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_STRTAB,
        val: data.dynstr.addr.unwrap(),
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_SYMTAB,
        val: data.dynsym.addr.unwrap(),
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_STRSZ,
        val: data.dynstr.size.unwrap() as u64,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_SYMENT,
        val: config.symbol_size() as u64,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_DEBUG,
        val: 0,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_PLTGOT,
        val: *data
            .addr
            .get(&AddressKey::Section(".got.plt".to_string()))
            .unwrap_or(&0),
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_PLTRELSZ,
        val: data.relaplt.size.unwrap() as u64,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_PLTREL,
        val: 7,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_JMPREL,
        val: data.addr_get(".rela.plt"),
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_RELA,
        val: data.addr_get(".rela.dyn"),
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_RELASZ,
        val: data.reladyn.size.unwrap() as u64,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_RELAENT,
        val: config.rel_size(true) as u64,
        string: None,
    });
    out.push(Dynamic {
        tag: elf::DT_NULL,
        val: 0,
        string: None,
    });
    out
}
