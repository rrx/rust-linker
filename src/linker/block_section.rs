use crate::writer::*;
use crate::*;
use object::read::elf;
use object::write::elf::{SectionIndex, Writer};
use object::write::StringId;
use object::ObjectSection;
use std::error::Error;

#[derive(Debug, Clone, Default)]
pub enum BlockSectionState {
    #[default]
    Start,
    Located,
}

pub trait BlockSection {
    fn size(&self) -> usize;
    fn bytes(&self) -> &[u8];
    fn relocations(&self) -> &Vec<CodeRelocation>;
    fn relocation_add(&mut self, r: CodeRelocation);
    fn extend_size(&mut self, s: usize);
    fn extend_bytes(&mut self, bytes: &[u8]);
    //fn reserve_section_index(&mut self, data: &mut Data, w: &mut Writer);
    //fn reserve(&mut self, data: &mut Data, w: &mut Writer);
    //fn write(&self, data: &Data, w: &mut Writer);
    //fn write_section_header(&self, w: &mut Writer);
}

#[derive(Debug)]
pub struct GeneralSection {
    state: BlockSectionState,
    pub(crate) name: &'static str,
    pub(crate) name_id: Option<StringId>,
    pub(crate) section_index: Option<SectionIndex>,
    pub(crate) size: usize,
    pub(crate) bytes: Vec<u8>,
    pub(crate) relocations: Vec<CodeRelocation>,
    pub(crate) offsets: SectionOffset,
}

fn resolve_r(data: &Data, r: &CodeRelocation) -> Option<u64> {
    //eprintln!("resolve: {}, kind: {:?}", &r.name, r.r.kind());

    // check if it's in the plt or got, and look it up in dynamics
    //if r.is_plt() || r.is_got() {
    if let Some(resolve_addr) = data.dynamics.lookup(r) {
        return resolve_addr.resolve(data);
    }
    //}

    // otherwise, just look up the symbol
    if let Some(resolve_addr) = data.pointers.get(&r.name) {
        resolve_addr.resolve(data)
    } else {
        None
    }
}

impl BlockSection for GeneralSection {
    fn size(&self) -> usize {
        self.size
    }

    fn bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    fn relocations(&self) -> &Vec<CodeRelocation> {
        &self.relocations
    }

    fn relocation_add(&mut self, r: CodeRelocation) {
        self.relocations.push(r);
    }

    fn extend_size(&mut self, s: usize) {
        self.size += s;
    }

    fn extend_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend(bytes.iter());
    }
}

impl ElfBlock for GeneralSection {
    fn name(&self) -> String {
        self.name.into()
    }

    fn alloc(&self) -> AllocSegment {
        self.offsets.alloc
    }

    fn reserve_section_index(&mut self, data: &mut Data, _: &mut ReadBlock, w: &mut Writer) {
        self.name_id = Some(w.add_section_name(self.name.as_bytes()));
        let index = w.reserve_section_index();
        self.section_index = Some(index);
        //eprintln!("section index set: {}, {:?}", self.name, index);
        data.section_index_set(&self.name, index);
    }

    fn reserve(&mut self, data: &mut Data, _: &mut ReadBlock, w: &mut Writer) {
        let file_offset = w.reserve_start_section(&self.offsets);
        w.reserve(self.bytes.len(), 1);
        let after = w.reserved_len();

        data.segments.add_offsets(
            self.offsets.alloc,
            &mut self.offsets,
            after - file_offset,
            w,
        );
        data.addr_set(&self.name, self.offsets.address);
        self.state = BlockSectionState::Located;
    }

    fn write(&self, data: &Data, _: &ReadBlock, w: &mut Writer) {
        w.write_start_section(&self.offsets);
        self.apply_relocations(data);

        w.write(self.bytes.as_slice());
    }

    fn write_section_header(&self, _: &Data, _: &ReadBlock, w: &mut Writer) {
        if let Some(name_id) = self.name_id {
            w.write_section_header(&object::write::elf::SectionHeader {
                name: Some(name_id),
                sh_type: object::elf::SHT_PROGBITS,
                sh_flags: self.offsets.alloc.section_header_flags() as u64,
                sh_addr: self.offsets.address,
                sh_offset: self.offsets.file_offset,
                sh_info: 0,
                sh_link: 0,
                sh_entsize: 0,
                sh_addralign: self.offsets.align,
                sh_size: self.size as u64,
            });
        }
    }
}

impl GeneralSection {
    pub fn new(alloc: AllocSegment, name: &'static str, align: u64) -> Self {
        Self {
            state: BlockSectionState::default(),
            name,
            name_id: None,
            section_index: None,
            size: 0,
            bytes: vec![],
            relocations: vec![],
            offsets: SectionOffset::new(name.into(), alloc, align),
        }
    }

    pub fn from_section<'a, 'b, A: elf::FileHeader, B: object::ReadRef<'a>>(
        &mut self,
        b: &elf::ElfFile<'a, A, B>,
        section: &elf::ElfSection<'a, 'b, A, B>,
    ) -> Result<(), Box<dyn Error>> {
        let data = section.uncompressed_data()?;
        let base_offset = self.size();
        log::debug!("name: {}", section.name()?);
        self.extend_size(data.len());
        self.extend_bytes(&data);
        for (offset, r) in section.relocations() {
            let r = code_relocation(b, r.into(), base_offset + offset as usize)?;
            self.relocations.push(r);
        }
        Ok(())
    }

    pub fn apply_relocations(&self, data: &Data) {
        let patch_base = self.bytes.as_ptr();
        //eprintln!("symbols: {:?}", data.dynamics.symbols());
        //eprintln!("plt: {:?}", data.dynamics.plt_hash);
        //eprintln!("pltgot: {:?}", data.dynamics.pltgot_hash);
        for r in self.relocations.iter() {
            if let Some(addr) = resolve_r(data, r) {
                log::info!(
                    target: "relocations",
                    "R-{:?}: vbase: {:#0x}, addr: {:#0x}, {}",
                    self.offsets.alloc, self.offsets.address, addr as usize, &r.name
                );
                r.patch(
                    patch_base as *mut u8,
                    self.offsets.address as *mut u8,
                    addr as *const u8,
                );
            } else {
                unreachable!("Unable to locate symbol: {}, {}", &r.name, &r);
            }
        }

        //if data.debug_enabled(&DebugFlag::Disassemble) {
        self.disassemble(data);
        //}
    }
}
