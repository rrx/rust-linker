use super::*;
use object::elf;
use object::write::elf::{SectionIndex, Writer};
use object::Endianness;

#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub enum AllocSegment {
    RO,
    RW,
    RX,
    #[default]
    None,
}

impl AllocSegment {
    pub fn section_header_flags(&self) -> u32 {
        match self {
            AllocSegment::RO => elf::SHF_ALLOC,
            AllocSegment::RW => elf::SHF_ALLOC | elf::SHF_WRITE,
            AllocSegment::RX => elf::SHF_ALLOC | elf::SHF_EXECINSTR,
            AllocSegment::None => 0,
        }
    }
    pub fn program_header_flags(&self) -> u32 {
        match self {
            AllocSegment::RO => elf::PF_R,
            AllocSegment::RW => elf::PF_R | elf::PF_W,
            AllocSegment::RX => elf::PF_R | elf::PF_X,
            AllocSegment::None => 0,
        }
    }
}

pub struct Blocks {
    //pub blocks: Vec<Box<dyn ElfBlock>>,
    //pub ph: Vec<ProgramHeaderEntry>,
}

impl Blocks {
    pub fn build(mut data: Data, target: Target, w: &mut Writer, config: &AOTConfig) {
        // preparation
        Data::write_strings(&mut data, &target, w);
        data.write_relocations(&target, w);
        data.update_data(&target);

        let mut blocks: Vec<Box<dyn ElfBlock>> = vec![];

        blocks.push(Box::new(FileHeader::default()));
        blocks.push(Box::new(ProgramHeader::default()));

        if data.is_dynamic() {
            blocks.push(Box::new(InterpSection::new(&data.interp)));
        }

        if config.use_gnuhash {
            blocks.push(Box::new(GnuHashSection::new()));
        } else {
            blocks.push(Box::new(HashSection::new()));
        }

        if data.is_dynamic() {
            blocks.push(Box::new(DynSymSection::default()));
            if w.dynstr_needed() {
                blocks.push(Box::new(DynStrSection::default()));
            }
            blocks.push(Box::new(RelaDynSection::new(GotSectionKind::GOT)));
            blocks.push(Box::new(RelaDynSection::new(GotSectionKind::GOTPLT)));
        }

        blocks.push(Box::new(target.ro.clone()));
        blocks.push(Box::new(target.rx.clone()));
        blocks.push(Box::new(PltSection::new(".plt")));
        blocks.push(Box::new(PltGotSection::new(".plt.got")));
        blocks.push(Box::new(target.rw.clone()));

        if data.is_dynamic() {
            blocks.push(Box::new(DynamicSection::new(config)));
            blocks.push(Box::new(GotSection::new(GotSectionKind::GOT)));
            blocks.push(Box::new(GotSection::new(GotSectionKind::GOTPLT)));
        }

        // bss is the last alloc block
        blocks.push(Box::new(target.bss.clone()));

        if config.add_symbols {
            blocks.push(Box::new(SymTabSection::default()));
        }

        assert!(w.strtab_needed());
        if config.add_symbols && w.strtab_needed() {
            blocks.push(Box::new(StrTabSection::new()));
        }

        // shstrtab needs to be allocated last, once all headers are reserved
        if config.add_symbols {
            blocks.push(Box::new(ShStrTabSection::default()));
        }

        let ph = Self::generate_ph(&mut blocks, config);

        // save program header
        data.ph = ph.clone();

        // RESERVE SECTION HEADERS
        // section headers are optional
        if config.add_section_headers {
            for b in blocks.iter_mut() {
                b.reserve_section_index(&mut data, w);
            }
        }

        // RESERVE SYMBOLS - requires section headers
        Self::reserve_symbols(&mut data, w);

        // RESERVE blocks - finalize the layout
        for b in blocks.iter_mut() {
            let pos = w.reserved_len();
            b.reserve(&mut data, w);
            let after = w.reserved_len();
            log::debug!(
                "reserve: {}, {:#0x}, {:#0x},  {:?}",
                b.name(),
                pos,
                after,
                b.alloc()
            );
        }

        if config.add_section_headers {
            w.reserve_section_headers();
        }

        // UPDATE PROGRAM HEADERS
        data.ph = Self::program_headers(&blocks, &mut data);

        // WRITE blocks
        for b in blocks.iter() {
            let pos = w.len();
            //eprintln!("write: {}", b.name());
            b.write(&data, w);
            let after = w.len();
            log::debug!(
                "write: {}, {:?}, pos: {:#0x}, after: {:#0x}, base: {:#0x}",
                b.name(),
                b.alloc(),
                pos,
                after,
                data.segments.current().base
            );
        }

        // SECTION HEADERS
        if config.add_section_headers {
            for b in blocks.iter() {
                b.write_section_header(&data, w);
            }
        }
    }

    /// generate a temporary list of program headers
    pub fn generate_ph(
        blocks: &mut Vec<Box<dyn ElfBlock>>,
        config: &AOTConfig,
    ) -> Vec<ProgramHeaderEntry> {
        // build a list of sections that are loaded
        // this is a hack to get tracker to build a correct list of program headers
        // without having to go through the blocks and do reservations
        let mut data = Data::new(vec![]);
        //data.addr_set(".got.plt", 0);
        //data.pointer_set("_start".to_string(), 0);
        //data.pointer_set("__data_start".to_string(), 0);
        let mut out_data = Vec::new();
        let endian = Endianness::Little;
        let mut w = object::write::elf::Writer::new(endian, config.is_64(), &mut out_data);

        //block.build_strings(&mut data, &mut w);
        for b in blocks.iter_mut() {
            b.reserve_section_index(&mut data, &mut w);
        }

        Self::reserve_symbols(&mut data, &mut w);

        for b in blocks.iter_mut() {
            b.reserve(&mut data, &mut w);
        }
        // get a list of program headers
        // we really only need to know the number of headers, so we can correctly
        // set the values in the file header
        Self::program_headers(blocks, &mut data)
    }

    pub fn program_headers(
        blocks: &Vec<Box<dyn ElfBlock>>,
        data: &Data,
    ) -> Vec<ProgramHeaderEntry> {
        let mut ph = vec![];
        for b in blocks.iter() {
            ph.extend(b.program_header());
        }
        ph.extend(data.segments.program_headers());

        ph
    }

    fn reserve_symbols(data: &mut Data, w: &mut Writer) {
        let syms = vec![
            (
                "data_start",
                ".data",
                SymbolBind::Weak,
                object::SymbolKind::Unknown,
            ),
            (
                "__data_start",
                ".data",
                SymbolBind::Global,
                object::SymbolKind::Unknown,
            ),
            (
                "__bss_start",
                ".bss",
                SymbolBind::Global,
                object::SymbolKind::Unknown,
            ),
            (
                "__rodata_start",
                ".rodata",
                SymbolBind::Global,
                object::SymbolKind::Unknown,
            ),
            (
                "_GLOBAL_OFFSET_TABLE_",
                ".got.plt",
                SymbolBind::Local,
                object::SymbolKind::Data,
            ),
            (
                "_DYNAMIC",
                ".dynamic",
                SymbolBind::Local,
                object::SymbolKind::Data,
            ),
        ];

        for (name, section_name, bind, kind) in syms {
            let pointer = ResolvePointer::Section(section_name.to_string(), 0);
            let mut symbol = ReadSymbol::from_pointer(name.to_string(), pointer);
            symbol.bind = bind;
            symbol.kind = kind;
            let section_index = data.section_index_get(section_name);
            data.statics.symbol_add(&symbol, Some(section_index), w);
        }
    }
}

#[derive(Debug, Default, Clone)]
pub struct SectionOffset {
    pub name: String,
    pub alloc: AllocSegment,
    pub base: u64,
    pub address: u64,
    pub file_offset: u64,
    pub align: u64,
    pub size: u64,
    pub section_index: Option<SectionIndex>,
}

impl SectionOffset {
    pub fn new(name: String, alloc: AllocSegment, align: u64) -> Self {
        Self {
            name,
            alloc,
            align,
            ..Default::default()
        }
    }
}

pub struct SegmentTracker {
    segments: Vec<Segment>,
    // track the current segment base
    start_base: u64,
    page_size: usize,
}

impl SegmentTracker {
    pub fn new(start_base: u64) -> Self {
        Self {
            segments: vec![],
            start_base,
            page_size: 0x1000,
        }
    }

    pub fn current(&self) -> &Segment {
        self.segments.last().unwrap()
    }

    pub fn current_mut(&mut self) -> &mut Segment {
        self.segments.last_mut().unwrap()
    }

    // add non-section data
    pub fn add_offsets(&mut self, alloc: AllocSegment, offsets: &mut SectionOffset) {
        let current_size;
        let current_file_offset;
        let current_alloc;
        let mut base;

        // get current segment, or defaults
        if let Some(c) = self.segments.last() {
            current_size = c.segment_size() as u64;
            current_file_offset = c.file_offset;
            current_alloc = c.alloc;
            base = c.base;
        } else {
            current_alloc = alloc;
            current_file_offset = 0;
            current_size = 0;
            base = self.start_base;
        }

        // if we are initializing the first segment, or the segment has changed
        // we start a new segment
        if self.segments.len() == 0 || alloc != current_alloc {
            // calculate the base for the segment, based on page size, and the size of the previous
            // segment
            base = size_align((base + current_size) as usize, self.page_size) as u64;

            // align the new file offset
            let file_offset = size_align(
                current_file_offset as usize + current_size as usize,
                offsets.align as usize,
            ) as u64;

            // new segment
            let segment = Segment::new(alloc, base, file_offset as u64);

            eprintln!(
                "new seg: {:?}, offset: {:#0x}, last_offset: {:#0x}, last_size: {:#0x}, size: {:#0x}, align: {:#0x}, base: {:#0x}",
                alloc,
                file_offset,
                current_file_offset,
                current_size,
                offsets.size,
                offsets.align,
                base,
            );
            self.segments.push(segment);

            if file_offset < (current_file_offset + current_size) {
                eprintln!(
                    "fail: {:?}, file_offset: {:#0x}: current offset: {:#0x}, current size: {:#0x}",
                    alloc, file_offset, current_file_offset, current_size
                );
            }
            assert!(file_offset >= (current_file_offset + current_size));
        }

        self.current_mut().add_offsets(offsets);
    }

    pub fn program_headers(&self) -> Vec<ProgramHeaderEntry> {
        let mut out = vec![];
        for s in self.segments.iter() {
            if let Some(ph) = s.program_header() {
                out.push(ph);
            }
        }
        out
    }
}

#[derive(Debug)]
pub struct Segment {
    // segment base
    pub base: u64,

    // address of the segment
    //pub addr: u64,

    // track the size of teh segment
    segment_size: usize,

    // segment alignment (0x1000)
    pub align: u32,

    pub alloc: AllocSegment,

    // file offset for the segment
    pub file_offset: u64,

    // keep track of the last section file offset for this segment
    pub adjusted_file_offset: u64,
}

impl Segment {
    pub fn new(alloc: AllocSegment, base: u64, file_offset: u64) -> Self {
        Self {
            base,
            //addr: 0,
            file_offset,
            adjusted_file_offset: file_offset,
            segment_size: 0,
            alloc,
            align: 0x1000,
        }
    }

    pub fn segment_size(&self) -> usize {
        self.segment_size
    }

    pub fn add_offsets(&mut self, offsets: &mut SectionOffset) {
        //, w: &Writer) {
        let aligned = size_align(self.segment_size, offsets.align as usize);
        self.segment_size = aligned + offsets.size as usize;
        self.adjusted_file_offset = self.file_offset + aligned as u64;

        offsets.base = self.base;
        offsets.address = self.base + self.adjusted_file_offset;
        offsets.file_offset = self.adjusted_file_offset;
    }

    pub fn program_header(&self) -> Option<ProgramHeaderEntry> {
        // add a load section for the file and program header, so it's covered
        let size = self.segment_size() as u64;
        Some(ProgramHeaderEntry {
            p_type: elf::PT_LOAD,
            p_flags: self.alloc.program_header_flags(),
            p_offset: self.file_offset,
            p_vaddr: self.base + self.file_offset,
            p_paddr: self.base + self.file_offset,
            p_filesz: size,
            p_memsz: size,
            p_align: self.align as u64,
        })
    }
}
