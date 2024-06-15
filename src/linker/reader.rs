// read elf file
use object::elf::FileHeader64;
use object::read::elf;
use object::read::elf::ProgramHeader;
use object::write::elf::{SectionIndex, Writer};
use object::write::StringId;
use object::{
    Object, ObjectKind, ObjectSection, ObjectSymbol, RelocationTarget, SectionKind, SymbolKind,
};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::Path;

use super::*;
use crate::writer::*;
use crate::*;

pub type SymbolMap = HashMap<String, ReadSymbol>;

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum ReadSectionKind {
    RX,
    //ROStrings,
    ROData,
    RW,
    Bss,
    Undefined,
    Other,
}

impl ReadSectionKind {
    pub fn new_section_kind(kind: SectionKind) -> Self {
        match kind {
            SectionKind::Text => ReadSectionKind::RX,
            SectionKind::Data => ReadSectionKind::RW,
            SectionKind::ReadOnlyData => ReadSectionKind::ROData,
            SectionKind::ReadOnlyString => ReadSectionKind::ROData,
            SectionKind::UninitializedData => ReadSectionKind::Bss,
            SectionKind::Metadata => ReadSectionKind::Other,
            SectionKind::OtherString => ReadSectionKind::Other,
            SectionKind::Other => ReadSectionKind::Other,
            SectionKind::Note => ReadSectionKind::Other,
            SectionKind::UninitializedTls => ReadSectionKind::Other,
            SectionKind::Tls => ReadSectionKind::Other,
            SectionKind::Elf(_) => ReadSectionKind::Other,
            _ => unimplemented!("{:?}", kind),
        }
    }

    pub fn alloc(&self) -> Option<AllocSegment> {
        match self {
            ReadSectionKind::RX => Some(AllocSegment::RX),
            ReadSectionKind::RW => Some(AllocSegment::RW),
            //ReadSectionKind::ROStrings => Some(AllocSegment::RO),
            ReadSectionKind::ROData => Some(AllocSegment::RO),
            ReadSectionKind::Bss => Some(AllocSegment::RW),
            _ => None,
        }
    }

    pub fn section_index(&self, data: &Data) -> Option<SectionIndex> {
        use ReadSectionKind::*;
        match self {
            RX | RW | ROData | Bss => data.section_index.get(self.section_name()).cloned(),
            _ => None,
        }
    }

    pub fn section_name(&self) -> &'static str {
        match self {
            Self::RX => ".text",
            Self::ROData => ".rodata",
            //Self::ROStrings => ".strtab",
            Self::RW => ".data",
            Self::Bss => ".bss",
            _ => unreachable!("Unhandled section: {:?}", self),
        }
    }

    pub fn pointer(&self, address: u64) -> ResolvePointer {
        match self {
            Self::RX | Self::ROData | Self::RW | Self::Bss => {
                ResolvePointer::Section(self.section_name().to_string(), address)
            }
            _ => ResolvePointer::Resolved(address),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SymbolSource {
    Dynamic,
    Static,
}

#[derive(Debug, Clone, PartialEq)]
pub enum SymbolBind {
    Local,
    Global,
    Weak,
}
impl SymbolBind {
    pub fn bind(&self) -> u8 {
        use object::elf;
        match self {
            Self::Local => elf::STB_LOCAL,
            Self::Global => elf::STB_GLOBAL,
            Self::Weak => elf::STB_WEAK,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ReadSymbol {
    pub(crate) name: String,
    //pub(crate) name_id: Option<StringId>,
    //pub(crate) dyn_name_id: Option<StringId>,
    pub(crate) section: ReadSectionKind,
    pub(crate) source: SymbolSource,
    pub(crate) kind: SymbolKind,
    pub(crate) bind: SymbolBind,
    pub(crate) pointer: ResolvePointer,
    pub(crate) size: u64,
}

impl ReadSymbol {
    pub fn from_pointer(name: String, pointer: ResolvePointer) -> Self {
        ReadSymbol {
            name,
            //name_id: None,
            //dyn_name_id: None,
            section: ReadSectionKind::Undefined,
            source: SymbolSource::Static,
            kind: SymbolKind::Unknown,
            bind: SymbolBind::Local,
            pointer,
            size: 0,
        }
    }

    pub fn is_static(&self) -> bool {
        self.source == SymbolSource::Static
    }

    pub fn relocate(&mut self, base: u64) {
        self.pointer = self.pointer.clone().relocate(base);
    }

    pub fn get_dynamic_symbol(&self, data: &Data) -> object::write::elf::Sym {
        let name = Some(data.dynamics.string_get(&self.name));
        self._get_symbol(name, 0, 0, None)
    }

    pub fn get_static_symbol(&self, data: &Data) -> object::write::elf::Sym {
        let name = data.statics.string_get(&self.name);
        let st_value = {
            if let Some(addr) = self.pointer.resolve(data) {
                addr
            } else {
                0
            }
        };
        let section = self.section.section_index(data);
        self._get_symbol(name, st_value, self.size, section)
    }

    pub fn _get_symbol(
        &self,
        string_id: Option<StringId>,
        st_value: u64,
        st_size: u64,
        section: Option<SectionIndex>,
    ) -> object::write::elf::Sym {
        use object::elf;

        let stt = match self.kind {
            SymbolKind::Data => elf::STT_OBJECT,
            SymbolKind::Text => elf::STT_FUNC,
            _ => elf::STT_NOTYPE,
        };

        let stb = self.bind.bind();

        let st_info = (stb << 4) + (stt & 0x0f);
        let st_other = elf::STV_DEFAULT;

        object::write::elf::Sym {
            name: string_id,
            section,
            st_info,
            st_other,
            st_shndx: 0,
            st_value,
            st_size,
        }
    }
}

#[derive(Debug)]
pub struct ReadBlock {
    name: String,
    // dynamic libraries referenced
    target: Target,
    pub libs: HashSet<String>,
    local_index: usize,
    pub got: GeneralSection,
    pub gotplt: GeneralSection,
}

impl ReadBlock {
    pub fn new(name: &str) -> Self {
        let mut target = Target::new();

        // These need to be declared
        let locals = vec![("_DYNAMIC", ".dynamic")];

        for (symbol_name, section_name) in locals {
            let symbol_name = symbol_name.to_string();
            let section_name = section_name.to_string();
            let pointer = ResolvePointer::Section(section_name, 0);
            let symbol = ReadSymbol::from_pointer(symbol_name, pointer);
            target.insert_local(symbol);
        }

        Self {
            name: name.to_string(),
            target,
            got: GeneralSection::new(AllocSegment::RW, ".got", 0x10),
            gotplt: GeneralSection::new(AllocSegment::RW, ".got.plt", 0x10),
            libs: HashSet::new(),
            local_index: 0,
        }
    }

    pub fn data(&self) -> crate::Data {
        let mut data = crate::Data::new(self.libs.iter().cloned().collect());
        data.target = self.target.clone();
        data
    }

    pub fn add(&mut self, path: &std::path::Path, config: &Config) -> Result<(), Box<dyn Error>> {
        let p = Path::new(&path);
        println!("p: {}", p.to_str().unwrap());
        let ext = p.extension().unwrap().to_str().unwrap();
        println!("ext: {}", ext);
        if ext == "a" {
            self.add_archive(&Path::new(&path), &config)?;
        } else {
            self.add_object(&Path::new(&path), &config)?;
        }
        Ok(())
    }

    pub fn add_object(
        &mut self,
        path: &std::path::Path,
        config: &Config,
    ) -> Result<(), Box<dyn Error>> {
        let buf = std::fs::read(path)?;
        self.read(path.to_str().unwrap(), &buf, config)?;
        //self.block.add_block(block);
        Ok(())
    }

    pub fn add_archive(
        &mut self,
        path: &std::path::Path,
        config: &Config,
    ) -> Result<(), Box<dyn Error>> {
        let buf = std::fs::read(path)?;
        self.add_archive_buf(path.to_str().unwrap(), &buf, config)?;
        Ok(())
    }

    pub fn add_archive_buf(
        &mut self,
        archive_name: &str,
        buf: &[u8],
        config: &Config,
    ) -> Result<(), Box<dyn Error>> {
        log::debug!("Archive: {}", archive_name);
        let archive = object::read::archive::ArchiveFile::parse(buf)?;
        log::debug!(
            "Archive: {}, size: {}, kind: {:?}",
            archive_name,
            buf.len(),
            archive.kind()
        );
        for result in archive.members() {
            let m = result?;
            let name = std::str::from_utf8(&m.name())?;
            let (offset, size) = m.file_range();
            let obj_buf = &buf[offset as usize..(offset + size) as usize];
            log::debug!("Member: {}, {:?}", &name, &m);
            self.read(name, &obj_buf, config)?;
            //self.block.add_block(block);
        }
        Ok(())
    }

    pub fn read<'a>(
        &mut self,
        name: &str,
        buf: &'a [u8],
        config: &Config,
    ) -> Result<(), Box<dyn Error>> {
        let b: elf::ElfFile<'a, FileHeader64<object::Endianness>> =
            object::read::elf::ElfFile::parse(buf)?;
        match b.kind() {
            ObjectKind::Relocatable | ObjectKind::Executable => {
                dump_header(&b)?;
                self.relocatable(name.to_string(), &b, config)?
            }
            ObjectKind::Dynamic => self.dynamic(&b, name)?,
            _ => unimplemented!("{:?}", b.kind()),
        };
        //Ok(block)
        Ok(())
    }

    fn dynamic<'a, 'b, A: elf::FileHeader, B: object::ReadRef<'a>>(
        &mut self,
        b: &elf::ElfFile<'a, A, B>,
        name: &str,
    ) -> Result<(), Box<dyn Error>> {
        //let mut block = ReadBlock::new(name);
        let mut count = 0;
        for symbol in b.dynamic_symbols() {
            let mut s = read_symbol(&b, 0, &symbol)?;
            s.pointer = ResolvePointer::Resolved(0);
            s.source = SymbolSource::Dynamic;
            s.size = 0;
            //eprintln!("s: {:#08x}, {:?}", 0, &s);
            count += 1;
            if s.kind != SymbolKind::Unknown {
                self.target.insert_dynamic(s);
            }
        }
        eprintln!("{} symbols read from {}", count, name);
        self.libs.insert(name.to_string());
        //Ok(block)
        Ok(())
    }

    fn relocatable<'a, 'b, A: elf::FileHeader, B: object::ReadRef<'a>>(
        &mut self,
        name: String,
        b: &elf::ElfFile<'a, A, B>,
        config: &Config,
    ) -> Result<(), Box<dyn Error>> {
        //let mut block = ReadBlock::new(&name);

        log::debug!("relocatable: {}", &name);

        for section in b.sections() {
            let kind = ReadSectionKind::new_section_kind(section.kind());

            if config.debug.contains(&DebugFlag::HashTables) && section.name()? == ".hash" {
                let data = section.uncompressed_data()?;
                dump_hash(&data);
            }

            // skip other kinds
            if kind == ReadSectionKind::Other {
                continue;
            }

            self.from_section(&b, &section)?;
        }

        Ok(())
    }

    pub fn update_data(&self, data: &mut Data) {
        for (name, _, pointer) in data.dynamics.symbols() {
            data.pointers.insert(name, pointer);
        }

        //eprintln!("plt: {:?}", data.dynamics.plt_hash);
        //eprintln!("pltgot: {:?}", data.dynamics.pltgot_hash);

        for (name, symbol) in self.target.locals.iter() {
            match symbol.section {
                ReadSectionKind::RX
                //| ReadSectionKind::ROStrings
                | ReadSectionKind::ROData
                | ReadSectionKind::RW
                | ReadSectionKind::Bss => {
                    data.pointers
                        .insert(name.to_string(), symbol.pointer.clone());
                }
                _ => (),
            }
        }

        // Add static symbols to data
        let locals = vec!["_DYNAMIC"];
        for symbol_name in locals {
            let s = self.target.lookup_static(symbol_name).unwrap();
            data.pointers.insert(s.name, s.pointer);
        }
    }

    pub fn update_relocations(&self, data: &mut Data, w: &mut Writer) {
        let iter = self
            .target
            .ro
            .relocations()
            .iter()
            .chain(self.target.rw.relocations().iter())
            .chain(self.target.rx.relocations().iter())
            .chain(self.target.bss.relocations().iter());

        // add the relocations to the sets
        // we only want to add a relocation to either got or gotplt
        // if it's being added to got, then only add it to got
        // with entries in the got and gotplt, we then apply relocations
        // to point to the appropriate got and gotplt entries
        let mut got = HashSet::new();
        let mut gotplt = HashSet::new();
        for r in iter.clone() {
            //if r.is_got() {
            //got.insert(r.name.clone());
            //} else if r.is_plt() {
            //gotplt.insert(r.name.clone());
            //} else {
            match r.effect() {
                PatchEffect::AddToGot => {
                    got.insert(r.name.clone());
                }
                PatchEffect::AddToPlt => {
                    gotplt.insert(r.name.clone());
                }
                _ => (),
            }
        }

        for r in iter {
            if let Some(s) = self.target.lookup(&r.name) {
                // we don't know the section yet, we just know which kind
                let def = match s.bind {
                    SymbolBind::Local => CodeSymbolDefinition::Local,
                    SymbolBind::Global => CodeSymbolDefinition::Defined,
                    SymbolBind::Weak => CodeSymbolDefinition::Defined,
                };

                let assign = match s.kind {
                    SymbolKind::Text => {
                        if s.is_static() {
                            if r.is_plt() {
                                GotPltAssign::GotPltWithPlt
                            } else {
                                GotPltAssign::Got
                            }
                        } else if got.contains(&r.name) {
                            if r.is_plt() {
                                GotPltAssign::GotWithPltGot
                            } else {
                                GotPltAssign::Got
                            }
                        } else if gotplt.contains(&r.name) {
                            GotPltAssign::GotPltWithPlt
                        } else {
                            GotPltAssign::None
                        }
                    }
                    SymbolKind::Data => GotPltAssign::Got,
                    //_ => unimplemented!("{:?}, {}", s, r)
                    _ => GotPltAssign::None,
                };

                if s.source == SymbolSource::Dynamic {
                    log::debug!("reloc {}", &r);
                    //data.statics.symbol_add(&s, None, w);
                    //data.dynamics.symbol_add(&s, None, w);
                    data.dynamics.relocation_add(&s, assign, r, w);
                } else if def != CodeSymbolDefinition::Local {
                    log::debug!("reloc2 {}", &r);
                    if assign == GotPltAssign::None {
                    } else {
                        data.dynamics.relocation_add(&s, assign, r, w);
                    }
                } else {
                    log::debug!("reloc3 {}", &r);
                }
            } else {
                unreachable!("Unable to find symbol for relocation: {}", &r.name)
            }
        }
    }

    fn build_strings(&self, data: &mut Data, w: &mut Writer) {
        self.update_relocations(data, w);
        self.update_data(data);

        // add libraries if they are configured
        for lib in data.libs.iter_mut() {
            unsafe {
                let buf = extend_lifetime(lib.name.as_bytes());
                lib.string_id = Some(w.add_dynamic_string(buf));
            }
        }

        for (name, symbol) in data.target.exports.iter() {
            // allocate string for the symbol table
            let _string_id = data.statics.string_add(name, w);
            data.pointers
                .insert(name.to_string(), symbol.pointer.clone());
        }
    }

    fn relocate_symbol(&self, mut s: ReadSymbol) -> ReadSymbol {
        let base = match s.section {
            ReadSectionKind::RX => self.target.rx.size() as u64,
            ReadSectionKind::ROData => self.target.ro.size() as u64,
            ReadSectionKind::RW => self.target.rw.size() as u64,
            ReadSectionKind::Bss => self.target.bss.size() as u64,
            _ => 0,
        };
        s.relocate(base);
        s
    }

    pub fn merge(
        renames: &HashMap<String, String>,
        src: &dyn BlockSection,
        dst: &mut dyn BlockSection,
    ) {
        let base_offset = dst.size();
        dst.extend_size(src.size());
        dst.extend_bytes(src.bytes());
        for r in src.relocations().iter() {
            let mut r = r.clone();
            r.offset += base_offset as u64;
            if let Some(name) = renames.get(&r.name) {
                r.name = name.clone();
            }
            dst.relocation_add(r);
        }
    }

    pub fn add_block(&mut self, block: ReadBlock) {
        let mut renames = HashMap::new();

        // rename local symbols so they are globally unique
        for (name, s) in block.target.locals.into_iter() {
            let mut s = self.relocate_symbol(s);
            let unique = format!(".u.{}{}", self.local_index, name);
            s.name = unique.clone();
            self.local_index += 1;
            self.target.insert_local(s);
            renames.insert(name, unique);
        }

        // exports
        for (_name, s) in block.target.exports.into_iter() {
            let s = self.relocate_symbol(s);
            //eprintln!("E: {:?}", (&block.name, name, &s));
            self.target.insert_export(s);
        }

        for (_name, s) in block.target.dynamic.into_iter() {
            self.target.insert_dynamic(s);
        }

        self.libs.extend(block.libs.into_iter());

        // update BSS
        /*
        let base_offset = self.bss.section.size;
        self.bss.section.size += block.bss.section.size;
        for r in block.bss.relocations() {
            let mut r = r.clone();
            r.offset += base_offset as u64;
            if let Some(name) = renames.get(&r.name) {
                r.name = name.clone();
            }
            self.bss.relocation_add(r);//().push(r);
        }
        */

        // update Bss
        Self::merge(&renames, &block.target.bss, &mut self.target.bss);
        assert_eq!(block.target.bss.bytes().len(), 0);

        // update RX
        Self::merge(&renames, &block.target.rx, &mut self.target.rx);
        assert_eq!(block.target.rx.size(), block.target.rx.bytes().len());

        // update RO
        Self::merge(&renames, &block.target.ro, &mut self.target.ro);
        assert_eq!(block.target.ro.size(), block.target.ro.bytes().len());

        // update RW
        Self::merge(&renames, &block.target.rw, &mut self.target.rw);
        assert_eq!(block.target.rw.size(), block.target.rw.bytes().len());

        //eprintln!("B: {:?}", (&self.rx));
    }

    pub fn from_section<'a, 'b, A: elf::FileHeader, B: object::ReadRef<'a>>(
        &mut self,
        b: &elf::ElfFile<'a, A, B>,
        section: &elf::ElfSection<'a, 'b, A, B>,
    ) -> Result<(), Box<dyn Error>> {
        let kind = ReadSectionKind::new_section_kind(section.kind());
        let base = match kind {
            ReadSectionKind::Bss => self.target.bss.size(),
            ReadSectionKind::RX => self.target.rx.size(),
            ReadSectionKind::ROData => self.target.ro.size(),
            ReadSectionKind::RW => self.target.rw.size(),
            _ => unimplemented!(),
        } as u64;

        let mut count = 0;
        for symbol in b.symbols() {
            count += 1;
            // skip the null symbol
            if symbol.kind() == object::SymbolKind::Null {
                continue;
            }
            if symbol.kind() == object::SymbolKind::File {
                continue;
            }

            if symbol.section_index() == Some(section.index()) {
                let s = read_symbol(&b, base, &symbol)?;
                log::debug!("Read: {:?}", &s);

                if s.bind == SymbolBind::Local {
                    // can't be local and unknown
                    //if symbol.kind() == SymbolKind::Unknown {
                    //unreachable!("{:?}", s);
                    //}
                    self.target.insert_local(s.clone());
                } else if s.section == ReadSectionKind::Undefined {
                    //block.insert_unknown(s);
                } else {
                    self.target.insert_export(s.clone());
                }
            }
        }
        eprintln!("{} symbols read from {}", count, section.name()?);

        match kind {
            ReadSectionKind::Bss => {
                self.target.bss.from_section(b, section)?;
            }
            ReadSectionKind::RX => {
                self.target.rx.from_section(b, section)?;
            }
            ReadSectionKind::ROData => {
                self.target.ro.from_section(b, section)?;
            }
            ReadSectionKind::RW => {
                self.target.rw.from_section(b, section)?;
            }
            _ => unimplemented!(),
        }
        Ok(())
    }

    pub fn dump(&self) {
        eprintln!("Block: {}", &self.name);
        self.target.dump();
    }
}

pub fn write<Elf: object::read::elf::FileHeader<Endian = object::Endianness>>(
    block: ReadBlock,
    data: &mut Data,
    path: &Path,
) -> Result<(), Box<dyn Error>> {
    let mut out_data = Vec::new();
    let endian = object::Endianness::Little;
    let mut writer = object::write::elf::Writer::new(endian, data.is_64(), &mut out_data);
    block.build_strings(data, &mut writer);
    let mut blocks = Blocks::new(data, &mut writer);
    blocks.build(data, &mut writer);
    let size = out_data.len();
    std::fs::write(path, out_data)?;
    eprintln!("Wrote {} bytes to {}", size, path.to_string_lossy());
    Ok(())
}

pub fn dump_hash(data: &[u8]) {
    eprintln!("Hash");
    let x: Vec<u32> = data
        .chunks(4)
        .map(|u| u32::from_le_bytes(u.try_into().unwrap()))
        .collect();
    let buckets = x[0];
    let chains = x[1];
    eprintln!("Buckets: {:#04x}", buckets);
    eprintln!("Chains:  {:#04x}", chains);

    let b = &x.as_slice()[2..(2 + buckets as usize)];
    let c = &x.as_slice()[(2 + buckets as usize)..];

    for (i, u) in b.iter().enumerate() {
        eprintln!("B: {:#0x}: {:#0x}", i, u);
    }

    for (i, u) in c.iter().enumerate() {
        eprintln!("C: {:#0x}: {:#0x}", i, u);
    }
}

pub fn code_relocation<'a, 'b, A: elf::FileHeader, B: object::ReadRef<'a>>(
    b: &elf::ElfFile<'a, A, B>,
    r: LinkRelocation,
    offset: usize,
) -> Result<CodeRelocation, Box<dyn Error>> {
    let name = match r.target {
        RelocationTarget::Section(index) => {
            let section = b.section_by_index(index)?;
            section.name()?.to_string()
        }
        RelocationTarget::Symbol(index) => {
            let symbol = b.symbol_by_index(index)?;
            let name = if symbol.kind() == SymbolKind::Section {
                let section = b.section_by_index(symbol.section_index().unwrap())?;
                section.name()?.to_string()
            } else {
                symbol.name()?.to_string()
            };
            name
        }
        _ => unreachable!(),
    };
    Ok(CodeRelocation {
        name,
        name_id: None,
        offset: offset as u64,
        r,
    })
}

pub fn read_symbol<'a, 'b, A: elf::FileHeader, B: object::ReadRef<'a>>(
    b: &elf::ElfFile<'a, A, B>,
    base: u64,
    symbol: &elf::ElfSymbol<'a, 'b, A, B>,
) -> Result<ReadSymbol, Box<dyn Error>> {
    let section_kind;

    let address = base + symbol.address();
    let size = symbol.size();

    let name = if symbol.kind() == SymbolKind::Section {
        let section = b.section_by_index(symbol.section_index().unwrap())?;
        section_kind = ReadSectionKind::new_section_kind(section.kind());
        section.name()?.to_string()
    } else {
        if let Some(section_index) = symbol.section_index() {
            let section = b.section_by_index(section_index)?;
            section_kind = ReadSectionKind::new_section_kind(section.kind());
        } else {
            section_kind = ReadSectionKind::Undefined;
        }
        symbol.name()?.to_string()
    };

    let pointer = section_kind.pointer(address);

    let bind = if symbol.is_local() {
        SymbolBind::Local
    } else if symbol.is_global() {
        SymbolBind::Global
    } else if symbol.is_weak() {
        SymbolBind::Weak
    } else {
        unreachable!()
    };

    Ok(ReadSymbol {
        name,
        //name_id: None,
        //dyn_name_id: None,
        section: section_kind,
        kind: symbol.kind(),
        bind,
        pointer,
        size,
        source: SymbolSource::Static,
        //lookup: SymbolLookupTable::None,
    })
}
//pub fn write<Elf: object::read::elf::FileHeader<Endian = object::Endianness>>(

pub fn dump_header<'a>(
    b: &elf::ElfFile<'a, FileHeader64<object::Endianness>>,
    //b: &elf::ElfFile<'a, A, B>,
) -> Result<(), Box<dyn Error>> {
    let endian = b.endian();

    let h = b.raw_header();
    eprintln!("{:?}", h);
    eprintln!("e_entry: {:#0x}", h.e_entry.get(endian));
    eprintln!("e_phoff: {:#0x}", h.e_phoff.get(endian));
    eprintln!("e_phnum: {:#0x}", h.e_phnum.get(endian));
    for seg in b.raw_segments() {
        eprintln!("Segment");
        eprintln!("  p_type:   {:#0x}", seg.p_type(endian));
        eprintln!("  p_flags {:#0x}", seg.p_flags(endian));
        eprintln!("  p_offset {:#0x}", seg.p_offset(endian));
        eprintln!("  p_vaddr {:#0x}", seg.p_vaddr(endian));
        eprintln!("  p_paddr {:#0x}", seg.p_paddr(endian));
        eprintln!("  p_filesz: {:#0x}", seg.p_filesz(endian));
        eprintln!("  p_memsz:  {:#0x}", seg.p_memsz(endian));
        eprintln!("  p_align {:#0x}", seg.p_align(endian));
        //let _offset = seg.p_offset(endian) as usize;
        //let _size = seg.p_filesz(endian) as usize;
    }
    Ok(())
}
