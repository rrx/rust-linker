use super::*;
use crate::format;
use crate::format::*;
use object::read::elf;
use object::write::elf::{SectionIndex, Writer};
use object::write::StringId;
use object::ObjectSection;
use object::SymbolKind;

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
}

#[derive(Debug, Clone)]
pub struct GeneralSection {
    state: BlockSectionState,
    pub(crate) name: &'static str,
    pub(crate) name_id: Option<StringId>,
    pub(crate) section_index: Option<SectionIndex>,
    pub(crate) bytes: Vec<u8>,
    pub(crate) relocations: Vec<CodeRelocation>,
    pub(crate) offsets: SectionOffset,
}

impl BlockSection for GeneralSection {
    fn size(&self) -> usize {
        self.offsets.size as usize
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
        self.offsets.size += s as u64;
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

    fn reserve_section_index(&mut self, data: &mut Data, w: &mut Writer) {
        self.name_id = Some(w.add_section_name(self.name.as_bytes()));
        let index = w.reserve_section_index();
        self.section_index = Some(index);
        data.section_index_set(&self.name, index);
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        let file_offset = w.reserve_start_section(&self.offsets);
        w.reserve(self.bytes.len(), 1);
        let after = w.reserved_len();
        let size = after - file_offset;
        self.offsets.size = size as u64;

        data.segments
            .add_offsets(self.offsets.alloc, &mut self.offsets);
        data.addr_set(&self.name, self.offsets.address);
        self.state = BlockSectionState::Located;
    }

    fn write(&self, data: &Data, w: &mut Writer) {
        w.write_start_section(&self.offsets);
        apply_relocations(self, data, false);
        w.write(self.bytes.as_slice());
    }

    fn write_section_header(&self, _: &Data, w: &mut Writer) {
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
                sh_size: self.offsets.size as u64,
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
            bytes: vec![],
            relocations: vec![],
            offsets: SectionOffset::new(name.into(), alloc, align),
        }
    }

    pub fn from_section<'a, 'b, A: elf::FileHeader, B: object::ReadRef<'a>>(
        &mut self,
        kind: ReadSectionKind,
        b: &elf::ElfFile<'a, A, B>,
        section: &elf::ElfSection<'a, 'b, A, B>,
    ) -> Result<(), Box<dyn Error>> {
        let data = section.uncompressed_data()?;
        let base_offset = self.size();
        log::debug!("name: {}, {}", section.name()?, kind.section_name());
        self.extend_size(data.len());
        self.extend_bytes(&data);
        for (offset, r) in section.relocations() {
            let r = code_relocation(kind, b, section, r.into(), base_offset + offset as usize)?;
            self.relocations.push(r);
        }
        Ok(())
    }
}

pub(crate) fn write_relocations(data: &mut Data, target: &Target, w: &mut Writer) {
    // add the relocations to the sets
    // we only want to add a relocation to either got or gotplt
    // if it's being added to got, then only add it to got
    // with entries in the got and gotplt, we then apply relocations
    // to point to the appropriate got and gotplt entries
    let iter = target
        .ro
        .relocations()
        .iter()
        .chain(target.rw.relocations().iter())
        .chain(target.rx.relocations().iter())
        .chain(target.bss.relocations().iter());

    for r in iter {
        /*
        let symbol = target
            .lookup(&r.name)
            .expect(&format!("Missing {}", &r.name));
        eprintln!("S: {:?}", symbol);
        */
        log::info!("r {:?}", (&r, target.lookup_dynamic(&r.name)));

        if let Some(mut s) = target.lookup_dynamic(&r.name) {
            if r.r.kind() == object::RelocationKind::Absolute && !s.is_static() {
                let p = ResolvePointer::Section(r.section_name.clone(), r.offset);
                log::info!("reloc0a {}, {:?}, {}", &r, s.bind, p);
                s.pointer = p;
            }

            data.dynamics.relocation_add_write(&s, r, w);
            data.symbols.insert(s.name.clone(), s.clone());
            log::info!("reloc0 {}, {:?}, {}", &r, s.bind, s.pointer);
            let symbol = target
                .lookup(&r.name)
                .expect(&format!("Missing {}", &r.name));
            eprintln!("S: {:?}", symbol);

            continue;
        }

        // static plt relatives
        if let Some(s) = target.lookup_static(&r.name) {
            let symbol = target
                .lookup(&r.name)
                .expect(&format!("Missing {}", &r.name));
            eprintln!("S: {:?}", symbol);

            if r.is_plt() {
                log::info!("reloc1 {}, {:?}, {:?}", &r, s.bind, s.pointer);
                //continue;
            } else {
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
                        } else if r.effect() == format::PatchEffect::AddToGot {
                            if r.is_plt() {
                                GotPltAssign::GotWithPltGot
                            } else {
                                GotPltAssign::Got
                            }
                        } else if r.effect() == format::PatchEffect::AddToPlt {
                            GotPltAssign::GotPltWithPlt
                        } else {
                            GotPltAssign::None
                        }
                    }
                    SymbolKind::Data => GotPltAssign::Got,
                    _ => GotPltAssign::None,
                };

                if s.source == SymbolSource::Dynamic {
                    unreachable!();
                } else if def != CodeSymbolDefinition::Local {
                    log::info!("reloc3 {}, bind: {:?}, {:?}", &r, s.bind, s.pointer);
                    if assign == GotPltAssign::None {
                    } else {
                        data.dynamics.relocation_add_write(&s, r, w);
                    }
                } else {
                    log::info!("reloc4 {}, bind: {:?}, {:?}", &r, s.bind, s.pointer);
                }
            }
        } else {
            unreachable!("Unable to find symbol for relocation: {}", &r.name)
        }
    }
}

pub fn apply_relocations(section: &GeneralSection, data: &Data, preload: bool) {
    let patch_base = section.bytes.as_ptr();
    for r in section.relocations.iter() {
        if let Some(symbol) = data.symbols.get(&r.name) {
            log::info!(target: "relocations", "{}: {:?}", &r.name, (symbol, r.is_plt(), r.is_got()));
            log::info!(target: "relocations", "{}: {:?}", &r.name, r);
            r.patch(
                data,
                &symbol,
                patch_base as *mut u8,
                section.offsets.address as *mut u8,
                preload,
            );
        } else {
            unreachable!("Unable to locate symbol: {}, {}", &r.name, &r);
        }
    }

    //if data.debug_enabled(&DebugFlag::Disassemble) {
    section.disassemble(data);
    //}
}
