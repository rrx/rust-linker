use object::elf;
use object::{
    Object, ObjectSection, ObjectSymbol, ObjectSymbolTable, RelocationTarget, SectionKind,
    SymbolFlags, SymbolKind, SymbolScope, SymbolSection,
};

use std::error::Error;
use std::fmt;
use std::sync::Arc;

use std::collections::HashMap;

use super::*;

#[derive(Clone, Debug, PartialEq)]
pub enum CodeSymbolDefinition {
    Extern,
    Defined,
    Local,
}

#[derive(Clone, Debug, PartialEq)]
pub enum CodeSymbolKind {
    Text,
    Data,
    Section,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct CodeSymbol {
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) address: u64,
    pub(crate) kind: CodeSymbolKind,
    pub(crate) def: CodeSymbolDefinition,
    pub(crate) st_info: u8,
    pub(crate) st_other: u8,
}

pub enum SymbolType {
    Func,
    Object,
    Notype,
}

impl CodeSymbol {
    pub fn get_type(&self) -> SymbolType {
        //eprintln!("s: {:?}", self);
        match self.st_info & 0x0f {
            elf::STT_FUNC => SymbolType::Func,
            elf::STT_NOTYPE => SymbolType::Notype,
            elf::STT_OBJECT => SymbolType::Object,
            _ => unimplemented!(),
        }
    }
}

impl fmt::Display for CodeSymbol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Symbol addr: {:6}, size: {:6}, kind: {:?}, def: {:?}: {}",
            self.address, self.size, self.kind, self.def, self.name
        )
    }
}

pub struct GotEntry {}

pub struct PltEntry {}

pub type UnlinkedCodeSegment = Arc<UnlinkedCodeSegmentInner>;

pub struct UnlinkedCodeSegmentInner {
    pub(crate) name: String,
    pub(crate) kind: SectionKind,
    pub(crate) section_name: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) defined: im::HashMap<String, CodeSymbol>,
    pub(crate) internal: im::HashMap<String, CodeSymbol>,
    pub(crate) externs: im::HashMap<String, CodeSymbol>,
    pub(crate) relocations: Vec<CodeRelocation>,
    pub(crate) symbols: Vec<CodeSymbol>,
}

impl UnlinkedCodeSegmentInner {
    pub fn read_archive(archive_name: &str, buf: &[u8]) -> Result<Vec<Self>, Box<dyn Error>> {
        log::debug!("Archive: {}", archive_name);
        let archive = object::read::archive::ArchiveFile::parse(buf)?;
        log::debug!(
            "Archive: {}, size: {}, kind: {:?}",
            archive_name,
            buf.len(),
            archive.kind()
        );
        let mut segments = vec![];
        for result in archive.members() {
            let m = result?;
            let name = std::str::from_utf8(&m.name())?;
            let (offset, size) = m.file_range();
            let obj_buf = &buf[offset as usize..(offset + size) as usize];
            log::debug!("Member: {}, {:?}", &name, &m);
            segments.extend(Self::create_segments(name, obj_buf)?);
        }
        Ok(segments)
    }

    pub fn create_segments_elf(_link_name: &str, buf: &[u8]) -> Result<Vec<Self>, Box<dyn Error>> {
        use object::elf::FileHeader64;
        use object::read::elf;
        let b: elf::ElfFile<'_, FileHeader64<object::Endianness>> =
            object::read::elf::ElfFile::parse(buf)?;

        let symbol_table = b.symbol_table().unwrap();
        //let mut symbols = vec![];
        let mut relocations = vec![];
        for section in b.sections() {
            let _section_name = section.name()?.to_string();
            match section.kind() {
                SectionKind::Text => {}
                _ => unimplemented!(),
            }

            for (reloc_offset, r) in section.relocations() {
                let symbol = if let RelocationTarget::Symbol(symbol_index) = r.target() {
                    symbol_table.symbol_by_index(symbol_index)?
                } else {
                    // relocation must be associated with a symbol
                    unimplemented!()
                };
                let name = symbol.name()?.to_string();

                match (symbol.kind(), symbol.scope()) {
                    (_, SymbolScope::Dynamic | SymbolScope::Unknown | SymbolScope::Linkage) => {
                        relocations.push(CodeRelocation {
                            name,
                            name_id: None,
                            offset: reloc_offset,
                            r: r.into(),
                        });
                    }

                    (SymbolKind::Data, SymbolScope::Compilation) => {
                        relocations.push(CodeRelocation {
                            name,
                            name_id: None,
                            offset: reloc_offset,
                            r: r.into(),
                        });
                    }

                    (SymbolKind::Section, SymbolScope::Compilation) => {
                        // if the relocation references a section, then look up the section
                        // name
                        let section_index = symbol.section().index().unwrap();
                        let section = b.section_by_index(section_index)?;
                        let name = section.name()?.to_string();
                        relocations.push(CodeRelocation {
                            name,
                            name_id: None,
                            offset: reloc_offset,
                            r: r.into(),
                        });
                    }
                    _ => unimplemented!("{:?}", symbol),
                }
            }
            for r in &relocations {
                log::debug!("  {}", r);
            }

            //let name = format!("{}{}", link_name, section_name);
            let data = section.uncompressed_data()?;

            // for bss, we have empty data, so we pass in a zero initialized buffer
            // to be consistent
            let _bytes = if section.size() as usize > data.len() {
                let mut data = Vec::new();
                data.resize(section.size() as usize, 0);
                data
            } else {
                data.to_vec()
            };
        }
        Ok(vec![])
    }

    pub fn create_segments(link_name: &str, buf: &[u8]) -> Result<Vec<Self>, Box<dyn Error>> {
        log::debug!("Segment: {}, size: {}", link_name, buf.len());
        let obj_file = object::File::parse(buf)?;
        let mut symbols = HashMap::new();
        let mut symbols_by_id = HashMap::new();
        let mut segments = vec![];
        let mut externs = im::HashMap::new();
        let mut internal = im::HashMap::new();

        if let Some(symbol_table) = obj_file.symbol_table() {
            for s in symbol_table.symbols() {
                // only track dynamic symbols for now
                let name = s.name()?.to_string();
                let maybe_section = match s.section() {
                    SymbolSection::Section(section_index) => {
                        Some(obj_file.section_by_index(section_index)?)
                    }
                    _ => None,
                };

                let section_name = maybe_section.as_ref().map(|section| {
                    section
                        .name()
                        .map_or("".to_string(), |n| n.to_string())
                        .to_string()
                });

                log::debug!(
                    " Symbol[{}, {:20}, address: {:#04x}, size: {}, kind: {:?}, scope: {:?}, weak: {}, section: {:?}]",
                    s.index().0,
                    &name,
                    s.size(),
                    s.address(),
                    s.kind(),
                    s.scope(),
                    s.is_weak(),
                    section_name,
                );

                let maybe_code_symbol = match &maybe_section {
                    Some(section) => {
                        let section_start = section.address();
                        let address = s.address() - section_start;
                        match (s.scope(), s.kind()) {
                            (SymbolScope::Dynamic | SymbolScope::Linkage, SymbolKind::Text) => {
                                if let SymbolFlags::Elf { st_info, st_other } = s.flags() {
                                    Some(CodeSymbol {
                                        name,
                                        address,
                                        size: s.size(),
                                        kind: CodeSymbolKind::Text,
                                        def: CodeSymbolDefinition::Defined,
                                        st_info,
                                        st_other,
                                    })
                                } else {
                                    unimplemented!()
                                }
                            }

                            (SymbolScope::Dynamic, SymbolKind::Unknown) => {
                                let kind = match section.kind() {
                                    SectionKind::Text => CodeSymbolKind::Text,
                                    SectionKind::Data => CodeSymbolKind::Data,
                                    SectionKind::ReadOnlyData => CodeSymbolKind::Data,
                                    // XXX:
                                    _ => continue,
                                };

                                if let SymbolFlags::Elf { st_info, st_other } = s.flags() {
                                    Some(CodeSymbol {
                                        name,
                                        address,
                                        size: s.size(),
                                        kind,
                                        def: CodeSymbolDefinition::Defined,
                                        st_info,
                                        st_other,
                                    })
                                } else {
                                    unimplemented!()
                                }
                            }

                            (
                                SymbolScope::Dynamic | SymbolScope::Linkage,
                                SymbolKind::Data | SymbolKind::Tls,
                            ) => {
                                if let SymbolFlags::Elf { st_info, st_other } = s.flags() {
                                    Some(CodeSymbol {
                                        name,
                                        address,
                                        size: s.size(),
                                        kind: CodeSymbolKind::Data,
                                        def: CodeSymbolDefinition::Defined,
                                        st_info,
                                        st_other,
                                    })
                                } else {
                                    unimplemented!()
                                }
                            }

                            (SymbolScope::Compilation, SymbolKind::Data) => {
                                if let SymbolFlags::Elf { st_info, st_other } = s.flags() {
                                    Some(CodeSymbol {
                                        name,
                                        address,
                                        size: s.size(),
                                        kind: CodeSymbolKind::Data,
                                        def: CodeSymbolDefinition::Defined,
                                        st_info,
                                        st_other,
                                    })
                                } else {
                                    unimplemented!()
                                }
                            }

                            (SymbolScope::Compilation, SymbolKind::Section) => {
                                if let SymbolFlags::Elf { st_info, st_other } = s.flags() {
                                    let name = section.name()?.to_string();
                                    let code_symbol = CodeSymbol {
                                        name: name.clone(),
                                        address,
                                        size: s.size(),
                                        kind: CodeSymbolKind::Section,
                                        def: CodeSymbolDefinition::Defined,
                                        st_info,
                                        st_other,
                                    };
                                    internal.insert(name, code_symbol.clone());
                                    Some(code_symbol)
                                } else {
                                    unimplemented!()
                                }
                            }

                            _ => unimplemented!(
                                "Symbol Scope: {:?}, Kind: {:?}",
                                s.scope(),
                                s.kind()
                            ),
                        }
                    }

                    None => match s.kind() {
                        SymbolKind::Unknown => {
                            //| SymbolKind::Tls => {
                            // external references
                            if let SymbolFlags::Elf { st_info, st_other } = s.flags() {
                                let code_symbol = CodeSymbol {
                                    name: name.clone(),
                                    address: s.address(),
                                    size: s.size(),
                                    kind: CodeSymbolKind::Unknown,
                                    def: CodeSymbolDefinition::Extern,
                                    st_info,
                                    st_other,
                                };
                                eprintln!("Extern: {}, {:?}", &name, &code_symbol);
                                externs.insert(name, code_symbol);
                                None
                            } else {
                                unimplemented!()
                            }
                        }

                        // skip these
                        SymbolKind::Null => None,
                        // we might want to capture the file info later
                        SymbolKind::File => None,
                        _ => unimplemented!(),
                    },
                };

                if let Some(code_symbol) = maybe_code_symbol {
                    symbols.insert(code_symbol.name.clone(), (maybe_section, code_symbol));
                }
                symbols_by_id.insert(s.index().clone(), s);
            }

            for section in obj_file.sections() {
                let section_name = section.name()?.to_string();
                let section_index = section.index().0;
                //let out_symbols = vec![];

                if section_name.starts_with(".eh_frame") {
                    continue;
                }

                log::debug!(
                    " Section[{:?}, {}, address: {}, size: {}, align: {}, kind: {:?}, relocs: {}]",
                    section_index,
                    section_name,
                    section.address(),
                    section.size(),
                    section.align(),
                    section.kind(),
                    section.relocations().count()
                );
                let mut defined = im::HashMap::new();

                let mut section_symbols = vec![];

                for (symbol_name, (maybe_section, code_symbol)) in &symbols {
                    match maybe_section {
                        Some(symbol_section) => {
                            if symbol_section.index() == section.index() {
                                section_symbols.push(code_symbol.clone());
                                if code_symbol.kind == CodeSymbolKind::Section {
                                    //log::debug!("  Internal Symbol[{}] = {:?}", &symbol_name, &code_symbol);
                                    //internal.insert(symbol_name.clone(), code_symbol.clone());
                                } else {
                                    log::debug!(
                                        "  Defined  Symbol[{}] = {:?}",
                                        &symbol_name,
                                        &code_symbol
                                    );
                                    defined.insert(symbol_name.clone(), code_symbol.clone());
                                }
                            }
                        }
                        None => (),
                    }
                }

                let mut relocations = vec![];
                for (reloc_offset, r) in section.relocations() {
                    //r.kind()
                    //log::debug!(" R:{:?}", (&reloc_offset,&r));
                    let symbol = if let RelocationTarget::Symbol(symbol_index) = r.target() {
                        symbol_table.symbol_by_index(symbol_index)?
                    } else {
                        // relocation must be associated with a symbol
                        unimplemented!()
                    };
                    let name = symbol.name()?.to_string();

                    match (symbol.kind(), symbol.scope()) {
                        (_, SymbolScope::Dynamic | SymbolScope::Unknown | SymbolScope::Linkage) => {
                            // | SymbolScope::Linkage | SymbolScope::Unknown => {
                            relocations.push(CodeRelocation {
                                name,
                                name_id: None,
                                offset: reloc_offset,
                                r: r.into(),
                            });
                        }

                        //do nothing here
                        //SymbolScope::Unknown => {
                        //unknowns.insert(name);
                        //}
                        (SymbolKind::Data, SymbolScope::Compilation) => {
                            relocations.push(CodeRelocation {
                                name,
                                name_id: None,
                                offset: reloc_offset,
                                r: r.into(),
                            });
                        }
                        (SymbolKind::Section, SymbolScope::Compilation) => {
                            // if the relocation references a section, then look up the section
                            // name
                            let section_index = symbol.section().index().unwrap();
                            let section = obj_file.section_by_index(section_index)?;
                            let name = section.name()?.to_string();
                            relocations.push(CodeRelocation {
                                name,
                                name_id: None,
                                offset: reloc_offset,
                                r: r.into(),
                            });
                        }
                        _ => unimplemented!("{:?}", symbol),
                    }
                }
                for r in &relocations {
                    log::debug!("  {}", r);
                }

                let name = format!("{}{}", link_name, section_name);
                let data = section.uncompressed_data()?;
                //log::debug!(" data: {}, size: {}", name, data.len());

                // for bss, we have empty data, so we pass in a zero initialized buffer
                // to be consistent
                let bytes = if section.size() as usize > data.len() {
                    let mut data = Vec::new();
                    data.resize(section.size() as usize, 0);
                    data
                } else {
                    data.to_vec()
                };

                segments.push(UnlinkedCodeSegmentInner {
                    name,
                    kind: section.kind(),
                    section_name,
                    bytes,
                    externs: externs.clone(),
                    defined,
                    internal: internal.clone(),
                    symbols: vec![],
                    relocations,
                });
            }
        }

        Ok(segments)
    }

    pub fn create_block(
        &self,
        code_page_name: &str,
        kind: PatchBlockKind,
        symbols: Vec<CodeSymbol>,
        b: &mut BlockFactory,
    ) -> Result<Option<PatchBlock>, Box<dyn Error>> {
        if symbols.len() > 0 {
            let size = self.bytes.len();
            if let Some(block) = b.alloc_block(size) {
                log::debug!(
                    "Block[{:?}]: {}, size: {}",
                    kind,
                    &code_page_name,
                    self.bytes.len()
                );
                for symbol in &symbols {
                    log::debug!(" Symbol: {}", symbol);
                }

                for r in &self.relocations {
                    log::debug!(" Relocation: {}", r);
                }

                // copy code into the block
                block.as_mut_slice()[0..size].copy_from_slice(&self.bytes);

                // for each symbol, add a reference to it's full address
                let mut pointers = HashMap::new();
                let mut internal = HashMap::new();
                let mut externs = HashMap::new();

                let block_ptr = RelocationPointer::Smart(block.offset(0));
                internal.insert(self.section_name.clone(), block_ptr.clone());
                pointers.insert(self.section_name.clone(), block_ptr);

                for s in &symbols {
                    let value_ptr = RelocationPointer::Smart(block.offset(s.address as usize));
                    pointers.insert(s.name.clone(), value_ptr);
                }

                for s in self.internal.values() {
                    let value_ptr = RelocationPointer::Smart(block.offset(s.address as usize));
                    internal.insert(s.name.clone(), value_ptr);
                }

                for s in self.externs.values() {
                    let value_ptr = RelocationPointer::Smart(block.offset(s.address as usize));
                    externs.insert(s.name.clone(), value_ptr);
                }

                Ok(Some(PatchBlock {
                    kind,
                    name: code_page_name.to_string(),
                    block,
                    externs,
                    symbols: pointers,
                    internal,
                    relocations: self.relocations.clone(),
                }))
            } else {
                // oom, throw error
                unimplemented!()
            }
        } else {
            log::debug!(
                "no symbols in {}, size:{}, {:?}",
                code_page_name,
                self.bytes.len(),
                &self.relocations.len()
            );
            Ok(None)
        }
    }
}
