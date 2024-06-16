use super::*;
use crate::format::*;
use object::write::elf::{SectionIndex, Writer};
use object::write::StringId;
use object::SymbolKind;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ProgramHeaderEntry {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

pub(crate) struct Library {
    //pub(crate) name: String,
    pub(crate) string_id: Option<StringId>,
}

#[derive(Eq, Hash, PartialEq, Debug)]
pub enum AddressKey {
    SectionIndex(SectionIndex),
    Section(String),
    PltGot(String),
}

#[derive(Default)]
pub struct TrackSection {
    pub size: Option<usize>,
    pub addr: Option<u64>,
    pub section_index: Option<SectionIndex>,
}

pub struct Data {
    pub interp: String,
    pub(crate) lib_names: Vec<String>,
    pub(crate) libs: Vec<Library>,
    pub dynamics: Dynamics,
    pub statics: Statics,
    debug: HashSet<DebugFlag>,
    pub ph: Vec<ProgramHeaderEntry>,

    pub addr: HashMap<AddressKey, u64>,
    pub pointers: HashMap<String, ResolvePointer>,
    pub section_index: HashMap<String, SectionIndex>,
    pub(crate) segments: SegmentTracker,
    pub(crate) dynstr: TrackSection,
    pub(crate) dynsym: TrackSection,
    pub(crate) reladyn: TrackSection,
    pub(crate) relaplt: TrackSection,
    pub(crate) hash: TrackSection,
    pub(crate) symtab: TrackSection,
    pub(crate) section_dynamic: TrackSection,
    //pub target: Target,
}

impl Data {
    pub fn new(lib_names: Vec<String>) -> Self {
        Self {
            // default gnu loader
            interp: "/lib64/ld-linux-x86-64.so.2".to_string(),
            lib_names,
            libs: vec![],
            ph: vec![],
            addr: HashMap::new(),
            section_index: HashMap::new(),
            segments: SegmentTracker::new(0x800000),
            dynstr: TrackSection::default(),
            dynsym: TrackSection::default(),
            reladyn: TrackSection::default(),
            relaplt: TrackSection::default(),
            hash: TrackSection::default(),
            symtab: TrackSection::default(),
            section_dynamic: TrackSection::default(),
            pointers: HashMap::new(),

            debug: HashSet::new(),

            // Tables
            dynamics: Dynamics::new(),
            statics: Statics::new(),
            //target: Target::new(),
        }
    }

    pub fn debug_enabled(&self, f: &DebugFlag) -> bool {
        self.debug.contains(f)
    }

    pub fn interp(mut self, interp: String) -> Self {
        self.interp = interp;
        self
    }

    pub(crate) fn is_dynamic(&self) -> bool {
        self.lib_names.len() > 0
    }

    pub fn pointer_set(&mut self, name: String, p: u64) {
        self.pointers.insert(name, ResolvePointer::Resolved(p));
    }

    pub fn pointer_get(&self, name: &str) -> u64 {
        self.pointers
            .get(name)
            .expect(&format!("Pointer not found: {}", name))
            .resolve(self)
            .expect(&format!("Pointer unresolved: {}", name))
    }

    pub fn addr_get_by_name(&self, name: &str) -> Option<u64> {
        self.addr
            .get(&AddressKey::Section(name.to_string()))
            .cloned()
    }

    pub fn addr_get_by_index(&self, index: SectionIndex) -> Option<u64> {
        self.addr.get(&AddressKey::SectionIndex(index)).cloned()
    }

    pub fn addr_get(&self, name: &str) -> u64 {
        *self
            .addr
            .get(&AddressKey::Section(name.to_string()))
            .expect(&format!("Address not found: {}", name))
    }

    pub fn addr_set(&mut self, name: &str, value: u64) {
        self.addr
            .insert(AddressKey::Section(name.to_string()), value);
    }

    pub fn section_index_get(&self, name: &str) -> SectionIndex {
        *self
            .section_index
            .get(name)
            .expect(&format!("Section Index not found: {}", name))
    }

    pub fn section_index_set(&mut self, name: &str, section_index: SectionIndex) {
        self.section_index.insert(name.to_string(), section_index);
    }

    pub fn write_strings(data: &mut Data, target: &Target, w: &mut Writer) {
        // add libraries if they are configured
        data.libs = data
            .lib_names
            .iter()
            .map(|name| {
                // hack to deal with string lifetimes
                unsafe {
                    let buf = extend_lifetime(name.as_bytes());
                    //let buf = name.as_bytes();
                    Library {
                        //name: name.clone(),
                        string_id: Some(w.add_dynamic_string(buf)),
                    }
                }
            })
            .collect();

        for (name, symbol) in target.exports.iter() {
            // allocate string for the symbol table
            let _string_id = data.statics.string_add(name, w);
            data.pointers
                .insert(name.to_string(), symbol.pointer.clone());
            let section_index = symbol.section.section_index(data);
            data.statics.symbol_add(symbol, section_index, w);
        }
    }

    pub(crate) fn write_relocations(&mut self, target: &Target, w: &mut Writer) {
        let iter = target
            .ro
            .relocations()
            .iter()
            .chain(target.rw.relocations().iter())
            .chain(target.rx.relocations().iter())
            .chain(target.bss.relocations().iter());

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
            if let Some(s) = target.lookup(&r.name) {
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
                    self.dynamics.relocation_add(&s, assign, r, w);
                } else if def != CodeSymbolDefinition::Local {
                    log::debug!("reloc2 {}", &r);
                    if assign == GotPltAssign::None {
                    } else {
                        self.dynamics.relocation_add(&s, assign, r, w);
                    }
                } else {
                    log::debug!("reloc3 {}", &r);
                }
            } else {
                unreachable!("Unable to find symbol for relocation: {}", &r.name)
            }
        }
    }

    pub(crate) fn update_data(&mut self, target: &Target) {
        for (name, _, pointer) in self.dynamics.symbols() {
            self.pointers.insert(name, pointer);
        }

        for (name, symbol) in target.locals.iter() {
            match symbol.section {
                ReadSectionKind::RX
                //| ReadSectionKind::ROStrings
                | ReadSectionKind::ROData
                | ReadSectionKind::RW
                | ReadSectionKind::Bss => {
                    self.pointers
                        .insert(name.to_string(), symbol.pointer.clone());
                }
                _ => (),
            }
        }

        // Add static symbols to data
        let locals = vec!["_DYNAMIC"];
        for symbol_name in locals {
            let s = target.lookup_static(symbol_name).unwrap();
            self.pointers.insert(s.name, s.pointer);
        }
    }

    pub fn write(
        data: Data,
        target: Target,
        path: &Path,
        config: &AOTConfig,
    ) -> Result<(), Box<dyn Error>> {
        let mut out_data = Vec::new();
        let endian = object::Endianness::Little;
        let mut writer = object::write::elf::Writer::new(endian, config.is_64(), &mut out_data);
        Blocks::build(data, target, &mut writer, config);
        let size = out_data.len();
        std::fs::write(path, out_data)?;
        eprintln!("Wrote {} bytes to {}", size, path.to_string_lossy());
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum ResolvePointer {
    Resolved(u64),
    Section(String, u64),
    Got(usize),
    GotPlt(usize),
    Plt(usize),
    PltGot(usize),
}

impl fmt::Display for ResolvePointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Resolved(p) => write!(f, "Abs({:#0x})", p),
            Self::Section(name, p) => write!(f, "Section({},{:#0x})", name, p),
            _ => write!(f, "{:?}", self),
        }
    }
}

impl ResolvePointer {
    pub fn relocate(self, base: u64) -> Self {
        match self {
            Self::Section(section_name, offset) => Self::Section(section_name, offset + base),
            Self::Resolved(address) => Self::Resolved(address + base),
            _ => unimplemented!("{:?}", self),
        }
    }

    pub fn resolve(&self, data: &Data) -> Option<u64> {
        //eprintln!("X: {:?}", self);
        //eprintln!("X: {:?}", &data.addr);
        match self {
            Self::Resolved(x) => Some(*x),
            Self::Section(section_name, offset) => {
                if let Some(base) = data
                    .addr
                    .get(&AddressKey::Section(section_name.to_string()))
                {
                    Some(base + offset)
                } else {
                    None
                }
            }

            Self::Got(index) => {
                if let Some(base) = data.addr_get_by_name(".got") {
                    let size = std::mem::size_of::<usize>() as u64;
                    Some(base + (*index as u64) * size)
                } else {
                    None
                }
            }

            Self::GotPlt(index) => {
                if let Some(base) = data.addr_get_by_name(".got.plt") {
                    let size = std::mem::size_of::<usize>() as u64;
                    // first 3 entries in the got.plt are already used
                    Some(base + (*index as u64 + 3) * size)
                } else {
                    None
                }
            }

            Self::Plt(index) => {
                if let Some(base) = data.addr_get_by_name(".plt") {
                    // each entry in small model is 0x10 in size
                    let size = 0x10;
                    // skip the stub (+1)
                    Some(base + (*index as u64 + 1) * size)
                } else {
                    None
                }
            }

            Self::PltGot(index) => {
                if let Some(base) = data.addr_get_by_name(".plt.got") {
                    // each entry in small model is 0x8 in size
                    let size = 0x08;
                    Some(base + (*index as u64 * size))
                } else {
                    None
                }
            }
        }
    }
}
