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
}

pub struct BuildPltSection {}

impl BuildPltSection {
    pub fn size(data: &Data) -> usize {
        let plt_entries_count = data.dynamics.plt_objects().len();
        // length + 1, to account for the stub.  Each entry is 0x10 in size
        (1 + plt_entries_count) * 0x10
    }

    pub fn align(data: &Data) -> usize {
        0x10
    }

    pub fn contents(data: &Data, base: usize) -> Vec<u8> {
        let got_addr = data.addr_get_by_name(".got.plt").unwrap() as isize;
        let vbase = base as isize;

        // PLT START
        let mut stub: Vec<u8> = vec![
            // 0x401020: push   0x2fe2(%rip)        # 404008 <_GLOBAL_OFFSET_TABLE_+0x8>
            // got+8 - rip // (0x404000+0x8) - (0x401020 + 0x06)
            0xff, 0x35, 0xe2, 0x2f, 0x00, 0x00,
            // 0x401026: jump to GOT[2]
            // jmp    *0x2fe4(%rip)        # 404010 <_GLOBAL_OFFSET_TABLE_+0x10>
            0xff, 0x25, 0xe4, 0x2f, 0x00, 0x00,
            // 40102c:       0f 1f 40 00             nopl   0x0(%rax)
            0x0f, 0x1f, 0x40, 0x00,
        ];

        let got1 = got_addr + 0x8 - (vbase + 0x06);
        let b = (got1 as i32).to_le_bytes();
        stub.as_mut_slice()[2..6].copy_from_slice(&b);

        let got2 = got_addr + 0x10 - (vbase + 0x0c);
        let b = (got2 as i32).to_le_bytes();
        stub.as_mut_slice()[8..12].copy_from_slice(&b);

        let plt_entries_count = data.dynamics.plt_objects().len();

        for slot_index in 0..plt_entries_count {
            // PLT ENTRY
            let mut slot: Vec<u8> = vec![
                // # 404018 <puts@GLIBC_2.2.5>, .got.plot 4th entry, GOT[3], jump there
                // # got.plt[3] = 0x401036, initial value,
                // which points to the second instruction (push) in this plt entry
                // # the dynamic linker will update GOT[3] with the actual address, so this lookup only happens once
                // 401030:       ff 25 e2 2f 00 00       jmp    *0x2fe2(%rip)        # 404018 <puts@GLIBC_2.2.5>
                0xff, 0x25, 0xe2, 0x2f, 0x00, 0x00,
                // # push plt index onto the stack
                // # this is a reference to the entry in the relocation table defined by DT_JMPREL (.rela.plt)
                // # that reloc will have type R_X86_64_JUMP_SLOT
                // # the reloc will have an offset that points to GOT[3], 0x404018 = BASE + 3*0x08
                // 401036:       68 00 00 00 00          push   $0x0
                0x68, 0x00, 0x00, 0x00, 0x00,
                // # jump to stub, which is (i+2)*0x10 relative to rip
                // 40103b:       e9 e0 ff ff ff          jmp    401020 <_init+0x20>,
                0xe9, 0xe0, 0xff, 0xff, 0xff,
            ];

            let offset = (slot_index + 1) * 0x10;

            // pointer to .got.plt entry
            let rip = vbase + offset as isize + 6;
            let addr = got_addr + (3 + slot_index as isize) * 0x08 - rip;
            let range = 2..6;
            slot.as_mut_slice()[range].copy_from_slice(&(addr as i32).to_le_bytes());

            // slot index
            let range = 7..11;
            slot.as_mut_slice()[range].copy_from_slice(&(slot_index as i32).to_le_bytes());

            // next instruction
            let rip = vbase + offset as isize + 0x10;
            let addr = vbase as isize - rip; //self.section.offsets.address as isize - rip;
            let range = 0x0c..0x0c + 4;
            slot.as_mut_slice()[range].copy_from_slice(&(addr as i32).to_le_bytes());

            stub.extend(slot);
        }
        stub
    }
}

impl Data {
    pub fn new() -> Self {
        Self {
            // default gnu loader
            interp: "/lib64/ld-linux-x86-64.so.2".to_string(),
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
        }
    }

    pub fn debug_enabled(&self, f: &DebugFlag) -> bool {
        self.debug.contains(f)
    }

    pub fn interp(mut self, interp: String) -> Self {
        self.interp = interp;
        self
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

    pub fn write_exports(data: &mut Data, exports: &SymbolMap, w: &mut Writer) {
        println!("ADD EXPORTS");
        for (name, symbol) in exports.iter() {
            data.pointers
                .insert(name.to_string(), symbol.pointer.clone());
            let section_index = symbol.section.section_index(data);
            data.statics.symbol_add(symbol, section_index, w);
        }
    }

    pub fn write_strings(data: &mut Data, target: &mut Target, w: &mut Writer) {
        // These need to be declared
        let locals = vec![("_DYNAMIC", ".dynamic")];

        for (symbol_name, section_name) in locals {
            let symbol_name = symbol_name.to_string();
            let section_name = section_name.to_string();
            let pointer = ResolvePointer::Section(section_name, 0);
            let symbol = ReadSymbol::from_pointer(symbol_name, pointer);
            target.insert_local(symbol);
        }

        // write strings first
        for (name, _) in target.exports.iter() {
            // allocate string for the symbol table
            let _string_id = data.statics.string_add(name, w);
        }

        // add libraries if they are configured
        data.libs = target
            .libs
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
            if let Some(s) = target.lookup_dynamic(&r.name) {
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
                    _ => GotPltAssign::None,
                };

                let pointer = self.dynamics.relocation_add(&s, assign, r, w);
                log::info!("reloc0 {}, {:?}, {:?}, {:?}", &r, assign, s.bind, pointer);
                continue;
            }

            // static plt relatives
            if let Some(s) = target.lookup_static(&r.name) {
                if r.is_plt() {
                    log::info!("reloc1 {}, {:?}, {:?}", &r, s.bind, s.pointer);
                    continue;
                }
            } else {
                unreachable!("Unable to find symbol for relocation: {}", &r.name);
            }

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
                    _ => GotPltAssign::None,
                };

                if s.source == SymbolSource::Dynamic {
                    log::info!("reloc2 {}", &r);
                    self.dynamics.relocation_add(&s, assign, r, w);
                } else if def != CodeSymbolDefinition::Local {
                    log::info!("reloc3 {}, bind: {:?}, {:?}", &r, s.bind, s.pointer);
                    if assign == GotPltAssign::None {
                    } else {
                        self.dynamics.relocation_add(&s, assign, r, w);
                    }
                } else {
                    log::info!("reloc4 {}, bind: {:?}, {:?}", &r, s.bind, s.pointer);
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
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).unwrap();
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
