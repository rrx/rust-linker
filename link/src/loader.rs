use crate::aot::{
    apply_relocations,
    BlockSection,
    BuildGotPltSection,
    BuildGotSection,
    BuildPltGotSection,
    BuildPltSection,
    GotPltAssign,
    //GotSectionKind,
    ReadSymbol,
    ResolvePointer,
    SymbolBind,
    SymbolSource,
    Target,
};
use crate::dynamic::{BlockFactoryInner, LinkError, SharedLibraryRepo};
use crate::format;
use crate::{Data, ReadBlock};
use object::SymbolKind;
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;

fn load_block(version: &mut LoaderVersion, target: &mut Target) -> Result<(), Box<dyn Error>> {
    let data = &mut version.data;
    for path in target.libs.iter() {
        let p = Path::new(&path);
        println!("p: {}", p.to_str().unwrap());
        let ext = p.extension().unwrap().to_str().unwrap();
        println!("ext: {}", ext);
        version
            .libraries
            .add_library(p.to_str().unwrap(), &Path::new(&path))?;
    }

    // RW
    let align = 0x10;
    let bss_size = target.bss.size();
    if bss_size > 0 {
        let bss_block = version.rw.alloc_block_align(bss_size, align).unwrap();
        data.addr_set(".bss", bss_block.as_ptr() as u64);
    }

    let rw_size = target.rw.size();
    if rw_size > 0 {
        let mut rw_block = version.rw.alloc_block_align(rw_size, align).unwrap();
        data.addr_set(".data", rw_block.as_ptr() as u64);
        rw_block.copy(target.rw.bytes());
        target.rw.offsets.address = rw_block.as_ptr() as u64;
    }

    // RO
    let ro_size = target.ro.size();
    if ro_size > 0 {
        let mut ro_block = version.ro.alloc_block_align(ro_size, align).unwrap();
        data.addr_set(".rodata", ro_block.as_ptr() as u64);
        ro_block.copy(target.ro.bytes());
        target.ro.offsets.address = ro_block.as_ptr() as u64;
    }

    // RX
    let rx_size = target.rx.size();
    let mut rx_block = version.rx.alloc_block_align(rx_size, align).unwrap();
    data.addr_set(".text", rx_block.as_ptr() as u64);
    let symbol =
        ReadSymbol::from_pointer(".text".into(), ResolvePointer::Section(".text".into(), 0));
    data.symbols.insert(".text".to_string(), symbol);
    target.rx.offsets.address = rx_block.as_ptr() as u64;

    for (name, symbol) in target.exports.iter() {
        eprintln!("ES: {:?}", (name, &symbol));
        let _p = symbol.pointer.resolve(data).unwrap();
        data.symbols.insert(name.clone(), symbol.clone());
    }

    let iter = target
        .rx
        .relocations
        .iter()
        .chain(target.ro.relocations.iter())
        .chain(target.rw.relocations.iter())
        .chain(target.bss.relocations.iter());

    let mut dynamic_lookups = HashMap::new();

    for r in iter.clone() {
        if let Some(_) = dynamic_lookups.get(&r.name) {
            continue;
        }

        if let Some(s) = target.lookup_dynamic(&r.name) {
            let pointer = if let Some(ptr) = version.libraries.search_dynamic(&r.name) {
                let p = ptr.as_ptr() as *const usize;
                log::debug!("Searching Shared {:#08x}:{}", p as usize, &r.name);
                ResolvePointer::Resolved(p as u64)
            } else {
                unimplemented!("dynamic not found: {:?}", s);
            };
            let mut symbol = s.clone();
            symbol.pointer = pointer.clone();

            dynamic_lookups.insert(&r.name, symbol);
        }
    }

    for r in iter {
        if let Some(s) = dynamic_lookups.get(&r.name) {
            let symbol = data.dynamics.save_relocation(s.clone(), r);
            log::info!("reloc0 {}, {:?}, {:?}", &r, symbol.bind, symbol.pointer);
            data.symbols.insert(s.name.clone(), symbol);
            continue;
        }

        // static plt relatives
        if let Some(s) = target.lookup_static(&r.name) {
            data.symbols.insert(s.name.clone(), s.clone());
            if r.is_plt() {
                log::info!("reloc1 {}, {:?}, {:?}", &r, s.bind, s.pointer);
                let _p = s.pointer.resolve(data).unwrap();
                continue;
            }

            let def = match s.bind {
                SymbolBind::Local => format::CodeSymbolDefinition::Local,
                SymbolBind::Global => format::CodeSymbolDefinition::Defined,
                SymbolBind::Weak => format::CodeSymbolDefinition::Defined,
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
            } else if def != format::CodeSymbolDefinition::Local {
                log::info!("reloc3 {}, bind: {:?}, {:?}", &r, s.bind, s.pointer);
                if assign == GotPltAssign::None {
                } else {
                    data.dynamics.relocation_add(&s, r);
                }
            } else {
                log::info!("reloc4 {}, bind: {:?}, {:?}", &r, s.bind, s.pointer);
            }
            continue;
        }

        if let Some(s) = data.symbols.get(&r.name) {
            log::info!("reloc5 {}, bind: {:?}, {:?}", &r, s.bind, s.pointer);
            continue;
        }

        unreachable!("Unable to find symbol for relocation: {}", &r.name);
    }

    // ALLOCATE TABLES

    // RW

    // GOT
    let mut got_size = BuildGotSection::size(data);
    if got_size == 0 {
        got_size = std::mem::size_of::<u64>();
    }
    let got_align = BuildGotSection::align(data);
    let mut got_block = version.rw.alloc_block_align(got_size, got_align).unwrap();
    data.addr_set(".got", got_block.as_ptr() as u64);
    let buf = BuildGotSection::contents_dynamic(data);
    got_block.copy(buf.as_slice());

    // GOTPLT
    let gotplt_size = BuildGotPltSection::size(data);
    let gotplt_align = BuildGotPltSection::align(data);
    let gotplt_block = version
        .rw
        .alloc_block_align(gotplt_size, gotplt_align)
        .unwrap();
    data.addr_set(".got.plt", gotplt_block.as_ptr() as u64);

    // RX

    // PLT
    let plt_size = BuildPltSection::size(data);
    let mut plt_block = None;
    if plt_size > 0 {
        let plt_align = BuildPltSection::align(data);
        let mut block = version.rx.alloc_block_align(plt_size, plt_align).unwrap();
        data.addr_set(".plt", block.as_ptr() as u64);
        let v = BuildPltSection::contents_dynamic(data, block.as_ptr() as usize);
        block.copy(v.as_slice());
        plt_block = Some(block);
    }

    // PLTGOT
    let pltgot_size = BuildPltGotSection::size(data);
    if pltgot_size > 0 {
        let pltgot_align = BuildPltGotSection::align(data);
        let mut pltgot_block = version
            .rx
            .alloc_block_align(pltgot_size, pltgot_align)
            .unwrap();
        data.addr_set(".plt.got", pltgot_block.as_ptr() as u64);
        let buf = BuildPltGotSection::contents(data, 0);
        pltgot_block.copy(buf.as_slice());
    }

    apply_relocations(&target.rx, data);
    apply_relocations(&target.ro, data);
    apply_relocations(&target.rw, data);

    rx_block.copy(target.rx.bytes());

    //for (name, p) in pointers.iter() {
    //eprintln!("P: {:#0x}: {}", p, name);
    //}
    unsafe {
        let buf = std::slice::from_raw_parts(rx_block.as_ptr(), rx_block.size());
        target
            .rx
            .disassemble_code_start(data, buf, rx_block.as_ptr() as usize, rx_block.size());
        if got_size > 0 {
            eprintln!(
                "GOT Disassemble, Base: {:#0x}, Size:{}",
                got_block.as_ptr() as usize,
                got_block.size()
            );
            let buf = std::slice::from_raw_parts(got_block.as_ptr(), got_block.size());
            format::print_bytes(buf, got_block.as_ptr() as usize);
        }
        if plt_size > 0 {
            let block = plt_block.as_ref().unwrap();
            eprintln!(
                "PLT Disassemble, Base: {:#0x}, Size:{}",
                block.as_ptr() as usize,
                block.size()
            );
            let buf = std::slice::from_raw_parts(block.as_ptr(), block.size());
            format::print_bytes(buf, block.as_ptr() as usize);
            format::disassemble_buf(buf);
        }

        if gotplt_size > 0 {
            eprintln!(
                "GOTPLT Disassemble, Base: {:#0x}, Size:{}",
                gotplt_block.as_ptr() as usize,
                gotplt_block.size()
            );
            let buf = std::slice::from_raw_parts(gotplt_block.as_ptr(), gotplt_block.size());
            format::print_bytes(buf, gotplt_block.as_ptr() as usize);
            format::disassemble_buf(buf);
        }
    }

    Ok(())
}

pub struct LoaderVersion {
    libraries: SharedLibraryRepo,
    ro: BlockFactoryInner,
    rw: BlockFactoryInner,
    rx: BlockFactoryInner,
    data: Data,
}

impl LoaderVersion {
    pub fn new() -> Self {
        let mut ro = BlockFactoryInner::create(10).unwrap();
        ro.force_rw();
        let mut rx = BlockFactoryInner::create(10).unwrap();
        rx.force_rw();
        let mut rw = BlockFactoryInner::create(10).unwrap();
        rw.force_rw();
        Self {
            libraries: SharedLibraryRepo::default(),
            ro,
            rx,
            rw,
            data: Data::new(),
        }
    }

    pub fn debug(&self) {
        log::debug!("Debug:");
        crate::dynamic::eprint_process_maps();
    }

    pub fn lookup(&self, name: &str) -> Option<u64> {
        if let Some(symbol) = self.data.symbols.get(name) {
            log::debug!("found in pointer: {}", name);
            return Some(symbol.pointer.resolve(&self.data).unwrap());
        }

        if let Some(ptr) = self.libraries.search_dynamic(name) {
            log::debug!("found in shared: {}", name);
            let p = ptr.as_ptr() as *const usize;
            return Some(p as u64);
        }
        log::debug!("not found: {}", name);
        None
    }

    pub fn invoke<P, T>(&self, name: &str, args: P) -> Result<T, Box<dyn Error>> {
        let p = self
            .lookup(name)
            .ok_or(LinkError::SymbolNotFound(name.to_string()))?;
        log::debug!("invoking {} @ {:#08x}", name, p as usize);
        unsafe {
            type MyFunc<P, T> = unsafe extern "cdecl" fn(P) -> T;
            let f: MyFunc<P, T> = std::mem::transmute(p);
            let ret = f(args);
            Ok(ret)
        }
    }

    pub fn load_block(block: &mut ReadBlock) -> Result<LoaderVersion, Box<dyn Error>> {
        let mut version = LoaderVersion::new();
        load_block(&mut version, &mut block.target)?;

        // set protection
        version.ro.force_ro();
        version.rx.force_rx();
        version.rw.force_rw();

        Ok(version)
    }
}
