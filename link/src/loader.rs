use crate::aot::{
    apply_relocations, BlockSection, BuildGotPltSection, BuildGotSection, BuildPltGotSection,
    BuildPltSection, GotPltAssign, GotSectionKind, ResolvePointer, SymbolBind, SymbolSource,
};
use crate::dynamic::{BlockFactoryInner, LinkError, SharedLibraryRepo};
use crate::format;
use crate::{Data, ReadBlock};
use object::SymbolKind;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::Path;

pub fn load_block(data: &mut Data, block: &mut ReadBlock) -> Result<LoaderVersion, Box<dyn Error>> {
    let mut version = LoaderVersion::new();

    for path in block.target.libs.iter() {
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
    let bss_size = block.target.bss.size();
    if bss_size > 0 {
        let bss_block = version.rw.alloc_block_align(bss_size, align).unwrap();
        data.addr_set(".bss", bss_block.as_ptr() as u64);
    }

    let rw_size = block.target.rw.size();
    if rw_size > 0 {
        let mut rw_block = version.rw.alloc_block_align(rw_size, align).unwrap();
        data.addr_set(".data", rw_block.as_ptr() as u64);
        rw_block.copy(block.target.rw.bytes());
        block.target.rw.offsets.address = rw_block.as_ptr() as u64;
    }

    // RO
    let ro_size = block.target.ro.size();
    if ro_size > 0 {
        let mut ro_block = version.ro.alloc_block_align(ro_size, align).unwrap();
        data.addr_set(".rodata", ro_block.as_ptr() as u64);
        ro_block.copy(block.target.ro.bytes());
        block.target.ro.offsets.address = ro_block.as_ptr() as u64;
    }

    // RX
    let rx_size = block.target.rx.size();
    let mut rx_block = version.rx.alloc_block_align(rx_size, align).unwrap();
    data.addr_set(".text", rx_block.as_ptr() as u64);
    block.target.rx.offsets.address = rx_block.as_ptr() as u64;

    for (name, symbol) in block.target.exports.iter() {
        eprintln!("ES: {:?}", (name, &symbol));
        let _p = symbol.pointer.resolve(data).unwrap();
        data.pointers.insert(name.clone(), symbol.pointer.clone());
    }

    /*
    for (name, symbol) in block.target.locals.iter() {
        eprintln!("LS: {:?}", (name, &symbol));
        data.pointers.insert(name.clone(), symbol.pointer.clone());
        let p = symbol.pointer.resolve(data).unwrap();
        data.pointers.insert(name.clone(), symbol.pointer.clone());
        //data.pointer_set(name.clone(), p);
        //pointers.insert(name.clone(), p as u64);
    }

    for (name, symbol) in block.target.dynamic.iter() {
        eprintln!("DS: {:?}", (name, &symbol));
        //data.pointers.insert(name.clone(), symbol.pointer.clone());
        //let p = symbol.pointer.resolve(data).unwrap();
        //data.pointers.insert(name.clone(), symbol.pointer.clone());
        //data.pointer_set(name.clone(), p);
        //pointers.insert(name.clone(), p as u64);
    }
    */

    let iter = block
        .target
        .rx
        .relocations
        .iter()
        .chain(block.target.ro.relocations.iter())
        .chain(block.target.rw.relocations.iter())
        .chain(block.target.bss.relocations.iter());

    let mut got = HashSet::new();
    let mut gotplt = HashSet::new();
    for r in iter.clone() {
        match r.effect() {
            format::PatchEffect::AddToGot => {
                got.insert(r.name.clone());
            }
            format::PatchEffect::AddToPlt => {
                gotplt.insert(r.name.clone());
            }
            _ => (),
        }
    }

    let mut lookups = HashMap::new();
    for r in iter {
        if let Some(s) = block.target.lookup_dynamic(&r.name) {
            if let Some(ptr) = version.libraries.search_dynamic(&r.name) {
                unsafe {
                    let p = ptr.as_ptr() as *const usize;
                    let v = *p as *const usize;
                    log::debug!(
                        "Searching Shared {:#08x}:{:#08x}:{}",
                        p as usize,
                        v as usize,
                        &r.name
                    );
                    let pointer = ResolvePointer::Got(got.len());
                    data.pointers.insert(r.name.clone(), pointer);
                    lookups.insert(r.name.clone(), ResolvePointer::Resolved(p as u64));
                    //got.push(p);
                    //data.pointer_set(r.name.clone(), p as u64);
                    //data.pointers.insert(r.name.clone(), p as u64);
                }
            } else {
                unimplemented!("dynamic not found: {:?}", s);
            }

            //let p = s.pointer.resolve(data).unwrap();
            //data.pointers.insert(s.name.clone(), s.pointer.clone());

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

            let symbol = data.dynamics.relocation_add(&s, assign, r);
            log::info!(
                "reloc0 {}, {:?}, {:?}, {:?}",
                &r,
                assign,
                s.bind,
                symbol.pointer
            );
            data.pointers.insert(s.name.clone(), symbol.pointer.clone());
            data.symbols.insert(s.name.clone(), symbol);
            //pointer.resolve(data).unwrap();
            continue;
        }

        // static plt relatives
        if let Some(s) = block.target.lookup_static(&r.name) {
            data.symbols.insert(s.name.clone(), s.clone());
            if r.is_plt() {
                log::info!("reloc1 {}, {:?}, {:?}", &r, s.bind, s.pointer);
                let _p = s.pointer.resolve(data).unwrap();
                data.pointers.insert(s.name.clone(), s.pointer.clone());
                continue;
            }
        } else {
            unreachable!("Unable to find symbol for relocation: {}", &r.name);
        }

        if let Some(s) = block.target.lookup(&r.name) {
            // we don't know the section yet, we just know which kind
            let def = match s.bind {
                SymbolBind::Local => format::CodeSymbolDefinition::Local,
                SymbolBind::Global => format::CodeSymbolDefinition::Defined,
                SymbolBind::Weak => format::CodeSymbolDefinition::Defined,
            };
            let _p = s.pointer.resolve(data).unwrap();
            data.pointers.insert(s.name.clone(), s.pointer.clone());

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
                data.dynamics.relocation_add(&s, assign, r);
            } else if def != format::CodeSymbolDefinition::Local {
                log::info!("reloc3 {}, bind: {:?}, {:?}", &r, s.bind, s.pointer);
                if assign == GotPltAssign::None {
                } else {
                    data.dynamics.relocation_add(&s, assign, r);
                }
            } else {
                log::info!("reloc4 {}, bind: {:?}, {:?}", &r, s.bind, s.pointer);
            }
        } else {
            unreachable!("Unable to find symbol for relocation: {}", &r.name)
        }
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
    let mut buf = BuildGotSection::contents(data);
    let unapplied = data.dynamics.relocations(GotSectionKind::GOT);
    for (i, symbol) in unapplied.iter().enumerate() {
        let p = symbol.pointer.resolve(data).unwrap();
        eprintln!("U1({}): {:?}, {:#0x}", i, symbol, p);

        let pp = if let Some(p) = lookups.get(&symbol.name) {
            p.clone()
        } else if let Some(s) = block.target.lookup(&symbol.name) {
            s.pointer.clone()
        } else {
            unreachable!();
        };

        //let s = block.target.lookup(&symbol.name).unwrap();
        let p = pp.resolve(data).unwrap();
        eprintln!("U2({}): {:?}, {:#0x}", i, pp, p);
        //if let Some(pp) = lookups.get(&s.name) {
        //let p = pp.resolve(data).unwrap();
        let b = (p as u64).to_le_bytes();
        buf[i * b.len()..(i + 1) * b.len()].copy_from_slice(&b);
        //}
    }
    got_block.copy(buf.as_slice());

    let gotplt_size = BuildGotPltSection::size(data);
    let gotplt_align = BuildGotPltSection::align(data);
    let gotplt_block = version
        .rw
        .alloc_block_align(gotplt_size, gotplt_align)
        .unwrap();
    data.addr_set(".got.plt", gotplt_block.as_ptr() as u64);
    //let buf = BuildGotPltSection::contents(data);
    //gotplt_block.copy(buf.as_slice());

    // RX
    // PLT
    let plt_size = BuildPltSection::size(data);
    let plt_align = BuildPltSection::align(data);
    let mut plt_block = version.rx.alloc_block_align(plt_size, plt_align).unwrap();
    data.addr_set(".plt", plt_block.as_ptr() as u64);

    let mut v = vec![0u8; 16];
    for (i, symbol) in data.dynamics.plt_objects().iter().enumerate() {
        // offset is from the next instruction - 5 bytes after the current instruction
        let rip = plt_block.as_ptr() as isize + (i as isize + 1) * 16 + 5;
        let p = lookups.get(&symbol.name).unwrap().resolve(data).unwrap();
        println!("PLT Symbol: {:?}", symbol);
        println!("PLT Symbol: {:#0x}, {:#0x}", p, rip);
        // E9 cd - JMP rel32
        let mut buf = [0u8; 16];
        buf[0] = 0xe9;
        let b = ((p as isize - rip as isize) as u32).to_le_bytes();
        buf[1..b.len() + 1].copy_from_slice(&b);
        v.extend(buf);
    }
    plt_block.copy(v.as_slice());

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

    // write data that depends on sections being known
    /*
    let buf = BuildGotPltSection::contents(data);
    gotplt_block.copy(buf.as_slice());

    let buf = BuildPltSection::contents(data, 0);
    plt_block.copy(buf.as_slice());
    */

    apply_relocations(&block.target.rx, data);
    apply_relocations(&block.target.ro, data);
    apply_relocations(&block.target.rw, data);

    rx_block.copy(block.target.rx.bytes());

    //for (name, p) in pointers.iter() {
    //eprintln!("P: {:#0x}: {}", p, name);
    //}
    unsafe {
        let buf = std::slice::from_raw_parts(rx_block.as_ptr(), rx_block.size());
        block.target.rx.disassemble_code_start(
            data,
            buf,
            rx_block.as_ptr() as usize,
            rx_block.size(),
        );
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
            eprintln!(
                "PLT Disassemble, Base: {:#0x}, Size:{}",
                plt_block.as_ptr() as usize,
                plt_block.size()
            );
            let buf = std::slice::from_raw_parts(plt_block.as_ptr(), plt_block.size());
            format::print_bytes(buf, plt_block.as_ptr() as usize);
            format::disassemble_buf(buf);
        }

        /*
        if gotplt_size > 0 {
            eprintln!("GOTPLT Disassemble, Base: {:#0x}, Size:{}", gotplt_block.as_ptr() as usize, gotplt_block.size());
            let buf = std::slice::from_raw_parts(gotplt_block.as_ptr(), gotplt_block.size());
            format::print_bytes(buf, gotplt_block.as_ptr() as usize);
            format::disassemble_buf(buf);
        }
        */
    }

    // set protection
    version.ro.force_ro();
    version.rx.force_rx();
    version.rw.force_rw();

    Ok(version)
}

pub struct LoaderVersion {
    libraries: SharedLibraryRepo,
    ro: BlockFactoryInner,
    rw: BlockFactoryInner,
    rx: BlockFactoryInner,
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
        }
    }

    pub fn debug(&self) {
        log::debug!("Debug:");
        crate::dynamic::eprint_process_maps();
    }

    pub fn lookup(&self, data: &Data, symbol: &str) -> Option<u64> {
        if let Some(ptr) = data.pointers.get(symbol) {
            log::debug!("found in pointer: {}", symbol);
            return Some(ptr.resolve(data).unwrap());
        }

        if let Some(ptr) = self.libraries.search_dynamic(symbol) {
            log::debug!("found in shared: {}", symbol);
            let p = ptr.as_ptr() as *const usize;
            return Some(p as u64);
        }
        log::debug!("not found: {}", symbol);
        None
    }

    pub fn invoke<P, T>(&self, data: &Data, name: &str, args: P) -> Result<T, Box<dyn Error>> {
        let p = self
            .lookup(data, name)
            .ok_or(LinkError::SymbolNotFound(name.to_string()))?;
        log::debug!("invoking {} @ {:#08x}", name, p as usize);
        unsafe {
            type MyFunc<P, T> = unsafe extern "cdecl" fn(P) -> T;
            let f: MyFunc<P, T> = std::mem::transmute(p);
            let ret = f(args);
            Ok(ret)
        }
    }
}
