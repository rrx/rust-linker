use crate::aot::{
    BlockSection, BuildGotPltSection, BuildGotSection, BuildPltGotSection, BuildPltSection,
    GotPltAssign, GotSectionKind, ResolvePointer, SymbolBind, SymbolSource,
};
use crate::dynamic::{BlockFactoryInner, SharedLibraryRepo};
use crate::format;
use crate::{Data, ReadBlock};
use object::SymbolKind;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::Path;

pub fn load_block(data: &mut Data, block: &ReadBlock) -> Result<(), Box<dyn Error>> {
    let mut ro = BlockFactoryInner::create(10)?;
    ro.force_rw();
    let mut rx = BlockFactoryInner::create(10)?;
    rx.force_rw();
    let mut rw = BlockFactoryInner::create(10)?;
    rw.force_rw();

    let mut libraries = SharedLibraryRepo::default();
    for path in block.target.libs.iter() {
        let p = Path::new(&path);
        println!("p: {}", p.to_str().unwrap());
        let ext = p.extension().unwrap().to_str().unwrap();
        println!("ext: {}", ext);
        libraries.add_library(p.to_str().unwrap(), &Path::new(&path))?;
    }

    // RW
    let bss_size = block.target.bss.size();
    if bss_size > 0 {
        let _bss_align = 0x10;
        let bss_block = rw.alloc_block(bss_size).unwrap();
        data.addr_set(".bss", bss_block.as_ptr() as u64);
    }

    let rw_size = block.target.rw.size();
    let _rw_align = 0x10;
    let mut rw_block = rw.alloc_block(rw_size).unwrap();
    data.addr_set(".data", rw_block.as_ptr() as u64);
    rw_block.copy(block.target.rw.bytes());

    // RO
    let ro_size = block.target.ro.size();
    let _ro_align = 0x10;
    let mut ro_block = ro.alloc_block(ro_size).unwrap();
    data.addr_set(".rodata", ro_block.as_ptr() as u64);
    ro_block.copy(block.target.ro.bytes());

    // RX
    let rx_size = block.target.rx.size();
    let _rx_align = 0x10;
    let mut rx_block = rx.alloc_block(rx_size).unwrap();
    data.addr_set(".text", rx_block.as_ptr() as u64);

    /*
    //let mut pointers = HashMap::new();
    for (name, symbol) in block.target.exports.iter() {
        eprintln!("ES: {:?}", (name, &symbol));
        let p = symbol.pointer.resolve(data).unwrap();
        data.pointers.insert(name.clone(), symbol.pointer.clone());
        //data.pointer_set(name.clone(), p);
        //pointers.insert(name.clone(), p as u64);
    }

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
            if let Some(ptr) = libraries.search_dynamic(&r.name) {
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

            let pointer = data.dynamics.relocation_add(&s, assign, r);
            log::info!("reloc0 {}, {:?}, {:?}, {:?}", &r, assign, s.bind, pointer);
            data.pointers.insert(s.name.clone(), pointer.clone());
            //pointer.resolve(data).unwrap();
            continue;
        }

        // static plt relatives
        if let Some(s) = block.target.lookup_static(&r.name) {
            if r.is_plt() {
                log::info!("reloc1 {}, {:?}, {:?}", &r, s.bind, s.pointer);
                let p = s.pointer.resolve(data).unwrap();
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
            let p = s.pointer.resolve(data).unwrap();
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

    /*
        for r in iter {
            //data.dynamics.relocation_add();
            if let Some(_p) = data.pointers.get(&r.name) {
                // already found
            } else if let Some(symbol) = block.target.lookup(&r.name) {
                eprintln!("LU: {:?}", (&r.name, &symbol));
                match symbol.source {
                    SymbolSource::Dynamic => {
                        if let Some(ptr) = libraries.search_dynamic(&r.name) {
                            unsafe {
                                let p = ptr.as_ptr() as *const usize;
                                let v = *p as *const usize;
                                log::debug!(
                                    "Searching Shared {:#08x}:{:#08x}:{}",
                                    p as usize,
                                    v as usize,
                                    &r.name
                                );
                                data.pointers.insert(r.name.clone(), ResolvePointer::Got(got.len()));
                                //got.push(p);
                                //data.pointer_set(r.name.clone(), p as u64);
                                pointers.insert(r.name.clone(), p as u64);
                            }
                        } else {
                            unimplemented!("dynamic not found: {:?}", symbol);
                        }
                    }
                    _ => {
                        let p = symbol.pointer.resolve(data).unwrap();
                        data.pointer_set(r.name.clone(), p);
                    }
                }

            } else {
                unimplemented!();
            }
            /*
            } else if let Some(ptr) = libraries.search_dynamic(&r.name) {
                // data pointers should already have a got in the shared library
                unsafe {
                    let p = ptr.as_ptr() as *const usize;
                    let v = *p as *const usize;
                    log::debug!(
                        "Searching Shared {:#08x}:{:#08x}:{}",
                        p as usize,
                        v as usize,
                        &r.name
                    );
                    data.pointers.insert(r.name.clone(), ResolvePointer::Got(got.len()));
                    got.push(p);
                    //data.pointer_set(r.name.clone(), p as u64);
                    pointers.insert(r.name.clone(), p as u64);
                }
            }
            */
        }
    */

    // ALLOCATE TABLES

    // RW

    // GOT
    let mut got_size = BuildGotSection::size(data);
    if got_size == 0 {
        got_size = std::mem::size_of::<u64>();
    }
    let _got_align = BuildGotSection::align(data);
    let mut got_block = rw.alloc_block(got_size).unwrap();
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
    let _gotplt_align = BuildGotPltSection::align(data);
    let mut gotplt_block = rw.alloc_block(gotplt_size).unwrap();
    data.addr_set(".got.plt", gotplt_block.as_ptr() as u64);

    // RX
    let plt_size = BuildPltSection::size(data);
    let _plt_align = BuildPltSection::align(data);
    let mut plt_block = rx.alloc_block(plt_size).unwrap();
    data.addr_set(".plt", plt_block.as_ptr() as u64);

    let pltgot_size = BuildPltGotSection::size(data);
    if pltgot_size > 0 {
        let pltgot_align = BuildPltGotSection::align(data);
        let mut pltgot_block = rx.alloc_block(pltgot_size).unwrap();
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

    block.target.rx.apply_relocations(data);
    block.target.ro.apply_relocations(data);
    block.target.rw.apply_relocations(data);

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
            eprintln!("GOT Disassemble, Size:{}", got_block.size());
            let buf = std::slice::from_raw_parts(got_block.as_ptr(), got_block.size());
            format::print_bytes(buf, got_block.as_ptr() as usize);
        }
    }

    Ok(())
}
