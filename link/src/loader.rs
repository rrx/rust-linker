use crate::aot::BlockSection;
use crate::dynamic::{BlockFactoryInner, SharedLibraryRepo};
use crate::format;
use crate::{Data, ReadBlock};
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;

pub fn load_block(data: &mut Data, block: &ReadBlock) -> Result<(), Box<dyn Error>> {
    let mut pointers = HashMap::new();
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
    /*
    let got_size = BuildGotSection::size(data);
    if got_size > 0 {
        let got_align = BuildGotSection::align(data);
        let mut got_block = rw.alloc_block(got_size).unwrap();
        data.addr_set(".got", got_block.as_ptr() as u64);
        let buf = BuildGotSection::contents(data);
        got_block.copy(buf.as_slice());
    }

    let gotplt_size = BuildGotPltSection::size(data);
    let gotplt_align = BuildGotPltSection::align(data);
    let mut gotplt_block = rw.alloc_block(gotplt_size).unwrap();
    data.addr_set(".got.plt", gotplt_block.as_ptr() as u64);
    */

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
    /*
    let plt_size = BuildPltSection::size(data);
    let plt_align = BuildPltSection::align(data);
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
    */

    let rx_size = block.target.rx.size();
    let _rx_align = 0x10;
    let mut rx_block = rx.alloc_block(rx_size).unwrap();
    data.addr_set(".text", rx_block.as_ptr() as u64);

    // write data that depends on sections being known
    /*
    let buf = BuildGotPltSection::contents(data);
    gotplt_block.copy(buf.as_slice());

    let buf = BuildPltSection::contents(data, 0);
    plt_block.copy(buf.as_slice());
    */
    for (name, symbol) in block.target.exports.iter() {
        eprintln!("ES: {:?}", (name, &symbol));
        let p = symbol.pointer.resolve(data).unwrap();
        data.pointer_set(name.clone(), p);
        pointers.insert(name.clone(), p as u64);
    }

    for (name, symbol) in block.target.locals.iter() {
        eprintln!("LS: {:?}", (name, &symbol));
        let p = symbol.pointer.resolve(data).unwrap();
        data.pointer_set(name.clone(), p);
        pointers.insert(name.clone(), p as u64);
    }

    let iter = block
        .target
        .rx
        .relocations
        .iter()
        .chain(block.target.ro.relocations.iter())
        .chain(block.target.rw.relocations.iter())
        .chain(block.target.bss.relocations.iter());

    for r in iter {
        if let Some(_p) = data.pointers.get(&r.name) {
            // already found
        } else if let Some(symbol) = block.target.lookup(&r.name) {
            eprintln!("LU: {:?}", (&r.name, &symbol));
            let p = symbol.pointer.resolve(data).unwrap();
            data.pointer_set(r.name.clone(), p);
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
                data.pointer_set(r.name.clone(), p as u64);
                pointers.insert(r.name.clone(), p as u64);
            }
        }
    }

    block.target.rx.apply_relocations(data);
    block.target.ro.apply_relocations(data);
    block.target.rw.apply_relocations(data);

    rx_block.copy(block.target.rx.bytes());

    for (name, p) in pointers.iter() {
        eprintln!("P: {:#0x}: {}", p, name);
    }
    unsafe {
        let buf = std::slice::from_raw_parts(rx_block.as_ptr(), rx_block.size());
        block.target.rx.disassemble_code_start(
            data,
            buf,
            rx_block.as_ptr() as usize,
            rx_block.size(),
        );
    }

    Ok(())
}
