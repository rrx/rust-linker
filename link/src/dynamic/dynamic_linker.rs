use super::*;
use crate::aot::{BlockSection, BuildGotPltSection, BuildGotSection, BuildPltSection};
use crate::format::*;
use crate::{Data, ReadBlock};
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::path::Path;
use std::sync::Arc;

pub struct DynamicLink {
    pub(crate) libraries: SharedLibraryRepo,
    pub(crate) mem: BlockFactory,
    pub(crate) got: Option<TableVersion>,
    pub(crate) plt: Option<TableVersion>,
    pub(crate) rx: Option<TableVersion>,
    pub(crate) rw: Option<TableVersion>,
    pub(crate) ro: Option<TableVersion>,
    pub(crate) bss: Option<TableVersion>,
    pub(crate) link: Link,
}

impl Drop for DynamicLink {
    fn drop(&mut self) {
        self.libraries.clear();
        log::debug!("GOT Used: {}", self.got.as_ref().unwrap().used());
        log::debug!("PLT Used: {}", self.plt.as_ref().unwrap().used());
        self.got.take();
        self.plt.take();
        self.rx.take();
        self.rw.take();
        self.ro.take();
        self.bss.take();
        log::debug!("MEM Used: {}", self.mem.used());
        assert_eq!(self.used(), 0);
    }
}
impl DynamicLink {
    pub fn new() -> Self {
        let mem = BlockFactory::create(2000).unwrap();
        let got_mem = mem.alloc_block(1024 * 1024).unwrap().make_heap_block();
        let plt_mem = mem.alloc_block(1024 * 1024).unwrap().make_heap_block();
        let rx_mem = mem.alloc_block(1024 * 1024).unwrap().make_heap_block();
        let rw_mem = mem.alloc_block(1024 * 1024).unwrap().make_heap_block();
        let ro_mem = mem.alloc_block(1024 * 1024).unwrap().make_heap_block();
        let bss_mem = mem.alloc_block(1024 * 1024).unwrap().make_heap_block();
        let got_block = SmartBlock::new(got_mem);
        let plt_block = SmartBlock::new(plt_mem);
        let rx_block = SmartBlock::new(rx_mem);
        let rw_block = SmartBlock::new(rw_mem);
        let ro_block = SmartBlock::new(ro_mem);
        let bss_block = SmartBlock::new(bss_mem);
        let got = TableVersion::new(got_block.clone());
        let plt = TableVersion::new(plt_block.clone());
        let rx = TableVersion::new(rx_block.clone());
        let rw = TableVersion::new(rw_block.clone());
        let ro = TableVersion::new(ro_block.clone());
        let bss = TableVersion::new(bss_block.clone());

        Self {
            libraries: SharedLibraryRepo::default(),
            mem,
            got: Some(got),
            plt: Some(plt),
            link: Link::new(),
            rx: Some(rx),
            rw: Some(rw),
            ro: Some(ro),
            bss: Some(bss),
        }
    }

    pub fn used(&self) -> usize {
        self.mem.used()
    }

    pub fn debug(&self) {
        log::debug!("GOT Used: {}", self.got.as_ref().unwrap().used());
        log::debug!("PLT Used: {}", self.plt.as_ref().unwrap().used());
        log::debug!("MEM Used: {}", self.mem.used());
        log::debug!("GOT");
        self.got.as_ref().unwrap().debug();
    }

    pub fn get_mem_ptr(&self) -> (*const u8, usize) {
        self.mem.get_mem_ptr()
    }

    pub fn load(&mut self, data: &Data, block: &ReadBlock) -> Result<(), Box<dyn Error>> {
        let gotplt_size = BuildGotPltSection::size(data);

        let plt_size = BuildPltSection::size(data); //(1 + plt_entries_count) * 0x10;
        let plt_align = BuildPltSection::align(data); //0x10;

        let p_gotplt = self.got.as_mut().unwrap().create_buffer_empty(gotplt_size);

        let p_plt = self.plt.as_mut().unwrap().create_buffer_empty(plt_size);

        for path in block.target.libs.iter() {
            let p = Path::new(&path);
            println!("p: {}", p.to_str().unwrap());
            let ext = p.extension().unwrap().to_str().unwrap();
            println!("ext: {}", ext);
            self.add_library(p.to_str().unwrap(), &Path::new(&path));
        }

        let p = p_plt.as_ptr() as *mut u8;
        let stub = BuildPltSection::contents(data, p as usize);

        unsafe {
            std::ptr::copy(stub.as_slice().as_ptr(), p, stub.len());
        }

        let p_rx = self
            .rx
            .as_mut()
            .unwrap()
            .create_buffer(block.target.rx.bytes.as_slice());
        let p = p_rx.as_ptr();
        let p_rw = self
            .rw
            .as_mut()
            .unwrap()
            .create_buffer(block.target.rw.bytes.as_slice());
        let p = p_rw.as_ptr();
        let p_ro = self
            .ro
            .as_mut()
            .unwrap()
            .create_buffer(block.target.ro.bytes.as_slice());
        let p = p_ro.as_ptr();
        let bss = vec![0; block.target.bss.size()];
        if bss.len() > 0 {
            println!("bss size: {}", bss.len());
            let p_bss = self.bss.as_mut().unwrap().create_buffer(bss.as_slice());
            let p = p_bss.as_ptr();
        }
        Ok(())
    }

    pub fn add(&mut self, path: &std::path::Path) -> Result<(), Box<dyn Error>> {
        let p = Path::new(&path);
        println!("p: {}", p.to_str().unwrap());
        let ext = p.extension().unwrap().to_str().unwrap();
        println!("ext: {}", ext);
        match ext {
            "6" => self.add_library(path.to_str().unwrap(), &Path::new(&path)),
            "so" => self.add_library(path.to_str().unwrap(), &Path::new(&path)),
            "o" => self
                .link
                .add_obj_file(path.to_str().unwrap(), &Path::new(&path)),
            "a" => self
                .link
                .add_archive_file(path.to_str().unwrap(), &Path::new(&path)),
            _ => unimplemented!(),
        }
    }

    pub fn add_library_repo(&mut self, repo: SharedLibraryRepo) -> Result<(), Box<dyn Error>> {
        self.libraries.update(repo);
        Ok(())
    }

    pub fn add_library(&mut self, name: &str, path: &Path) -> Result<(), Box<dyn Error>> {
        unsafe {
            let lib = libloading::Library::new(path)?;
            self.libraries.add(name, lib);
            self.link.add_library(name, path)?;
            log::info!("Loaded library: {}", &path.to_string_lossy());
        }
        Ok(())
    }

    pub fn link(&mut self) -> Result<LinkVersion, Box<dyn Error>> {
        let mut pointers = im::HashMap::new();
        let mut duplicates = HashSet::new();

        // get all of the symbols and the name that provides it
        for (link_name, unlinked) in &self.link.unlinked {
            log::debug!("Linking: {}", link_name);
            for (symbol_name, code_symbol) in &unlinked.defined {
                if code_symbol.def == CodeSymbolDefinition::Defined {
                    //log::debug!("\tSymbol: {}", &symbol_name);
                    if pointers.contains_key(symbol_name) {
                        log::error!(" Duplicate symbol: {}", &symbol_name);
                        duplicates.insert(symbol_name);
                    } else {
                        pointers.insert(symbol_name.clone(), code_symbol.address);
                    }
                } else {
                    unreachable!()
                }
            }
        }

        // check for missing symbols, and try shared libraries to fill in the details
        let mut missing = HashSet::new();
        let mut found = HashSet::new();
        for (_name, unlinked) in &self.link.unlinked {
            //let mut children = HashSet::new();
            //log::debug!("checking: {}", name);
            // ensure all externs and relocations map somewhere
            for (extern_symbol, _s) in &unlinked.externs {
                if found.contains(extern_symbol) {
                    continue;
                } else if pointers.contains_key(extern_symbol) {
                    found.insert(extern_symbol);
                } else if self.libraries.search_dynamic(&extern_symbol).is_some() {
                    found.insert(extern_symbol);
                    log::info!(" Symbol {} found in shared library", &extern_symbol);
                } else {
                    log::error!(" Symbol {} not found in shared libraries", &extern_symbol);
                    missing.insert(extern_symbol.clone());
                }
            }

            for r in &unlinked.relocations {
                //log::debug!("\tReloc: {}", &symbol_name);
                if found.contains(&r.name) {
                    continue;
                } else if pointers.contains_key(&r.name) {
                    //children.insert(r.name.clone());
                } else if unlinked.internal.contains_key(&r.name) {
                    //children.insert(r.name.clone());
                } else if self.libraries.search_dynamic(&r.name).is_some() {
                    //children.insert(r.name.clone());
                    log::info!(" Relocation Symbol {} found in shared library", &r.name);
                } else {
                    log::debug!("{:?}", &unlinked.internal);
                    log::error!(" Symbol {} not found", &r.name);
                    missing.insert(r.name.clone());
                }
            }
        }

        if missing.len() == 0 && duplicates.len() == 0 {
            build_version(self)
        } else {
            for symbol in missing {
                log::error!("Missing symbol: {}", symbol);
            }
            Err(LinkError::MissingSymbol.into())
        }
    }
}

pub(crate) type UnlinkedMap = HashMap<String, UnlinkedCodeSegment>;

pub struct Link {
    pub(crate) unlinked: UnlinkedMap,
    libs: HashSet<String>,
}

impl Link {
    pub fn new() -> Self {
        Self {
            unlinked: HashMap::new(),
            libs: HashSet::default(),
        }
    }

    /*
    pub fn remove(&mut self, name: &str) {
        self.unlinked.remove(&name.to_string());
    }
    */

    pub fn add_library(&mut self, _name: &str, path: &Path) -> Result<(), Box<dyn Error>> {
        self.libs.insert(path.to_string_lossy().to_string());
        Ok(())
    }

    fn add_segments(&mut self, segments: Vec<UnlinkedCodeSegmentInner>) {
        for s in segments {
            self.unlinked.insert(s.name.clone(), Arc::new(s));
        }
    }

    pub fn add_archive_file(&mut self, name: &str, path: &Path) -> Result<(), Box<dyn Error>> {
        let buf = fs::read(path)?;
        self.add_archive_buf(name, buf.as_slice())
    }

    pub fn add_archive_buf(
        &mut self,
        archive_name: &str,
        buf: &[u8],
    ) -> Result<(), Box<dyn Error>> {
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
            segments.extend(UnlinkedCodeSegmentInner::create_segments(name, obj_buf)?);
        }
        self.add_segments(segments);
        Ok(())
    }

    pub fn add_obj_file(&mut self, name: &str, path: &Path) -> Result<(), Box<dyn Error>> {
        let buf = fs::read(path)?;
        self.add_obj_buf(name, buf.as_slice())
    }

    pub fn add_obj_buf(&mut self, name: &str, buf: &[u8]) -> Result<(), Box<dyn Error>> {
        let segments = UnlinkedCodeSegmentInner::create_segments(name, buf)?;
        self.add_segments(segments);
        Ok(())
    }
}
