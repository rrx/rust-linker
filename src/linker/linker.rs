use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::path::Path;
use std::sync::Arc;

use std::fs;

use super::*;
use crate::*;

pub struct DynamicLink {
    pub(crate) libraries: SharedLibraryRepo,
    pub(crate) mem: BlockFactory,
    pub(crate) got: Option<TableVersion>,
    pub(crate) plt: Option<TableVersion>,
    pub(crate) link: Link,
}
impl Drop for DynamicLink {
    fn drop(&mut self) {
        self.libraries.clear();
        log::debug!("GOT Used: {}", self.got.as_ref().unwrap().used());
        log::debug!("PLT Used: {}", self.plt.as_ref().unwrap().used());
        self.got.take();
        self.plt.take();
        log::debug!("MEM Used: {}", self.mem.used());
        assert_eq!(self.used(), 0);
    }
}
impl DynamicLink {
    pub fn new() -> Self {
        let mem = BlockFactory::create(2000).unwrap();
        let got_mem = mem.alloc_block(1024 * 1024).unwrap().make_heap_block();
        let plt_mem = mem.alloc_block(1024 * 1024).unwrap().make_heap_block();
        let got_block = SmartBlock::new(got_mem);
        let plt_block = SmartBlock::new(plt_mem);
        let got = TableVersion::new(got_block.clone());
        let plt = TableVersion::new(plt_block.clone());

        Self {
            libraries: SharedLibraryRepo::default(),
            mem,
            got: Some(got),
            plt: Some(plt),
            link: Link::new(),
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

    pub fn add_library_repo(&mut self, repo: SharedLibraryRepo) -> Result<(), Box<dyn Error>> {
        self.libraries.update(repo);
        Ok(())
    }

    pub fn add_library(&mut self, name: &str, path: &Path) -> Result<(), Box<dyn Error>> {
        unsafe {
            let lib = libloading::Library::new(path)?;
            self.libraries.add(name, lib);
            self.link.add_library(name, path)?;
            log::debug!("Loaded library: {}", &path.to_string_lossy());
        }
        Ok(())
    }

    pub fn add_obj_file(&mut self, name: &str, path: &Path) -> Result<(), Box<dyn Error>> {
        self.link.add_obj_file(name, path)
    }

    pub fn add_obj_buf(&mut self, name: &str, buf: &[u8]) -> Result<(), Box<dyn Error>> {
        self.link.add_obj_buf(name, buf)
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
        for (_name, unlinked) in &self.link.unlinked {
            let mut children = HashSet::new();
            //log::debug!("checking: {}", name);
            // ensure all relocations map somewhere
            for (extern_symbol, _s) in &unlinked.externs {
                if pointers.contains_key(extern_symbol) {
                } else if self.libraries.search_dynamic(&extern_symbol).is_some() {
                    log::debug!(" Symbol {} found in shared library", &extern_symbol);
                } else {
                    log::error!(" Symbol {} missing", &extern_symbol);
                    missing.insert(extern_symbol.clone());
                }
            }

            for r in &unlinked.relocations {
                //log::debug!("\tReloc: {}", &symbol_name);
                if pointers.contains_key(&r.name) {
                    children.insert(r.name.clone());
                } else if unlinked.internal.contains_key(&r.name) {
                    //children.insert(r.name.clone());
                } else if self.libraries.search_dynamic(&r.name).is_some() {
                    children.insert(r.name.clone());
                    log::debug!(" Symbol {} found in shared library", &r.name);
                } else {
                    log::debug!("{:?}", &unlinked.internal);
                    log::error!(" Symbol {} missing", &r.name);
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
    //dynamic: Option<DynamicLink>,
    libs: HashSet<String>,
}

/*
impl Drop for Link {
    fn drop(&mut self) {
        self.unlinked.clear();
    }
}
*/

impl Link {
    pub fn new() -> Self {
        Self {
            unlinked: HashMap::new(),
            //dynamic: None,
            libs: HashSet::default(),
        }
    }

    pub fn remove(&mut self, name: &str) {
        self.unlinked.remove(&name.to_string());
    }

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
        let segments = UnlinkedCodeSegmentInner::read_archive(name, buf.as_slice())?;
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

    /*
    pub fn write(&mut self, path: &Path) -> Result<(), Box<dyn Error>> {
        use object::elf;
        use object::Endianness;
        let data = crate::writer::Data::new(self.libs.iter().cloned().collect());
        //data.add_section_headers = true;
        //data.add_symbols = true;

        let out_data = crate::writer::write_file::<elf::FileHeader64<Endianness>>(self, data)?;
        std::fs::write(path, out_data)?;
        Ok(())
    }
    */
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use test_log::test;

    #[test]
    fn linker_segfault() {
        let mut b = DynamicLink::new();
        b.add_library("test", Path::new("libsigsegv.so")).unwrap();
        b.add_obj_file("test", Path::new("build/clang-glibc/segfault.o"))
            .unwrap();
        let _version = b.link().unwrap();
        // XXX: This isn't working yet
        //let ret: i64 = version.invoke("handlers_init", ()).unwrap();
        //let ret: i64 = version.invoke("segfault_me", ()).unwrap();
        //log::debug!("ret: {:#08x}", ret);
        //assert_eq!(13, ret);
    }

    #[test]
    fn linker_global_long() {
        let mut b = DynamicLink::new();
        b.add_obj_file("test", Path::new("build/clang-glibc/live.o")).unwrap();
        let collection = b.link().unwrap();

        let ret: i64 = collection.invoke("call_live", (3,)).unwrap();
        log::debug!("ret: {:#08x}", ret);
        assert_eq!(17, ret);

        let ret: i64 = collection.invoke("simple_function", ()).unwrap();
        log::debug!("ret: {:#08x}", ret);
        assert_eq!(1, ret);

        let ret: i64 = collection.invoke("func2", (2,)).unwrap();
        log::debug!("ret: {:#08x}", ret);
        assert_eq!(3, ret);
    }

    #[test]
    fn linker_shared() {
        let mut b = DynamicLink::new();
        b.add_library("gz", Path::new("build/testlibs/libz.so")).unwrap();
        b.add_obj_file("test", Path::new("build/clang-glibc/link_shared.o"))
            .unwrap();
        let collection = b.link().unwrap();
        let ret: *const () = collection.invoke("call_z", ()).unwrap();
        log::debug!("ret: {:#08x}", ret as usize);
        assert!(ret.is_null());
    }

    #[test]
    fn linker_livelink() {
        let mut b = DynamicLink::new();
        b.add_library("libc", Path::new("/usr/lib/x86_64-linux-musl/libc.so"))
            .unwrap();
        b.add_library("libc", Path::new("../tmp/live.so")).unwrap();

        // unable to link, missing symbol
        b.add_obj_file("test1", Path::new("../tmp/testfunction.o"))
            .unwrap();
        assert_eq!(false, b.link().is_ok());

        // provide missing symbol
        b.add_obj_file("asdf", Path::new("../tmp/asdf.o")).unwrap();
        assert_eq!(true, b.link().is_ok());

        // links fine
        b.add_obj_file("simple", Path::new("../tmp/simplefunction.o"))
            .unwrap();
        assert_eq!(true, b.link().is_ok());

        let collection = b.link().unwrap();
        let ret: i64 = collection.invoke("func", ()).unwrap();
        log::debug!("ret: {}", ret);
        assert_eq!(10001, ret);

        let ret: i64 = collection.invoke("simple", ()).unwrap();
        log::debug!("ret: {}", ret);
        assert_eq!(10012, ret);

        let ret: i64 = collection.invoke("call_external", ()).unwrap();
        log::debug!("ret: {}", ret);
        assert_eq!(4, ret);

        let ret: i64 = collection.invoke("asdf", (2,)).unwrap();
        log::debug!("ret: {}", ret);
        assert_eq!(3, ret);
    }
}
