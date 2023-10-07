use super::*;
use std::error::Error;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::ptr::NonNull;
use std::sync::Arc;
pub type SharedLibrary = Arc<Library>;

pub enum Library {
    Raw(RawLibrary),
    Loading(libloading::Library),
}

impl Library {
    pub fn lookup(&self, name: &str) -> Option<RelocationPointer> {
        let cstr = CString::new(name).unwrap();
        unsafe {
            match self {
                Self::Loading(lib) => {
                    let result: Result<libloading::Symbol<unsafe fn()>, libloading::Error> =
                        lib.get(cstr.as_bytes());
                    if let Ok(f) = result {
                        RelocationPointer::shared(f.into_raw().into_raw() as *const ())
                    } else {
                        None
                    }
                }
                Self::Raw(lib) => {
                    let symbol = libc::dlsym(lib.handle as *mut libc::c_void, cstr.as_ptr());
                    if symbol.is_null() {
                        None
                    } else {
                        RelocationPointer::shared(symbol as *const ())
                    }
                }
            }
        }
    }

    pub fn namespace(&self) -> Namespace {
        match self {
            Self::Loading(_) => Namespace { lm_id: 0 },
            Self::Raw(lib) => lib.namespace,
        }
    }

    pub fn invoke<P, T>(&self, name: &str, args: P) -> Result<T, Box<dyn Error>> {
        // call the main function

        // make sure we dereference the pointer!
        let ptr = self.lookup(name).ok_or(crate::LinkError::SymbolNotFound)?;
        unsafe {
            type MyFunc<P, T> = unsafe extern "cdecl" fn(P) -> T;
            log::debug!("invoking {} @ {:#08x}", name, ptr.as_ptr() as usize);
            let f: MyFunc<P, T> = std::mem::transmute(ptr.as_ptr());
            let ret = f(args);
            Ok(ret)
        }
    }
}

#[derive(Clone)]
pub struct SharedLibraryRepo {
    map: im::HashMap<String, SharedLibrary>,
}
impl SharedLibraryRepo {
    pub fn clear(&mut self) {
        self.map.clear();
    }
    pub fn update(&mut self, repo: SharedLibraryRepo) {
        self.map = self.map.clone().union(repo.map.clone());
    }
}

#[derive(Clone)]
pub struct RawLibrary {
    namespace: Namespace,
    handle: *const (),
}

impl Drop for RawLibrary {
    fn drop(&mut self) {
        unsafe {
            libc::dlclose(self.handle as *mut libc::c_void);
            log::debug!("Dropping library");
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub struct Namespace {
    lm_id: i64,
}

impl SharedLibraryRepo {
    pub fn get(&self, name: &str) -> Option<SharedLibrary> {
        self.map.get(name).cloned()
    }

    pub fn add(&mut self, name: &str, lib: libloading::Library) {
        self.map
            .insert(name.to_string(), Arc::new(Library::Loading(lib)));
    }

    pub fn add_to_new_namespace(&mut self, name: &str, path: &Path) -> Option<Namespace> {
        unsafe {
            let c_str = CString::new(path.as_os_str().as_bytes()).unwrap();
            let handle = libc::dlmopen(libc::LM_ID_NEWLM, c_str.as_ptr(), libc::RTLD_LAZY);
            if handle.is_null() {
                None
            } else {
                let mut lm_id = 0;
                let ptr = &mut lm_id as *mut i64;
                libc::dlinfo(handle, libc::RTLD_DI_LMID, ptr as *mut libc::c_void);
                let namespace = Namespace { lm_id };
                let lib = RawLibrary {
                    handle: handle as *const (),
                    namespace,
                };
                self.map
                    .insert(name.to_string(), Arc::new(Library::Raw(lib)));
                Some(namespace)
            }
        }
    }

    pub fn add_to_namespace(
        &mut self,
        name: &str,
        path: &Path,
        namespace: Namespace,
    ) -> Option<()> {
        unsafe {
            let c_str = CString::new(path.as_os_str().as_bytes()).unwrap();
            let handle = libc::dlmopen(namespace.lm_id, c_str.as_ptr(), libc::RTLD_LAZY);
            if handle.is_null() {
                None
            } else {
                let lib = RawLibrary {
                    handle: handle as *const (),
                    namespace,
                };
                self.map
                    .insert(name.to_string(), Arc::new(Library::Raw(lib)));
                Some(())
            }
        }
    }

    // search the dynamic libraries to see if the symbol exists
    pub fn search_dynamic(&self, symbol: &str) -> Option<RelocationPointer> {
        for (_name, lib) in &self.map {
            if let Some(p) = lib.lookup(symbol) {
                return Some(RelocationPointer::Shared(
                    NonNull::new(p.as_ptr() as *mut u8).unwrap(),
                ));
            }
        }
        None
    }
}

impl Default for SharedLibraryRepo {
    fn default() -> Self {
        Self {
            map: im::HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn lib_namespace() {
        let mut libs = SharedLibraryRepo::default();

        // these should resolve, but we dont' implement that yet
        assert!(libs.add_to_new_namespace("libc1", Path::new("c")).is_none());
        assert!(libs
            .add_to_new_namespace("libc2", Path::new("libc.so"))
            .is_none());

        let libc_path = Path::new("/lib/x86_64-linux-gnu/libc.so.6");
        let musl_path = Path::new("/usr/lib/x86_64-linux-musl/libc.so");
        let musl_n = libs.add_to_new_namespace("musl", musl_path).unwrap();
        let libc_n = libs.add_to_new_namespace("libc3", libc_path).unwrap();
        log::debug!("{:?}", (musl_n, libc_n));

        // adding them a second time, should do nothing
        libs.add_to_namespace("musl2", musl_path, musl_n).unwrap();
        libs.add_to_namespace("libc4", libc_path, musl_n).unwrap();
        crate::eprint_process_maps();
    }
}
