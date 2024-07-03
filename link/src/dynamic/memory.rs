use linked_list_allocator::*;
use memmap::*;
use std::alloc::Layout;
use std::error::Error;
//use std::fmt;
use std::io;
use std::ptr::NonNull;

pub struct BlockFactoryInner {
    page_size: usize,
    m: MmapMut,
    heap: Heap,
}

pub struct BlockInner {
    layout: Layout,
    size: usize,
    p: NonNull<u8>,
}

impl BlockInner {
    pub fn as_ptr(&self) -> *const u8 {
        self.p.as_ptr() as *const u8
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn copy(&mut self, buf: &[u8]) {
        // copy data into the area
        assert!(buf.len() <= self.layout.size());
        let size = std::cmp::min(buf.len(), self.layout.size());
        unsafe {
            std::ptr::copy(buf.as_ptr(), self.p.as_ptr(), size);
        }
    }
}

impl BlockFactoryInner {
    pub fn create(num_pages: usize) -> Result<BlockFactoryInner, Box<dyn Error>> {
        // the total amount of space allocated should not be more than 4GB,
        // because we are limited to 32bit relative addressing
        // we can address things outside this block, but we need 64 bit addressing
        let ps = page_size();
        let size = ps * num_pages;
        let m = MmapMut::map_anon(size)?;
        //unsafe {
        //libc::mprotect(m.as_ptr() as *mut libc::c_void, size_plus_metadata, 7);
        //}
        let mut heap = Heap::empty();

        unsafe {
            let ptr = m.as_ptr();
            log::debug!("Memory Block Created: {:#08x}+{:x}", ptr as usize, size);
            heap.init(ptr as *mut u8, ps * num_pages);
            assert_eq!(heap.bottom(), ptr as *mut u8);
        }

        Ok(Self {
            page_size: ps,
            heap,
            m,
        })
    }

    pub fn used(&self) -> usize {
        self.heap.used()
    }

    pub fn force_rw(&mut self) {
        self.mprotect(libc::PROT_READ | libc::PROT_WRITE).unwrap();
    }

    pub fn force_rx(&mut self) {
        self.mprotect(libc::PROT_READ | libc::PROT_EXEC).unwrap();
    }

    pub fn force_ro(&mut self) {
        self.mprotect(libc::PROT_READ).unwrap();
    }

    pub fn alloc_block_align(&mut self, size: usize, align: usize) -> Option<BlockInner> {
        assert!(size > 0);
        let layout = Layout::from_size_align(size, align).unwrap();
        match self.heap.allocate_first_fit(layout) {
            Ok(p) => Some(BlockInner { layout, size, p }),
            Err(_e) => None,
        }
    }

    pub fn alloc_block(&mut self, size: usize) -> Option<BlockInner> {
        assert!(size > 0);
        let aligned_size = page_align(size, self.page_size);
        let layout = Layout::from_size_align(aligned_size, 16).unwrap();
        match self.heap.allocate_first_fit(layout) {
            Ok(p) => Some(BlockInner { layout, size, p }),
            Err(_e) => None,
        }
    }

    fn mprotect(&mut self, prot: libc::c_int) -> io::Result<()> {
        unsafe {
            let alignment = self.m.as_ptr() as usize % self.page_size;
            let ptr = self.m.as_ptr().offset(-(alignment as isize));
            let len = self.m.len() + alignment;
            log::debug!("mprotect: {:#08x}+{:x}: {:x}", ptr as usize, len, prot);
            if libc::mprotect(ptr as *mut libc::c_void, len, prot) == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }
}

impl BlockFactoryInner {
    pub fn debug(&self) {
        let ps = page_size();
        let size = self.heap.size();
        log::debug!("Start: {:#08x}", self.m.as_ptr() as usize);
        log::debug!("Heap Bottom: {:#08x}", self.heap.bottom() as usize);
        log::debug!("Heap Top: {:#08x}", self.heap.top() as usize);
        log::debug!("Heap Size: {:#08x} ({})", size, size);
        log::debug!("Page Size: {:#08x} ({})", ps, ps);
    }
}

pub enum BlockPermission {
    RW,
    RO,
    RX,
}

fn page_align(n: usize, ps: usize) -> usize {
    // hardwired for now, but we can get this from the target we are running at at runtime
    (n + (ps - 1)) & !(ps - 1)
}

fn page_size() -> usize {
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}
