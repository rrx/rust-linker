use crate::memory::*;

#[derive(Clone)]
pub struct SmartBlock {
    heap: HeapBlock,
}

impl SmartBlock {
    pub fn new(heap: HeapBlock) -> Self {
        Self { heap }
    }

    pub fn used(&self) -> usize {
        self.heap.used()
    }
}

#[derive(Clone)]
pub struct TableVersion {
    block: SmartBlock,
    entries: im::HashMap<String, SmartPointer>,
}

impl TableVersion {
    pub fn new(block: SmartBlock) -> Self {
        Self {
            block,
            entries: im::HashMap::new(),
        }
    }

    pub fn used(&self) -> usize {
        self.block.used()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    pub fn create_buffer(&mut self, buf: &[u8]) -> SmartPointer {
        self.block.heap.add_buf(buf).unwrap()
    }

    pub fn create_buffer_empty(&mut self, size: usize) -> SmartPointer {
        self.block.heap.alloc(size).unwrap()
    }

    // update and return a new version of the table
    pub fn update(mut self, name: String, p: SmartPointer) -> Self {
        self.entries.insert(name, p);
        self
    }

    pub fn get(&self, name: &str) -> Option<SmartPointer> {
        self.entries.get(name).cloned()
    }

    pub fn debug(&self) {
        log::debug!("Table@{:#08x}", self.block.heap.base() as usize);
        for (k, v) in &self.entries {
            unsafe {
                let ptr = v.as_ptr() as *const usize;
                log::debug!(" {:#08x}:*{:#08x}:{}", ptr as usize, *ptr, k);
            }
        }
    }
}
