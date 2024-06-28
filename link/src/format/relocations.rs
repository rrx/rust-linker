use crate::aot::{Data, ReadSymbol, ResolvePointer};
use object::{
    elf::R_X86_64_GOTPCRELX, Relocation, RelocationEncoding, RelocationKind, RelocationTarget,
};
use std::fmt;

const R_X86_64_GOTPCREL: u32 = 0x29; //41;
const R_X86_64_REX_GOTP: u32 = 0x2a; //42;

#[derive(Debug, Clone, PartialEq)]
pub enum PatchEffect {
    AddToGot,
    AddToPlt,
    DoNothing,
}

#[derive(Debug, Clone)]
pub struct LinkRelocation {
    kind: RelocationKind,
    encoding: RelocationEncoding,
    pub(crate) size: u8,
    pub(crate) target: RelocationTarget,
    pub(crate) addend: i64,
    implicit_addend: bool,
}

impl LinkRelocation {
    pub fn size(&self) -> u8 {
        self.size
    }
    pub fn kind(&self) -> RelocationKind {
        self.kind
    }
    pub fn encoding(&self) -> RelocationEncoding {
        self.encoding
    }
    pub fn effect(&self) -> PatchEffect {
        use PatchEffect::*;
        match self.kind {
            RelocationKind::Elf(R_X86_64_GOTPCREL) => AddToGot,
            RelocationKind::Elf(R_X86_64_REX_GOTP) => AddToGot,
            RelocationKind::Absolute => DoNothing,
            RelocationKind::Relative => DoNothing,
            RelocationKind::PltRelative => AddToPlt,
            _ => unimplemented!("{:?}", self.kind),
        }
    }
}

impl From<Relocation> for LinkRelocation {
    fn from(item: Relocation) -> Self {
        Self {
            kind: item.kind(),
            encoding: item.encoding(),
            size: item.size(),
            target: item.target(),
            addend: item.addend(),
            implicit_addend: item.has_implicit_addend(),
        }
    }
}

#[derive(Clone, Debug)]
pub struct CodeRelocation {
    pub(crate) name: String,
    pub(crate) offset: u64,
    pub(crate) r: LinkRelocation,
}

impl fmt::Display for CodeRelocation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Relocation[{}@{:#04x}, kind: {:?}, enc: {:?}, sz: {}, addend: {}]",
            self.name, self.offset, self.r.kind, self.r.encoding, self.r.size, self.r.addend
        )
    }
}

impl CodeRelocation {
    pub fn effect(&self) -> PatchEffect {
        self.r.effect()
    }

    pub fn is_plt(&self) -> bool {
        match self.r.kind() {
            RelocationKind::PltRelative => true,
            _ => false,
        }
    }

    pub fn is_got(&self) -> bool {
        match self.r.kind() {
            RelocationKind::Elf(R_X86_64_REX_GOTP) => true,
            RelocationKind::Elf(R_X86_64_GOTPCREL) => true,
            _ => false,
        }
    }

    pub fn patch_dynamic(
        &self,
        // pointer to the base of the relocation slice
        patch_base: *mut u8,

        // this will be the same for patch_base when live
        v_base: *mut u8, // the virtual base, where the segment will be mapped

        // pointer to address
        addr: *const u8,
    ) {
        match self.r.kind {
            RelocationKind::Elf(R_X86_64_GOTPCREL /* 41 */) => {
                unsafe {
                    let patch = patch_base.offset(self.offset as isize);
                    let v = v_base.offset(self.offset as isize);
                    log::debug!("v: {:#08x}", v as usize);

                    // this works
                    let value = addr as isize + self.r.addend as isize - v as isize;
                    log::debug!("value: {:#04x}", value as u32);

                    let before = std::ptr::read(patch);
                    std::ptr::write(patch as *mut u32, value as u32);

                    log::debug!("patch: {:#08x}", patch as usize);

                    log::info!(
                        "rel got {}: patch {:#08x}:{:#08x}=>{:#08x} addend:{:#08x} addr:{:#08x}",
                        &self.name,
                        patch as usize,
                        before,
                        value as u32,
                        self.r.addend,
                        addr as usize,
                    );
                }
            }

            RelocationKind::Elf(R_X86_64_REX_GOTP /* 42 */) => {
                // R_X86_64_REX_GOTPCRELX
                // got entry + addend - reloc_offset(patch)
                // we are computing the offset from the current instruction pointer
                unsafe {
                    let patch = patch_base.offset(self.offset as isize);
                    let v = v_base.offset(self.offset as isize);

                    // this works
                    let value = addr as isize + self.r.addend as isize - v as isize;

                    // this does not work
                    //let value = patch as isize + rel.r.addend as isize - addr as isize;

                    let before = std::ptr::read(patch);
                    log::debug!("patch_base: {:#08x}", patch_base as usize);
                    log::debug!("patch: {:#08x}", patch as usize);
                    log::debug!("v_base: {:#08x}", v_base as usize);
                    log::debug!("v: {:#08x}", v as usize);
                    log::debug!("value: {:#04x}", value as u32);
                    log::debug!("addr:  {:#08x}", addr as usize);

                    //(patch as *mut u32).replace(value as u32);
                    std::ptr::write(patch as *mut u32, value as u32);

                    log::info!(
                        "rel got {}: patch {:#08x}:{:#08x}=>{:#08x} addend:{:#08x} addr:{:#08x}",
                        &self.name,
                        patch as usize,
                        before,
                        value as u32,
                        self.r.addend,
                        addr as usize,
                    );
                }
            }

            RelocationKind::Absolute => {
                // S + A
                // S = Address of the symbol
                // A = value of the Addend
                //
                let name = &self.name;
                unsafe {
                    // we need to dereference here, because the pointer is coming from the GOT
                    let vaddr = *(addr as *const usize) as usize;
                    let adjusted = vaddr + self.r.addend as usize;
                    let patch = patch_base.offset(self.offset as isize);
                    let _v = v_base.offset(self.offset as isize);
                    let before = std::ptr::read(patch);

                    let patch = match self.r.size {
                        32 => {
                            // patch as 32 bit
                            //let adjusted = addr.offset(self.r.addend as isize) as u64;
                            //*(patch as *mut i32) = adjusted as i32;
                            unimplemented!("32 bit absolute relocation does not work");
                            //patch as u64
                        }
                        64 => {
                            // patch as 64 bit
                            let patch = patch_base.offset(self.offset as isize) as *mut u64;
                            std::ptr::write(patch as *mut u64, adjusted as u64);
                            patch as u64
                        }
                        _ => unimplemented!(),
                    };

                    log::info!(
                        "rel absolute {}: patch {:#16x}:{:#16x}=>{:#16x} addend:{:#08x} addr:{:#08x}, vaddr:{:#08x}",
                        name, patch, before, adjusted as usize, self.r.addend, addr as u64, vaddr as usize
                    );
                }
            }

            RelocationKind::Relative => {
                unsafe {
                    // we need to dereference here, because the pointer is coming from the GOT
                    //log::debug!("addr:  {:#08x}", addr as usize);
                    //let vaddr = *(addr as *const usize) as usize;
                    //
                    // R_X86_64_PC32
                    // This should just be a simple offset, no need for the GOT
                    //
                    let vaddr = addr as *const usize;
                    let patch = patch_base.offset(self.offset as isize);
                    let v = v_base.offset(self.offset as isize);
                    let before = std::ptr::read(patch as *const usize);
                    let relative_address = vaddr as isize + self.r.addend as isize - v as isize;

                    // patch as 32 bit
                    std::ptr::write(patch as *mut u32, relative_address as u32);

                    log::info!(
                        "rel relative {}: patch {:#08x}:{:#08x}=>{:#08x} addend:{:#08x} addr:{:#08x}, vaddr:{:#08x}",
                        &self.name, patch as usize, before, relative_address as usize, self.r.addend, addr as u64, vaddr as usize
                    );
                }
            }

            RelocationKind::PltRelative => {
                // L + A - P, 32 bit output
                // L = address of the symbols entry within the procedure linkage table
                // A = value of the Addend
                // P = address of the place of the relocation

                // address should point to the PLT

                // complicated pointer arithmetic to update the relocations
                unsafe {
                    let patch = patch_base.offset(self.offset as isize);
                    let v = v_base.offset(self.offset as isize);

                    let symbol_address = addr as isize + self.r.addend as isize - v as isize;
                    let before = std::ptr::read(patch as *const u32);

                    // patch as 32 bit
                    let patch = patch as *mut u32;
                    std::ptr::write(patch as *mut u32, symbol_address as u32);

                    log::info!(
                        "plt relative {}: patch {:#08x}:{:#08x}=>{:#08x} addend:{:#08x} addr:{:#08x}",
                        &self.name, patch as usize, before, symbol_address as usize, self.r.addend, addr as u64
                    );
                }
            }
            _ => unimplemented!(),
        }
    }

    pub fn pointer(&self, data: &Data, symbol: &ReadSymbol) -> ResolvePointer {
        let pointer = symbol.pointer.clone();
        log::info!(target: "relocations", "{}: relocation: {:?}", &self.name, self);
        log::info!(target: "relocations", "{}: offset: {:#0x}", &self.name, self.offset);
        log::info!(target: "relocations", "{}: symbol pointer:  {}, addend: {:#0x}", &self.name, symbol.pointer, self.r.addend);
        log::info!(target: "relocations", "{}: is_static: {}, got: {}, plt: {}", &self.name, symbol.is_static(), self.is_got(), self.is_plt());

        let pointer = if symbol.is_static() {
            if self.is_got() {
                let index = data.dynamics.got_lookup.get(&symbol.name).unwrap();
                ResolvePointer::Got(*index)
            } else {
                pointer
            }
        } else {
            if self.is_got() {
                let index = data.dynamics.got_lookup.get(&symbol.name).unwrap();
                ResolvePointer::Got(*index)
            } else if self.is_plt() {
                let index = data.dynamics.pltgot_lookup.get(&symbol.name).unwrap();
                ResolvePointer::PltGot(*index)
            } else {
                pointer
            }
        };
        log::info!(target: "relocations", "{}: pointer:  {}", &self.name, pointer);
        pointer
    }

    pub fn patch(
        &self,
        data: &Data,
        symbol: &ReadSymbol,
        // pointer to the base of the relocation slice
        patch_base: *mut u8,
        // this will be the same for patch_base when live
        v_base: *mut u8, // the virtual base, where the segment will be mapped
        preload: bool,
    ) {
        let pointer = self.pointer(data, symbol);
        log::info!(target: "relocations", "{}: pointer: {}", &self.name, pointer);
        let mut addr = pointer.resolve(data).unwrap();
        log::info!(target: "relocations", "{}: resolved: {:#0x}", &self.name, addr);

        match self.r.kind {
            RelocationKind::Elf(R_X86_64_GOTPCREL /* 41 */)
            | RelocationKind::Elf(R_X86_64_REX_GOTP /* 42 */) => {
                /* Note: R_X86_64_REX_GOTPCRELX relocation has an optimization as defined in the ABI
                 * converting a relative offset to an immediate one
                 */

                // R_X86_64_GOTPCRELX
                // R_X86_64_REX_GOTPCRELX
                // G + GOT + A - P
                unsafe {
                    let patch = patch_base.offset(self.offset as isize);
                    let v = v_base.offset(self.offset as isize);
                    log::debug!("v: {:#08x}", v as usize);

                    // this works
                    let value = addr as isize + self.r.addend as isize - v as isize;
                    log::debug!("value: {:#04x}", value as u32);

                    let before = std::ptr::read(patch);
                    std::ptr::write(patch as *mut u32, value as u32);

                    log::debug!("patch: {:#08x}", patch as usize);

                    log::info!(
                        "rel got {}: patch {:#08x}:{:#08x}=>{:#08x} addend:{:#08x} addr:{:#08x}",
                        &self.name,
                        patch as usize,
                        before,
                        value as u32,
                        self.r.addend,
                        addr as usize,
                    );
                }
            }

            /*
            RelocationKind::Elf(R_X86_64_REX_GOTP /* 42 */) => {
                // R_X86_64_REX_GOTPCRELX
                // G + GOT + A - P
                /* Note: This relocation has an optimization as defined in the ABI
                 * converting a relative offset to an immediate one
                 */

                // got entry + addend - reloc_offset(patch)
                // we are computing the offset from the current instruction pointer

                //if preload {
                    // skip GOT and just point direct
                    //addr = symbol.pointer.resolve(data).unwrap();
                //}

                unsafe {
                    let v = v_base.offset(self.offset as isize);

                    // this works
                    let value = addr as isize + self.r.addend as isize - v as isize;

                    // this does not work
                    //let value = patch as isize + rel.r.addend as isize - addr as isize;

                    let patch = patch_base.offset(self.offset as isize);
                    let before = std::ptr::read(patch);
                    log::debug!("patch_base: {:#08x}", patch_base as usize);
                    log::debug!("patch: {:#08x}", patch as usize);
                    log::debug!("v_base: {:#08x}", v_base as usize);
                    log::debug!("v: {:#08x}", v as usize);
                    log::debug!("value: {:#04x}", value as u32);
                    log::debug!("addr:  {:#08x}", addr as usize);

                    std::ptr::write(patch as *mut u32, value as u32);

                    log::info!(
                        "rel got {}: patch {:#08x}:{:#08x}=>{:#08x} addend:{:#08x} addr:{:#08x}",
                        &self.name,
                        patch as usize,
                        before,
                        value as u32,
                        self.r.addend,
                        addr as usize,
                    );
                }
            }
            */
            RelocationKind::Absolute => {
                // S + A
                // S = Address of the symbol
                // A = value of the Addend
                //
                let name = &self.name;
                unsafe {
                    log::debug!("addr:  {:#08x}", addr as usize);
                    log::debug!("patch_base: {:#08x}", patch_base as usize);

                    // we need to dereference here, because the pointer is coming from the GOT
                    //let vaddr = std::ptr::read(addr as *const usize) as usize;
                    //log::debug!("vaddr: {:#08x}", vaddr as usize);

                    let adjusted = addr as usize + self.r.addend as usize;
                    log::debug!("adjusted: {:#0x}", adjusted);

                    let patch = patch_base.offset(self.offset as isize);
                    log::debug!("patch: {:#08x}", patch as usize);

                    //let _v = v_base.offset(self.offset as isize);
                    let before = std::ptr::read(patch);
                    log::debug!("before: {:#08x}", before);

                    let patch = match self.r.size {
                        32 => {
                            // patch as 32 bit
                            //let adjusted = addr.offset(self.r.addend as isize) as u64;
                            //*(patch as *mut i32) = adjusted as i32;
                            unimplemented!("32 bit absolute relocations not implemented");
                            //patch as u64
                        }
                        64 => {
                            // R_X86_64_64
                            // patch as 64 bit
                            let patch = patch_base.offset(self.offset as isize) as *mut u64;
                            log::debug!("write:  {:#0x} -> {:#0x}", adjusted as u64, patch as u64);
                            std::ptr::write(patch as *mut u64, adjusted as u64);
                            patch as u64
                        }
                        _ => unimplemented!(),
                    };

                    log::info!(
                        "rel absolute {}: patch {:#16x}:{:#16x}=>{:#16x} addend:{:#08x} addr:{:#08x}, vaddr:{:#08x}",
                        name, patch, before, adjusted as usize, self.r.addend, addr as u64, addr as usize
                    );
                }
            }

            RelocationKind::Relative => {
                unsafe {
                    // we need to dereference here, because the pointer is coming from the GOT
                    //log::debug!("addr:  {:#08x}", addr as usize);
                    //let vaddr = *(addr as *const usize) as usize;
                    //
                    // R_X86_64_PC32
                    // This should just be a simple offset, no need for the GOT
                    //
                    let vaddr = addr as *const usize;
                    let patch = patch_base.offset(self.offset as isize);
                    let v = v_base.offset(self.offset as isize);
                    let before = std::ptr::read(patch as *const usize);
                    let relative_address = vaddr as isize + self.r.addend as isize - v as isize;

                    // patch as 32 bit
                    std::ptr::write(patch as *mut u32, relative_address as u32);

                    log::info!(
                        "rel relative {}: patch {:#08x}:{:#08x}=>{:#08x} addend:{:#08x} addr:{:#08x}, vaddr:{:#08x}",
                        &self.name, patch as usize, before, relative_address as usize, self.r.addend, addr as u64, vaddr as usize
                    );
                }
            }

            RelocationKind::PltRelative => {
                // L + A - P, 32 bit output
                // L = address of the symbols entry within the procedure linkage table
                // A = value of the Addend
                // P = address of the place of the relocation

                // address should point to the PLT

                // complicated pointer arithmetic to update the relocations
                //
                if preload {
                    addr = symbol.pointer.resolve(data).unwrap();
                }

                unsafe {
                    let patch = patch_base.offset(self.offset as isize);
                    let v = v_base.offset(self.offset as isize);

                    let symbol_address = addr as isize + self.r.addend as isize - v as isize;
                    let before = std::ptr::read(patch as *const u32);

                    // patch as 32 bit
                    let patch = patch as *mut u32;
                    std::ptr::write(patch as *mut u32, symbol_address as u32);

                    log::info!(
                        "plt relative {}: patch {:#08x}:{:#08x}=>{:#08x} addend:{:#08x} addr:{:#08x}",
                        &self.name, patch as usize, before, symbol_address as usize, self.r.addend, addr as u64
                    );
                }
            }
            _ => unimplemented!(),
        }
    }
}
