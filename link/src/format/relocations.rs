use object::{Relocation, RelocationEncoding, RelocationKind, RelocationTarget};
use std::fmt;

const R_X86_64_GOTPCREL: u32 = 0x29; //41;
const R_X86_64_REX_GOTP: u32 = 0x2a; //42;

#[derive(Debug, Clone)]
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
    //pub(crate) name_id: Option<StringId>,
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
            _ => false,
        }
    }

    pub fn patch(
        &self,
        // pointer to the base of the relocation slice
        patch_base: *mut u8,

        // this will be the same for patch_base when live
        v_base: *mut u8, // the virtual base, where the segment will be mapped

        // pointer to address
        addr: *const u8,
    ) {
        log::debug!("{}", self);
        log::debug!("patch_base: {:#08x}", patch_base as usize);
        log::debug!("v_base:  {:#08x}", v_base as usize);
        log::debug!("addr:    {:#08x}", addr as usize);
        log::debug!("offset:  {:#08x}", self.offset);
        match self.r.kind {
            RelocationKind::Elf(R_X86_64_GOTPCREL) => {
                unsafe {
                    let patch = patch_base.offset(self.offset as isize);
                    let v = v_base.offset(self.offset as isize);
                    log::debug!("v: {:#08x}", v as usize);

                    // this works
                    let value = addr as isize + self.r.addend as isize - v as isize;
                    log::debug!("value: {:#04x}", value as u32);

                    let before = std::ptr::read(patch);
                    (patch as *mut u32).replace(value as u32);
                    log::debug!("patch: {:#08x}", patch as usize);

                    log::debug!(
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

            RelocationKind::Elf(R_X86_64_REX_GOTP) => {
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

                    (patch as *mut u32).replace(value as u32);

                    log::debug!(
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
                            *(patch as *mut u64) = adjusted as u64;
                            patch as u64
                        }
                        _ => unimplemented!(),
                    };

                    log::debug!(
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
                    //patch.as_mut_slice()[2..6].copy_from_slice(&b);
                    std::ptr::write(patch as *mut u32, relative_address as u32);
                    //std::slice::from_raw_parts_mut(patch as *mut u32, 1)[0] = relative_address as u32;
                    //patch.as_slice
                    //let patch = patch as *mut u32;
                    //*patch = relative_address as u32;

                    log::debug!(
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

                    // patch as 32 bit
                    let patch = patch as *mut u32;
                    //*patch = symbol_address as u32;
                    std::ptr::write(patch as *mut u32, symbol_address as u32);

                    log::debug!(
                            "rel {}: patch:{:#08x} patchv:{:#08x} addend:{:#08x} addr:{:#08x} symbol:{:#08x}",
                            &self.name,
                            patch as usize,
                            std::ptr::read(patch),
                            self.r.addend,
                            addr as isize,
                            symbol_address as isize,
                            );
                }
            }
            _ => unimplemented!(),
        }
    }
}