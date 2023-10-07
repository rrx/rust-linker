use super::*;
use crate::SmartPointer;
use object::write::StringId;
use object::{Relocation, RelocationEncoding, RelocationKind, RelocationTarget};
use std::fmt;
use std::ptr::NonNull;

const R_X86_64_GOTPCREL: u32 = 0x29; //41;
const R_X86_64_REX_GOTP: u32 = 0x2a; //42;

#[derive(Clone, Debug)]
pub enum RelocationPointer {
    Got(SmartPointer), //NonNull<u8>),
    Plt(NonNull<u8>),
    Direct(NonNull<u8>),
    Shared(NonNull<u8>),
    Smart(SmartPointer),
}
impl RelocationPointer {
    pub fn as_ptr(&self) -> *const () {
        match self {
            Self::Plt(p) | Self::Direct(p) | Self::Shared(p) => p.as_ptr() as *const (),
            Self::Got(p) => p.as_ptr() as *const (),
            Self::Smart(p) => p.as_ptr() as *const (),
        }
    }
    pub fn direct2(p: *const ()) -> Option<Self> {
        NonNull::new(p as *mut u8).map(|p| Self::Direct(p))
    }

    pub fn shared(p: *const ()) -> Option<Self> {
        NonNull::new(p as *mut u8).map(|p| Self::Shared(p))
    }

    pub fn smart(p: SmartPointer) -> Self {
        Self::Smart(p)
    }
}
impl fmt::Display for RelocationPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Got(p) => write!(f, "G({:#08x})", p.as_ptr() as usize),
            Self::Plt(p) => write!(f, "P({:#08x})", p.as_ptr() as usize),
            Self::Direct(p) => write!(f, "D({:#08x})", p.as_ptr() as usize),
            Self::Shared(p) => write!(f, "S({:#08x})", p.as_ptr() as usize),
            Self::Smart(p) => write!(f, "X({:#08x})", p.as_ptr() as usize),
        }
    }
}

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
            _ => unimplemented!(),
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
    pub(crate) name_id: Option<StringId>,
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
                    let patch = patch as *mut u32;
                    *patch = relative_address as u32;

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
                    *patch = symbol_address as u32;

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

pub fn patch_code(
    block: PatchBlock,
    pointers: PatchSymbolPointers,
    _got: TableVersion,
    _plt: TableVersion,
) -> PatchBlock {
    log::debug!(
        "patching code {} at base {:#08x}",
        &block.name,
        block.block.as_ptr() as usize
    );

    for r in &block.relocations {
        let patch_base = block.block.as_ptr();
        let addr = pointers
            .get(&r.name)
            .expect(&format!("missing symbol: {}", &r.name))
            .as_ptr() as *const u8;
        log::debug!(
            "r ptr: {:#08x}:{:#08x}: {}",
            patch_base as usize,
            addr as usize,
            &r.name
        );

        r.patch(patch_base as *mut u8, patch_base as *mut u8, addr);
    }

    block
}

pub fn patch_data(
    block: PatchBlock,
    pointers: PatchSymbolPointers,
    got: TableVersion,
    _plt: TableVersion,
) -> PatchBlock {
    log::debug!(
        "patching data {} at base {:#08x}",
        &block.name,
        block.block.as_ptr() as usize
    );

    for r in &block.relocations {
        let patch_base = block.block.as_ptr();
        let addr = match r.effect() {
            PatchEffect::AddToGot => got.get(&r.name).unwrap().as_ptr(),
            _ => {
                if let Some(p) = pointers.get(&r.name) {
                    p.as_ptr() as *const u8
                } else if let Some(p) = block.internal.get(&r.name) {
                    p.as_ptr() as *const u8
                } else {
                    unreachable!("symbol not found:{}", &r.name)
                }
            }
        };

        log::debug!(
            "r ptr: {:#08x}:{:#08x}:{:?}:{}",
            patch_base as usize,
            addr as usize,
            r.effect(),
            &r.name
        );

        r.patch(patch_base as *mut u8, patch_base as *mut u8, addr);
    }
    block
}

use object::elf;
use object::Architecture;
//use std::error::Error;
//use object::read::Error;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Error(String);

// taken from object library
pub fn r_type(arch: Architecture, reloc: &LinkRelocation) -> Result<u32, Error> {
    let r_type = match arch {
        Architecture::Aarch64 => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, RelocationEncoding::Generic, 64) => elf::R_AARCH64_ABS64,
            (RelocationKind::Absolute, RelocationEncoding::Generic, 32) => elf::R_AARCH64_ABS32,
            (RelocationKind::Absolute, RelocationEncoding::Generic, 16) => elf::R_AARCH64_ABS16,
            (RelocationKind::Relative, RelocationEncoding::Generic, 64) => elf::R_AARCH64_PREL64,
            (RelocationKind::Relative, RelocationEncoding::Generic, 32) => elf::R_AARCH64_PREL32,
            (RelocationKind::Relative, RelocationEncoding::Generic, 16) => elf::R_AARCH64_PREL16,
            (RelocationKind::Relative, RelocationEncoding::AArch64Call, 26)
            | (RelocationKind::PltRelative, RelocationEncoding::AArch64Call, 26) => {
                elf::R_AARCH64_CALL26
            }
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::Arm => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_ARM_ABS32,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::Avr => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_AVR_32,
            (RelocationKind::Absolute, _, 16) => elf::R_AVR_16,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::Bpf => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 64) => elf::R_BPF_64_64,
            (RelocationKind::Absolute, _, 32) => elf::R_BPF_64_32,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::I386 => match (reloc.kind(), reloc.size()) {
            (RelocationKind::Absolute, 32) => elf::R_386_32,
            (RelocationKind::Relative, 32) => elf::R_386_PC32,
            (RelocationKind::Got, 32) => elf::R_386_GOT32,
            (RelocationKind::PltRelative, 32) => elf::R_386_PLT32,
            (RelocationKind::GotBaseOffset, 32) => elf::R_386_GOTOFF,
            (RelocationKind::GotBaseRelative, 32) => elf::R_386_GOTPC,
            (RelocationKind::Absolute, 16) => elf::R_386_16,
            (RelocationKind::Relative, 16) => elf::R_386_PC16,
            (RelocationKind::Absolute, 8) => elf::R_386_8,
            (RelocationKind::Relative, 8) => elf::R_386_PC8,
            (RelocationKind::Elf(x), _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::X86_64 | Architecture::X86_64_X32 => {
            match (reloc.kind(), reloc.encoding(), reloc.size()) {
                (RelocationKind::Absolute, RelocationEncoding::Generic, 64) => elf::R_X86_64_64,
                (RelocationKind::Relative, _, 32) => elf::R_X86_64_PC32,
                (RelocationKind::Got, _, 32) => elf::R_X86_64_GOT32,
                (RelocationKind::PltRelative, _, 32) => elf::R_X86_64_PLT32,
                (RelocationKind::GotRelative, _, 32) => elf::R_X86_64_GOTPCREL,
                (RelocationKind::Absolute, RelocationEncoding::Generic, 32) => elf::R_X86_64_32,
                (RelocationKind::Absolute, RelocationEncoding::X86Signed, 32) => elf::R_X86_64_32S,
                (RelocationKind::Absolute, _, 16) => elf::R_X86_64_16,
                (RelocationKind::Relative, _, 16) => elf::R_X86_64_PC16,
                (RelocationKind::Absolute, _, 8) => elf::R_X86_64_8,
                (RelocationKind::Relative, _, 8) => elf::R_X86_64_PC8,
                (RelocationKind::Elf(x), _, _) => x,
                _ => {
                    return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                }
            }
        }
        Architecture::Hexagon => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_HEX_32,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::LoongArch64 => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_LARCH_32,
            (RelocationKind::Absolute, _, 64) => elf::R_LARCH_64,
            (RelocationKind::Relative, _, 32) => elf::R_LARCH_32_PCREL,
            (RelocationKind::Relative, RelocationEncoding::LoongArchBranch, 16)
            | (RelocationKind::PltRelative, RelocationEncoding::LoongArchBranch, 16) => {
                elf::R_LARCH_B16
            }
            (RelocationKind::Relative, RelocationEncoding::LoongArchBranch, 21)
            | (RelocationKind::PltRelative, RelocationEncoding::LoongArchBranch, 21) => {
                elf::R_LARCH_B21
            }
            (RelocationKind::Relative, RelocationEncoding::LoongArchBranch, 26)
            | (RelocationKind::PltRelative, RelocationEncoding::LoongArchBranch, 26) => {
                elf::R_LARCH_B26
            }
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::Mips | Architecture::Mips64 => {
            match (reloc.kind(), reloc.encoding(), reloc.size()) {
                (RelocationKind::Absolute, _, 16) => elf::R_MIPS_16,
                (RelocationKind::Absolute, _, 32) => elf::R_MIPS_32,
                (RelocationKind::Absolute, _, 64) => elf::R_MIPS_64,
                (RelocationKind::Elf(x), _, _) => x,
                _ => {
                    return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                }
            }
        }
        Architecture::Msp430 => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_MSP430_32,
            (RelocationKind::Absolute, _, 16) => elf::R_MSP430_16_BYTE,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::PowerPc => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_PPC_ADDR32,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::PowerPc64 => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_PPC64_ADDR32,
            (RelocationKind::Absolute, _, 64) => elf::R_PPC64_ADDR64,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::Riscv32 | Architecture::Riscv64 => {
            match (reloc.kind(), reloc.encoding(), reloc.size()) {
                (RelocationKind::Absolute, _, 32) => elf::R_RISCV_32,
                (RelocationKind::Absolute, _, 64) => elf::R_RISCV_64,
                (RelocationKind::Relative, RelocationEncoding::Generic, 32) => {
                    elf::R_RISCV_32_PCREL
                }
                (RelocationKind::Elf(x), _, _) => x,
                _ => {
                    return Err(Error(format!("unimplemented relocation {:?}", reloc)));
                }
            }
        }
        Architecture::S390x => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, RelocationEncoding::Generic, 8) => elf::R_390_8,
            (RelocationKind::Absolute, RelocationEncoding::Generic, 16) => elf::R_390_16,
            (RelocationKind::Absolute, RelocationEncoding::Generic, 32) => elf::R_390_32,
            (RelocationKind::Absolute, RelocationEncoding::Generic, 64) => elf::R_390_64,
            (RelocationKind::Relative, RelocationEncoding::Generic, 16) => elf::R_390_PC16,
            (RelocationKind::Relative, RelocationEncoding::Generic, 32) => elf::R_390_PC32,
            (RelocationKind::Relative, RelocationEncoding::Generic, 64) => elf::R_390_PC64,
            (RelocationKind::Relative, RelocationEncoding::S390xDbl, 16) => elf::R_390_PC16DBL,
            (RelocationKind::Relative, RelocationEncoding::S390xDbl, 32) => elf::R_390_PC32DBL,
            (RelocationKind::PltRelative, RelocationEncoding::S390xDbl, 16) => elf::R_390_PLT16DBL,
            (RelocationKind::PltRelative, RelocationEncoding::S390xDbl, 32) => elf::R_390_PLT32DBL,
            (RelocationKind::Got, RelocationEncoding::Generic, 16) => elf::R_390_GOT16,
            (RelocationKind::Got, RelocationEncoding::Generic, 32) => elf::R_390_GOT32,
            (RelocationKind::Got, RelocationEncoding::Generic, 64) => elf::R_390_GOT64,
            (RelocationKind::GotRelative, RelocationEncoding::S390xDbl, 32) => elf::R_390_GOTENT,
            (RelocationKind::GotBaseOffset, RelocationEncoding::Generic, 16) => elf::R_390_GOTOFF16,
            (RelocationKind::GotBaseOffset, RelocationEncoding::Generic, 32) => elf::R_390_GOTOFF32,
            (RelocationKind::GotBaseOffset, RelocationEncoding::Generic, 64) => elf::R_390_GOTOFF64,
            (RelocationKind::GotBaseRelative, RelocationEncoding::Generic, 64) => elf::R_390_GOTPC,
            (RelocationKind::GotBaseRelative, RelocationEncoding::S390xDbl, 32) => {
                elf::R_390_GOTPCDBL
            }
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::Sbf => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 64) => elf::R_SBF_64_64,
            (RelocationKind::Absolute, _, 32) => elf::R_SBF_64_32,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::Sparc64 => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            // TODO: use R_SPARC_32/R_SPARC_64 if aligned.
            (RelocationKind::Absolute, _, 32) => elf::R_SPARC_UA32,
            (RelocationKind::Absolute, _, 64) => elf::R_SPARC_UA64,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        Architecture::Xtensa => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_XTENSA_32,
            (RelocationKind::Relative, RelocationEncoding::Generic, 32) => elf::R_XTENSA_32_PCREL,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        },
        _ => {
            if let RelocationKind::Elf(x) = reloc.kind() {
                x
            } else {
                return Err(Error(format!("unimplemented relocation {:?}", reloc)));
            }
        }
    };
    Ok(r_type)
}
