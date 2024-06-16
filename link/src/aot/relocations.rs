use crate::format::*;
use object::{RelocationEncoding, RelocationKind};

use object::elf;
use object::Architecture;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationError(String);

// taken from object library
pub fn r_type(arch: Architecture, reloc: &LinkRelocation) -> Result<u32, RelocationError> {
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
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
            }
        },
        Architecture::Arm => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_ARM_ABS32,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
            }
        },
        Architecture::Avr => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_AVR_32,
            (RelocationKind::Absolute, _, 16) => elf::R_AVR_16,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
            }
        },
        Architecture::Bpf => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 64) => elf::R_BPF_64_64,
            (RelocationKind::Absolute, _, 32) => elf::R_BPF_64_32,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
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
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
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
                    return Err(RelocationError(format!(
                        "unimplemented relocation {:?}",
                        reloc
                    )));
                }
            }
        }
        Architecture::Hexagon => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_HEX_32,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
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
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
            }
        },
        Architecture::Mips | Architecture::Mips64 => {
            match (reloc.kind(), reloc.encoding(), reloc.size()) {
                (RelocationKind::Absolute, _, 16) => elf::R_MIPS_16,
                (RelocationKind::Absolute, _, 32) => elf::R_MIPS_32,
                (RelocationKind::Absolute, _, 64) => elf::R_MIPS_64,
                (RelocationKind::Elf(x), _, _) => x,
                _ => {
                    return Err(RelocationError(format!(
                        "unimplemented relocation {:?}",
                        reloc
                    )));
                }
            }
        }
        Architecture::Msp430 => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_MSP430_32,
            (RelocationKind::Absolute, _, 16) => elf::R_MSP430_16_BYTE,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
            }
        },
        Architecture::PowerPc => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_PPC_ADDR32,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
            }
        },
        Architecture::PowerPc64 => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_PPC64_ADDR32,
            (RelocationKind::Absolute, _, 64) => elf::R_PPC64_ADDR64,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
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
                    return Err(RelocationError(format!(
                        "unimplemented relocation {:?}",
                        reloc
                    )));
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
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
            }
        },
        Architecture::Sbf => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 64) => elf::R_SBF_64_64,
            (RelocationKind::Absolute, _, 32) => elf::R_SBF_64_32,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
            }
        },
        Architecture::Sparc64 => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            // TODO: use R_SPARC_32/R_SPARC_64 if aligned.
            (RelocationKind::Absolute, _, 32) => elf::R_SPARC_UA32,
            (RelocationKind::Absolute, _, 64) => elf::R_SPARC_UA64,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
            }
        },
        Architecture::Xtensa => match (reloc.kind(), reloc.encoding(), reloc.size()) {
            (RelocationKind::Absolute, _, 32) => elf::R_XTENSA_32,
            (RelocationKind::Relative, RelocationEncoding::Generic, 32) => elf::R_XTENSA_32_PCREL,
            (RelocationKind::Elf(x), _, _) => x,
            _ => {
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
            }
        },
        _ => {
            if let RelocationKind::Elf(x) = reloc.kind() {
                x
            } else {
                return Err(RelocationError(format!(
                    "unimplemented relocation {:?}",
                    reloc
                )));
            }
        }
    };
    Ok(r_type)
}
