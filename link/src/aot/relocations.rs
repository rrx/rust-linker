use super::*;
use crate::format::*;
use object::write::elf::{SectionIndex, Writer};
use object::write::StringId;
use object::{RelocationEncoding, RelocationKind};

use object::elf;
use object::Architecture;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelocationError(String);

pub struct RelaDynSection {
    kind: GotSectionKind,
    name_id: Option<StringId>,
    count: usize,
    offsets: SectionOffset,
    is_rela: bool,
}

impl RelaDynSection {
    pub fn new(kind: GotSectionKind) -> Self {
        let name = format!("reladyn:{:?}", kind);
        Self {
            kind,
            name_id: None,
            count: 0,
            offsets: SectionOffset::new(name, AllocSegment::RO, 0x08),
            is_rela: true,
        }
    }

    fn section_relocation_reserve(&mut self, data: &mut Data, w: &mut Writer) {
        let relocations = data.dynamics.relocations.relocations(self.kind);

        self.count = relocations.len();
        let file_offset = w.reserve_start_section(&self.offsets);
        w.reserve_relocations(relocations.len(), self.is_rela);

        let after = w.reserved_len();
        let size = after - file_offset;
        self.offsets.size = size as u64;

        data.segments
            .add_offsets(self.offsets.alloc, &mut self.offsets);
        assert_eq!(
            data.segments.current().adjusted_file_offset as usize + self.offsets.size as usize,
            w.reserved_len()
        );

        match self.kind {
            GotSectionKind::GOT => {
                data.addr_set(".rela.dyn", self.offsets.address);
                data.reladyn.size = Some(w.rel_size(self.is_rela) * relocations.len());
            }
            GotSectionKind::GOTPLT => {
                data.addr_set(".rela.plt", self.offsets.address);
                data.relaplt.size = Some(w.rel_size(self.is_rela) * relocations.len());
            }
        }
    }

    fn section_write_relocations(&self, data: &Data, w: &mut Writer) {
        let relocations = data.dynamics.relocations.relocations(self.kind);
        w.write_start_section(&self.offsets);
        assert_eq!(self.count, relocations.len());

        // we are writing a relocation for the GOT entries
        for (r, symbol) in relocations.iter() {
            let mut r_addend = 0;
            let mut r_sym = 0;

            // if relative, look up the pointer in statics
            if symbol.is_static() {
                let _static_sym = data
                    .statics
                    .symbol_hash
                    .get(&symbol.name)
                    .expect(&format!("not found {}", &symbol.name));
                //r_sym = if let Some(symbol_index) = static_sym.symbol_index {
                //symbol_index.0
                //} else {
                //0
                //};
                //r_sym = 0;

                if let Some(p) = data.statics.symbol_get(&symbol.name) {
                    if let Some(addr) = p.resolve(data) {
                        r_addend = addr as i64;
                    }
                }
            } else {
                // we needed to fork object in order to access .0
                let (symbol_index, _sym) = data
                    .dynamics
                    .symbol_get(&symbol.name, data)
                    .expect(&format!("not found {}", &symbol.name));
                r_sym = symbol_index.0;
                r_addend = 0;
            }

            let r_type = match self.kind {
                GotSectionKind::GOT => {
                    if symbol.is_static() {
                        elf::R_X86_64_RELATIVE
                    } else if r.r.kind() == object::RelocationKind::Absolute {
                        elf::R_X86_64_64
                    } else {
                        elf::R_X86_64_GLOB_DAT
                    }
                }
                GotSectionKind::GOTPLT => elf::R_X86_64_JUMP_SLOT,
            };

            let r_offset = match self.kind {
                GotSectionKind::GOT => {
                    if r.r.kind() == object::RelocationKind::Absolute {
                        let addr = data.addr_get(&r.section_name);
                        addr as usize + r.offset as usize
                    } else {
                        let got_addr = data.addr_get(".got");
                        let got_index = data
                            .dynamics
                            .relocations
                            .got_lookup
                            .get(&symbol.name)
                            .unwrap();
                        got_addr as usize + got_index * std::mem::size_of::<usize>()
                    }
                }
                GotSectionKind::GOTPLT => {
                    let start = 3;
                    let plt_addr = data.addr_get(".got.plt");
                    let plt_index = data
                        .dynamics
                        .relocations
                        .plt_lookup
                        .get(&symbol.name)
                        .unwrap();
                    plt_addr as usize + (plt_index + start) * std::mem::size_of::<usize>()
                }
            };

            w.write_relocation(
                true,
                &object::write::elf::Rel {
                    r_offset: r_offset as u64,
                    r_sym,
                    r_type,
                    r_addend,
                },
            );
        }
    }

    fn section_write_relocation_header(&self, data: &Data, w: &mut Writer) {
        let relocations = data.dynamics.relocations.relocations(self.kind);

        let sh_addralign = self.offsets.align;

        let sh_info = match self.kind {
            GotSectionKind::GOT => SectionIndex::default(),
            GotSectionKind::GOTPLT => data.section_index_get(".got.plt"),
        };

        let sh_link = data.dynsym.section_index.unwrap().0;
        let sh_entsize = w.rel_size(self.is_rela) as u64;

        let sh_type = if self.is_rela {
            elf::SHT_RELA
        } else {
            elf::SHT_REL
        };

        w.write_section_header(&object::write::elf::SectionHeader {
            name: self.name_id,
            sh_type,
            sh_flags: self.kind.rel_flags().into(),
            sh_addr: self.offsets.address,
            sh_offset: self.offsets.file_offset,
            sh_info: sh_info.0,
            sh_link,
            sh_entsize,
            sh_addralign,
            sh_size: sh_entsize * relocations.len() as u64,
        });
    }
}

impl ElfBlock for RelaDynSection {
    fn name(&self) -> String {
        self.offsets.name.clone()
    }

    fn alloc(&self) -> AllocSegment {
        self.offsets.alloc
    }

    fn reserve_section_index(&mut self, _: &mut Data, w: &mut Writer) {
        let name = self.kind.rel_section_name();
        self.name_id = Some(w.add_section_name(name.as_bytes()));
        self.offsets.section_index = Some(w.reserve_section_index());
    }

    fn reserve(&mut self, data: &mut Data, w: &mut Writer) {
        self.section_relocation_reserve(data, w);
    }

    fn write(&self, data: &Data, w: &mut Writer) {
        self.section_write_relocations(data, w);
    }

    fn write_section_header(&self, data: &Data, w: &mut Writer) {
        self.section_write_relocation_header(data, w);
    }
}

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
