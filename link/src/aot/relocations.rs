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
                // TODO: Adding symbols to the relative relocations causes musl to segfault

                /*
                if let Some((symbol_index, sym)) = data.dynamics.symbol_get(&symbol.name, data) {
                    r_sym = symbol_index.0;
                }
                */

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
