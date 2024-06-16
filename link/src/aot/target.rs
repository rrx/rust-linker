use super::*;
use crate::format::{disassemble_code_with_symbols, print_bytes, Symbol};
use std::collections::HashSet;

#[derive(Debug, Clone)]
pub struct Target {
    pub dynamic: SymbolMap,
    pub locals: SymbolMap,
    pub exports: SymbolMap,
    pub ro: GeneralSection,
    pub rw: GeneralSection,
    pub rx: GeneralSection,
    pub bss: GeneralSection,
    //pub got: GeneralSection,
    //pub gotplt: GeneralSection,
    pub unresolved: HashSet<String>,
    pub unknown: SymbolMap,
}

impl Target {
    pub fn new() -> Self {
        Self {
            locals: SymbolMap::new(),
            exports: SymbolMap::new(),
            dynamic: SymbolMap::new(),
            ro: GeneralSection::new(AllocSegment::RO, ".rodata", 0x10),
            rw: GeneralSection::new(AllocSegment::RW, ".data", 0x10),
            rx: GeneralSection::new(AllocSegment::RX, ".text", 0x10),
            bss: GeneralSection::new(AllocSegment::RW, ".bss", 0x10),
            //got: GeneralSection::new(AllocSegment::RW, ".got", 0x10),
            //gotplt: GeneralSection::new(AllocSegment::RW, ".got.plt", 0x10),
            unresolved: HashSet::new(),
            unknown: SymbolMap::new(),
        }
    }

    pub fn lookup_static(&self, name: &str) -> Option<ReadSymbol> {
        if let Some(symbol) = self.locals.get(name) {
            Some(symbol.clone())
        } else if let Some(symbol) = self.exports.get(name) {
            Some(symbol.clone())
        } else {
            None
        }
    }

    pub fn lookup_dynamic(&self, name: &str) -> Option<ReadSymbol> {
        if let Some(symbol) = self.dynamic.get(name) {
            Some(symbol.clone())
        } else {
            None
        }
    }

    pub fn lookup(&self, name: &str) -> Option<ReadSymbol> {
        if let Some(symbol) = self.lookup_static(name) {
            Some(symbol.clone())
        } else if let Some(symbol) = self.lookup_dynamic(name) {
            Some(symbol.clone())
        } else {
            None
        }
    }

    pub fn insert_local(&mut self, s: ReadSymbol) {
        self.locals.insert(s.name.clone(), s);
    }

    pub fn insert_export(&mut self, s: ReadSymbol) {
        self.exports.insert(s.name.clone(), s);
    }

    pub fn insert_dynamic(&mut self, s: ReadSymbol) {
        self.dynamic.insert(s.name.clone(), s);
    }

    pub fn insert_unknown(&mut self, s: ReadSymbol) {
        self.unknown.insert(s.name.clone(), s);
    }

    pub fn dump(&self) {
        let mut rx_symbols = vec![];
        let mut rw_symbols = vec![];
        let mut ro_symbols = vec![];
        //let mut strings_symbols = vec![];
        let mut bss_symbols = vec![];
        let mut other_symbols = vec![];

        for (_name, sym) in self.locals.iter().chain(self.exports.iter()) {
            match sym.section {
                ReadSectionKind::RX => rx_symbols.push(sym),
                ReadSectionKind::RW => rw_symbols.push(sym),
                ReadSectionKind::ROData => ro_symbols.push(sym),
                //ReadSectionKind::ROStrings => strings_symbols.push(sym),
                ReadSectionKind::Bss => bss_symbols.push(sym),
                _ => other_symbols.push(sym),
            }
        }

        eprintln!("RX, size: {:#0x}", self.rx.size());
        for local in rx_symbols.iter() {
            eprintln!(" S: {:?}", local);
        }
        for r in self.rx.relocations().iter() {
            eprintln!(" R: {}, {:?}", r, self.lookup(&r.name));
        }

        let symbols = rx_symbols
            .into_iter()
            .map(|s| {
                if let ResolvePointer::Section(_name, address) = &s.pointer {
                    Symbol::new(0, *address, &s.name)
                } else {
                    unreachable!()
                }
            })
            .collect();
        disassemble_code_with_symbols(self.rx.bytes(), &symbols, &self.rx.relocations());

        eprintln!("RO, size: {:#0x}", self.ro.size());
        for local in ro_symbols.iter() {
            eprintln!(" S: {:?}", local);
        }
        for r in self.ro.relocations().iter() {
            eprintln!(" R: {}, {:?}", r, self.lookup(&r.name));
        }
        print_bytes(self.ro.bytes(), 0);

        eprintln!("RW, size: {:#0x}", self.rw.size());
        for local in rw_symbols.iter() {
            eprintln!(" S: {:?}", local);
        }
        for r in self.rw.relocations().iter() {
            eprintln!(" R: {}, {:?}", r, self.lookup(&r.name));
        }
        print_bytes(self.rw.bytes(), 0);

        eprintln!("Bss, size: {:#0x}", self.bss.size());
        for local in bss_symbols.iter() {
            eprintln!(" S: {:?}", local);
        }
        for r in self.bss.relocations().iter() {
            eprintln!(" R: {}, {:?}", r, self.lookup(&r.name));
        }

        //eprintln!("Strings");
        //for local in strings_symbols.iter() {
        //eprintln!(" S: {:?}", local);
        //}

        if other_symbols.len() > 0 {
            eprintln!("Other");
            for local in other_symbols.iter() {
                eprintln!(" S: {:?}", local);
            }
        }

        if self.unresolved.len() > 0 {
            eprintln!("Unresolved: {}", self.unresolved.len());
            for s in self.unresolved.iter() {
                eprintln!(" {}", s);
            }
        }
    }
}
