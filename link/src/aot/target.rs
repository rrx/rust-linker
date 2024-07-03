use super::*;
use crate::format::{disassemble_code_with_symbols, print_bytes, Symbol};
use std::collections::HashSet;

#[derive(Debug)]
pub struct Target {
    pub libs: HashSet<String>,
    pub dynamic: SymbolMap,
    pub locals: SymbolMap,
    pub exports: SymbolMap,
    pub ro: GeneralSection,
    pub rw: GeneralSection,
    pub rx: GeneralSection,
    pub bss: GeneralSection,
    pub unresolved: HashSet<String>,
    pub unknown: SymbolMap,
}

impl Default for Target {
    fn default() -> Self {
        Self::new()
    }
}

impl Target {
    pub fn new() -> Self {
        Self {
            libs: HashSet::new(),
            locals: SymbolMap::new(),
            exports: SymbolMap::new(),
            dynamic: SymbolMap::new(),
            ro: ReadSectionKind::ROData.section(),
            rw: ReadSectionKind::RW.section(),
            rx: ReadSectionKind::RX.section(),
            bss: ReadSectionKind::Bss.section(),
            unresolved: HashSet::new(),
            unknown: SymbolMap::new(),
        }
    }

    pub(crate) fn is_dynamic(&self) -> bool {
        !self.libs.is_empty()
    }

    pub fn lookup_static(&self, name: &str) -> Option<ReadSymbol> {
        if let Some(symbol) = self.locals.get(name) {
            Some(symbol.clone())
        } else {
            self.exports.get(name).cloned()
        }
    }

    pub fn lookup_dynamic(&self, name: &str) -> Option<ReadSymbol> {
        self.dynamic.get(name).cloned()
    }

    pub fn lookup(&self, name: &str) -> Option<ReadSymbol> {
        if let Some(symbol) = self.lookup_static(name) {
            Some(symbol.clone())
        } else {
            self.lookup_dynamic(name)
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
        for s in rx_symbols.iter() {
            eprintln!(" S: {:?}", s);
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
            .collect::<Vec<_>>();
        disassemble_code_with_symbols(self.rx.bytes(), &symbols, self.rx.relocations());

        eprintln!("RO, size: {:#0x}", self.ro.size());
        for s in ro_symbols.iter() {
            eprintln!(" S: {:?}", s);
        }
        for r in self.ro.relocations().iter() {
            eprintln!(" R: {}, {:?}", r, self.lookup(&r.name));
        }
        print_bytes(self.ro.bytes(), 0);

        eprintln!("RW, size: {:#0x}", self.rw.size());
        for s in rw_symbols.iter() {
            eprintln!(" S: {:?}", s);
        }
        for r in self.rw.relocations().iter() {
            eprintln!(" R: {}, {:?}", r, self.lookup(&r.name));
        }
        print_bytes(self.rw.bytes(), 0);

        eprintln!("Bss, size: {:#0x}", self.bss.size());
        for s in bss_symbols.iter() {
            eprintln!(" S: {:?}", s);
        }
        for r in self.bss.relocations().iter() {
            eprintln!(" R: {}, {:?}", r, self.lookup(&r.name));
        }

        //eprintln!("Strings");
        //for local in strings_symbols.iter() {
        //eprintln!(" S: {:?}", local);
        //}

        if !other_symbols.is_empty() {
            eprintln!("Other");
            for s in other_symbols.iter() {
                eprintln!(" S: {:?}", s);
            }
        }

        if !self.unresolved.is_empty() {
            eprintln!("Unresolved: {}", self.unresolved.len());
            for s in self.unresolved.iter() {
                eprintln!(" {}", s);
            }
        }
    }
}
