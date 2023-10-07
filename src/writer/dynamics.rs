use super::*;
use object::write::elf::Sym;
use object::write::elf::{SymbolIndex, Writer};
use object::write::StringId;
use std::collections::HashMap;

struct TrackStringIndex {
    index: usize,
    string_id: StringId,
}

#[derive(Debug, PartialEq)]
pub enum GotPltAssign {
    Got,           // object
    GotWithPltGot, // function
    GotPltWithPlt, // function
    None,
}

struct TrackSymbolIndex {
    index: usize,
    string_id: Option<StringId>,
    symbol_index: Option<SymbolIndex>,
    symbol: ReadSymbol,
    pointer: ResolvePointer,
}

pub struct Dynamics {
    // ordered list
    strings: Vec<String>,
    // hash of index
    string_hash: HashMap<String, TrackStringIndex>,

    // ordered list
    symbols: Vec<String>,
    symbol_hash: HashMap<String, TrackSymbolIndex>,

    r_got: Vec<ReadSymbol>,
    r_gotplt: Vec<ReadSymbol>,

    // plt entries
    plt: Vec<ReadSymbol>,
    pub plt_hash: HashMap<String, ReadSymbol>,
    pltgot: Vec<ReadSymbol>,
    pub pltgot_hash: HashMap<String, ReadSymbol>,

    got_index: usize,
    gotplt_index: usize,
    plt_index: usize,
    pltgot_index: usize,
}

impl Dynamics {
    pub fn new() -> Self {
        Self {
            strings: vec![],
            string_hash: HashMap::new(),
            symbols: vec![],
            symbol_hash: HashMap::new(),
            r_got: vec![],
            r_gotplt: vec![],

            plt: vec![],
            plt_hash: HashMap::new(),

            pltgot: vec![],
            pltgot_hash: HashMap::new(),
            got_index: 0,
            gotplt_index: 3,
            plt_index: 0,
            pltgot_index: 0,
        }
    }

    pub fn relocations(&self, kind: GotSectionKind) -> Vec<ReadSymbol> {
        match kind {
            GotSectionKind::GOT => self.r_got.iter().cloned().collect(),
            GotSectionKind::GOTPLT => self.r_gotplt.iter().cloned().collect(),
        }
    }

    pub fn lookup(&self, r: &CodeRelocation) -> Option<ResolvePointer> {
        if r.is_got() {
            if let Some(track) = self.symbol_hash.get(&r.name) {
                Some(track.pointer.clone())
            } else {
                None
            }
        } else if r.is_plt() {
            if let Some(symbol) = self.plt_hash.get(&r.name) {
                Some(symbol.pointer.clone())
            } else if let Some(symbol) = self.pltgot_hash.get(&r.name) {
                Some(symbol.pointer.clone())
            } else if let Some(track) = self.symbol_hash.get(&r.name) {
                Some(track.pointer.clone())
            } else {
                None
            }
        } else {
            None
        }
    }

    pub fn pltgot_objects(&self) -> Vec<ReadSymbol> {
        self.pltgot.clone()
    }

    pub fn plt_objects(&self) -> Vec<ReadSymbol> {
        self.plt.clone()
    }

    pub fn string_get(&self, name: &str) -> StringId {
        self.string_hash
            .get(name)
            .expect(&format!("String not found: {}", name))
            .string_id
    }

    pub fn string_add(&mut self, name: &str, w: &mut Writer) -> StringId {
        if let Some(index) = self.string_hash.get(name) {
            index.string_id
        } else {
            let name = name.to_string();
            let cloned_name = name.clone();
            unsafe {
                let buf = extend_lifetime(name.as_bytes());
                // save the string
                let index = self.strings.len();
                self.strings.push(name);
                let string_id = w.add_dynamic_string(buf);
                let string_index = TrackStringIndex { index, string_id };
                self.string_hash.insert(cloned_name, string_index);
                string_id
            }
        }
    }

    pub fn symbol_count(&self) -> usize {
        self.symbol_hash
            .iter()
            .filter(|(_name, s)| s.string_id.is_some())
            .count()
    }

    pub fn relocation_add(
        &mut self,
        symbol: &ReadSymbol,
        assign: GotPltAssign,
        r: &CodeRelocation,
        w: &mut Writer,
    ) {
        let name = &symbol.name;

        if let Some(_track) = self.symbol_hash.get(name) {
            ()
        } else {
            //eprintln!("sym: {:?}", symbol);
            log::debug!(target: "symbols", "r: {:?}, {}", assign, r);
            let mut symbol = symbol.clone();

            match assign {
                GotPltAssign::Got => {
                    symbol.pointer = ResolvePointer::Got(self.got_index);

                    self.r_got.push(symbol.clone());

                    self.got_index += 1;
                    self.symbol_add(symbol, w);
                }

                GotPltAssign::GotWithPltGot => {
                    symbol.pointer = ResolvePointer::PltGot(self.pltgot_index);
                    self.pltgot.push(symbol.clone());
                    self.pltgot_hash.insert(name.to_string(), symbol.clone());
                    self.pltgot_index += 1;

                    symbol.pointer = ResolvePointer::Got(self.got_index);
                    self.r_got.push(symbol.clone());

                    self.got_index += 1;
                    self.symbol_add(symbol, w);
                }

                GotPltAssign::GotPltWithPlt => {
                    symbol.pointer = ResolvePointer::Plt(self.plt_index);
                    self.plt.push(symbol.clone());
                    self.plt_hash.insert(name.to_string(), symbol.clone());
                    self.plt_index += 1;

                    self.r_gotplt.push(symbol.clone());
                    self.gotplt_index += 1;
                    self.symbol_add(symbol, w);
                }
                _ => unreachable!(),
            };
        }
    }

    fn symbol_add(&mut self, symbol: ReadSymbol, w: &mut Writer) -> Option<SymbolIndex> {
        let index = self.symbols.len();
        self.symbols.push(symbol.name.clone());

        let string_id;
        let symbol_index;
        if symbol.is_static() {
            string_id = None;
            symbol_index = None;
        } else {
            string_id = Some(self.string_add(&symbol.name, w));
            symbol_index = Some(SymbolIndex(w.reserve_dynamic_symbol_index().0));
            log::debug!(target: "symbols", "ADD: {} => {:?}", &symbol.name, symbol_index);
        }
        let symbol = symbol.clone();
        let name = symbol.name.clone();
        let track = TrackSymbolIndex {
            index,
            string_id,
            symbol_index,
            pointer: symbol.pointer.clone(),
            symbol,
            //relative,
        };

        self.symbol_hash.insert(name.clone(), track);
        symbol_index
    }

    pub fn symbol_lookup(&self, name: &str) -> Option<ResolvePointer> {
        self.symbol_hash
            .get(name)
            .map(|track| track.pointer.clone())
    }

    pub fn symbol_get(&self, name: &str, data: &Data) -> Option<(SymbolIndex, Sym)> {
        if let Some(track) = self.symbol_hash.get(name) {
            if let Some(symbol_index) = track.symbol_index {
                let sym = track.symbol.get_dynamic_symbol(data);
                return Some((symbol_index, sym));
            }
        }
        None
    }

    pub fn symbols_local_count(&self) -> usize {
        let mut locals = 1;
        for name in self.symbols.iter() {
            let track = self.symbol_hash.get(name).unwrap();
            if track.symbol_index.is_some() {
                if track.symbol.bind == SymbolBind::Local {
                    locals += 1;
                }
            }
        }
        locals
    }

    pub fn symbols_write(&self, data: &Data, w: &mut Writer) {
        w.write_null_dynamic_symbol();
        for name in self.symbols.iter() {
            let track = self.symbol_hash.get(name).unwrap();
            if track.symbol_index.is_some() {
                let sym = track.symbol.get_dynamic_symbol(data);
                //let (_symbol_index, sym) = self.symbol_get(name, data).expect(&format!("not found {}", name));
                w.write_dynamic_symbol(&sym);
            }
        }
    }

    pub fn symbols(&self) -> Vec<(String, Option<SymbolIndex>, ResolvePointer)> {
        let mut out = vec![];
        for name in self.symbols.iter() {
            let track = self.symbol_hash.get(name).unwrap();
            out.push((name.to_string(), track.symbol_index, track.pointer.clone()));
        }
        out
    }
}
