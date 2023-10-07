use std::fmt;

#[derive(Debug)]
pub enum LinkError {
    NotFound,
    MissingSymbol,
    SymbolNotFound,
}
impl std::error::Error for LinkError {}
impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "LinkError: {:?}", &self)
    }
}
