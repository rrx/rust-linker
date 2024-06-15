use link::*;
use std::env;
use std::error::Error;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let mut reader = Reader::new();
    let config = Config::new();
    for path in env::args().skip(1) {
        reader.add(Path::new(&path), &config)?;
        reader.block.dump();
    }
    Ok(())
}
