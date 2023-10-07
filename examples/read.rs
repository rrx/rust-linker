use link::*;
use std::env;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let mut reader = Reader::new();
    for path in env::args().skip(1) {
        let buf = std::fs::read(path.clone())?;
        let block = reader.read(&path, &buf)?;
        block.dump();
    }
    Ok(())
}
