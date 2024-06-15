use link::*;
use std::env;
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let mut reader = Reader::new();
    let config = Config::new();
    for path in env::args().skip(1) {
        let buf = std::fs::read(path.clone())?;
        reader.read(&path, &buf, &config)?;
        reader.block.dump();
    }
    Ok(())
}
