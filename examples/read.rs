use link::*;
use std::env;
use std::error::Error;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let config = Config::new();
    let mut block = ReadBlock::new("exe");
    for path in env::args().skip(1) {
        block.add(Path::new(&path), &config)?;
        block.dump();
    }
    Ok(())
}
