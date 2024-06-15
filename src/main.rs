use clap::Parser;
use link::*;
use std::error::Error;
use std::path::Path;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    interp: Option<String>,
    #[arg(short, long)]
    output: Option<String>,
    inputs: Vec<String>,
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init();
    let args = Args::parse();
    if args.inputs.len() == 0 {
        panic!("Missing files");
    }

    let config = Config::new();
    let mut block = ReadBlock::new("exe");
    for path in args.inputs.iter() {
        block.add(&Path::new(&path), &config)?;
    }

    block.dump();

    let mut data = block.data(&config);
    if let Some(interp) = args.interp {
        data = data.interp(interp);
    }

    let output = args.output.unwrap_or("a.out".to_string());

    reader::write::<object::elf::FileHeader64<object::Endianness>>(
        block,
        &mut data,
        Path::new(&output),
        &config,
    )?;

    Ok(())
}
