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
    let mut reader = Reader::new();
    for path in args.inputs.iter() {
        reader.add(&Path::new(&path))?;
    }

    let block = reader.build();
    //block.dump();

    let mut data = link::Data::new(block.libs.iter().cloned().collect());
    if let Some(interp) = args.interp {
        data = data.interp(interp);
    }
    let output = args.output.unwrap_or("a.out".to_string());

    block.write::<object::elf::FileHeader64<object::Endianness>>(&mut data, Path::new(&output))?;
    Ok(())
}
