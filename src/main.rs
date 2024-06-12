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

    let mut reader = Reader::new();
    for path in args.inputs.iter() {
        let p = Path::new(&path);
        println!("p: {}", p.to_str().unwrap());
        let ext = p.extension().unwrap().to_str().unwrap();
        println!("ext: {}", ext);
        if ext == "a" {
            reader.add_archive(&Path::new(&path))?;
        } else {
            reader.add(&Path::new(&path))?;
        }
    }

    let block = reader.build();
    block.dump();

    //let mut libs: Vec<String> = block.libs.iter().cloned().collect();
    //libs.push("/usr/lib/x86_64-linux-gnu/libc.so.6".to_string());

    let mut data = link::Data::new(block.libs.iter().cloned().collect());
    if let Some(interp) = args.interp {
        data = data.interp(interp);
    }

    let output = args.output.unwrap_or("a.out".to_string());
    block.write::<object::elf::FileHeader64<object::Endianness>>(&mut data, Path::new(&output))?;
    Ok(())
}
