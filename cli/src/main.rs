use clap::Parser;
use link::dynamic::*;
use link::*;
use std::error::Error;
use std::path::Path;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    dynamic: bool,
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

    if args.dynamic {
        let mut b = DynamicLink::new();
        for path in args.inputs.iter() {
            b.add_obj_file("asdf", &Path::new(&path))?;
        }
        let version = b.link()?;
        let ret: i64 = version.invoke("main", ())?;
        std::process::exit(ret as i32);
    } else {
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
        Data::write(&mut data, Path::new(&output), &config)?;
    }

    Ok(())
}
