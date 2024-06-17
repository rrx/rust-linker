use clap::Parser;
use link::*;
use std::error::Error;
use std::path::Path;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    dynamic: bool,
    #[arg(short, long)]
    verbose: bool,
    #[arg(long)]
    link: bool,
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

    let mut config = AOTConfig::new();
    if args.verbose {
        config.verbose = true;
    }

    if args.dynamic {
        let mut b = DynamicLink::new();
        for path in args.inputs.iter() {
            b.add(&Path::new(path))?;
        }
        let version = b.link()?;
        let ret: i64 = version.invoke("main", ())?;
        std::process::exit(ret as i32);
    } else {
        let mut exe = ReadBlock::new("exe");
        for path in args.inputs.iter() {
            let block = ReadBlock::from_path(Path::new(&path), &config)?;
            block.dump();
            exe.add_block(block);
            //block.add(&Path::new(&path), &config)?;
        }

        if args.verbose {
            exe.dump();
        }

        if args.link {
            let mut data = Data::new();
            if let Some(interp) = args.interp {
                data = data.interp(interp);
            }

            let output = args.output.unwrap_or("a.out".to_string());
            Data::write(data, exe.target, Path::new(&output), &config)?;
        }
    }

    Ok(())
}
