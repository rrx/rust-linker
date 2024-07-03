use clap::Parser;
use link::*;
use std::error::Error;
use std::path::Path;

#[derive(Debug, Parser)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    verbose: bool,
    #[arg(long)]
    link: bool,
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

    let mut config = AOTConfig::new();
    if args.verbose {
        config.verbose = true;
    }

    let mut exe = ReadBlock::new("exe");
    for path in args.inputs.iter() {
        if !Path::new(&path).exists() {
            eprintln!("File does not exist: {}", path);
            return Err(LinkError::FileNotFound(path.clone()).into());
        }
    }

    for path in args.inputs.iter() {
        //let block = ReadBlock::from_path(Path::new(&path), &config)?;
        //block.dump();
        //exe.add_block(block);
        //block.add(&Path::new(&path), &config)?;
        exe.add(&Path::new(&path), &config)?;
    }

    //exe.resolve();

    if args.verbose {
        exe.dump();
    }

    if args.dynamic {
        let version = LoaderVersion::load_block(&mut exe)?;
        version.debug();
        let r: u32 = version.invoke("main", (0,))?;
        println!("ret: {}", r);
    } else if args.link {
        let mut data = Data::new();
        if let Some(interp) = args.interp {
            data = data.interp(interp);
        }

        let output = args.output.unwrap_or("a.out".to_string());
        let path = Path::new(&output);
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        Data::write(data, exe.target, Path::new(&output), &config)?;
    }

    Ok(())
}
