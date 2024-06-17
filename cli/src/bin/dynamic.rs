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

    let mut b = DynamicLink::new();
    for path in args.inputs.iter() {
        b.add(&Path::new(path))?;
    }
    let version = b.link()?;
    let ret: i64 = version.invoke("main", ())?;
    std::process::exit(ret as i32);
}
