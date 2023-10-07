use link::*;
use std::path::{Path, PathBuf};

fn temp_path(filename: &str) -> Box<Path> {
    let mut p = PathBuf::new();
    p.push("tmp");
    p.push(filename);
    p.into_boxed_path()
}

fn test_live_static() {
    eprintln!("cwd:{}", std::env::current_dir().unwrap().to_string_lossy());
    let mut b = DynamicLink::new();
    b.add_obj_file("t1", &temp_path("live.o")).unwrap();
    let version = b.link().unwrap();
    let ret: i64 = version.invoke("call_live", (3,)).unwrap();
    log::debug!("ret: {:#08x}", ret);
    assert_eq!(0x11, ret);
}

fn main() {
    env_logger::init();
    test_live_static();
}
