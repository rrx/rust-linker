use link::*;
use std::path::Path;

fn main() {
    env_logger::init();
    let mut b = Link::new();
    //b.add_library("live", Path::new("globals.so")).unwrap();
    b.add_library("libc", Path::new("libc.so.6")).unwrap();
    //b.add_obj_file("test", Path::new("./tmp/start.o")).unwrap();
    let path = Path::new("/usr/lib/x86_64-linux-gnu/crt1.o");
    b.add_obj_file("crt1", path).unwrap();
    //let path = Path::new("/usr/lib/x86_64-linux-gnu/crti.o");
    //b.add_obj_file("crti", path).unwrap();
    //let path = Path::new("/usr/lib/x86_64-linux-gnu/crtn.o");
    //b.add_obj_file("crtn", path).unwrap();

    b.add_obj_file("test", Path::new("./tmp/empty_main.o"))
        .unwrap();

    //b.write(Path::new("./tmp/dynamic.exe")).unwrap();
}
