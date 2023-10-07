use link::*;
use std::path::Path;

fn write_static() {
    let mut b = Link::new();
    b.add_obj_file("test", Path::new("./tmp/start.o")).unwrap();
    b.add_obj_file("globals", Path::new("./tmp/globals.o"))
        .unwrap();
    //b.write(Path::new("./tmp/static.exe")).unwrap();
}

fn main() {
    env_logger::init();
    write_static();
}
