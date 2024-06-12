use link::*;
use std::path::Path;

fn main() {
    env_logger::init();
    let mut b = DynamicLink::new();

    b.add_library("live", Path::new("build/clang-glibc/globals.so"))
        .unwrap();
    b.add_library("libc", Path::new("libc.so.6")).unwrap();
    b.add_library("gz", Path::new("build/testlibs/libz.so"))
        .unwrap();
    b.add_obj_file("test", Path::new("build/clang-glibc/link_shared.o"))
        .unwrap();
    let _version = b.link().unwrap();
}
