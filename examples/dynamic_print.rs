use link::*;
use std::ffi::CString;
use std::path::Path;

fn test_lib(lib: SharedLibrary) {
    let _stdout_ptr = lib.lookup("stdout").unwrap().as_ptr() as *const usize;
    let ret: i64 = lib.invoke("printf", ("asdf1\n",)).unwrap();
    eprintln!("{:?}", ret);

    let c_str = CString::new("asdf2\n").unwrap();
    let ret: i64 = lib.invoke("printf", (c_str.as_ptr(),)).unwrap();
    eprintln!("{:?}", ret);
}

fn main() {
    eprintln!("test from rust");
    let mut repo = SharedLibraryRepo::default();

    let libc_path = Path::new("/lib/x86_64-linux-gnu/libc.so.6");
    let musl_path = Path::new("/usr/lib/x86_64-linux-musl/libc.so");
    let _musl_n = repo.add_to_new_namespace("musl", musl_path).unwrap();
    let _libc_n = repo.add_to_new_namespace("libc", libc_path).unwrap();

    let musl = repo.get("musl").unwrap();
    let libc = repo.get("libc").unwrap();

    test_lib(musl);
    test_lib(libc);

    //let libc_stdout_ptr = libc.lookup("stdout").unwrap() as *const usize;
    //let libc_stdout = *libc_stdout_ptr as *const usize;
}
