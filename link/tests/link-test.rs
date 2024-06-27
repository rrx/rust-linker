use link::*;
use std::path::{Path, PathBuf};
use test_log::test;

#[test]
fn loader_shared() {
    let mut config = AOTConfig::new();
    config.verbose = true;
    let mut exe = ReadBlock::new("exe");
    exe.add(Path::new("../build/testlibs/libz.so"), &config)
        .unwrap();
    exe.add(&temp_path("link_shared.o"), &config).unwrap();
    let version = LoaderVersion::load_block(&mut exe).unwrap();
    version.debug();
    let ret: *const () = version.invoke("call_z", ()).unwrap();
    log::debug!("ret: {:#08x}", ret as usize);
    assert!(ret.is_null());
}

#[test]
fn loader_main() {
    let mut config = AOTConfig::new();
    config.verbose = true;
    let mut exe = ReadBlock::new("exe");
    exe.add(&temp_path("/lib/x86_64-linux-gnu/libc.so.6"), &config)
        .unwrap();
    exe.add(&temp_path("print_main1.o"), &config).unwrap();
    exe.add(&temp_path("asdf1.o"), &config).unwrap();
    let version = LoaderVersion::load_block(&mut exe).unwrap();
    version.debug();
    let ret: i64 = version.invoke("main", (0,)).unwrap();
    log::debug!("ret: {:#08x}", ret as usize);
    assert_eq!(0, ret);
}

#[test]
fn loader_livelink() {
    let mut config = AOTConfig::new();
    config.verbose = true;
    let mut exe = ReadBlock::new("exe");
    exe.add(&temp_path("/lib/x86_64-linux-gnu/libc.so.6"), &config)
        .unwrap();
    exe.add(&temp_path("globals.o"), &config).unwrap();
    exe.add(&temp_path("live.so"), &config).unwrap();
    exe.add(&temp_path("testfunction.o"), &config).unwrap();
    exe.add(&temp_path("simplefunction.o"), &config).unwrap();
    exe.add(&temp_path("call_extern.o"), &config).unwrap();
    exe.add(&temp_path("asdf1.o"), &config).unwrap();
    let version = LoaderVersion::load_block(&mut exe).unwrap();
    version.debug();
    let ret: i64 = version.invoke("simple_function", ()).unwrap();
    log::debug!("ret: {:#08x}", ret);
    assert_eq!(ret, 1);

    let ret: i64 = version.invoke("asdf", (2,)).unwrap();
    log::debug!("ret: {}", ret);
    assert_eq!(3, ret);

    let ret: i64 = version.invoke("call_external", ()).unwrap();
    log::debug!("ret: {}", ret);
    assert_eq!(4, ret);

    let ret: i64 = version.invoke("simple", ()).unwrap();
    log::debug!("ret: {}", ret);
    assert_eq!(10012, ret);

    let ret: i64 = version.invoke("func", ()).unwrap();
    log::debug!("ret: {}", ret);
    assert_eq!(10001, ret);

    let ret: i64 = version.invoke("call_live", (3,)).unwrap();
    log::debug!("ret: {:#08x}", ret);
    assert_eq!(0x11, ret);

    let ret: i64 = version.invoke("simple_function", ()).unwrap();
    log::debug!("ret: {:#08x}", ret);
    assert_eq!(1, ret);

    let ret: i64 = version.invoke("func2", (2,)).unwrap();
    log::debug!("ret: {:#08x}", ret);
    assert_eq!(3, ret);

    let x = version.lookup("x").unwrap();
    log::debug!("{:#08x}: x", x as usize);
    let ptr = version.lookup("ptr").unwrap();
    log::debug!("{:#08x}: ptr", ptr as usize);
    let g2 = version.lookup("g2").unwrap();
    log::debug!("{:#08x}: g2", g2 as usize);
    let global_ptr = version.lookup("global_int2").unwrap();
    log::debug!("{:#08x}: global_int2", global_ptr as usize);

    let ret: i64 = version.invoke("load_from_extern", ()).unwrap();
    log::debug!("ret: {:#08x}", ret);
}

#[test]
fn loader_live_static() {
    let mut config = AOTConfig::new();
    config.verbose = true;
    let mut exe = ReadBlock::new("exe");
    exe.add(&temp_path("live.o"), &config).unwrap();
    let version = LoaderVersion::load_block(&mut exe).unwrap();
    version.debug();
    let ret: i64 = version.invoke("call_live", (3,)).unwrap();
    log::debug!("ret: {:#08x}", ret as usize);
    assert_eq!(0x11, ret);
}

#[test]
fn loader_empty_main() {
    let mut config = AOTConfig::new();
    config.verbose = true;
    let mut exe = ReadBlock::new("exe");
    exe.add(&temp_path("empty_main.o"), &config).unwrap();
    let version = LoaderVersion::load_block(&mut exe).unwrap();
    version.debug();
    let ret: i64 = version.invoke("main", (3,)).unwrap();
    log::debug!("ret: {:#08x}", ret as usize);
    assert_eq!(0, ret);
    let main_ptr = version.lookup("main").unwrap();
    log::debug!("ptr: {:#08x}", main_ptr as usize);
}

#[test]
fn loader_libuv() {
    let mut config = AOTConfig::new();
    config.verbose = true;
    let mut exe = ReadBlock::new("exe");
    exe.add(Path::new("/lib/x86_64-linux-gnu/libc.so.6"), &config)
        .unwrap();
    exe.add(Path::new("/usr/lib/x86_64-linux-gnu/libuv.so"), &config)
        .unwrap();
    exe.add(&temp_path("uvtest.o"), &config).unwrap();

    let version = LoaderVersion::load_block(&mut exe).unwrap();
    version.debug();
    let ret: i64 = version.invoke("uvtest", ()).unwrap();
    log::debug!("ret: {:#08x}", ret as usize);
    assert_eq!(0, ret);
}

#[test]
fn loader_libc() {
    let mut config = AOTConfig::new();
    config.verbose = true;
    let mut exe = ReadBlock::new("exe");
    exe.add(&temp_path("print_stuff.o"), &config).unwrap();
    exe.add(&temp_path("print_string.o"), &config).unwrap();
    exe.add(&temp_path("/lib/x86_64-linux-gnu/libc.so.6"), &config)
        .unwrap();
    let version = LoaderVersion::load_block(&mut exe).unwrap();
    version.debug();
    test_loader_print_string(&version);
    test_loader_lib_print(&version);
    test_loader_print_stuff(&version);
}

#[test]
fn loader_musl() {
    let mut config = AOTConfig::new();
    config.verbose = true;
    let mut exe = ReadBlock::new("exe");
    exe.add(Path::new("/lib/x86_64-linux-musl/libc.so"), &config)
        .unwrap();
    exe.add(&temp_path("print_stuff.o"), &config).unwrap();
    exe.add(&temp_path("print_string.o"), &config).unwrap();
    let version = LoaderVersion::load_block(&mut exe).unwrap();
    version.debug();
    test_loader_print_string(&version);
    test_loader_lib_print(&version);
    test_loader_print_stuff(&version);
}

#[test]
fn loader_string() {
    let mut config = AOTConfig::new();
    config.verbose = true;
    let mut exe = ReadBlock::new("exe");
    exe.add(Path::new("/lib/x86_64-linux-gnu/libc.so.6"), &config)
        .unwrap();
    exe.add(&temp_path("print_string.o"), &config).unwrap();
    let version = LoaderVersion::load_block(&mut exe).unwrap();
    version.debug();
    test_loader_print_string(&version);
}

fn test_loader_print_string(version: &LoaderVersion) {
    let ret: *const () = version.invoke("print_string", ()).unwrap();
    log::debug!("ret: {:#08x}", ret as usize);
}

fn test_loader_print_stuff(version: &LoaderVersion) {
    let c_str = std::ffi::CString::new("asdf1: %d\n").unwrap();
    let c_str_ptr = c_str.as_ptr();

    let v_ptr: *const usize = version.lookup("g_v").unwrap() as *const usize;

    let g_ptr: *const usize = version.lookup("g_str2").unwrap() as *const usize;
    unsafe {
        let g = *g_ptr as *const usize;
        let g_ret: *const usize = version.invoke("get_str2", ()).unwrap();
        log::debug!(
            "g: {:#08x}:{:#08x}:{:#08x}",
            g_ptr as usize,
            g as usize,
            g_ret as usize
        );

        let v = *v_ptr as *const usize;
        let v_ret: *const usize = version.invoke("get_v", ()).unwrap();
        log::debug!(
            "v: {:#08x}:{:#08x}:{:#08x}",
            v_ptr as usize,
            v as usize,
            v_ret as usize
        );

        assert_eq!(v_ptr, v_ret);
        assert_eq!(g_ptr, g_ret);
    }

    let ret: i32 = version.invoke("print_stuff1", ()).unwrap();
    log::debug!("ret: {:#08x}", ret);
    let ret: i32 = version.invoke("print_stuff2", (c_str_ptr, 7i32)).unwrap();
    log::debug!("ret: {:#08x}", ret);
    assert_eq!(18, ret);
    let ret: i32 = version.invoke("print_stuff3", (8i32,)).unwrap();
    log::debug!("ret: {:#08x}", ret);
    let ret: i32 = version.invoke("print_stuff4", (c_str_ptr, 9i32)).unwrap();
    log::debug!("ret: {:#08x}", ret);
}

fn test_loader_lib_print(version: &LoaderVersion) {
    unsafe {
        let stdout_ptr = version.lookup("stdout").unwrap() as *const usize;
        //log::debug!(
        //"p0: stdout: {:#08x}: {:#08x}",
        //stdout_ptr as usize, *stdout_ptr
        //);
        let p1 = *stdout_ptr as *const usize;
        //log::debug!("p1: *stdout: {:#08x}", p1 as usize);
        let _p2 = *p1 as *const usize;
        //log::debug!("p2: **stdout: {:#08x}", p2 as usize);
        //let p3 = *p2 as *const usize;
        //log::debug!("p3: ***stdout: {:#08x}", p3 as usize);
        let _s = std::slice::from_raw_parts(p1, 0x20);
        //log::debug!("***stdout: {:#08x?}", s);
        let works = p1;

        // call strlen
        let cstr = std::ffi::CString::new("asdf").unwrap();
        let ret: i64 = version.invoke("strlen", cstr.as_ptr()).unwrap();
        assert_eq!(4, ret);

        let ret: i64 = version.invoke("fputc", (0x30u32, works)).unwrap();
        log::debug!("ret: {:#08x}", ret);
        assert_eq!(0x30, ret);

        let ret: i64 = version.invoke("putc", (0x31u32, works)).unwrap();
        log::debug!("ret: {:#08x}", ret);
        assert_eq!(0x31, ret);
        let ret: i64 = version.invoke("fflush", (works,)).unwrap();
        log::debug!("ret: {:#08x}", ret);
        assert_eq!(0x0, ret);

        let c_str = std::ffi::CString::new("asdf1: %d\n").unwrap();
        let c_str_ptr = c_str.as_ptr();
        let ret: i32 = version.invoke("fputs", (c_str_ptr, works)).unwrap();
        log::debug!("ret: {:#08x}", ret);
        assert!(ret >= 0);

        let ret: i32 = version.invoke("printf", (c_str_ptr, 4)).unwrap();
        log::debug!("ret: {:#08x}", ret);
        if ret < 0 {
            log::error!("{:?}", std::io::Error::last_os_error());
        }
        assert!(ret >= 0);

        let ret: i32 = version.invoke("fputs", (c_str_ptr, works)).unwrap();
        log::debug!("ret: {:#08x}", ret);
        assert!(ret >= 0);

        let ret: i64 = version.invoke("fflush", (works,)).unwrap();
        log::debug!("ret: {:#08x}", ret);
        assert_eq!(0x0, ret);
    }
}

fn temp_path(filename: &str) -> Box<Path> {
    let mut p = PathBuf::new();
    p.push("../build/clang-glibc");
    p.push(filename);
    p.into_boxed_path()
}
