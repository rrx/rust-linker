use link::*;
use std::path::{Path, PathBuf};
use test_log::test;

//#[test]
// not working yet
fn test_start() {
    let mut b = DynamicLink::new();
    b.add_obj_file("start", &temp_path("start.o")).unwrap();
    let version = b.link().unwrap();
    let ret: i64 = version.invoke("_start", ()).unwrap();
    assert_eq!(0, ret);
}

#[test]
fn test_live_shared() {
    let mut b = DynamicLink::new();
    b.add_library("t1", &temp_path("live.so")).unwrap();
    let version = b.link().unwrap();
    let ret: i64 = version.invoke("call_live", (3,)).unwrap();
    log::debug!("ret: {:#08x}", ret);
    assert_eq!(0x11, ret);
}

#[test]
fn test_load_from_shared() {
    let mut b = DynamicLink::new();
    b.add_library("live", &temp_path("live.so")).unwrap();
    b.add_obj_file("globals", &temp_path("globals.o")).unwrap();
    b.add_obj_file("call", &temp_path("call_extern.o")).unwrap();
    let version = b.link().unwrap();

    let x = version.lookup("x").unwrap().as_ptr();
    log::debug!("{:#08x}: x", x as usize);
    let ptr = version.lookup("ptr").unwrap().as_ptr();
    log::debug!("{:#08x}: ptr", ptr as usize);
    let g2 = version.lookup("g2").unwrap().as_ptr();
    log::debug!("{:#08x}: g2", g2 as usize);
    let global_ptr = version.lookup("global_int2").unwrap().as_ptr();
    log::debug!("{:#08x}: global_int2", global_ptr as usize);

    let ret: i64 = version.invoke("load_from_extern", ()).unwrap();
    log::debug!("ret: {:#08x}", ret);
}

#[test]
fn test_live_static() {
    let mut b = DynamicLink::new();
    b.add_obj_file("t1", &temp_path("live.o")).unwrap();
    let version = b.link().unwrap();
    let ret: i64 = version.invoke("call_live", (3,)).unwrap();
    log::debug!("ret: {:#08x}", ret);
    assert_eq!(0x11, ret);
}

//#[test]
// not working yet
fn test_empty_main() {
    let mut b = DynamicLink::new();
    b.add_obj_file("main", &temp_path("empty_main.o")).unwrap();
    b.add_library("libc", Path::new("/usr/lib/x86_64-linux-musl/libc.so"))
        .unwrap();
    let version = b.link().unwrap();

    // just call the mepty main
    let ret: i64 = version.invoke("main", ()).unwrap();
    assert_eq!(0, ret);

    let main_ptr = version.lookup("main").unwrap().as_ptr();
    log::debug!("ptr: {:#08x}", main_ptr as usize);
    let main_ptr = 0;

    let init_ptr = version.lookup("_init").unwrap().as_ptr();
    log::debug!("init_ptr: {:#08x}", init_ptr as usize);
    let init_ptr = 0;

    let (base, _size) = b.get_mem_ptr();
    let ret: i64 = version
        .invoke("initialize", (base, main_ptr, init_ptr))
        .unwrap();
    assert_eq!(0, ret);
}

// not working yet
//#[test]
fn test_segfault() {
    let mut b = DynamicLink::new();
    b.add_library("t2", &temp_path("libsigsegv.so")).unwrap();
    b.add_obj_file("t3", &temp_path("segfault.o")).unwrap();
    let version = b.link().unwrap();
    let _ret: i64 = version.invoke("handlers_init", ()).unwrap();
}

#[test]
fn test_libuv() {
    let mut b = DynamicLink::new();
    b.add_library("libc", Path::new("/lib/x86_64-linux-gnu/libc.so.6"))
        .unwrap();
    b.add_library("libuv", Path::new("libuv.so")).unwrap();
    b.add_obj_file("test", &temp_path("uvtest.o")).unwrap();
    let version = b.link().unwrap();
    let ret: i64 = version.invoke("uvtest", ()).unwrap();
    log::debug!("ret: {:#08x}", ret);
    assert_eq!(0x0, ret);

    // flush
    unsafe {
        let stdout = *(version.lookup("stdout").unwrap().as_ptr() as *const usize);
        log::debug!("stdout: {:#08x}", stdout);
        //let ret: i64 = version.invoke("fflush", (stdout,)).unwrap();
        //log::debug!("ret: {:#08x}", ret);
        //assert_eq!(0x0, ret);
    }
}

#[test]
fn test_libc() {
    let mut b = DynamicLink::new();
    b.add_library("libc", &temp_path("/lib/x86_64-linux-gnu/libc.so.6"))
        .unwrap();
    b.add_obj_file("stuff", &temp_path("print_stuff.o"))
        .unwrap();
    b.add_obj_file("string", &temp_path("print_string.o"))
        .unwrap();
    let version = b.link().unwrap();
    test_lib_print(version.clone());
    test_print_stuff(version.clone());
    test_print_string(version);
}

//#[test]
fn test_libc_musl() {
    let mut b = DynamicLink::new();
    b.add_library("libc", &temp_path("/usr/lib/x86_64-linux-musl/libc.so"))
        .unwrap();
    b.add_obj_file("stuff", &temp_path("print_stuff.o"))
        .unwrap();
    b.add_obj_file("string", &temp_path("print_string.o"))
        .unwrap();

    // if we link with live.so, it will try to load the system libc, which conflicts with musl
    // it's random which one loads when we dlsym.
    //b.add_library("test", &temp_path("live.so")).unwrap();

    let version = b.link().unwrap();
    test_lib_print(version.clone());
    test_print_stuff(version.clone());
    test_print_string(version);
}

#[test]
fn test_multi_libc() {
    let mut b = DynamicLink::new();
    b.add_library("libc", &temp_path("/lib/x86_64-linux-gnu/libc.so.6"))
        .unwrap();
    b.add_library("musl", &temp_path("/usr/lib/x86_64-linux-musl/libc.so"))
        .unwrap();
    b.add_obj_file("stuff", &temp_path("print_stuff.o"))
        .unwrap();
    b.add_obj_file("string", &temp_path("print_string.o"))
        .unwrap();

    let version = b.link().unwrap();
    test_lib_print(version.clone());
    test_print_stuff(version.clone());
    test_print_string(version);
}

#[test]
fn test_string() {
    let mut b = DynamicLink::new();
    b.add_library("libc", &temp_path("/lib/x86_64-linux-gnu/libc.so.6"))
        .unwrap();
    //b.add_library("libc", &temp_path("/usr/lib/x86_64-linux-musl/libc.so"))
    //.unwrap();
    b.add_obj_file("string", &temp_path("print_string.o"))
        .unwrap();

    let version = b.link().unwrap();
    test_print_string(version.clone());
}

fn test_print_string(version: LinkVersion) {
    let ret: *const () = version.invoke("print_string", ()).unwrap();
    log::debug!("ret: {:#08x}", ret as usize);
}

fn test_print_stuff(version: LinkVersion) {
    let c_str = std::ffi::CString::new("asdf1: %d\n").unwrap();
    let c_str_ptr = c_str.as_ptr();

    let v_ptr: *const usize = version.lookup("g_v").unwrap().as_ptr() as *const usize;

    let g_ptr: *const usize = version.lookup("g_str2").unwrap().as_ptr() as *const usize;
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

fn test_lib_print(version: LinkVersion) {
    unsafe {
        let stdout_ptr = version.lookup("stdout").unwrap().as_ptr() as *const usize;
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
    p.push("../tmp");
    p.push(filename);
    p.into_boxed_path()
}
