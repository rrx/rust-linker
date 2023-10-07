pub fn eprint_process_maps() {
    eprintln!("Process Maps:");
    for map in proc_maps::get_process_maps(std::process::id() as proc_maps::Pid).unwrap() {
        eprintln!(
            "Map: {:#08x}+{:x}, {}, {:?}",
            map.start(),
            map.size(),
            map.flags,
            map.filename()
        );
    }
}
