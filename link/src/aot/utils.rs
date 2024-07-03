pub unsafe fn extend_lifetime<'b>(r: &'b [u8]) -> &'static [u8] {
    std::mem::transmute::<&'b [u8], &'static [u8]>(r)
}

/// align size
pub fn size_align(n: usize, align: usize) -> usize {
    (n + (align - 1)) & !(align - 1)
}
