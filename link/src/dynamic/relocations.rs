use std::fmt;
use std::ptr::NonNull;

#[derive(Clone, Debug)]
pub enum RelocationPointer {
    Plt(NonNull<u8>),
    Direct(NonNull<u8>),
    Shared(NonNull<u8>),
}

impl RelocationPointer {
    pub fn as_ptr(&self) -> *const () {
        match self {
            Self::Plt(p) | Self::Direct(p) | Self::Shared(p) => p.as_ptr() as *const (),
        }
    }

    pub fn direct2(p: *const ()) -> Option<Self> {
        NonNull::new(p as *mut u8).map(Self::Direct)
    }

    pub fn shared(p: *const ()) -> Option<Self> {
        NonNull::new(p as *mut u8).map(Self::Shared)
    }
}

impl fmt::Display for RelocationPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plt(p) => write!(f, "P({:#08x})", p.as_ptr() as usize),
            Self::Direct(p) => write!(f, "D({:#08x})", p.as_ptr() as usize),
            Self::Shared(p) => write!(f, "S({:#08x})", p.as_ptr() as usize),
        }
    }
}
