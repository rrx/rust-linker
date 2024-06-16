use super::SmartPointer;
use std::fmt;
use std::ptr::NonNull;

#[derive(Clone, Debug)]
pub enum RelocationPointer {
    Got(SmartPointer), //NonNull<u8>),
    Plt(NonNull<u8>),
    Direct(NonNull<u8>),
    Shared(NonNull<u8>),
    Smart(SmartPointer),
}

impl RelocationPointer {
    pub fn as_ptr(&self) -> *const () {
        match self {
            Self::Plt(p) | Self::Direct(p) | Self::Shared(p) => p.as_ptr() as *const (),
            Self::Got(p) => p.as_ptr() as *const (),
            Self::Smart(p) => p.as_ptr() as *const (),
        }
    }
    pub fn direct2(p: *const ()) -> Option<Self> {
        NonNull::new(p as *mut u8).map(|p| Self::Direct(p))
    }

    pub fn shared(p: *const ()) -> Option<Self> {
        NonNull::new(p as *mut u8).map(|p| Self::Shared(p))
    }

    pub fn smart(p: SmartPointer) -> Self {
        Self::Smart(p)
    }
}

impl fmt::Display for RelocationPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Got(p) => write!(f, "G({:#08x})", p.as_ptr() as usize),
            Self::Plt(p) => write!(f, "P({:#08x})", p.as_ptr() as usize),
            Self::Direct(p) => write!(f, "D({:#08x})", p.as_ptr() as usize),
            Self::Shared(p) => write!(f, "S({:#08x})", p.as_ptr() as usize),
            Self::Smart(p) => write!(f, "X({:#08x})", p.as_ptr() as usize),
        }
    }
}
