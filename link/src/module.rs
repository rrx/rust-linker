/// A Link module is a grouping of items that share how symbols are resolved
/// A module could be totally isolated from other modules, and not resolve outside
/// of itself.
/// A module can also have a list of references to other modules, in order of priority
/// for resolution.  So if we have a main module, with symbols we want to override in
/// this module, we can list that first.
///
/// Overrides and Fallbacks:
/// We can have modules with higher priority that the current module, or lower priority.
/// A lower priority will resolve if it doesn't resolve in the overrides, or in the
/// current module.  It will then check the remainder.
///
pub struct LinkModule {
    overrides: im::Vector<String>,
    fallbacks: im::Vector<String>,

    /// symbols exported
    exports: im::HashMap<String, *const ()>,
    // Global Object Table, optional
    //got: Option<DataBlock>,
    //blocks: im::HashMap<String, Block>,
}

impl LinkModule {
    pub fn add(&mut self) {}
}
