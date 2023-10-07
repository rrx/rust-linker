# TLDR

A personal proof-of-concept linker that works only on Linux x86_64, with hot-reload potential

# Why

This project is a proof-of-concept linker built in Rust.  The purpose of this project was to learn more about how linkers and loaders work.  It's one of those things you don't think about until you need to, and if you're like me, you're a little surprised at the complexity that hides behind such a simple interface.  But if it was just a linker, that's not very interesting, so I'm also working on adding some hot-reloading functionality that will swap out code at runtime.  I wrote a wild blog post about this called [Hot-Reloading like it's 1972](https://rrx.github.io/posts/2023-02-13-hotreloading/).  It turns out that hot-reloading is a bit of a difficult problem, which is why you don't see it much any more as the focus has moved from developer productivity towards production stability.  I still think the developer experience aspect is important though, so I'd like to explore it's potential further as part of my language research.

# Limitations

- Only compiles for Linux on x86_64
- No linker options, only the simplest were used for implementation
- Hot-reloading is very primitive and not yet usable

# Developing

You will need a few libraries to build the test functions.  On ubuntu you will need:

```
sudo apt install libsigsegv-dev libsdl2-dev libuv1-dev
make functions
```

See the Makefile for examples of usage.

# Helpful links

Some helpful links for building linkers:

- https://wiki.osdev.org/ELF
- https://web.archive.org/web/20140130143820/http://www.robinhoksbergen.com/papers/howto_elf.html
- http://www.skyfree.org/linux/references/ELF_Format.pdf
- https://gitlab.com/x86-psABIs/x86-64-ABI

# Similar Work in Rust

- https://github.com/aep/elfkit
- https://github.com/m4b/dryad
- https://github.com/m4b/goblin
- https://github.com/bloff/runtime-static-linking-with-libbfd/blob/master/main.c
- https://github.com/m4b/faerie/blob/master/examples/prototype.rs

