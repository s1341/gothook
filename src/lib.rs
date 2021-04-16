use goblin::{
    container::{Container, Ctx},
    elf::{dynamic::{Dynamic, DT_RELA, DT_LOOS}, sym::Symtab, Elf, ProgramHeader, RelocSection},
    strtab::Strtab,
};
use libloading::Library;
use nix::sys::mman::{mprotect, ProtFlags};
use regex::Regex;
use scroll::Endian;
use std::{ffi::c_void, fs::File, io::{BufRead, BufReader}};

pub struct GotHookLibrary<'a> {
    path: &'a str,
    start: usize,
    end: usize,
    file_in_memory: Box<&'a [u8]>,
    elf: Elf<'a>,
}

impl<'a> GotHookLibrary<'a> {
    /// Create a new library to be hooked from a path. If the load boolean is true, the library will first be
    /// loaded.
    pub fn new(path: &'a str, load: bool) -> Self {
        println!("Path is {:?}", path);
        let library = if load {
            Some(unsafe { Library::new(path) })
        } else {
            None
        };

        println!("library: {:?}", library);

        let (start, end) = mapping_for_library(path);

        let file_in_memory = unsafe { std::slice::from_raw_parts(start as *const u8, end - start) };
        let mut elf = Elf::lazy_parse(
           Elf::parse_header(file_in_memory).expect("Failed to parse elf"),
        )
        .expect("Failed to parse elf lazily");

        let ctx = Ctx {
            le: Endian::Little,
            container: Container::Big,
        };
        elf.program_headers = ProgramHeader::parse(
            &file_in_memory,
            elf.header.e_phoff as usize,
            elf.header.e_phnum as usize,
            ctx,
        )
        .expect("parse program headers");
        // because we're in memory, we need to use the vaddr. goblin uses offsets, so we'll
        // just patch the PHDRS so that they have offsets equal to vaddr.
        for mut program_header in &mut elf.program_headers {
            program_header.p_offset = program_header.p_vaddr;
        }
        elf.dynamic =
            Dynamic::parse(&file_in_memory, &elf.program_headers, ctx)
                .expect("parse dynamic section");


        //let mut android_relr_offset = 0;
        //let mut android_relr_size = 0;

        //for entry in elf.dynamic.dyns {
            //match entry.tag {
                //// DT_ANDROID_REL
                //DT_LOOS + 2 => {

                //},
                //// DT_ANDROID_RELSZ
                //DT_LOOS + 3 => {

                //},
                //// DT_ANDROID_RELA
                //DT_LOOS + 4 => {

                //},
                //// DT_ANDROID_RELASZ
                //DT_LOOS + 5 => {

                //},
                //// DT_ANDROID_RELR
                //0x6fffe000 | 36 => {
                    //android_rel_offset = entry.val;
                //},
                //// DT_ANDROID_RELRSZ
                //0x6fffe001 | 35 => {
                    //android_relr_size = entry.val;
                //},
                //// DT_ANDROID_RELRENT
                //0x6fffe003 | 37 => {
                    //android_relr_entry_size = entry.val;
                //},
                //// DT_ANDROID_RELRCOUNT
                //0x6fffe005 => {

                //},
                //_ => (),
            //}
        //}

        //if android_relr_offset != 0 {
            //let mut relocations: Vec<usize> = vec!();
            //let qwords = std::slice::from_raw_parts((start + android_relr_offset) as usize as *mut usize, android_relr_size / android_relr_entry_size);
            //let mut index = 0;
            //while index < qwords.len() {
                //let base_address = qwords[index];
                //assert!(base_address % 2 == 0);

                //index += 1;
                //while qwords[index] & 1 == 1 {
                    //let bitmap = qwords[index];
                    //index += 1;

                    //for bitindex in 1..63 {
                        //if (bitmap >> bitindex) & 1 == 1 {

                        //}
                    //}
                //}


            //}

        //}

        let info = &elf.dynamic.as_ref().unwrap().info;

        // second word of hash
        let chain_count = unsafe {
            if let Some(offset) = info.hash {
                std::slice::from_raw_parts((start + offset as usize + 4) as *mut u32, 1)[0]
            } else {
                (info.pltrelsz / info.syment) as u32
            }
        };

        elf.dynsyms = Symtab::parse(
            &file_in_memory,
            info.symtab,
            chain_count as usize,
            ctx,
        )
        .expect("parse dynsyms");
        elf.dynstrtab =
            Strtab::parse(&file_in_memory, info.strtab, info.strsz, b'\x00')
                .expect("parse dynstrtab");
        elf.pltrelocs = RelocSection::parse(
            &file_in_memory,
            info.jmprel,
            info.pltrelsz,
            info.pltrel == DT_RELA,
            ctx,
        )
        .expect("parse pltrel");
        //
        //let dynsyms = &elf.dynsyms.to_vec();
        //let gnu_hash_metadata = unsafe { std::slice::from_raw_parts((start + dynamic.info.gnu_hash.unwrap() as usize) as *mut u32, 4)};
        //let gnu_hash_size = (dynsyms.len() - gnu_hash_metadata[1] as usize) * 4 + gnu_hash_metadata[0] as usize * 4 + gnu_hash_metadata[2] as usize  * 8 + 4 * 4;
        //let gnu_hash = unsafe { goblin::elf64::gnu_hash::GnuHash::from_raw_table(
        //std::slice::from_raw_parts((start + dynamic.info.gnu_hash.unwrap() as usize) as *mut u8,  gnu_hash_size as usize),
        //dynsyms) }.expect("parse gnu_hash");

        Self {
            path,
            start,
            end,
            file_in_memory: Box::new(file_in_memory),
            elf,
        }
    }

    /// Get the start address of this library
    pub fn start(&self) -> usize {
        self.start
    }

    /// Get the end address of this library
    pub fn end(&self) -> usize {
        self.end
    }

    /// Get the library's path
    pub fn path(&self) -> &str {
        self.path
    }

    /// Hook the function specified by name
    ///
    /// #Safety:
    /// This function is inherently unsafe as it modifies the got.plt of the target library,
    /// dereferncing raw pointers as necessary.
    pub unsafe fn hook_function(&self, name: &str, newfunc: *const c_void) -> bool {
        let mut symindex: isize = -1;
        for (i, symbol) in self.elf.dynsyms.iter().enumerate() {
            if name == self.elf.dynstrtab.get(symbol.st_name).unwrap().unwrap() {
                symindex = i as isize;
                break;
            }
        }

        if symindex == -1 {
            println!("failed to find function {:?}", name);
            return false;
        }

        let mut offset: isize = -1;
        for reloc in self.elf.pltrelocs.iter() {
            if reloc.r_sym == symindex as usize {
                offset = reloc.r_offset as isize;
                break;
            }
        }
        if offset == -1 {
            println!("failed to find relocation for {:?}", name);
            return false;
        }

        let address = self.start + offset as usize;
        let value = std::ptr::read(address as *const *const c_void);
        println!(
            "found {:?} at address {:x}, with value {:x}, replacing...",
            name, address, value as usize
        );
        mprotect(
            ((address / 0x1000) * 0x1000) as *mut c_void,
            0x1000,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        )
        .expect("Failed to mprotect to read/write");
        std::ptr::replace(address as *mut *const c_void, newfunc);
        mprotect(
            ((address / 0x1000) * 0x1000) as *mut c_void,
            0x1000,
            ProtFlags::PROT_READ,
        )
        .expect("Failed to mprotect back to read-only");

        let value = std::ptr::read(address as *const *const c_void);
        println!(
            "verified value set to {:x}, expected {:x}",
            value as usize, newfunc as usize
        );

        value == newfunc
    }
}

/// Allows one to walk the mappings in /proc/self/maps, caling a callback function for each
/// mapping.
/// If the callback returns true, we stop the walk.
fn walk_self_maps(visitor: &mut dyn FnMut(usize, usize, String, String) -> bool) {
    let re = Regex::new(r"^(?P<start>[0-9a-f]{8,16})-(?P<end>[0-9a-f]{8,16}) (?P<perm>[-rwxp]{4}) (?P<offset>[0-9a-f]{8}) [0-9a-f]+:[0-9a-f]+ [0-9]+\s+(?P<path>.*)$")
        .unwrap();

    let mapsfile = File::open("/proc/self/maps").expect("Unable to open /proc/self/maps");

    for line in BufReader::new(mapsfile).lines() {
        let line = line.unwrap();
        if let Some(caps) = re.captures(&line) {
            if visitor(
                usize::from_str_radix(caps.name("start").unwrap().as_str(), 16).unwrap(),
                usize::from_str_radix(caps.name("end").unwrap().as_str(), 16).unwrap(),
                caps.name("perm").unwrap().as_str().to_string(),
                caps.name("path").unwrap().as_str().to_string(),
            ) {
                break;
            };
        }
    }
}
/// Get the start and end address of the mapping containing a particular address
fn mapping_for_library(libpath: &str) -> (usize, usize) {
    let mut libstart = 0;
    let mut libend = 0;
    walk_self_maps(&mut |start, end, _permissions, path| {
        if libpath == path {
            if libstart == 0 {
                libstart = start;
            }

            libend = end;
        }
        false
    });

    (libstart, libend)
}
