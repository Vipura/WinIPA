// Copyright (C) 2026 WinIPA Contributors
// SPDX-License-Identifier: GPL-3.0-only

pub const MH_MAGIC_64: u32 = 0xfeedfacf;
pub const MH_CIGAM_64: u32 = 0xcffaedfe;
pub const MH_MAGIC: u32 = 0xfeedface;
pub const MH_CIGAM: u32 = 0xcefaedfe;
pub const FAT_MAGIC: u32 = 0xcafebabe;
pub const FAT_CIGAM: u32 = 0xbebafeca;

pub const LC_CODE_SIGNATURE: u32 = 0x1d;
pub const LC_ENCRYPTION_INFO: u32 = 0x21;
pub const LC_ENCRYPTION_INFO_64: u32 = 0x2c;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MachOInspectionResult {
    pub is_encrypted: bool,
    pub is_signed: bool,
    pub crypt_id: u32,
    pub arches: Vec<String>,
}

/// Inspects a Mach-O binary (single architecture or universal Fat) for FairPlay DRM encryption
/// and code signature load commands.
pub fn inspect_macho(bytes: &[u8]) -> MachOInspectionResult {
    if bytes.len() < 4 {
        return MachOInspectionResult {
            is_encrypted: false,
            is_signed: false,
            crypt_id: 0,
            arches: vec![],
        };
    }

    let magic = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    if magic == FAT_MAGIC || magic == FAT_CIGAM {
        inspect_fat_binary(bytes, magic == FAT_CIGAM)
    } else {
        let (res, arch) = inspect_single_macho(bytes);
        let mut arches = vec![];
        if let Some(a) = arch {
            arches.push(a);
        }
        MachOInspectionResult { arches, ..res }
    }
}

fn inspect_fat_binary(bytes: &[u8], is_swapped: bool) -> MachOInspectionResult {
    if bytes.len() < 8 {
        return MachOInspectionResult {
            is_encrypted: false,
            is_signed: false,
            crypt_id: 0,
            arches: vec![],
        };
    }

    let nfat_arch = if is_swapped {
        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
    } else {
        u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]])
    };

    let mut is_encrypted = false;
    let mut is_signed = false;
    let mut crypt_id = 0;
    let mut arches = vec![];

    let mut offset = 8;
    for _ in 0..nfat_arch {
        if offset + 20 > bytes.len() {
            break;
        }

        let arch_slice = &bytes[offset..offset + 20];
        let arch_offset = if is_swapped {
            u32::from_le_bytes([arch_slice[8], arch_slice[9], arch_slice[10], arch_slice[11]])
        } else {
            u32::from_be_bytes([arch_slice[8], arch_slice[9], arch_slice[10], arch_slice[11]])
        } as usize;

        let arch_size = if is_swapped {
            u32::from_le_bytes([
                arch_slice[12],
                arch_slice[13],
                arch_slice[14],
                arch_slice[15],
            ])
        } else {
            u32::from_be_bytes([
                arch_slice[12],
                arch_slice[13],
                arch_slice[14],
                arch_slice[15],
            ])
        } as usize;

        if arch_offset + arch_size <= bytes.len() {
            let slice_bytes = &bytes[arch_offset..arch_offset + arch_size];
            let (slice_res, arch) = inspect_single_macho(slice_bytes);
            if slice_res.is_encrypted {
                is_encrypted = true;
                crypt_id = slice_res.crypt_id;
            }
            if slice_res.is_signed {
                is_signed = true;
            }
            if let Some(a) = arch {
                arches.push(a);
            }
        }

        offset += 20;
    }

    MachOInspectionResult {
        is_encrypted,
        is_signed,
        crypt_id,
        arches,
    }
}

fn inspect_single_macho(bytes: &[u8]) -> (MachOInspectionResult, Option<String>) {
    if bytes.len() < 28 {
        return (
            MachOInspectionResult {
                is_encrypted: false,
                is_signed: false,
                crypt_id: 0,
                arches: vec![],
            },
            None,
        );
    }

    let magic_le = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let is_64 = magic_le == MH_MAGIC_64 || magic_le == MH_CIGAM_64;
    let is_little_endian = magic_le == MH_MAGIC_64 || magic_le == MH_MAGIC;

    let header_size = if is_64 { 32 } else { 28 };
    if bytes.len() < header_size {
        return (
            MachOInspectionResult {
                is_encrypted: false,
                is_signed: false,
                crypt_id: 0,
                arches: vec![],
            },
            None,
        );
    }

    let read_u32 = |offset: usize| -> u32 {
        if offset + 4 > bytes.len() {
            return 0;
        }
        if is_little_endian {
            u32::from_le_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ])
        } else {
            u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ])
        }
    };

    let cputype = read_u32(4);
    let ncmds = read_u32(16) as usize;

    let arch_name = match cputype {
        0x0100000c => "arm64",
        0x0200000c => "arm64_32",
        12 => "armv7",
        0x01000007 => "x86_64",
        _ => "unknown",
    }
    .to_string();

    let mut is_encrypted = false;
    let mut is_signed = false;
    let mut crypt_id = 0;

    let mut cursor = header_size;
    for _ in 0..ncmds {
        if cursor + 8 > bytes.len() {
            break;
        }

        let cmd = read_u32(cursor);
        let cmdsize = read_u32(cursor + 4) as usize;

        if cmdsize == 0 || cursor + cmdsize > bytes.len() {
            break;
        }

        if cmd == LC_CODE_SIGNATURE {
            is_signed = true;
        } else if cmd == LC_ENCRYPTION_INFO_64 {
            // struct encryption_info_command_64 { cmd, cmdsize, cryptoff, cryptsize, cryptid, pad }
            if cmdsize >= 24 {
                let id = read_u32(cursor + 16);
                if id != 0 {
                    is_encrypted = true;
                    crypt_id = id;
                }
            }
        } else if cmd == LC_ENCRYPTION_INFO {
            // struct encryption_info_command { cmd, cmdsize, cryptoff, cryptsize, cryptid }
            if cmdsize >= 20 {
                let id = read_u32(cursor + 16);
                if id != 0 {
                    is_encrypted = true;
                    crypt_id = id;
                }
            }
        }

        cursor += cmdsize;
    }

    (
        MachOInspectionResult {
            is_encrypted,
            is_signed,
            crypt_id,
            arches: vec![],
        },
        Some(arch_name),
    )
}

/// Constructs a synthetic Mach-O 64-bit binary header for testing.
pub fn create_test_macho(encrypted: bool, signed: bool) -> Vec<u8> {
    let mut bytes = Vec::new();

    // Mach-O 64 header (little-endian)
    bytes.extend_from_slice(&MH_MAGIC_64.to_le_bytes()); // magic
    bytes.extend_from_slice(&0x0100000cu32.to_le_bytes()); // cputype = arm64
    bytes.extend_from_slice(&0u32.to_le_bytes()); // cpusubtype
    bytes.extend_from_slice(&2u32.to_le_bytes()); // filetype = MH_EXECUTE

    let mut ncmds = 0u32;
    if encrypted {
        ncmds += 1;
    }
    if signed {
        ncmds += 1;
    }

    let mut sizeofcmds = 0u32;
    if encrypted {
        sizeofcmds += 24; // LC_ENCRYPTION_INFO_64 size
    }
    if signed {
        sizeofcmds += 16; // LC_CODE_SIGNATURE size
    }

    bytes.extend_from_slice(&ncmds.to_le_bytes());
    bytes.extend_from_slice(&sizeofcmds.to_le_bytes());
    bytes.extend_from_slice(&0u32.to_le_bytes()); // flags
    bytes.extend_from_slice(&0u32.to_le_bytes()); // reserved

    // LC_ENCRYPTION_INFO_64 command
    if encrypted {
        bytes.extend_from_slice(&LC_ENCRYPTION_INFO_64.to_le_bytes()); // cmd (44)
        bytes.extend_from_slice(&24u32.to_le_bytes()); // cmdsize
        bytes.extend_from_slice(&4096u32.to_le_bytes()); // cryptoff
        bytes.extend_from_slice(&8192u32.to_le_bytes()); // cryptsize
        bytes.extend_from_slice(&1u32.to_le_bytes()); // cryptid = 1 (ENCRYPTED)
        bytes.extend_from_slice(&0u32.to_le_bytes()); // pad
    }

    // LC_CODE_SIGNATURE command
    if signed {
        bytes.extend_from_slice(&LC_CODE_SIGNATURE.to_le_bytes()); // cmd (29)
        bytes.extend_from_slice(&16u32.to_le_bytes()); // cmdsize
        bytes.extend_from_slice(&16384u32.to_le_bytes()); // dataoff
        bytes.extend_from_slice(&1024u32.to_le_bytes()); // datasize
    }

    bytes
}

/// Constructs a synthetic valid Mach-O 64-bit executable with __TEXT, __LINKEDIT,
/// and LC_CODE_SIGNATURE segments that can be accepted and signed by code signing tools.
pub fn create_signable_test_macho() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x8000]; // 32KB

    // Header
    bytes[0..4].copy_from_slice(&MH_MAGIC_64.to_le_bytes()); // magic 0xfeedfacf
    bytes[4..8].copy_from_slice(&0x0100000cu32.to_le_bytes()); // cputype = arm64
    bytes[8..12].copy_from_slice(&0u32.to_le_bytes()); // cpusubtype = 0
    bytes[12..16].copy_from_slice(&2u32.to_le_bytes()); // filetype = MH_EXECUTE
    bytes[16..20].copy_from_slice(&4u32.to_le_bytes()); // ncmds = 4
    bytes[20..24].copy_from_slice(&232u32.to_le_bytes()); // sizeofcmds = 72*3 + 16 = 232
    bytes[24..28].copy_from_slice(&0x00200085u32.to_le_bytes()); // flags
    bytes[28..32].copy_from_slice(&0u32.to_le_bytes()); // reserved

    // LC_SEGMENT_64: __PAGEZERO (72 bytes)
    let off1 = 32;
    bytes[off1..off1 + 4].copy_from_slice(&0x19u32.to_le_bytes()); // LC_SEGMENT_64
    bytes[off1 + 4..off1 + 8].copy_from_slice(&72u32.to_le_bytes());
    let mut segname_pz = [0u8; 16];
    segname_pz[..10].copy_from_slice(b"__PAGEZERO");
    bytes[off1 + 8..off1 + 24].copy_from_slice(&segname_pz);
    bytes[off1 + 24..off1 + 32].copy_from_slice(&0u64.to_le_bytes()); // vmaddr
    bytes[off1 + 32..off1 + 40].copy_from_slice(&0x100000000u64.to_le_bytes()); // vmsize
    bytes[off1 + 40..off1 + 48].copy_from_slice(&0u64.to_le_bytes()); // fileoff
    bytes[off1 + 48..off1 + 56].copy_from_slice(&0u64.to_le_bytes()); // filesize

    // LC_SEGMENT_64: __TEXT (72 bytes)
    let off2 = 104;
    bytes[off2..off2 + 4].copy_from_slice(&0x19u32.to_le_bytes());
    bytes[off2 + 4..off2 + 8].copy_from_slice(&72u32.to_le_bytes());
    let mut segname_text = [0u8; 16];
    segname_text[..6].copy_from_slice(b"__TEXT");
    bytes[off2 + 8..off2 + 24].copy_from_slice(&segname_text);
    bytes[off2 + 24..off2 + 32].copy_from_slice(&0x100000000u64.to_le_bytes()); // vmaddr
    bytes[off2 + 32..off2 + 40].copy_from_slice(&0x4000u64.to_le_bytes()); // vmsize
    bytes[off2 + 40..off2 + 48].copy_from_slice(&0u64.to_le_bytes()); // fileoff
    bytes[off2 + 48..off2 + 56].copy_from_slice(&0x4000u64.to_le_bytes()); // filesize
    bytes[off2 + 56..off2 + 60].copy_from_slice(&7u32.to_le_bytes()); // maxprot = rwx
    bytes[off2 + 60..off2 + 64].copy_from_slice(&5u32.to_le_bytes()); // initprot = r-x

    // LC_SEGMENT_64: __LINKEDIT (72 bytes)
    let off3 = 176;
    bytes[off3..off3 + 4].copy_from_slice(&0x19u32.to_le_bytes());
    bytes[off3 + 4..off3 + 8].copy_from_slice(&72u32.to_le_bytes());
    let mut segname_le = [0u8; 16];
    segname_le[..10].copy_from_slice(b"__LINKEDIT");
    bytes[off3 + 8..off3 + 24].copy_from_slice(&segname_le);
    bytes[off3 + 24..off3 + 32].copy_from_slice(&0x100004000u64.to_le_bytes()); // vmaddr
    bytes[off3 + 32..off3 + 40].copy_from_slice(&0x4000u64.to_le_bytes()); // vmsize
    bytes[off3 + 40..off3 + 48].copy_from_slice(&0x4000u64.to_le_bytes()); // fileoff
    bytes[off3 + 48..off3 + 56].copy_from_slice(&0x4000u64.to_le_bytes()); // filesize
    bytes[off3 + 56..off3 + 60].copy_from_slice(&7u32.to_le_bytes()); // maxprot
    bytes[off3 + 60..off3 + 64].copy_from_slice(&1u32.to_le_bytes()); // initprot = r--

    // LC_CODE_SIGNATURE (16 bytes)
    let off4 = 248;
    bytes[off4..off4 + 4].copy_from_slice(&LC_CODE_SIGNATURE.to_le_bytes()); // 0x1d
    bytes[off4 + 4..off4 + 8].copy_from_slice(&16u32.to_le_bytes());
    bytes[off4 + 8..off4 + 12].copy_from_slice(&0x4000u32.to_le_bytes()); // dataoff in file
    bytes[off4 + 12..off4 + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // datasize

    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_inspect_unencrypted_unsigned_binary() {
        let binary = create_test_macho(false, false);
        let res = inspect_macho(&binary);
        assert!(!res.is_encrypted);
        assert!(!res.is_signed);
        assert_eq!(res.crypt_id, 0);
        assert_eq!(res.arches, vec!["arm64"]);
    }

    #[test]
    fn test_inspect_encrypted_binary() {
        let binary = create_test_macho(true, true);
        let res = inspect_macho(&binary);
        assert!(res.is_encrypted);
        assert!(res.is_signed);
        assert_eq!(res.crypt_id, 1);
        assert_eq!(res.arches, vec!["arm64"]);
    }
}
