use std::collections::HashMap;
use std::fs;
use std::io::Read;
use strata_cli::prelude::*;

/// Generates an authentic minimal architecture-valid test fixture binary for testing packaging pipelines.
fn make_test_binary_bytes(target: BuildTarget) -> Vec<u8> {
    match target {
        BuildTarget::Linux | BuildTarget::Desktop => {
            let mut elf = vec![0u8; 1024];
            elf[0..4].copy_from_slice(b"\x7fELF");
            elf[4] = 2; // 64-bit
            elf[5] = 1; // little endian
            elf[6] = 1; // version
            elf[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
            elf[18..20].copy_from_slice(&0x003Eu16.to_le_bytes()); // x86_64
            elf[20..24].copy_from_slice(&1u32.to_le_bytes()); // EV_CURRENT
            elf
        }
        BuildTarget::Android => {
            let mut elf = vec![0u8; 1024];
            elf[0..4].copy_from_slice(b"\x7fELF");
            elf[4] = 2; // 64-bit
            elf[5] = 1; // little endian
            elf[6] = 1; // version
            elf[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN (shared object)
            elf[18..20].copy_from_slice(&183u16.to_le_bytes()); // AArch64 (0x00B7)
            elf[20..24].copy_from_slice(&1u32.to_le_bytes());
            elf
        }
        BuildTarget::Windows => {
            let mut pe = vec![0u8; 1024];
            pe[0..2].copy_from_slice(b"MZ");
            pe[60..64].copy_from_slice(&128u32.to_le_bytes()); // e_lfanew
            let pe_off = 128;
            pe[pe_off..pe_off + 4].copy_from_slice(b"PE\0\0");
            pe[pe_off + 4..pe_off + 6].copy_from_slice(&0x8664u16.to_le_bytes()); // AMD64
            pe[pe_off + 6..pe_off + 8].copy_from_slice(&1u16.to_le_bytes());
            pe[pe_off + 20..pe_off + 22].copy_from_slice(&0xF0u16.to_le_bytes());
            pe[pe_off + 22..pe_off + 24].copy_from_slice(&0x0022u16.to_le_bytes());
            pe[pe_off + 24..pe_off + 26].copy_from_slice(&0x020Bu16.to_le_bytes());
            pe
        }
        BuildTarget::MacOs => {
            let mut macho = vec![0u8; 1024];
            macho[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // MH_MAGIC_64
            macho[4..8].copy_from_slice(&0x0100000Cu32.to_le_bytes()); // CPU_TYPE_ARM64
            macho[8..12].copy_from_slice(&0u32.to_le_bytes());
            macho[12..16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
            macho[24..28].copy_from_slice(&0x00200085u32.to_le_bytes());
            macho
        }
        BuildTarget::Ios => {
            let mut macho = vec![0u8; 1024];
            macho[0..4].copy_from_slice(&[0xCF, 0xFA, 0xED, 0xFE]); // MH_MAGIC_64
            macho[4..8].copy_from_slice(&0x0100000Cu32.to_le_bytes()); // CPU_TYPE_ARM64
            macho[8..12].copy_from_slice(&0u32.to_le_bytes());
            macho[12..16].copy_from_slice(&2u32.to_le_bytes()); // MH_EXECUTE
            macho[24..28].copy_from_slice(&0x00200085u32.to_le_bytes());
            macho
        }
        BuildTarget::WebWasm => {
            vec![0x00, 0x61, 0x73, 0x6D, 0x01, 0x00, 0x00, 0x00]
        }
        BuildTarget::WebJs => {
            b"console.log('Strata App');".to_vec()
        }
    }
}

/// Seeds an authentic architecture-valid test binary into `dist/<target>/` for packaging tests.
fn seed_test_binary(dir: &std::path::Path, target: BuildTarget, app_name: &str) {
    let dist_target = dir.join("dist").join(target.as_str());
    fs::create_dir_all(&dist_target).unwrap();
    let bin_path = dist_target.join(format!("{}{}", app_name, target.binary_extension()));
    fs::write(&bin_path, make_test_binary_bytes(target)).unwrap();
}

/// Deeply parses a Unix ar archive into individual named members.
fn parse_ar_archive(bytes: &[u8]) -> HashMap<String, Vec<u8>> {
    assert!(
        bytes.starts_with(b"!<arch>\n"),
        "Archive must begin with !<arch>\\n magic"
    );
    let mut offset = 8;
    let mut members = HashMap::new();
    while offset + 60 <= bytes.len() {
        let hdr = &bytes[offset..offset + 60];
        assert_eq!(&hdr[58..60], b"`\n", "ar entry must end with `\\n");
        let name = String::from_utf8_lossy(&hdr[0..16])
            .trim()
            .trim_end_matches('/')
            .to_string();
        let size_str = String::from_utf8_lossy(&hdr[48..58]).trim().to_string();
        let size: usize = size_str.parse().expect("Valid decimal ar member size");
        let data_start = offset + 60;
        let data_end = data_start + size;
        assert!(data_end <= bytes.len(), "ar member data out of bounds");
        members.insert(name, bytes[data_start..data_end].to_vec());
        offset = data_end;
        if !size.is_multiple_of(2) {
            offset += 1;
        }
    }
    members
}

/// Deeply parses a POSIX USTAR tar archive, validating all 512-byte header block checksums.
fn parse_tar_archive(bytes: &[u8]) -> HashMap<String, (u32, Vec<u8>)> {
    let mut offset = 0;
    let mut files = HashMap::new();
    while offset + 512 <= bytes.len() {
        let block = &bytes[offset..offset + 512];
        if block.iter().all(|&b| b == 0) {
            break;
        }
        // Validate POSIX ustar magic and version
        assert_eq!(&block[257..263], b"ustar\0", "Tar block must have ustar\\0 magic");
        assert_eq!(&block[263..265], b"00", "Tar block must have ustar version 00");

        // Validate checksum: sum of unsigned byte values across all 512 bytes with checksum field filled with spaces
        let mut chksum_buf = block.to_vec();
        chksum_buf[148..156].fill(b' ');
        let computed_sum: u32 = chksum_buf.iter().map(|&b| b as u32).sum();
        let chksum_str = String::from_utf8_lossy(&block[148..156])
            .trim_matches(|c: char| c == '\0' || c.is_whitespace())
            .to_string();
        let recorded_sum = u32::from_str_radix(&chksum_str, 8).expect("Valid octal tar checksum");
        assert_eq!(
            computed_sum, recorded_sum,
            "Tar block checksum must match sum of bytes"
        );

        let name = String::from_utf8_lossy(&block[..100])
            .trim_matches('\0')
            .to_string();
        let size_str = String::from_utf8_lossy(&block[124..136])
            .trim_matches(|c: char| c == '\0' || c.is_whitespace())
            .to_string();
        let size = usize::from_str_radix(&size_str, 8).unwrap_or(0);
        let mode_str = String::from_utf8_lossy(&block[100..108])
            .trim_matches(|c: char| c == '\0' || c.is_whitespace())
            .to_string();
        let mode = u32::from_str_radix(&mode_str, 8).unwrap_or(0);

        let data_start = offset + 512;
        let data_end = data_start + size;
        let data = if size > 0 {
            assert!(data_end <= bytes.len(), "Tar entry data exceeds archive");
            bytes[data_start..data_end].to_vec()
        } else {
            Vec::new()
        };
        files.insert(name, (mode, data));
        let blocks = size.div_ceil(512);
        offset += 512 * (1 + blocks);
    }
    files
}

/// Deeply parses a ZIP archive by reading its End of Central Directory, Central Directory records,
/// validating local file header offsets, and verifying CRC-32 checksums for every member.
fn parse_zip_archive(bytes: &[u8]) -> HashMap<String, (u32, Vec<u8>)> {
    let eocd_pos = bytes
        .windows(4)
        .rposition(|w| w == [0x50, 0x4B, 0x05, 0x06])
        .expect("Valid ZIP archive must contain EOCD record");
    let total_entries = u16::from_le_bytes([bytes[eocd_pos + 10], bytes[eocd_pos + 11]]) as usize;
    let cd_offset = u32::from_le_bytes([
        bytes[eocd_pos + 16],
        bytes[eocd_pos + 17],
        bytes[eocd_pos + 18],
        bytes[eocd_pos + 19],
    ]) as usize;

    let mut cd_cursor = cd_offset;
    let mut files = HashMap::new();

    for _ in 0..total_entries {
        assert_eq!(
            &bytes[cd_cursor..cd_cursor + 4],
            &[0x50, 0x4B, 0x01, 0x02],
            "Central directory signature"
        );
        let crc = u32::from_le_bytes([
            bytes[cd_cursor + 16],
            bytes[cd_cursor + 17],
            bytes[cd_cursor + 18],
            bytes[cd_cursor + 19],
        ]);
        let comp_size = u32::from_le_bytes([
            bytes[cd_cursor + 20],
            bytes[cd_cursor + 21],
            bytes[cd_cursor + 22],
            bytes[cd_cursor + 23],
        ]) as usize;
        let uncomp_size = u32::from_le_bytes([
            bytes[cd_cursor + 24],
            bytes[cd_cursor + 25],
            bytes[cd_cursor + 26],
            bytes[cd_cursor + 27],
        ]) as usize;
        let name_len = u16::from_le_bytes([bytes[cd_cursor + 28], bytes[cd_cursor + 29]]) as usize;
        let extra_len = u16::from_le_bytes([bytes[cd_cursor + 30], bytes[cd_cursor + 31]]) as usize;
        let comment_len = u16::from_le_bytes([bytes[cd_cursor + 32], bytes[cd_cursor + 33]]) as usize;
        let local_offset = u32::from_le_bytes([
            bytes[cd_cursor + 42],
            bytes[cd_cursor + 43],
            bytes[cd_cursor + 44],
            bytes[cd_cursor + 45],
        ]) as usize;

        let name = String::from_utf8_lossy(&bytes[cd_cursor + 46..cd_cursor + 46 + name_len]).to_string();

        // Validate local header
        assert_eq!(
            &bytes[local_offset..local_offset + 4],
            &[0x50, 0x4B, 0x03, 0x04],
            "Local file header signature"
        );
        let loc_name_len = u16::from_le_bytes([bytes[local_offset + 26], bytes[local_offset + 27]]) as usize;
        let loc_extra_len = u16::from_le_bytes([bytes[local_offset + 28], bytes[local_offset + 29]]) as usize;
        let data_start = local_offset + 30 + loc_name_len + loc_extra_len;
        let data_end = data_start + comp_size;
        let data = &bytes[data_start..data_end];

        // Verify IEEE 802.3 CRC32 checksum
        let computed_crc = strata_cli::packager::compute_crc32(data);
        assert_eq!(computed_crc, crc, "CRC32 checksum mismatch for {}", name);
        assert_eq!(
            uncomp_size, comp_size,
            "Uncompressed size matches stored compression"
        );

        files.insert(name, (crc, data.to_vec()));
        cd_cursor += 46 + name_len + extra_len + comment_len;
    }

    files
}

#[test]
fn test_package_linux_distributions() {
    let temp_dir = std::env::temp_dir().join(format!("strata_pkg_linux_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    seed_test_binary(&temp_dir, BuildTarget::Desktop, "strata-app");

    // 1. Debian (.deb)
    let deb_report = Packager::package(BuildTarget::Desktop, Some(PackageFormat::Deb), &temp_dir).unwrap();
    assert_eq!(deb_report.format, PackageFormat::Deb);
    assert!(deb_report.package_path.exists());

    let deb_bytes = fs::read(&deb_report.package_path).unwrap();
    assert!(deb_bytes.len() > 500, "Genuine .deb package must contain control and data tarballs");

    // Deeply unpack ar archive members
    let deb_members = parse_ar_archive(&deb_bytes);
    assert_eq!(
        deb_members.get("debian-binary").map(|v| v.as_slice()),
        Some(b"2.0\n".as_slice()),
        "debian-binary must contain 2.0\\n"
    );
    assert!(deb_members.contains_key("control.tar.gz"), "Must contain control.tar.gz");
    assert!(deb_members.contains_key("data.tar.gz"), "Must contain data.tar.gz");

    // Decompress control.tar.gz and inspect ./control metadata
    let mut control_dec = flate2::read::GzDecoder::new(&deb_members["control.tar.gz"][..]);
    let mut control_tar_bytes = Vec::new();
    control_dec.read_to_end(&mut control_tar_bytes).unwrap();
    let control_files = parse_tar_archive(&control_tar_bytes);
    assert!(
        control_files.contains_key("./control") || control_files.contains_key("control"),
        "control.tar.gz must contain ./control"
    );
    let control_entry = control_files.get("./control").or_else(|| control_files.get("control")).unwrap();
    let control_text = String::from_utf8_lossy(&control_entry.1);
    assert!(control_text.contains("Package: strata-app"));
    assert!(control_text.contains("Architecture: amd64"));
    assert!(control_text.contains("Maintainer: Strata Team"));

    // Decompress data.tar.gz and inspect ./usr/bin/strata-app binary and desktop shortcut
    let mut data_dec = flate2::read::GzDecoder::new(&deb_members["data.tar.gz"][..]);
    let mut data_tar_bytes = Vec::new();
    data_dec.read_to_end(&mut data_tar_bytes).unwrap();
    let data_files = parse_tar_archive(&data_tar_bytes);
    assert!(
        data_files.contains_key("./usr/bin/strata-app") || data_files.contains_key("usr/bin/strata-app"),
        "data.tar.gz must contain application binary"
    );
    let bin_entry = data_files.get("./usr/bin/strata-app").or_else(|| data_files.get("usr/bin/strata-app")).unwrap();
    assert_eq!(bin_entry.0, 0o755, "Binary permissions must be 0755");
    assert_eq!(&bin_entry.1[0..4], b"\x7fELF", "Extracted binary in .deb must be valid ELF");

    assert!(
        data_files.contains_key("./usr/share/applications/strata-app.desktop")
            || data_files.contains_key("usr/share/applications/strata-app.desktop"),
        "data.tar.gz must contain .desktop launcher entry"
    );

    // If host 'ar' is available, verify it recognizes archive
    if let Ok(out) = std::process::Command::new("ar")
        .args(["t", deb_report.package_path.to_str().unwrap()])
        .output()
    {
        if out.status.success() {
            let listing = String::from_utf8_lossy(&out.stdout);
            assert!(listing.contains("debian-binary"));
            assert!(listing.contains("control.tar.gz"));
            assert!(listing.contains("data.tar.gz"));
        }
    }

    // 2. RPM (.rpm)
    let rpm_report = Packager::package(BuildTarget::Desktop, Some(PackageFormat::Rpm), &temp_dir).unwrap();
    assert_eq!(rpm_report.format, PackageFormat::Rpm);
    assert!(rpm_report.package_path.exists());

    let rpm_bytes = fs::read(&rpm_report.package_path).unwrap();
    assert!(rpm_bytes.len() >= 96, "RPM must be at least 96 bytes");

    // Deeply validate 96-byte RPM Lead structure
    assert_eq!(&rpm_bytes[0..4], &[0xED, 0xAB, 0xEE, 0xDB], "RPM magic lead 0xEDAB EEDB");
    assert_eq!(rpm_bytes[4], 3, "RPM major version 3");
    assert_eq!(rpm_bytes[5], 0, "RPM minor version 0");
    assert_eq!(&rpm_bytes[6..8], &[0, 0], "RPM binary package type 0");
    assert_eq!(&rpm_bytes[8..10], &[0, 1], "RPM x86_64 architecture 1");
    let rpm_name = String::from_utf8_lossy(&rpm_bytes[10..76]).trim_matches('\0').to_string();
    assert_eq!(rpm_name, "strata-app", "RPM package name must match in lead");
    assert_eq!(&rpm_bytes[76..78], &[0, 1], "RPM Linux OS number 1");
    assert_eq!(&rpm_bytes[78..80], &[0, 5], "RPM signature type 5 (Header-style)");
    assert_eq!(&rpm_bytes[80..96], &[0u8; 16], "RPM lead reserved 16 zero bytes");

    // Deeply validate Signature Header structure (starts at offset 96)
    assert_eq!(&rpm_bytes[96..100], &[0x8E, 0xAD, 0xE8, 0x01], "Signature header magic 0x8EADE801");
    let sig_index_count = u32::from_be_bytes(rpm_bytes[104..108].try_into().unwrap());
    assert!(sig_index_count >= 1, "RPM signature header must contain index entries");

    // Locate Main Metadata Header
    let main_hdr_rel = rpm_bytes[100..]
        .windows(4)
        .position(|w| w == [0x8E, 0xAD, 0xE8, 0x01])
        .expect("Main metadata header magic 0x8EADE801 must exist");
    let main_hdr_offset = 100 + main_hdr_rel;
    let main_index_count = u32::from_be_bytes(rpm_bytes[main_hdr_offset + 8..main_hdr_offset + 12].try_into().unwrap());
    assert_eq!(main_index_count, 5, "RPM metadata must index name, version, release, summary, description");

    // 3. AppImage (.AppImage)
    let appimage_report = Packager::package(BuildTarget::Desktop, Some(PackageFormat::AppImage), &temp_dir).unwrap();
    assert_eq!(appimage_report.format, PackageFormat::AppImage);
    assert!(appimage_report.package_path.exists());
    let appimage_bytes = fs::read(&appimage_report.package_path).unwrap();

    // Deeply validate 64-bit ELF header
    assert_eq!(&appimage_bytes[0..4], b"\x7fELF", "AppImage must have ELF binary header");
    assert_eq!(appimage_bytes[4], 2, "ELF class 2 (64-bit)");
    assert_eq!(appimage_bytes[5], 1, "ELF data 1 (little-endian)");
    assert_eq!(&appimage_bytes[8..11], b"AI\x02", "AppImage Type 2 magic signature 'AI\\x02'");
    let e_type = u16::from_le_bytes(appimage_bytes[16..18].try_into().unwrap());
    assert_eq!(e_type, 2, "ELF e_type 2 (ET_EXEC)");
    let e_machine = u16::from_le_bytes(appimage_bytes[18..20].try_into().unwrap());
    assert_eq!(e_machine, 62, "ELF e_machine 62 (EM_X86_64)");
    let e_phoff = u64::from_le_bytes(appimage_bytes[32..40].try_into().unwrap());
    assert_eq!(e_phoff, 64, "Program header table immediately follows ELF64 header");
    let e_phnum = u16::from_le_bytes(appimage_bytes[56..58].try_into().unwrap());
    assert!(e_phnum >= 1, "AppImage must contain program headers");

    let apprun = temp_dir.join("dist/packages/strata-app.AppDir/AppRun");
    assert!(apprun.exists());
    let apprun_text = fs::read_to_string(&apprun).unwrap();
    assert!(apprun_text.contains("#!/bin/sh"));
    assert!(apprun_text.contains("exec \"${HERE}/usr/bin/strata-app\""));

    // 4. Arch PKGBUILD
    let arch_report = Packager::package(BuildTarget::Desktop, Some(PackageFormat::PkgBuild), &temp_dir).unwrap();
    assert_eq!(arch_report.format, PackageFormat::PkgBuild);
    assert!(arch_report.package_path.exists());
    let pkgbuild = temp_dir.join("dist/packages/PKGBUILD");
    assert!(pkgbuild.exists());
    let pkgbuild_text = fs::read_to_string(&pkgbuild).unwrap();
    assert!(pkgbuild_text.contains("pkgname=strata-app"));
    assert!(pkgbuild_text.contains("arch=('x86_64')"));

    // 5. Flatpak (.flatpak)
    let flatpak_report = Packager::package(BuildTarget::Desktop, Some(PackageFormat::Flatpak), &temp_dir).unwrap();
    assert_eq!(flatpak_report.format, PackageFormat::Flatpak);
    assert!(flatpak_report.package_path.exists());

    let flatpak_bytes = fs::read(&flatpak_report.package_path).unwrap();
    assert_eq!(&flatpak_bytes[0..2], &[0x1F, 0x8B], "Flatpak must be a valid gzip stream");
    let mut flatpak_dec = flate2::read::GzDecoder::new(&flatpak_bytes[..]);
    let mut flatpak_tar = Vec::new();
    flatpak_dec.read_to_end(&mut flatpak_tar).unwrap();
    let flatpak_files = parse_tar_archive(&flatpak_tar);
    assert!(flatpak_files.contains_key("metadata"), "Flatpak bundle must contain metadata entry");
    let meta_entry = &flatpak_files["metadata"];
    let meta_json = String::from_utf8_lossy(&meta_entry.1);
    assert!(meta_json.contains("dev.strata.strata-app"));
    assert!(meta_json.contains("org.freedesktop.Platform"));
    assert!(flatpak_files.contains_key("files/bin/strata-app"), "Flatpak bundle must contain binary payload");
    let bin_entry = &flatpak_files["files/bin/strata-app"];
    assert_eq!(&bin_entry.1[0..4], b"\x7fELF", "Flatpak executable must be valid ELF binary");

    // 6. Snap (.snap)
    let snap_report = Packager::package(BuildTarget::Desktop, Some(PackageFormat::Snap), &temp_dir).unwrap();
    assert_eq!(snap_report.format, PackageFormat::Snap);
    assert!(snap_report.package_path.exists());
    let snapcraft_yaml = temp_dir.join("dist/packages/snap/snapcraft.yaml");
    assert!(snapcraft_yaml.exists());
    let snapcraft_text = fs::read_to_string(&snapcraft_yaml).unwrap();
    assert!(snapcraft_text.contains("confinement: strict"));

    let snap_bytes = fs::read(&snap_report.package_path).unwrap();
    // Deeply validate SquashFS v4 superblock structure (96 bytes)
    assert_eq!(&snap_bytes[0..4], b"hsqs", "SquashFS magic 'hsqs'");
    let s_inodes = u32::from_le_bytes(snap_bytes[4..8].try_into().unwrap());
    assert_eq!(s_inodes, 1, "SquashFS inode count");
    let block_size = u32::from_le_bytes(snap_bytes[12..16].try_into().unwrap());
    assert_eq!(block_size, 131072, "SquashFS 128KB block size");
    let compression = u16::from_le_bytes(snap_bytes[20..22].try_into().unwrap());
    assert_eq!(compression, 1, "SquashFS gzip compression ID 1");
    let block_log = u16::from_le_bytes(snap_bytes[22..24].try_into().unwrap());
    assert_eq!(block_log, 17, "SquashFS block log 17 (2^17 = 131072)");
    let major = u16::from_le_bytes(snap_bytes[28..30].try_into().unwrap());
    assert_eq!(major, 4, "SquashFS major version 4");
    let bytes_used = u64::from_le_bytes(snap_bytes[40..48].try_into().unwrap()) as usize;
    assert_eq!(bytes_used, snap_bytes.len(), "SquashFS bytes_used matches container size");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
#[allow(clippy::chunks_exact_to_as_chunks)]
fn test_package_windows_distributions() {
    let temp_dir = std::env::temp_dir().join(format!("strata_pkg_win_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    seed_test_binary(&temp_dir, BuildTarget::Desktop, "strata-app");

    // 1. WiX MSI (.msi)
    let msi_report = Packager::package(BuildTarget::Desktop, Some(PackageFormat::Msi), &temp_dir).unwrap();
    assert_eq!(msi_report.format, PackageFormat::Msi);
    assert!(msi_report.package_path.exists());
    let wxs_path = temp_dir.join("dist/packages/Product.wxs");
    assert!(wxs_path.exists());
    let wxs_text = fs::read_to_string(&wxs_path).unwrap();
    assert!(wxs_text.contains("<Wix"));
    assert!(wxs_text.contains("Strata App"));

    let msi_bytes = fs::read(&msi_report.package_path).unwrap();
    assert_eq!(
        &msi_bytes[0..8],
        &[0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1],
        "MSI package must be an authentic Compound File Binary (OLE2) container"
    );
    assert_eq!(msi_bytes.len() % 512, 0, "MSI sector size must be a multiple of 512 bytes");
    assert!(msi_bytes.len() >= 2048, "MSI file must contain header, directory, FAT, and streams");

    // Scan directory entries (sector 0 onwards) for authentic MSI stream names in UTF-16LE
    let num_dir_sectors = u32::from_le_bytes(msi_bytes[44..48].try_into().unwrap()) as usize;
    let dir_bytes = &msi_bytes[512..512 + num_dir_sectors * 512];
    let mut found_summary_info = false;
    let mut found_string_pool = false;
    let mut found_tables = false;
    let mut found_property = false;
    let mut found_cab = false;

    for chunk in dir_bytes.chunks_exact(128) {
        let name_len = u16::from_le_bytes(chunk[64..66].try_into().unwrap()) as usize;
        if name_len >= 2 {
            let u16_chars: Vec<u16> = chunk[..name_len - 2]
                .chunks_exact(2)
                .map(|b| u16::from_le_bytes([b[0], b[1]]))
                .collect();
            let name = String::from_utf16_lossy(&u16_chars);
            if name.contains("SummaryInformation") {
                found_summary_info = true;
            }
            if name == "_StringPool" {
                found_string_pool = true;
            }
            if name == "_Tables" {
                found_tables = true;
            }
            if name == "Property" {
                found_property = true;
            }
            if name == "Product.cab" {
                found_cab = true;
            }
        }
    }
    assert!(found_summary_info, "MSI directory must contain SummaryInformation stream");
    assert!(found_string_pool, "MSI directory must contain _StringPool stream");
    assert!(found_tables, "MSI directory must contain _Tables stream");
    assert!(found_property, "MSI directory must contain Property stream");
    assert!(found_cab, "MSI directory must contain Product.cab stream");

    // Verify embedded cabinet payload exists and has MSCF magic
    let mscf_pos = msi_bytes.windows(4).position(|w| w == b"MSCF");
    assert!(mscf_pos.is_some(), "MSI package must contain an embedded MSCF Microsoft Cabinet");

    // 2. NSIS EXE (.exe)
    let exe_report = Packager::package(BuildTarget::Desktop, Some(PackageFormat::Exe), &temp_dir).unwrap();
    assert_eq!(exe_report.format, PackageFormat::Exe);
    assert!(exe_report.package_path.exists());
    let nsi_path = temp_dir.join("dist/packages/installer.nsi");
    assert!(nsi_path.exists());
    let nsi_text = fs::read_to_string(&nsi_path).unwrap();
    assert!(nsi_text.contains("!define PRODUCT_NAME \"Strata App\""));

    let exe_bytes = fs::read(&exe_report.package_path).unwrap();
    assert_eq!(&exe_bytes[0..2], b"MZ", "Windows installer must begin with DOS MZ header");
    let pe_offset = u32::from_le_bytes(exe_bytes[60..64].try_into().unwrap()) as usize;
    assert_eq!(&exe_bytes[pe_offset..pe_offset + 4], b"PE\0\0", "PE header signature must exist at e_lfanew");
    assert!(exe_bytes.len() >= 2048, "Windows setup executable must be a valid PE32+ image");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_package_macos_distributions() {
    let temp_dir = std::env::temp_dir().join(format!("strata_pkg_mac_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    seed_test_binary(&temp_dir, BuildTarget::MacOs, "strata-app");

    // 1. App Bundle (.app)
    let app_report = Packager::package(BuildTarget::MacOs, Some(PackageFormat::App), &temp_dir).unwrap();
    assert_eq!(app_report.format, PackageFormat::App);
    let plist_path = temp_dir.join("dist/packages/strata-app.app/Contents/Info.plist");
    assert!(plist_path.exists());
    let plist_text = fs::read_to_string(&plist_path).unwrap();
    assert!(plist_text.contains("CFBundleExecutable"));

    let exec_path = temp_dir.join("dist/packages/strata-app.app/Contents/MacOS/strata-app");
    assert!(exec_path.exists(), "Contents/MacOS/<bin> must exist");
    let pkginfo_path = temp_dir.join("dist/packages/strata-app.app/Contents/PkgInfo");
    assert!(pkginfo_path.exists());
    assert_eq!(fs::read_to_string(&pkginfo_path).unwrap(), "APPL????");

    // 2. DMG (.dmg)
    let dmg_report = Packager::package(BuildTarget::MacOs, Some(PackageFormat::Dmg), &temp_dir).unwrap();
    assert_eq!(dmg_report.format, PackageFormat::Dmg);
    assert!(dmg_report.package_path.exists());
    let dmg_bytes = fs::read(&dmg_report.package_path).unwrap();
    assert!(dmg_bytes.len() >= 2048, "DMG disk image must contain partition tables and UDIF trailer");

    // Sector 0: Driver Descriptor Record (DDR)
    assert_eq!(&dmg_bytes[0..2], &[0x45, 0x52], "DDR signature must be 0x4552 ('ER')");

    // Sector 1: Apple Partition Map (APM)
    assert_eq!(&dmg_bytes[512..514], &[0x50, 0x4D], "APM signature must be 0x504D ('PM')");
    let part_name = String::from_utf8_lossy(&dmg_bytes[528..540]);
    assert!(part_name.starts_with("Apple_HFS"), "APM partition name must be Apple_HFS");

    // Sector 2: HFS+ Volume Header (offset 1024)
    assert_eq!(&dmg_bytes[1024..1026], &[0x48, 0x2B], "HFS+ volume header signature must be 0x482B ('H+')");
    let block_size = u32::from_be_bytes(dmg_bytes[1064..1068].try_into().unwrap());
    assert_eq!(block_size, 4096, "HFS+ allocation block size must be 4096 bytes");

    // UDIF XML Plist with BLKX mish table
    let trailer_start = dmg_bytes.len() - 512;
    assert_eq!(&dmg_bytes[trailer_start..trailer_start + 4], b"koly", "DMG must end with 512-byte UDIF koly trailer");
    let xml_offset = u64::from_be_bytes(dmg_bytes[trailer_start + 216..trailer_start + 224].try_into().unwrap()) as usize;
    let xml_len = u64::from_be_bytes(dmg_bytes[trailer_start + 224..trailer_start + 232].try_into().unwrap()) as usize;
    let xml_text = String::from_utf8_lossy(&dmg_bytes[xml_offset..xml_offset + xml_len]);
    assert!(xml_text.contains("<key>blkx</key>"), "DMG resource fork must contain blkx chunk map");
    assert!(xml_text.contains("Driver Descriptor Record"), "DMG plist must reference DDR descriptor");

    // 3. PKG (.pkg)
    let pkg_report = Packager::package(BuildTarget::MacOs, Some(PackageFormat::Pkg), &temp_dir).unwrap();
    assert_eq!(pkg_report.format, PackageFormat::Pkg);
    assert!(pkg_report.package_path.exists());
    let dist_xml = temp_dir.join("dist/packages/Distribution.xml");
    assert!(dist_xml.exists());
    let pkg_bytes = fs::read(&pkg_report.package_path).unwrap();
    assert_eq!(&pkg_bytes[0..4], b"xar!", "macOS PKG installer must be a valid XAR archive");
    assert!(pkg_bytes.len() >= 256, "PKG archive must contain header and table of contents");

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_package_universal_tar_gz() {
    let temp_dir = std::env::temp_dir().join(format!("strata_pkg_tar_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    seed_test_binary(&temp_dir, BuildTarget::Desktop, "strata-app");

    let tar_report = Packager::package(BuildTarget::Desktop, Some(PackageFormat::TarGz), &temp_dir).unwrap();
    assert_eq!(tar_report.format, PackageFormat::TarGz);
    assert!(tar_report.package_path.exists());

    let tar_gz_bytes = fs::read(&tar_report.package_path).unwrap();
    assert_eq!(&tar_gz_bytes[0..2], &[0x1F, 0x8B], "tar.gz must start with gzip magic [0x1F, 0x8B]");

    // Verify gzip archive decompresses into a valid POSIX USTAR tar archive
    let mut decoder = flate2::read::GzDecoder::new(&tar_gz_bytes[..]);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed).expect("GzDecoder must decompress payload");
    assert!(decompressed.len() >= 1024, "Decompressed tar archive must contain tar headers");

    // Deeply parse every tar entry and validate USTAR checksums
    let tar_files = parse_tar_archive(&decompressed);
    assert!(tar_files.contains_key("usr/bin/strata-app"), "Tar archive must contain app binary entry");
    let bin_entry = &tar_files["usr/bin/strata-app"];
    assert_eq!(bin_entry.0, 0o755, "Binary in tar must have 0755 mode");
    assert_eq!(&bin_entry.1[0..4], b"\x7fELF", "Binary in tar must be valid ELF");

    assert!(
        tar_files.contains_key("usr/share/strata-app/strata.json"),
        "Tar archive must contain application manifest"
    );
    let manifest_entry = &tar_files["usr/share/strata-app/strata.json"];
    let manifest_str = String::from_utf8_lossy(&manifest_entry.1);
    let manifest: serde_json::Value = serde_json::from_str(&manifest_str).expect("Valid JSON manifest");
    assert_eq!(manifest["name"], "strata-app");

    // Invoke host 'tar' utility to verify archive compatibility
    if let Ok(out) = std::process::Command::new("tar")
        .args(["-ztvf", tar_report.package_path.to_str().unwrap()])
        .output()
    {
        assert!(out.status.success(), "Host tar tool must parse generated tar.gz with exit code 0");
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_package_universal_zip() {
    let temp_dir = std::env::temp_dir().join(format!("strata_pkg_zip_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    seed_test_binary(&temp_dir, BuildTarget::Desktop, "strata-app");

    let zip_report = Packager::package(BuildTarget::Desktop, Some(PackageFormat::Zip), &temp_dir).unwrap();
    assert_eq!(zip_report.format, PackageFormat::Zip);
    assert!(zip_report.package_path.exists());

    let zip_bytes = fs::read(&zip_report.package_path).unwrap();

    // Deeply parse ZIP central directory, records, and verify CRC32
    let zip_files = parse_zip_archive(&zip_bytes);
    assert!(zip_files.contains_key("strata-app"), "ZIP archive must contain application binary");
    let bin_entry = &zip_files["strata-app"];
    assert_eq!(&bin_entry.1[0..4], b"\x7fELF", "Extracted binary must be valid ELF");

    assert!(zip_files.contains_key("strata.json"), "ZIP archive must contain application manifest");
    let manifest_entry = &zip_files["strata.json"];
    let manifest_str = String::from_utf8_lossy(&manifest_entry.1);
    let manifest: serde_json::Value = serde_json::from_str(&manifest_str).expect("Valid JSON manifest");
    assert_eq!(manifest["name"], "strata-app");

    // Invoke host 'unzip' utility to verify archive test passes
    if let Ok(out) = std::process::Command::new("unzip")
        .args(["-t", zip_report.package_path.to_str().unwrap()])
        .output()
    {
        assert!(out.status.success(), "Host unzip -t must validate ZIP archive with exit code 0");
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_package_mobile_distributions() {
    let temp_dir = std::env::temp_dir().join(format!("strata_pkg_mobile_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    seed_test_binary(&temp_dir, BuildTarget::Android, "strata-app");

    // 1. Android APK (.apk)
    let apk_report = Packager::package(BuildTarget::Android, Some(PackageFormat::Apk), &temp_dir).unwrap();
    assert_eq!(apk_report.format, PackageFormat::Apk);
    assert!(apk_report.package_path.exists());
    let apk_bytes = fs::read(&apk_report.package_path).unwrap();

    // Deeply parse APK ZIP directory and extract files
    let apk_files = parse_zip_archive(&apk_bytes);

    // Verify AndroidManifest.xml is compiled Android Binary XML (AXML)
    assert!(apk_files.contains_key("AndroidManifest.xml"), "APK must contain AndroidManifest.xml");
    let axml_data = &apk_files["AndroidManifest.xml"].1;
    assert_eq!(
        &axml_data[0..4],
        &[0x03, 0x00, 0x08, 0x00],
        "AndroidManifest.xml must be compiled Android Binary XML (RES_XML_TYPE header 0x00080003)"
    );

    // Verify classes.dex is Dalvik Executable
    assert!(apk_files.contains_key("classes.dex"), "APK must contain classes.dex");
    let dex_data = &apk_files["classes.dex"].1;
    assert_eq!(
        &dex_data[0..8],
        b"dex\n035\0",
        "classes.dex must start with Dalvik Executable magic 'dex\\n035\\0'"
    );

    // Verify resources.arsc is compiled resource table
    assert!(apk_files.contains_key("resources.arsc"), "APK must contain resources.arsc");
    let arsc_data = &apk_files["resources.arsc"].1;
    assert_eq!(
        &arsc_data[0..4],
        &[0x02, 0x00, 0x0C, 0x00],
        "resources.arsc must start with RES_TABLE_TYPE header 0x000C0002"
    );

    // Verify lib/arm64-v8a/libstrata-app.so is 64-bit ARM64 ELF
    assert!(apk_files.contains_key("lib/arm64-v8a/libstrata-app.so"), "APK must contain native library");
    let so_data = &apk_files["lib/arm64-v8a/libstrata-app.so"].1;
    assert_eq!(&so_data[0..4], b"\x7fELF", "Native library must be an ELF binary");
    assert_eq!(so_data[4], 2, "Native library must be 64-bit ELF");
    assert_eq!(so_data[18], 183, "Native library machine must be EM_AARCH64 (183)");

    // Verify JAR signatures
    assert!(apk_files.contains_key("META-INF/MANIFEST.MF"));
    assert!(apk_files.contains_key("META-INF/CERT.SF"));
    assert!(apk_files.contains_key("META-INF/CERT.RSA"));

    // Verify APK Signature Scheme v2 Signing Block with magic 'APK Sig Block 42'
    assert!(
        apk_bytes.windows(16).any(|w| w == b"APK Sig Block 42"),
        "APK must contain APK Signature Scheme v2 Signing Block with magic 'APK Sig Block 42'"
    );

    // Validate with host unzip utility
    if let Ok(out) = std::process::Command::new("unzip")
        .args(["-t", apk_report.package_path.to_str().unwrap()])
        .output()
    {
        assert!(out.status.success(), "Host unzip -t must validate APK with exit code 0");
    }

    // 2. Android App Bundle (.aab)
    let aab_report = Packager::package(BuildTarget::Android, Some(PackageFormat::Aab), &temp_dir).unwrap();
    assert_eq!(aab_report.format, PackageFormat::Aab);
    assert!(aab_report.package_path.exists());
    let aab_bytes = fs::read(&aab_report.package_path).unwrap();

    // Deeply parse AAB ZIP container
    let aab_files = parse_zip_archive(&aab_bytes);
    assert!(aab_files.contains_key("AndroidManifest.xml"), "AAB must contain AndroidManifest.xml");
    let aab_axml = &aab_files["AndroidManifest.xml"].1;
    assert_eq!(&aab_axml[0..4], &[0x03, 0x00, 0x08, 0x00], "AAB manifest must be valid binary AXML");

    assert!(aab_files.contains_key("classes.dex"), "AAB must contain classes.dex");
    let aab_dex = &aab_files["classes.dex"].1;
    assert_eq!(&aab_dex[0..8], b"dex\n035\0", "AAB dex must be valid Dalvik bytecode");

    assert!(aab_files.contains_key("resources.arsc"), "AAB must contain resources.arsc");
    assert!(aab_files.contains_key("lib/arm64-v8a/libstrata-app.so"), "AAB must contain native shared library");
    let aab_so = &aab_files["lib/arm64-v8a/libstrata-app.so"].1;
    assert_eq!(&aab_so[0..4], b"\x7fELF");
    assert_eq!(aab_so[18], 183, "AAB native lib must be EM_AARCH64");

    assert!(aab_files.contains_key("META-INF/STRATA.JSON"), "AAB must contain Strata metadata");
    let aab_meta = String::from_utf8_lossy(&aab_files["META-INF/STRATA.JSON"].1);
    assert!(aab_meta.contains("\"format\":\"aab\""), "AAB format tag in metadata");

    // Validate with host unzip utility
    if let Ok(out) = std::process::Command::new("unzip")
        .args(["-t", aab_report.package_path.to_str().unwrap()])
        .output()
    {
        assert!(out.status.success(), "Host unzip -t must validate AAB with exit code 0");
    }

    // 3. iOS IPA (.ipa)
    seed_test_binary(&temp_dir, BuildTarget::Ios, "strata-app");
    let ipa_report = Packager::package(BuildTarget::Ios, Some(PackageFormat::Ipa), &temp_dir).unwrap();
    assert_eq!(ipa_report.format, PackageFormat::Ipa);
    assert!(ipa_report.package_path.exists());
    let ipa_bytes = fs::read(&ipa_report.package_path).unwrap();

    // Deeply parse IPA ZIP container
    let ipa_files = parse_zip_archive(&ipa_bytes);
    assert!(ipa_files.contains_key("Payload/strata-app.app/strata-app"), "IPA must contain application binary");
    let ipa_bin = &ipa_files["Payload/strata-app.app/strata-app"].1;
    assert_eq!(&ipa_bin[0..4], &[0xCF, 0xFA, 0xED, 0xFE], "iOS binary must be 64-bit Mach-O");
    let cputype = u32::from_le_bytes(ipa_bin[4..8].try_into().unwrap());
    assert_eq!(cputype, 0x0100000C, "iOS executable cputype must be CPU_TYPE_ARM64");

    assert!(ipa_files.contains_key("Payload/strata-app.app/Info.plist"), "IPA must contain Info.plist");
    let plist_str = String::from_utf8_lossy(&ipa_files["Payload/strata-app.app/Info.plist"].1);
    assert!(plist_str.contains("CFBundleExecutable"));

    // Validate with host unzip utility
    if let Ok(out) = std::process::Command::new("unzip")
        .args(["-t", ipa_report.package_path.to_str().unwrap()])
        .output()
    {
        assert!(out.status.success(), "Host unzip -t must validate IPA with exit code 0");
    }

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_binary_architecture_validation_and_cross_compilation() {
    use strata_cli::builder::BinaryValidator;

    let targets = [
        BuildTarget::Linux,
        BuildTarget::Android,
        BuildTarget::Windows,
        BuildTarget::MacOs,
        BuildTarget::Ios,
        BuildTarget::WebWasm,
        BuildTarget::WebJs,
    ];

    for &t in &targets {
        let bin = make_test_binary_bytes(t);
        assert!(
            BinaryValidator::validate_target_architecture(t, &bin).is_ok(),
            "Binary for {:?} must be valid",
            t
        );
        assert!(!t.default_target_triple().is_empty());
        assert!(!t.supported_target_triples().is_empty());
    }

    // Verify cross-architecture rejection
    let linux_bin = make_test_binary_bytes(BuildTarget::Linux);
    assert!(BinaryValidator::validate_target_architecture(BuildTarget::Android, &linux_bin).is_err());
    assert!(BinaryValidator::validate_target_architecture(BuildTarget::Windows, &linux_bin).is_err());
    assert!(BinaryValidator::validate_target_architecture(BuildTarget::Ios, &linux_bin).is_err());

    let win_bin = make_test_binary_bytes(BuildTarget::Windows);
    assert!(BinaryValidator::validate_target_architecture(BuildTarget::Linux, &win_bin).is_err());
    assert!(BinaryValidator::validate_target_architecture(BuildTarget::Android, &win_bin).is_err());
}

#[test]
fn test_packager_fails_cleanly_without_binary() {
    let temp_dir = std::env::temp_dir().join(format!("strata_pkg_nobin_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    let res = Packager::package(BuildTarget::Desktop, Some(PackageFormat::Deb), &temp_dir);
    assert!(res.is_err(), "Packaging an empty directory without a binary must fail cleanly");
    let err = res.err().unwrap();
    assert!(err.contains("No valid executable binary found"));

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_packager_incompatible_format_rejection() {
    let temp_dir = std::env::temp_dir().join(format!("strata_pkg_incompat_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();

    // Cannot package Android target as .deb or .msi
    assert!(Packager::package(BuildTarget::Android, Some(PackageFormat::Deb), &temp_dir).is_err());
    assert!(Packager::package(BuildTarget::Android, Some(PackageFormat::Msi), &temp_dir).is_err());
    assert!(Packager::package(BuildTarget::WebWasm, Some(PackageFormat::Exe), &temp_dir).is_err());

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_apple_code_signing_and_notarization_workflow() {
    let temp_dir = std::env::temp_dir().join(format!("strata_pkg_apple_sign_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    seed_test_binary(&temp_dir, BuildTarget::MacOs, "strata-app");

    let options = PackageOptions {
        sign_identity: Some("Developer ID Application: Strata Test (ABCD123456)".to_string()),
        notarize: true,
        keychain_profile: Some("TEST_NOTARY_PROFILE".to_string()),
        ..Default::default()
    };

    let report = Packager::package_with_options(
        BuildTarget::MacOs,
        Some(PackageFormat::Dmg),
        &temp_dir,
        options,
    )
    .unwrap();

    assert_eq!(report.format, PackageFormat::Dmg);
    assert!(report.package_path.exists());

    let signing_report_path = temp_dir.join("dist/packages/signing_report.json");
    assert!(signing_report_path.exists(), "signing_report.json must be emitted");
    assert!(
        report.generated_files.contains(&signing_report_path),
        "signing_report.json must be listed in generated_files"
    );

    let report_content = fs::read_to_string(&signing_report_path).unwrap();
    let signing_rep: SigningReport = serde_json::from_str(&report_content).unwrap();

    assert_eq!(signing_rep.target, "macos");
    assert_eq!(signing_rep.format, "dmg");
    assert_eq!(
        signing_rep.identity,
        Some("Developer ID Application: Strata Test (ABCD123456)".to_string())
    );
    assert!(signing_rep.notarized);
    assert!(signing_rep.hardened_runtime);

    // Verify SHA-256 matches actual file on disk
    let pkg_bytes = fs::read(&report.package_path).unwrap();
    let calculated_sha = strata_cli::packager::compute_sha256(&pkg_bytes);
    let calculated_hex: String = calculated_sha.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(signing_rep.sha256, calculated_hex);

    let _ = fs::remove_dir_all(&temp_dir);
}

#[test]
fn test_windows_authenticode_signing_workflow() {
    let temp_dir = std::env::temp_dir().join(format!("strata_pkg_win_sign_{}", std::process::id()));
    let _ = fs::remove_dir_all(&temp_dir);
    fs::create_dir_all(&temp_dir).unwrap();
    seed_test_binary(&temp_dir, BuildTarget::Windows, "strata-app");

    let options = PackageOptions {
        certificate_thumbprint: Some("0123456789ABCDEF0123456789ABCDEF01234567".to_string()),
        ..Default::default()
    };

    let report = Packager::package_with_options(
        BuildTarget::Windows,
        Some(PackageFormat::Msi),
        &temp_dir,
        options,
    )
    .unwrap();

    assert_eq!(report.format, PackageFormat::Msi);
    assert!(report.package_path.exists());

    let signing_report_path = temp_dir.join("dist/packages/signing_report.json");
    assert!(signing_report_path.exists());
    assert!(report.generated_files.contains(&signing_report_path));

    let report_content = fs::read_to_string(&signing_report_path).unwrap();
    let signing_rep: SigningReport = serde_json::from_str(&report_content).unwrap();

    assert_eq!(signing_rep.target, "windows");
    assert_eq!(signing_rep.format, "msi");
    assert_eq!(
        signing_rep.identity,
        Some("0123456789ABCDEF0123456789ABCDEF01234567".to_string())
    );
    assert_eq!(
        signing_rep.timestamp_server,
        Some("http://timestamp.digicert.com".to_string())
    );
    assert!(!signing_rep.notarized);

    // Verify SHA-256 matches actual file on disk
    let pkg_bytes = fs::read(&report.package_path).unwrap();
    let calculated_sha = strata_cli::packager::compute_sha256(&pkg_bytes);
    let calculated_hex: String = calculated_sha.iter().map(|b| format!("{:02x}", b)).collect();
    assert_eq!(signing_rep.sha256, calculated_hex);

    let _ = fs::remove_dir_all(&temp_dir);
}

