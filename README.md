<div align="center"><img src="https://raw.githubusercontent.com/Falkrian/MercuryKit/main/assets/mercurykit-banner.png" alt="MercuryKit" width="900"></div>

# MercuryKit

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](https://opensource.org/licenses/MIT)
[![PyPI](https://img.shields.io/pypi/v/mercurykit?style=flat&label=PyPI&color=red)](https://pypi.org/project/mercurykit/)
[![Twitter](https://img.shields.io/twitter/follow/FalkrianTTV?label=%40FalkrianTTV)](https://twitter.com/FalkrianTTV)

[**Overview**](https://github.com/Falkrian/MercuryKit#overview)
| [**Features**](https://github.com/Falkrian/MercuryKit/#features)
| [**Supported Games**](https://github.com/Falkrian/MercuryKit/#supported-games)
| [**Installation**](https://github.com/Falkrian/MercuryKit/#installation)
| [**Quick Start**](https://github.com/Falkrian/MercuryKit#quick-start)
| [**CLI Reference**](https://github.com/Falkrian/MercuryKit/#cli-reference)

## Overview

MercuryKit is a Python package and command line toolkit for working with MercurySteam archive files. It can scan archives, unpack their contents safely, and repack edited directory trees back into archive form for supported game layouts.

## Features

- Scan individual files or whole directories for supported MercurySteam archives.
- Recursively scan directory trees and print verbose archive details when needed.
- Print scan-generated repack guidance by default, including the required options recovered from each archive such as `layout`, `archive_version`, `file_chunk_size`, and safely inferred `trailing_padding`.
- Unpack archives with path safety checks to avoid writing outside the destination directory.
- Repack extracted folders back into supported archive versions.
- Preserve useful archive metadata, including encrypted picture archive table metadata.
- Support raw, zlib-compressed, LZ4-block-compressed, AES-encrypted table, and encrypted picture archive layouts.
- Show progress automatically on interactive terminals, with switches to force or suppress it.
- Use MercuryKit from Python through the public `mercurykit` package.

## Supported Games

| Game | Support | Support Comment |
| --- | --- | --- |
| Scrapland Remastered | Full | Supports raw `.packed` archives using BFPK version `0`, including scan, unpack, and directory-based repack with `cp1252` path encoding. |
| Castlevania: Lords of Shadow - Ultimate Edition | Full | Supports Steam `.dat` archives using AES-256-CBC encrypted file tables, including raw `0x2` and zlib-record `0x3` variants. |
| Castlevania: Lords of Shadow 2 | Full | Supports archive versions `0x100`, `0x101`, and `0x102`, including raw, zlib, and chunked zlib variants. |
| Castlevania Lords of Shadow - Mirror of Fate HD | Full | Supports `.pack` archives, including scan, unpack, directory-based repack, computed header fields, and automatic `system/files.toc` updates. |
| Blades of Fire | Full* | Supports archive versions `0x100`, `0x102`, `0x300`, and encrypted `Pics.packed` archives using `0x901`. JPG entries are preserved as packed payloads until the viewer-ready restoration transform is implemented. |
| Spacelords | Full | Supports archive versions `0x500`, `0x502`, and encrypted `Pics.packed` archives using `0xD01`, including LZ4-block variants. |

Blades of Fire `0x901` JPG entries are currently extracted as their original packed payloads. They are preserved for archive round trips, but the viewer-ready JPG restoration transform is still being researched.

## Installation

MercuryKit requires Python 3.11 or newer.

Install the latest release from [MercuryKit on PyPI](https://pypi.org/project/mercurykit/):

```powershell
python -m pip install mercurykit
```

Install optional LZ4 support from PyPI when working with archive versions that use LZ4-block compression:

```powershell
python -m pip install "mercurykit[lz4]"
```

For local development or direct use from this checkout:

```powershell
python -m pip install -e .
```

Local editable installs can include optional extras:

```powershell
python -m pip install -e ".[lz4]"
```

## Quick Start

Start with `scan` for the archive you want to edit. MercuryKit prints a `Repack:` block by default with the command and options for that exact archive. Copy that command, replace `<SOURCE_DIR>` with your unpacked folder, and keep any recovered values such as `file_chunk_size` or `trailing_padding`.

### Scrapland Remastered

Scan:

```powershell
mercurykit scan "D:\Steam\steamapps\common\Scrapland\data.packed"
```

Unpack:

```powershell
mercurykit unpack "D:\Steam\steamapps\common\Scrapland\data.packed" --dest ".\Output\scrapland-data"
```

Repack:

```powershell
mercurykit repack ".\Output\scrapland-data" --output ".\data.repacked.packed" --option layout=scrapland
```

Scrapland `.packed` archives are raw containers. MercuryKit recalculates table offsets during repack and writes paths using Windows-compatible `cp1252` encoding. `archive_version=0` may appear in scan notes as an optional validation value.

### Castlevania: Lords of Shadow - Ultimate Edition

Scan:

```powershell
mercurykit scan "D:\Steam\steamapps\common\CastlevaniaLoS\Data00.dat"
```

Unpack:

```powershell
mercurykit unpack "D:\Steam\steamapps\common\CastlevaniaLoS\Data00.dat" --dest ".\Output\losue-data00"
```

Repack a zlib-record `.dat` archive:

```powershell
mercurykit repack ".\Output\losue-data00" --output ".\Data00.repacked.dat" --option layout=lords_of_shadow_ultimate --option archive_version=0x3
```

Repack a raw `.dat` archive:

```powershell
mercurykit repack ".\Output\losue-data03" --output ".\Data03.repacked.dat" --option layout=lords_of_shadow_ultimate --option archive_version=0x2
```

`compression_level` may be added for `0x3` zlib repacks, but MercuryKit cannot recover the original compression level from a scanned archive.

### Castlevania: Lords of Shadow 2

Scan:

```powershell
mercurykit scan "D:\Steam\steamapps\common\Castlevania Lords of Shadow 2\English.packed"
```

Unpack:

```powershell
mercurykit unpack "D:\Steam\steamapps\common\Castlevania Lords of Shadow 2\English.packed" --dest ".\Output\los2-english"
```

Repack:

```powershell
mercurykit repack ".\Output\los2-english" --output ".\English.repacked.packed" --option archive_version=0x102 --option file_chunk_size=0x40000 --option trailing_padding=0x8000
```

Use the values printed by `scan` for the specific archive you are rebuilding. For zlib-based versions, `compression_level` is optional and is not shown as a recovered value.

### Castlevania Lords of Shadow - Mirror of Fate HD

Scan:

```powershell
mercurykit scan "D:\Steam\steamapps\common\Castlevania Lords of Shadow - Mirror of Fate HD\data.pack"
```

Unpack:

```powershell
mercurykit unpack "D:\Steam\steamapps\common\Castlevania Lords of Shadow - Mirror of Fate HD\data.pack" --dest ".\Output\mofh-data"
```

Repack:

```powershell
mercurykit repack ".\Output\mofh-data" --output ".\data.repacked.pack"
```

Mirror of Fate HD `.pack` output automatically uses the Mirror of Fate HD repacker when no BFPK `layout` or `archive_version` option is supplied. If `system/files.toc` is present, MercuryKit updates its path-hash and file-size records in the repacked archive.
The `pack_size` value shown by `scan` is optional validation only; normal repacks do not require it.

### Blades of Fire

Scan:

```powershell
mercurykit scan "D:\Steam\steamapps\common\Blades of Fire\Data00.packed"
```

Unpack:

```powershell
mercurykit unpack "D:\Steam\steamapps\common\Blades of Fire\Data00.packed" --dest ".\Output\blades-data" --overwrite
```

Repack:

```powershell
mercurykit repack ".\Output\blades-data" --output ".\Data00.repacked.packed" --option layout=blades_of_fire --option archive_version=0x102 --option file_chunk_size=0x40000 --option trailing_padding=0x8000
```

Repack encrypted picture archives with the picture layout version:

```powershell
mercurykit repack ".\Output\blades-pics" --output ".\Pics.repacked.packed" --option layout=blades_of_fire --option archive_version=0x901
```

Encrypted picture archives do not need a `trailing_padding` option in the scan-generated command.

### Spacelords

Scan:

```powershell
mercurykit scan "D:\Steam\steamapps\common\Spacelords\Data00.packed"
```

Unpack:

```powershell
mercurykit unpack "D:\Steam\steamapps\common\Spacelords\Data00.packed" --dest ".\Output\spacelords-data"
```

Repack:

```powershell
mercurykit repack ".\Output\spacelords-data" --output ".\Data00.repacked.packed" --option layout=spacelords --option archive_version=0x502 --option file_chunk_size=0x40000 --option trailing_padding=0x10000
```

Repack encrypted picture archives with the picture layout version:

```powershell
mercurykit repack ".\Output\spacelords-pics" --output ".\Pics.repacked.packed" --option layout=spacelords --option archive_version=0xd01
```

### Directory Scans

Scan a folder recursively and print detailed matches:

```powershell
mercurykit scan "D:\Steam\steamapps\common" --recursive --verbose
```

## CLI Reference

### `mercurykit scan`

```text
mercurykit scan PATH... [--recursive] [--verbose]
```

Scans files or directories for all supported archive types. Default scan output includes the file path, format, confidence, entry count, and a `Repack:` command with the recovered options MercuryKit needs to rebuild the same archive family.

| Switch | Description |
| --- | --- |
| `PATH...` | One or more files or directories to scan. |
| `-r`, `--recursive` | Recursively scan directories. |
| `--verbose` | Print additional archive details, including match reasons and entry listings. |

Empty files are skipped. A scan of unsupported files reports that no compatible archive was found.
Use the scan-generated repack guidance as the safest starting point for repacking; replace `<SOURCE_DIR>` with the folder you unpacked or edited.

### `mercurykit unpack`

```text
mercurykit unpack FILE... [--dest PATH] [--overwrite] [--progress | --no-progress]
```

Extracts one or more supported archives.

| Switch | Description |
| --- | --- |
| `FILE...` | One or more archive files to unpack. |
| `--dest PATH` | Destination directory for extracted files. |
| `--overwrite` | Replace existing files in the destination. |
| `--progress` | Show progress even when stderr is not interactive. |
| `--no-progress` | Suppress progress output. |

When `--dest` is omitted, MercuryKit uses the command's default extraction behavior for the selected input.

### `mercurykit repack`

```text
mercurykit repack SOURCE_DIR --output OUTPUT [--option KEY=VALUE]... [--progress | --no-progress]
```

Builds an archive from a directory tree.

| Switch | Description |
| --- | --- |
| `SOURCE_DIR` | Directory containing the files to pack. |
| `--output OUTPUT` | Required output archive path. |
| `--option KEY=VALUE` | Repack option. May be repeated. |
| `--progress` | Show progress even when stderr is not interactive. |
| `--no-progress` | Suppress progress output. |

`--option` values accept strings, decimal integers, hexadecimal integers such as `0x901`, and booleans.

Run `mercurykit scan` on the original archive before repacking. The printed `Repack:` command includes required values such as `layout`, `archive_version`, `file_chunk_size`, and safely recovered `trailing_padding` when those values apply.

Mirror of Fate HD repacks are selected automatically when `--output` ends in `.pack` and no BFPK `layout` or `archive_version` option is supplied. Scrapland Remastered `.packed` repacks use `layout=scrapland`. Castlevania: Lords of Shadow - Ultimate Edition `.dat` repacks use `layout=lords_of_shadow_ultimate` with `archive_version=0x2` or `archive_version=0x3`. Other BFPK repacks use the options below.

## Repack Options

| Option | Description |
| --- | --- |
| `archive_version` | Required for most BFPK repacks, or optional validation for Scrapland. Examples include `0`, `0x2`, `0x3`, `0x100`, `0x102`, `0x500`, `0x502`, `0x901`, and `0xd01`. |
| `layout` | Archive layout. Supported values include `scrapland`, `legacy`, `lords_of_shadow_ultimate`, `blades_of_fire`, and `spacelords`. Defaults to `legacy`. |
| `file_chunk_size` | Positive chunk size used by chunked compressed archive versions. |
| `trailing_padding` | Non-negative number of padding bytes to append after archive data. Scan output includes this only when the value can be safely inferred. |
| `compression_level` | Optional zlib compression level for zlib-based repacks. Defaults to Python's zlib default and cannot be recovered from an existing archive. |
| `pack_size` | Mirror of Fate HD `.pack` payload-area size validation value. MercuryKit computes this during repack and fails if a supplied value does not match. |

Encrypted picture archive repacks preserve `opaque_hash` metadata for unchanged files when manifest metadata is available. New or changed entries receive a deterministic value; MercuryKit does not validate that field as a CRC.

Mirror of Fate HD repacks compute the `.pack` header fields automatically. The optional `pack_size` value is only a validation check; it is not required for normal repacks.

Castlevania: Lords of Shadow - Ultimate Edition `.dat` archives use AES-256-CBC encrypted file tables. MercuryKit decrypts those tables for scanning and unpacking, and writes new encrypted tables during repack.

Scrapland Remastered `.packed` repacks do not use compression, trailing padding, or sidecar metadata. Use `layout=scrapland`; `archive_version=0` may be supplied as a validation check.
