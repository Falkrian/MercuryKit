<div align="center"><img src="assets/mercurykit-banner.png" alt="MercuryKit" width="900"></div>

# MercuryKit

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](https://opensource.org/licenses/MIT)
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
- Unpack archives with path safety checks to avoid writing outside the destination directory.
- Repack extracted folders back into supported archive versions.
- Preserve useful archive metadata, including encrypted picture archive table metadata.
- Support raw, zlib-compressed, LZ4-block-compressed, and encrypted picture archive layouts.
- Show progress automatically on interactive terminals, with switches to force or suppress it.
- Use MercuryKit from Python through the public `mercurykit` package.

## Supported Games

| Game | Support | Support Comment |
| --- | --- | --- |
| Castlevania: Lords of Shadow 2 | Full | Supports archive versions `0x100`, `0x101`, and `0x102`, including raw, zlib, and chunked zlib variants. |
| Blades of Fire | Full* | Supports archive versions `0x100`, `0x102`, `0x300`, and encrypted `Pics.packed` archives using `0x901`. JPG entries are preserved as packed payloads until the viewer-ready restoration transform is implemented. |
| Spacelords | Full | Supports archive versions `0x500`, `0x502`, and encrypted `Pics.packed` archives using `0xD01`, including LZ4-block variants. |

Blades of Fire `0x901` JPG entries are currently extracted as their original packed payloads. They are preserved for archive round trips, but the viewer-ready JPG restoration transform is still being researched.

## Installation

MercuryKit requires Python 3.11 or newer.

For local development or direct use from this checkout:

```powershell
python -m pip install -e .
```

Install optional LZ4 support when working with archive versions that use LZ4-block compression:

```powershell
python -m pip install -e ".[lz4]"
```

## Quick Start

Scan a single archive:

```powershell
mercurykit scan "D:\Steam\steamapps\common\Castlevania Lords of Shadow 2\English.packed"
```

Scan a folder recursively and print detailed matches:

```powershell
mercurykit scan "D:\Steam\steamapps\common\Castlevania Lords of Shadow 2" --recursive --verbose
```

Unpack an archive:

```powershell
mercurykit unpack "D:\Steam\steamapps\common\Spacelords\Music.packed" --dest ".\Output"
```

Unpack and overwrite existing files:

```powershell
mercurykit unpack "D:\Steam\steamapps\common\Project Iron\Data00.packed" --dest ".\Output" --overwrite
```

Repack a chunked archive with explicit chunk and compression settings:

```powershell
mercurykit repack ".\Output" --output ".\Data.repacked" --option archive_version=0x102 --option file_chunk_size=262144 --option compression_level=6
```

## CLI Reference

### `mercurykit scan`

```text
mercurykit scan PATH... [--recursive] [--verbose]
```

Scans files or directories for supported archives.

| Switch | Description |
| --- | --- |
| `PATH...` | One or more files or directories to scan. |
| `-r`, `--recursive` | Recursively scan directories. |
| `--verbose` | Print additional archive details, including match reasons and manifest summaries. |

Empty files are skipped. A scan of unsupported files reports that no compatible archive was found.

### `mercurykit unpack`

```text
mercurykit unpack FILE... [--dest PATH] [--overwrite] [--progress | --no-progress]
```

Extracts one or more archives.

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

## Repack Options

| Option | Description |
| --- | --- |
| `archive_version` | Required archive version, such as `0x100`, `0x102`, `0x500`, `0x502`, `0x901`, or `0xd01`. |
| `layout` | Archive layout. Supported values include `legacy`, `blades_of_fire`, and `spacelords`. Defaults to `legacy`. |
| `file_chunk_size` | Positive chunk size used by chunked compressed archive versions. |
| `trailing_padding` | Non-negative number of padding bytes to append after archive data. |
| `compression_level` | zlib compression level for zlib-based repacks. Defaults to Python's zlib default. |

Encrypted picture archive repacks preserve `opaque_hash` metadata for unchanged files when manifest metadata is available. New or changed entries receive a deterministic value; MercuryKit does not validate that field as a CRC.
