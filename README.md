# eXpurg: A Small Professional File Eraser
![Logo](logo.png)

eXpurg is a lightweight, professional-grade file erasure utility designed for security-conscious environments.  
It securely overwrites and deletes files to reduce the chance of forensic recovery.

## Features
- Multi-pass overwrite with cryptographically secure random data
- Detection of SSD vs HDD and filesystem type
- Cleans extended attributes and ACLs (Linux)
- Handles immutable/append-only flags (Linux)
- Cross-platform design (Linux/Windows)
- MIT licensed, fully open-source

## Build
On Linux:
```bash
make
```

This will produce the binary `expurg-auditor`.

## Usage
```bash
./expurg-auditor [options] <file>

Options:
  -h, --help        Show help
  -v, --verbose     Verbose output
  -q, --quiet       Quiet mode
  -p, --passes N    Number of overwrite passes (default: 20)
  -s, --strict      Strict mode (abort on SSD/COW/NTFS)
```

## Download

[![Download eXpurg](https://img.shields.io/badge/Download-eXpurg-blue?style=for-the-badge&logo=github)](https://github.com/victormeloasm/eXpurg/releases/download/eraser/eXpurg.zip)


## License
MIT License © 2025 Víctor Duarte Melo <victormeloasm@gmail.com>
