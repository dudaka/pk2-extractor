# PK2 Extractor (Python)

A Python-based tool for extracting files from PK2 archives (Silkroad Online game format).

## Features

- Interactive console GUI with folder navigation
- Browse archive contents with tree view
- Extract individual files or entire folders
- **Preserves original folder structure** when extracting
- Search files by name/path
- **Filter & extract by pattern** (extension, glob, regex, substring)
- Progress display during extraction
- Command-line extraction mode with pattern filtering
- Iterative parsing (no recursion depth issues)
- Loop detection to prevent infinite parsing

## Requirements

- Python 3.8+ (tested with Python 3.12)
- pycryptodome (Blowfish decryption)
- rich (Console UI)

## Installation

### Using conda (recommended)

```bash
# Create environment
conda create -n pk2extractor python=3.12 -y
conda activate pk2extractor

# Install dependencies
cd Pk2Extractor/python
pip install -r requirements.txt
```

### Using pip only

```bash
cd Pk2Extractor/python
pip install -r requirements.txt
```

## Usage

### Interactive Mode (Console GUI)

```bash
python pk2_extractor.py
# or
python pk2_extractor.py path/to/file.pk2
```

### Commands in Interactive Mode

| Command | Description |
|---------|-------------|
| `<number>` | Navigate to folder or select file |
| `0` | Go to parent folder |
| `e <num>` | Extract file/folder at index |
| `ea` | Extract all contents of current folder |
| `t` | Show tree view of current folder |
| `s <query>` | Search for files matching query |
| `f` | **Filter & extract by pattern** (extension, glob, regex, substring) |
| `q` | Quit |

### Filter & Extract (f command)

The `f` command provides an interactive way to filter and extract files:

```
Filter Options:
  1. Extension filter (e.g., .txt .ddj .dds)
  2. Substring match (e.g., icon, config)
  3. Glob pattern (e.g., *.txt, icon_*.ddj)
  4. Regex pattern (e.g., .*config.*\.txt$)

Extensions (space-separated): .txt .ddj
Contains substring:
Glob pattern:
Regex pattern:
Case-insensitive? [Y/n]: y

Found 2354 matching files
...
Action [extract/list/cancel]: extract
Output directory [./extracted]:
```

### Command-Line Mode

**Extract entire archive:**
```bash
python pk2_extractor.py file.pk2 -e ./output_directory
```

**Extract with pattern filters:**
```bash
# By file extension
python pk2_extractor.py file.pk2 -e ./output --ext .txt .ddj

# By substring in path
python pk2_extractor.py file.pk2 -e ./output --contains config

# By glob pattern
python pk2_extractor.py file.pk2 -e ./output --glob "icon_*.ddj"

# By regex pattern
python pk2_extractor.py file.pk2 -e ./output -p ".*config.*\.txt$"

# Case-insensitive matching
python pk2_extractor.py file.pk2 -e ./output --contains CONFIG -i
```

**List archive contents:**
```bash
python pk2_extractor.py file.pk2 -l

# List with filter
python pk2_extractor.py file.pk2 -l --ext .txt
python pk2_extractor.py file.pk2 -l --contains config
```

### Command-Line Options

| Option | Description |
|--------|-------------|
| `-e`, `--extract` | Output directory for extraction |
| `-l`, `--list` | List contents only (no extraction) |
| `-p`, `--pattern` | Regex pattern to match file paths |
| `--ext` | File extensions (e.g., `.txt .ddj`) |
| `--contains` | Substring to match in file path |
| `--glob` | Glob pattern (e.g., `*.txt`, `icon_*`) |
| `-i`, `--ignore-case` | Case-insensitive matching |

## Test Results

Tested with Media.pk2 (~990 MB):

| Metric | Value |
|--------|-------|
| Total entries | 30,764 |
| Files | 30,591 |
| Folders | 168 |
| Parsing time | ~2 seconds |

## Screenshots

```
+----------------------------------------------------------+
|                     PK2 Extractor                        |
|   A Python tool for extracting Silkroad Online PK2       |
+----------------------------------------------------------+

Current path: /

+------+--------------------------------+----------+------------+
| #    | Name                           | Type     | Size       |
+------+--------------------------------+----------+------------+
| 0    | ..                             | <UP>     |            |
| 1    | acobject                       | <DIR>    | <DIR>      |
| 2    | config                         | <DIR>    | <DIR>      |
| 3    | Effect                         | <DIR>    | <DIR>      |
| 4    | Fonts                          | <DIR>    | <DIR>      |
| 5    | icon                           | <DIR>    | <DIR>      |
| 6    | interface                      | <DIR>    | <DIR>      |
+------+--------------------------------+----------+------------+

Files: 30591 | Folders: 168

Commands:
  <number>  - Navigate to folder / Select file
  0         - Go to parent folder
  e <num>   - Extract file/folder
  ea        - Extract all
  t         - Show tree view
  s <query> - Search files
  q         - Quit

>
```

## Folder Structure Preservation

When extracting files, the original folder structure from the PK2 archive is preserved:

```
# Example: Navigate to server_dep/silkroad/textdata/ and extract a file
# The file will be extracted with its full path:

./extracted/
└── server_dep/
    └── silkroad/
        └── textdata/
            └── worldmapguidedata.txt   ✓ Full path preserved
```

This applies to all extraction methods:
- Single file extraction (`e <num>`)
- Folder extraction (`e <num>` on a folder)
- Extract all (`ea`)
- Filter & extract (`f`)
- Command-line extraction (`-e`)

## Technical Details

### Blowfish Decryption

- Uses Blowfish cipher (ECB mode) for decrypting entry headers
- **Important**: PyCryptodome uses big-endian byte order, but PK2 files use little-endian
- Byte swapping is performed on each 4-byte word before and after decryption
- Encryption key: `0x32, 0xCE, 0xDD, 0x7C, 0xBC, 0xA8`

### PK2 Format

- Header: 256 bytes (plaintext)
- Entry: 128 bytes (Blowfish encrypted)
- File data: Stored unencrypted at recorded positions
- Special entries `.` and `..` are automatically filtered out

### Parsing Algorithm

- Uses iterative stack-based approach (avoids Python recursion limit)
- Tracks visited positions to prevent infinite loops
- Safety limit of 500,000 entries maximum

## License

This tool is provided for educational and personal use.
