# PK2 Extractor - AI Coding Agent Context Document

## Overview

**Purpose:** Extract files from PK2 archives (encrypted file format used by Silkroad Online game)

**Original Implementation:** C++ with MFC/Win32 (Drew Benton - http://0x33.org)

**Core Components:**
1. Blowfish encryption/decryption
2. PK2 file format parser
3. Multi-threaded file extraction
4. User interface (optional for CLI implementations)

---

## PK2 File Format Specification

### Archive Structure
```
+------------------+
| PK2 Header       |  (256 bytes, plaintext)
+------------------+
| Entry Block 1    |  (128 bytes each, encrypted)
| Entry Block 2    |
| ...              |
+------------------+
| File Data        |  (unencrypted raw bytes)
| ...              |
+------------------+
```

### Header Structure (256 bytes)
```
Offset  Size    Field           Description
------  ----    -----           -----------
0x00    30      signature       "JoyMax File Manager!\n" (magic string)
0x1E    4       version         0x01000002 (required)
0x22    4       validation      0x30dad801 (validation constant)
0x26    218     reserved        Padding/unused bytes
```

### Entry Structure (128 bytes, Blowfish encrypted)
```
Offset  Size    Field           Description
------  ----    -----           -----------
0x00    1       type            0=null/end, 1=folder, 2=file
0x01    81      name            Entry name (null-terminated string)
0x52    8       accessTime      FILETIME - last access
0x5A    8       createTime      FILETIME - creation time
0x62    8       modifyTime      FILETIME - modification time
0x6A    4       positionLow     For files: byte offset in archive
                                For folders: offset to child entries
0x6E    4       positionHigh    High 32-bits (rarely used)
0x72    4       size            File size in bytes (0 for folders)
0x76    4       nextChain       Offset to next sibling entry block
0x7A    6       reserved        Padding
```

### Entry Types
| Value | Type   | Description |
|-------|--------|-------------|
| 0     | NULL   | End of current directory/chain marker |
| 1     | FOLDER | Directory entry |
| 2     | FILE   | File entry |

---

## Blowfish Encryption Details

### Encryption Key
```
Key bytes: { 0x32, 0xCE, 0xDD, 0x7C, 0xBC, 0xA8 }
Key length: 6 bytes
```

### Algorithm Properties
- Block cipher: 64-bit (8 bytes) blocks
- Key size: Variable (up to 448 bits, here 48 bits)
- Rounds: 16 iterations
- Uses: P-array (18 x 32-bit) + 4 S-boxes (256 x 32-bit each)

### Usage in PK2
- Only entry headers (128 bytes) are encrypted
- File content is stored unencrypted at recorded positions
- Each 128-byte entry decrypted as a single operation

### CRITICAL: Byte Order Issue

The original C++ implementation uses **little-endian** byte order for the 32-bit words
in Blowfish block operations. Most modern crypto libraries (like PyCryptodome) use
**big-endian** byte order internally.

**Solution:** Swap byte order within each 4-byte word before and after decryption:

```python
def decrypt_block(cipher, block):
    # Swap little-endian to big-endian before decryption
    swapped = bytes([
        block[3], block[2], block[1], block[0],  # First 32-bit word
        block[7], block[6], block[5], block[4]   # Second 32-bit word
    ])

    # Decrypt
    dec_block = cipher.decrypt(swapped)

    # Swap back to little-endian after decryption
    result = bytes([
        dec_block[3], dec_block[2], dec_block[1], dec_block[0],
        dec_block[7], dec_block[6], dec_block[5], dec_block[4]
    ])
    return result
```

---

## High-Level Workflow

### Phase 1: Initialization
```
1. Initialize Blowfish cipher with key {0x32, 0xCE, 0xDD, 0x7C, 0xBC, 0xA8}
2. Pre-expand P-array and S-boxes with key
3. Allocate entry storage (vector/list for ~100,000 entries)
```

### Phase 2: Open and Validate Archive
```
1. Open PK2 file in binary read mode
2. Read 256-byte header
3. Validate:
   - Signature == "JoyMax File Manager!\n"
   - Version == 0x01000002
4. Position file pointer at offset 256 (first entry block)
```

### Phase 3: Parse Archive Structure (Recursive)
```
1. Read 128-byte encrypted entry
2. Decrypt entry using Blowfish
3. Check entry type:
   - Type 0 (null): End of directory, return to parent
   - Type 1 (folder):
     * Save entry metadata
     * Save current file position
     * Seek to positionLow offset
     * Recursively parse children (level + 1)
     * Restore file position
   - Type 2 (file):
     * Save entry metadata (name, position, size, timestamps)
4. Check nextChain:
   - If non-zero: Seek to nextChain offset, continue parsing
5. Build full paths by tracking directory hierarchy
```

### Phase 4: Search/Filter (Optional)
```
1. Iterate through parsed entries
2. Apply filter criteria:
   - String match on name/path
   - Size range (min/max)
   - Type filter (files/folders)
3. Return filtered result set
```

### Phase 5: Extract Files
```
For each entry to extract:
  If folder:
    1. Create directory structure recursively
  If file:
    1. Seek to entry.position in PK2
    2. Read entry.size bytes
    3. Create output file
    4. Write data to output file
    5. Set file timestamps (create, modify)
    6. Close output file
```

---

## Pseudocode

### Main Structures
```pseudocode
STRUCTURE PK2Header:
    signature: STRING[30]        // "JoyMax File Manager!\n"
    version: UINT32              // 0x01000002
    validation: UINT32           // 0x30dad801
    reserved: BYTE[218]

STRUCTURE PK2Entry:
    type: BYTE                   // 0=null, 1=folder, 2=file
    name: STRING[81]
    accessTime: FILETIME
    createTime: FILETIME
    modifyTime: FILETIME
    positionLow: UINT32
    positionHigh: UINT32
    size: UINT32
    nextChain: UINT32
    reserved: BYTE[6]

STRUCTURE ExtractedEntry:
    type: INT
    name: STRING
    path: STRING                 // Full relative path
    position: UINT32             // Offset in PK2 file
    size: UINT32
    createTime: FILETIME
    modifyTime: FILETIME
    level: INT                   // Directory depth (0 = root)
```

### Blowfish Cipher
```pseudocode
CLASS Blowfish:
    P: ARRAY[18] OF UINT32       // P-array
    S: ARRAY[4][256] OF UINT32   // S-boxes (4 boxes, 256 entries each)

    FUNCTION Initialize(key: BYTE[], keyLength: INT):
        // Initialize P and S with pi digits (standard values)
        P = STANDARD_P_ARRAY
        S = STANDARD_S_BOXES

        // XOR P-array with key (cyclically)
        j = 0
        FOR i = 0 TO 17:
            data = 0
            FOR k = 0 TO 3:
                data = (data << 8) | key[j]
                j = (j + 1) MOD keyLength
            P[i] = P[i] XOR data

        // Encrypt zero block and replace P entries
        left = 0, right = 0
        FOR i = 0 TO 17 STEP 2:
            Encrypt(left, right)
            P[i] = left
            P[i+1] = right

        // Similarly expand S-boxes
        FOR each S-box:
            FOR j = 0 TO 255 STEP 2:
                Encrypt(left, right)
                S[i][j] = left
                S[i][j+1] = right

    FUNCTION F(x: UINT32) -> UINT32:
        a = (x >> 24) & 0xFF
        b = (x >> 16) & 0xFF
        c = (x >> 8) & 0xFF
        d = x & 0xFF
        RETURN ((S[0][a] + S[1][b]) XOR S[2][c]) + S[3][d]

    FUNCTION EncryptBlock(left: UINT32, right: UINT32) -> (UINT32, UINT32):
        FOR round = 0 TO 15:
            left = left XOR P[round]
            right = F(left) XOR right
            SWAP(left, right)
        SWAP(left, right)
        right = right XOR P[16]
        left = left XOR P[17]
        RETURN (left, right)

    FUNCTION DecryptBlock(left: UINT32, right: UINT32) -> (UINT32, UINT32):
        FOR round = 17 DOWN TO 2:
            left = left XOR P[round]
            right = F(left) XOR right
            SWAP(left, right)
        SWAP(left, right)
        right = right XOR P[1]
        left = left XOR P[0]
        RETURN (left, right)

    FUNCTION Decode(input: BYTE[], output: BYTE[], size: INT):
        // Process in 8-byte blocks
        FOR offset = 0 TO size STEP 8:
            left = ReadUInt32BigEndian(input, offset)
            right = ReadUInt32BigEndian(input, offset + 4)
            (left, right) = DecryptBlock(left, right)
            WriteUInt32BigEndian(output, offset, left)
            WriteUInt32BigEndian(output, offset + 4, right)
```

### PK2 Reader
```pseudocode
CLASS PK2Reader:
    file: FILE_HANDLE
    cipher: Blowfish
    entries: LIST<ExtractedEntry>
    currentPath: STRING
    pathStack: STACK<STRING>

    CONSTANT BLOWFISH_KEY = {0x32, 0xCE, 0xDD, 0x7C, 0xBC, 0xA8}
    CONSTANT ENTRY_SIZE = 128
    CONSTANT HEADER_SIZE = 256

    FUNCTION Initialize():
        cipher.Initialize(BLOWFISH_KEY, 6)
        entries = EMPTY_LIST

    FUNCTION Open(filename: STRING) -> BOOL:
        file = OpenFile(filename, READ_BINARY)
        IF file == NULL:
            RETURN FALSE

        // Read and validate header
        header = ReadBytes(file, HEADER_SIZE)

        IF NOT header.signature.StartsWith("JoyMax File Manager!"):
            RETURN FALSE
        IF header.version != 0x01000002:
            RETURN FALSE

        // Begin parsing from offset 256
        RETURN Parse(level: 0)

    FUNCTION Parse(level: INT) -> BOOL:
        LOOP:
            // Read encrypted entry
            encryptedData = ReadBytes(file, ENTRY_SIZE)
            IF encryptedData.length < ENTRY_SIZE:
                RETURN FALSE

            // Decrypt entry
            decryptedData = NEW BYTE[ENTRY_SIZE]
            cipher.Decode(encryptedData, decryptedData, ENTRY_SIZE)

            // Parse entry fields
            entry = ParseEntry(decryptedData)

            SWITCH entry.type:
                CASE 0:  // NULL - end marker
                    RETURN TRUE

                CASE 1:  // FOLDER
                    // Create entry record
                    extracted = NEW ExtractedEntry
                    extracted.type = 1
                    extracted.name = entry.name
                    extracted.path = BuildPath(currentPath, entry.name)
                    extracted.level = level
                    extracted.createTime = entry.createTime
                    extracted.modifyTime = entry.modifyTime
                    entries.Add(extracted)

                    // Save position and recurse
                    savedPosition = GetFilePosition(file)
                    pathStack.Push(currentPath)
                    currentPath = extracted.path

                    SeekFile(file, entry.positionLow)
                    Parse(level + 1)

                    // Restore position
                    currentPath = pathStack.Pop()
                    SeekFile(file, savedPosition)

                CASE 2:  // FILE
                    extracted = NEW ExtractedEntry
                    extracted.type = 2
                    extracted.name = entry.name
                    extracted.path = BuildPath(currentPath, entry.name)
                    extracted.position = entry.positionLow
                    extracted.size = entry.size
                    extracted.level = level
                    extracted.createTime = entry.createTime
                    extracted.modifyTime = entry.modifyTime
                    entries.Add(extracted)

            // Check for chain continuation
            IF entry.nextChain != 0:
                SeekFile(file, entry.nextChain)
            ELSE:
                // Continue reading sequential entries
                // (already at correct position)

    FUNCTION BuildPath(basePath: STRING, name: STRING) -> STRING:
        IF basePath.IsEmpty():
            RETURN name
        RETURN basePath + PATH_SEPARATOR + name

    FUNCTION ExtractAll(outputDir: STRING) -> BOOL:
        FOR entry IN entries:
            ExtractEntry(entry, outputDir)
        RETURN TRUE

    FUNCTION ExtractEntry(entry: ExtractedEntry, outputDir: STRING) -> BOOL:
        fullPath = outputDir + PATH_SEPARATOR + entry.path

        IF entry.type == 1:  // FOLDER
            CreateDirectoryRecursive(fullPath)
            RETURN TRUE

        IF entry.type == 2:  // FILE
            // Ensure parent directory exists
            parentDir = GetParentDirectory(fullPath)
            CreateDirectoryRecursive(parentDir)

            // Read file data from PK2
            SeekFile(file, entry.position)
            data = ReadBytes(file, entry.size)

            // Write to output file
            outFile = CreateFile(fullPath, WRITE_BINARY)
            WriteBytes(outFile, data)
            CloseFile(outFile)

            // Set file timestamps
            SetFileTimestamps(fullPath, entry.createTime, entry.modifyTime)

            RETURN TRUE

        RETURN FALSE

    FUNCTION Search(query: STRING) -> LIST<ExtractedEntry>:
        results = EMPTY_LIST
        queryLower = query.ToLowerCase()

        FOR entry IN entries:
            IF entry.name.ToLowerCase().Contains(queryLower):
                results.Add(entry)
            ELSE IF entry.path.ToLowerCase().Contains(queryLower):
                results.Add(entry)

        RETURN results

    FUNCTION Close():
        CloseFile(file)
        entries.Clear()
```

### Multi-threaded Extraction
```pseudocode
FUNCTION ExtractMultiThreaded(entries: LIST<ExtractedEntry>, outputDir: STRING, threadCount: INT):
    // Divide entries among threads
    batchSize = CEILING(entries.Count / threadCount)
    threads = NEW LIST<THREAD>

    FOR i = 0 TO threadCount - 1:
        startIndex = i * batchSize
        endIndex = MIN((i + 1) * batchSize, entries.Count)
        batch = entries.Slice(startIndex, endIndex)

        thread = CreateThread(ExtractBatch, batch, outputDir)
        threads.Add(thread)

    // Wait for all threads to complete
    WaitForAllThreads(threads)

FUNCTION ExtractBatch(entries: LIST<ExtractedEntry>, outputDir: STRING):
    // Each thread opens its own file handle
    pk2File = OpenFile(pk2Filename, READ_BINARY)

    FOR entry IN entries:
        ExtractSingleEntry(pk2File, entry, outputDir)

    CloseFile(pk2File)
```

---

## Implementation Notes

### Memory Considerations
- Pre-allocate entry list for ~100,000 entries
- Use streaming for large file extraction (don't load entire file to memory)
- Consider memory-mapped files for very large archives

### Performance Optimizations
1. **Buffer I/O**: Use buffered reads/writes (e.g., 64KB buffers)
2. **Multi-threading**: Extract using 4-8 threads for I/O parallelism
3. **Lazy parsing**: Only parse entries as needed (for browse-only mode)

### Error Handling
- Validate header signature and version
- Handle truncated entries gracefully
- Check for circular chain references (prevent infinite loops)
- Verify file positions don't exceed archive size

### Cross-Platform Considerations
- Path separators: Use platform-specific (`/` vs `\`)
- Endianness: PK2 uses little-endian for integers
- File timestamps: Convert Windows FILETIME to platform format
- Character encoding: Entry names use ASCII/ANSI encoding

---

## Test Data

Sample PK2 archives available in `/data/`:
| File | Size | Description |
|------|------|-------------|
| Data.pk2 | 2.8 GB | Main game data |
| Map.pk2 | 1.1 GB | Map/level files |
| Media.pk2 | 990 MB | Textures/models |
| Music.pk2 | 68 MB | Audio tracks |
| Particles.pk2 | 124 MB | Visual effects |

---

## Key Constants Reference

```
// Header validation
SIGNATURE = "JoyMax File Manager!\n"
VERSION = 0x01000002
VALIDATION = 0x30DAD801

// Sizes
HEADER_SIZE = 256
ENTRY_SIZE = 128

// Entry types
TYPE_NULL = 0
TYPE_FOLDER = 1
TYPE_FILE = 2

// Blowfish key
BLOWFISH_KEY = {0x32, 0xCE, 0xDD, 0x7C, 0xBC, 0xA8}
```

---

## File Dependencies for Reference Implementation

```
common/
  BlowFish.cpp      - Blowfish cipher implementation
  BlowFish.h        - Cipher class declaration
  pk2Reader.cpp     - PK2 parsing and extraction
  pk2Reader.h       - Reader class declaration

Pk2Extractor/
  Pk2Extractor.cpp  - Application entry point
  Pk2ExtractorDlg.cpp - UI logic (MFC-specific)
```

---

## API Summary

### Core Functions to Implement

```
// Initialization
Blowfish.Initialize(key, keyLength)
PK2Reader.Initialize()

// Archive Operations
PK2Reader.Open(filename) -> bool
PK2Reader.Close()
PK2Reader.GetEntries() -> List<Entry>

// Extraction
PK2Reader.ExtractAll(outputDir) -> bool
PK2Reader.ExtractEntry(entry, outputDir) -> bool
PK2Reader.ExtractMultiple(entries, outputDir) -> bool

// Search
PK2Reader.Search(query) -> List<Entry>
PK2Reader.SearchBySize(minSize, maxSize) -> List<Entry>
PK2Reader.SearchByType(type) -> List<Entry>

// Utility
PK2Reader.GenerateListing(outputFile) -> bool
PK2Reader.GetEntryCount() -> int
```

---

## Quick Start Guide for AI Agent

1. **Implement Blowfish cipher first** - This is the foundation for decryption
2. **Implement header validation** - Simple binary read and comparison
3. **Implement entry parsing** - Read, decrypt, extract fields
4. **Implement recursive tree traversal** - Handle folders and chains
5. **Implement file extraction** - Seek, read, write operations
6. **Add search/filter** - String matching on parsed entries
7. **Add multi-threading** - Parallel extraction for performance
8. **Add UI** (optional) - Tree view, search box, progress display

---

## Verification Checklist

- [x] Header signature matches exactly
- [x] Version equals 0x01000002
- [x] All 128-byte entries decrypt correctly
- [x] Folders recurse to correct positions
- [x] Chain links followed correctly
- [x] Extracted file sizes match entry.size
- [ ] Extracted file timestamps preserved
- [x] No memory leaks after parsing
- [x] All test archives parse without errors

---

## Python Implementation (Completed)

A working Python implementation is available in `Pk2Extractor/python/`:

### Files
```
python/
├── pk2_extractor.py    # Main application (~740 lines)
├── requirements.txt    # Dependencies (pycryptodome, rich)
└── README.md           # Usage documentation
```

### Key Implementation Details

#### 1. Blowfish Byte Order Fix
```python
from Crypto.Cipher import Blowfish

# PyCryptodome uses big-endian, PK2 uses little-endian
# Swap bytes within each 4-byte word before/after decryption
def decrypt_entry(cipher, data):
    decrypted = bytearray()
    for i in range(0, len(data), 8):
        block = data[i:i+8]
        # Swap to big-endian
        swapped = bytes([block[3], block[2], block[1], block[0],
                        block[7], block[6], block[5], block[4]])
        dec = cipher.decrypt(swapped)
        # Swap back to little-endian
        result = bytes([dec[3], dec[2], dec[1], dec[0],
                       dec[7], dec[6], dec[5], dec[4]])
        decrypted.extend(result)
    return bytes(decrypted)
```

#### 2. Iterative Parsing (Avoid Recursion Limit)
```python
def parse(self, parent):
    # Use stack instead of recursion
    stack = [(parent, file_position, return_position)]

    while stack:
        current_parent, pos, return_pos = stack.pop()
        # ... parse entry ...

        # Push next sibling
        stack.append((current_parent, next_pos, return_pos))

        # If folder, push children
        if entry.is_folder():
            stack.append((entry, entry.position, next_pos))
```

#### 3. Loop Detection
```python
visited_positions = set()

# Before parsing at position
if position in visited_positions:
    continue  # Skip - already visited
visited_positions.add(position)
```

#### 4. Filter Special Entries
```python
# Skip . and .. directory entries
if entry.name in ('.', '..'):
    continue
```

### Test Results (Media.pk2 - 990 MB)

| Metric | Value |
|--------|-------|
| Total entries | 30,764 |
| Files | 30,591 |
| Folders | 168 |
| Parsing time | ~2 seconds |
| Extraction | Working |

### Usage

```bash
# Setup
conda create -n pk2extractor python=3.12 -y
conda activate pk2extractor
pip install -r requirements.txt

# Interactive GUI
python pk2_extractor.py path/to/file.pk2

# Command-line extraction
python pk2_extractor.py file.pk2 -e ./output

# List contents
python pk2_extractor.py file.pk2 -l
```
