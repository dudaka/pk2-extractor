#!/usr/bin/env python3
"""
PK2 Extractor - A Python tool to extract files from PK2 archives (Silkroad Online)
Uses pycryptodome for Blowfish decryption and rich for console UI
"""

import os
import struct
import sys
from dataclasses import dataclass, field
from typing import Optional

from Crypto.Cipher import Blowfish
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.tree import Tree
from rich.prompt import Prompt, IntPrompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich import box


# ============================================================================
# Constants
# ============================================================================

PK2_SIGNATURE = b"JoyMax File Manager!\n"
PK2_VERSION = 0x01000002
PK2_HEADER_SIZE = 256
PK2_ENTRY_SIZE = 128
PK2_BLOWFISH_KEY = bytes([0x32, 0xCE, 0xDD, 0x7C, 0xBC, 0xA8])

# Entry types
ENTRY_NULL = 0
ENTRY_FOLDER = 1
ENTRY_FILE = 2


# ============================================================================
# Data Structures
# ============================================================================

@dataclass
class PK2Header:
    """PK2 archive header structure (256 bytes)"""
    signature: bytes
    version: int
    encrypted: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "PK2Header":
        if len(data) < PK2_HEADER_SIZE:
            raise ValueError(f"Invalid header size: {len(data)}")

        signature = data[0:30]
        version = struct.unpack_from("<I", data, 30)[0]
        encrypted = struct.unpack_from("<I", data, 34)[0]

        return cls(signature=signature, version=version, encrypted=encrypted)

    def is_valid(self) -> bool:
        return (self.signature.startswith(PK2_SIGNATURE.rstrip(b'\x00')[:20]) and
                self.version == PK2_VERSION)


@dataclass
class PK2EntryRaw:
    """Raw PK2 entry structure (128 bytes, after decryption)"""
    entry_type: int
    name: str
    access_time: int
    create_time: int
    modify_time: int
    position: int
    size: int
    next_chain: int

    @classmethod
    def from_bytes(cls, data: bytes) -> "PK2EntryRaw":
        if len(data) < PK2_ENTRY_SIZE:
            raise ValueError(f"Invalid entry size: {len(data)}")

        entry_type = data[0]

        # Name is 81 bytes, null-terminated
        name_bytes = data[1:82]
        try:
            null_pos = name_bytes.index(0)
            name = name_bytes[:null_pos].decode('ascii', errors='replace')
        except ValueError:
            name = name_bytes.decode('ascii', errors='replace')

        # Parse timestamps and other fields (little-endian)
        access_time = struct.unpack_from("<Q", data, 82)[0]
        create_time = struct.unpack_from("<Q", data, 90)[0]
        modify_time = struct.unpack_from("<Q", data, 98)[0]
        position = struct.unpack_from("<I", data, 106)[0]
        # position_high = struct.unpack_from("<I", data, 110)[0]  # Usually 0
        size = struct.unpack_from("<I", data, 114)[0]
        next_chain = struct.unpack_from("<I", data, 118)[0]

        return cls(
            entry_type=entry_type,
            name=name,
            access_time=access_time,
            create_time=create_time,
            modify_time=modify_time,
            position=position,
            size=size,
            next_chain=next_chain
        )


@dataclass
class PK2Entry:
    """Processed PK2 entry with full path information"""
    entry_type: int
    name: str
    path: str
    position: int
    size: int
    create_time: int
    modify_time: int
    children: list = field(default_factory=list)
    parent: Optional["PK2Entry"] = None

    def is_folder(self) -> bool:
        return self.entry_type == ENTRY_FOLDER

    def is_file(self) -> bool:
        return self.entry_type == ENTRY_FILE

    def get_size_str(self) -> str:
        """Return human-readable size string"""
        if self.is_folder():
            return "<DIR>"

        size = self.size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024:
                return f"{size:.1f} {unit}" if unit != 'B' else f"{size} {unit}"
            size /= 1024
        return f"{size:.1f} TB"


# ============================================================================
# PK2 Reader
# ============================================================================

class PK2Reader:
    """Reads and parses PK2 archive files"""

    MAX_ENTRIES = 500000  # Safety limit
    MAX_DEPTH = 100  # Maximum folder depth

    def __init__(self, filepath: str):
        self.filepath = filepath
        self.file = None
        self.cipher = None
        self.header: Optional[PK2Header] = None
        self.root: Optional[PK2Entry] = None
        self.all_entries: list[PK2Entry] = []
        self._entry_count = 0
        self._visited_positions: set = set()  # Track visited positions to prevent loops

    def open(self) -> bool:
        """Open and parse the PK2 archive"""
        try:
            self.file = open(self.filepath, 'rb')

            # Initialize Blowfish cipher (ECB mode)
            self.cipher = Blowfish.new(PK2_BLOWFISH_KEY, Blowfish.MODE_ECB)

            # Read and validate header
            header_data = self.file.read(PK2_HEADER_SIZE)
            self.header = PK2Header.from_bytes(header_data)

            if not self.header.is_valid():
                raise ValueError("Invalid PK2 header")

            # Create root entry
            self.root = PK2Entry(
                entry_type=ENTRY_FOLDER,
                name="/",
                path="",
                position=0,
                size=0,
                create_time=0,
                modify_time=0
            )

            # Parse the file tree
            self._parse(self.root)

            return True

        except Exception as e:
            if self.file:
                self.file.close()
                self.file = None
            raise e

    def _decrypt_entry(self, data: bytes) -> bytes:
        """Decrypt a 128-byte entry using Blowfish

        The original C++ Blowfish implementation uses little-endian byte order
        for the 32-bit words, but PyCryptodome uses big-endian. We need to
        swap byte order within each 4-byte word before and after decryption.
        """
        decrypted = bytearray()
        for i in range(0, len(data), 8):
            block = data[i:i+8]
            if len(block) == 8:
                # Swap byte order within each 4-byte word (little-endian to big-endian)
                swapped = bytes([
                    block[3], block[2], block[1], block[0],
                    block[7], block[6], block[5], block[4]
                ])
                # Decrypt
                dec_block = self.cipher.decrypt(swapped)
                # Swap back (big-endian to little-endian)
                result = bytes([
                    dec_block[3], dec_block[2], dec_block[1], dec_block[0],
                    dec_block[7], dec_block[6], dec_block[5], dec_block[4]
                ])
                decrypted.extend(result)
            else:
                decrypted.extend(block)
        return bytes(decrypted)

    def _parse(self, parent: PK2Entry):
        """Parse the PK2 file tree using iterative approach with stack"""
        # Stack contains (parent_entry, file_position, return_position)
        stack = [(parent, self.file.tell(), None)]

        while stack:
            if self._entry_count >= self.MAX_ENTRIES:
                break

            current_parent, current_pos, return_pos = stack.pop()

            # Seek to current position if needed
            if self.file.tell() != current_pos:
                self.file.seek(current_pos)

            # Check if we've visited this position already (prevent loops)
            if current_pos in self._visited_positions:
                if return_pos is not None:
                    self.file.seek(return_pos)
                continue
            self._visited_positions.add(current_pos)

            # Read encrypted entry
            encrypted_data = self.file.read(PK2_ENTRY_SIZE)
            if len(encrypted_data) < PK2_ENTRY_SIZE:
                if return_pos is not None:
                    self.file.seek(return_pos)
                continue

            # Decrypt entry
            decrypted_data = self._decrypt_entry(encrypted_data)
            raw_entry = PK2EntryRaw.from_bytes(decrypted_data)

            if raw_entry.entry_type == ENTRY_NULL:
                # End of current directory - continue with return position
                if return_pos is not None:
                    self.file.seek(return_pos)
                continue

            # Skip . and .. entries
            if raw_entry.name in ('.', '..'):
                # Still need to process next entry
                next_pos = self.file.tell()
                if raw_entry.next_chain > 0:
                    next_pos = raw_entry.next_chain
                stack.append((current_parent, next_pos, return_pos))
                continue

            # Build full path
            if current_parent.path:
                full_path = f"{current_parent.path}/{raw_entry.name}"
            else:
                full_path = raw_entry.name

            # Create entry
            entry = PK2Entry(
                entry_type=raw_entry.entry_type,
                name=raw_entry.name,
                path=full_path,
                position=raw_entry.position,
                size=raw_entry.size,
                create_time=raw_entry.create_time,
                modify_time=raw_entry.modify_time,
                parent=current_parent
            )

            current_parent.children.append(entry)
            self.all_entries.append(entry)
            self._entry_count += 1

            # Calculate next position (for chain or sequential reading)
            next_pos = self.file.tell()
            if raw_entry.next_chain > 0:
                next_pos = raw_entry.next_chain

            # Push next sibling to stack (will be processed after children)
            stack.append((current_parent, next_pos, return_pos))

            # If folder, push children to be processed first
            if raw_entry.entry_type == ENTRY_FOLDER and raw_entry.position > 0:
                # Push folder contents - will be processed next
                stack.append((entry, raw_entry.position, next_pos))

    def extract_file(self, entry: PK2Entry, output_path: str) -> bool:
        """Extract a single file from the archive"""
        if not entry.is_file():
            return False

        try:
            # Ensure output directory exists
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

            # Seek to file position
            self.file.seek(entry.position)

            # Read and write file data
            data = self.file.read(entry.size)

            with open(output_path, 'wb') as f:
                f.write(data)

            return True

        except Exception:
            return False

    def extract_folder(self, entry: PK2Entry, output_dir: str,
                       progress_callback=None) -> tuple[int, int]:
        """Extract a folder and all its contents"""
        success = 0
        failed = 0

        if entry.is_folder():
            # Create the folder
            folder_path = os.path.join(output_dir, entry.name) if entry.name != "/" else output_dir
            os.makedirs(folder_path, exist_ok=True)

            # Extract all children
            for child in entry.children:
                if child.is_folder():
                    s, f = self.extract_folder(child, folder_path, progress_callback)
                    success += s
                    failed += f
                else:
                    output_path = os.path.join(folder_path, child.name)
                    if self.extract_file(child, output_path):
                        success += 1
                    else:
                        failed += 1

                    if progress_callback:
                        progress_callback(child.name)
        else:
            output_path = os.path.join(output_dir, entry.name)
            if self.extract_file(entry, output_path):
                success += 1
            else:
                failed += 1

            if progress_callback:
                progress_callback(entry.name)

        return success, failed

    def get_entry_count(self) -> int:
        """Get total number of entries"""
        return self._entry_count

    def count_files_in_folder(self, entry: PK2Entry) -> tuple[int, int]:
        """Count files and folders recursively"""
        files = 0
        folders = 0

        for child in entry.children:
            if child.is_folder():
                folders += 1
                f, d = self.count_files_in_folder(child)
                files += f
                folders += d
            else:
                files += 1

        return files, folders

    def close(self):
        """Close the archive"""
        if self.file:
            self.file.close()
            self.file = None


# ============================================================================
# Console GUI
# ============================================================================

class PK2ExtractorGUI:
    """Console-based GUI for PK2 extraction"""

    def __init__(self):
        self.console = Console()
        self.reader: Optional[PK2Reader] = None
        self.current_folder: Optional[PK2Entry] = None
        self.history: list[PK2Entry] = []

    def clear_screen(self):
        """Clear the console screen"""
        os.system('cls' if os.name == 'nt' else 'clear')

    def print_header(self):
        """Print application header"""
        self.console.print(Panel.fit(
            "[bold cyan]PK2 Extractor[/bold cyan]\n"
            "[dim]A Python tool for extracting Silkroad Online PK2 archives[/dim]",
            border_style="cyan"
        ))

    def print_current_path(self):
        """Print current navigation path"""
        if self.current_folder:
            path = self.current_folder.path or "/"
            self.console.print(f"\n[bold yellow]Current path:[/bold yellow] {path}")

    def show_folder_contents(self):
        """Display contents of current folder"""
        if not self.current_folder:
            return

        self.print_current_path()

        # Create table
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold magenta")
        table.add_column("#", style="dim", width=4)
        table.add_column("Name", style="cyan", min_width=30)
        table.add_column("Type", style="green", width=8)
        table.add_column("Size", style="yellow", justify="right", width=12)

        # Add parent folder navigation if not at root
        if self.current_folder.parent:
            table.add_row("0", "[bold]..[/bold]", "<UP>", "")

        # Add children
        children = sorted(self.current_folder.children,
                         key=lambda x: (not x.is_folder(), x.name.lower()))

        for idx, entry in enumerate(children, 1):
            entry_type = "[blue]<DIR>[/blue]" if entry.is_folder() else "FILE"
            name = f"[bold blue]{entry.name}[/bold blue]" if entry.is_folder() else entry.name
            table.add_row(str(idx), name, entry_type, entry.get_size_str())

        self.console.print(table)

        # Show stats
        files, folders = self.reader.count_files_in_folder(self.current_folder)
        self.console.print(f"\n[dim]Files: {files} | Folders: {folders}[/dim]")

    def show_tree(self, entry: PK2Entry = None, max_depth: int = 3):
        """Display folder structure as a tree"""
        if entry is None:
            entry = self.reader.root

        tree = Tree(f"[bold cyan]{entry.name or '/'}[/bold cyan]")
        self._build_tree(tree, entry, 0, max_depth)
        self.console.print(tree)

    def _build_tree(self, tree: Tree, entry: PK2Entry, depth: int, max_depth: int):
        """Recursively build tree structure"""
        if depth >= max_depth:
            if entry.children:
                tree.add("[dim]...[/dim]")
            return

        # Sort: folders first, then files
        children = sorted(entry.children,
                         key=lambda x: (not x.is_folder(), x.name.lower()))

        for child in children:
            if child.is_folder():
                branch = tree.add(f"[bold blue]{child.name}/[/bold blue]")
                self._build_tree(branch, child, depth + 1, max_depth)
            else:
                tree.add(f"[green]{child.name}[/green] [dim]({child.get_size_str()})[/dim]")

    def navigate_to(self, entry: PK2Entry):
        """Navigate to a folder"""
        if entry.is_folder():
            self.history.append(self.current_folder)
            self.current_folder = entry

    def navigate_up(self):
        """Navigate to parent folder"""
        if self.current_folder and self.current_folder.parent:
            self.current_folder = self.current_folder.parent

    def navigate_back(self):
        """Navigate back in history"""
        if self.history:
            self.current_folder = self.history.pop()

    def extract_entry(self, entry: PK2Entry, output_dir: str):
        """Extract an entry with progress display, preserving folder structure"""
        if entry.is_file():
            # Use full path to preserve folder structure
            output_path = os.path.join(output_dir, entry.path)
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            if self.reader.extract_file(entry, output_path):
                self.console.print(f"[green]Extracted:[/green] {output_path}")
            else:
                self.console.print(f"[red]Failed:[/red] {entry.path}")
        else:
            # For folders, collect all files recursively and extract with full paths
            all_files = self._collect_files_recursive(entry)

            if not all_files:
                self.console.print("[yellow]No files to extract[/yellow]")
                return

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                console=self.console
            ) as progress:
                task = progress.add_task(f"Extracting {entry.name}...", total=len(all_files))
                success = 0
                failed = 0

                for file_entry in all_files:
                    output_path = os.path.join(output_dir, file_entry.path)
                    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
                    if self.reader.extract_file(file_entry, output_path):
                        success += 1
                    else:
                        failed += 1
                    progress.advance(task)
                    progress.update(task, description=f"Extracting: {file_entry.name[:30]}...")

            self.console.print(f"\n[green]Extracted:[/green] {success} files")
            if failed > 0:
                self.console.print(f"[red]Failed:[/red] {failed} files")

    def _collect_files_recursive(self, entry: PK2Entry) -> list:
        """Collect all files from a folder recursively"""
        files = []
        for child in entry.children:
            if child.is_file():
                files.append(child)
            elif child.is_folder():
                files.extend(self._collect_files_recursive(child))
        return files

    def show_menu(self):
        """Show action menu"""
        self.console.print("\n[bold]Commands:[/bold]")
        self.console.print("  [cyan]<number>[/cyan]  - Navigate to folder / Select file")
        self.console.print("  [cyan]0[/cyan]         - Go to parent folder")
        self.console.print("  [cyan]e <num>[/cyan]   - Extract file/folder")
        self.console.print("  [cyan]ea[/cyan]        - Extract all")
        self.console.print("  [cyan]t[/cyan]         - Show tree view")
        self.console.print("  [cyan]s <query>[/cyan] - Search files")
        self.console.print("  [cyan]f[/cyan]         - Filter & extract by pattern")
        self.console.print("  [cyan]q[/cyan]         - Quit")

    def search_files(self, query: str):
        """Search for files matching query"""
        query_lower = query.lower()
        results = []

        for entry in self.reader.all_entries:
            if query_lower in entry.name.lower() or query_lower in entry.path.lower():
                results.append(entry)

        if not results:
            self.console.print(f"[yellow]No results found for '{query}'[/yellow]")
            return

        self.console.print(f"\n[green]Found {len(results)} results:[/green]")

        table = Table(box=box.ROUNDED)
        table.add_column("#", style="dim", width=4)
        table.add_column("Name", style="cyan")
        table.add_column("Path", style="dim")
        table.add_column("Size", style="yellow", justify="right")

        for idx, entry in enumerate(results[:50], 1):  # Limit to 50 results
            table.add_row(
                str(idx),
                entry.name,
                entry.path,
                entry.get_size_str()
            )

        self.console.print(table)

        if len(results) > 50:
            self.console.print(f"[dim]... and {len(results) - 50} more results[/dim]")

        # Allow extraction from search results
        choice = Prompt.ask("\nExtract result # (or Enter to cancel)")
        if choice.isdigit():
            idx = int(choice) - 1
            if 0 <= idx < len(results):
                output_dir = Prompt.ask("Output directory", default="./extracted")
                self.extract_entry(results[idx], output_dir)

    def filter_and_extract(self):
        """Filter files by pattern and extract matching files"""
        import re
        import fnmatch

        self.console.print("\n[bold cyan]Filter & Extract[/bold cyan]")
        self.console.print("[dim]Leave blank to skip a filter option[/dim]\n")

        # Get filter options
        self.console.print("[bold]Filter Options:[/bold]")
        self.console.print("  1. Extension filter (e.g., .txt .ddj .dds)")
        self.console.print("  2. Substring match (e.g., icon, config)")
        self.console.print("  3. Glob pattern (e.g., *.txt, icon_*.ddj)")
        self.console.print("  4. Regex pattern (e.g., .*config.*\\.txt$)")
        self.console.print("")

        ext_input = Prompt.ask("[cyan]Extensions[/cyan] (space-separated)", default="").strip()
        contains_input = Prompt.ask("[cyan]Contains substring[/cyan]", default="").strip()
        glob_input = Prompt.ask("[cyan]Glob pattern[/cyan]", default="").strip()
        regex_input = Prompt.ask("[cyan]Regex pattern[/cyan]", default="").strip()
        ignore_case = Confirm.ask("[cyan]Case-insensitive?[/cyan]", default=True)

        # Parse extensions
        extensions = []
        if ext_input:
            extensions = ext_input.split()
            extensions = [ext if ext.startswith('.') else f'.{ext}' for ext in extensions]
            if ignore_case:
                extensions = [ext.lower() for ext in extensions]

        # Compile regex if provided
        regex_pattern = None
        if regex_input:
            try:
                flags = re.IGNORECASE if ignore_case else 0
                regex_pattern = re.compile(regex_input, flags)
            except re.error as e:
                self.console.print(f"[red]Invalid regex: {e}[/red]")
                return

        # Filter entries
        def matches(entry):
            if not entry.is_file():
                return False

            name = entry.name
            path = entry.path

            if ignore_case:
                name = name.lower()
                path = path.lower()

            # Extension filter
            if extensions:
                file_ext = os.path.splitext(name)[1]
                if file_ext not in extensions:
                    return False

            # Contains filter
            if contains_input:
                substr = contains_input.lower() if ignore_case else contains_input
                if substr not in path:
                    return False

            # Glob filter
            if glob_input:
                pattern = glob_input.lower() if ignore_case else glob_input
                if not fnmatch.fnmatch(name, pattern):
                    return False

            # Regex filter
            if regex_pattern:
                if not regex_pattern.search(entry.path):
                    return False

            return True

        # Get matching entries
        matching = [e for e in self.reader.all_entries if matches(e)]

        if not matching:
            self.console.print("[yellow]No files match the specified filters[/yellow]")
            return

        self.console.print(f"\n[green]Found {len(matching)} matching files[/green]")

        # Show preview
        table = Table(box=box.ROUNDED, title="Preview (first 20)")
        table.add_column("#", style="dim", width=4)
        table.add_column("Path", style="cyan")
        table.add_column("Size", style="yellow", justify="right")

        for idx, entry in enumerate(matching[:20], 1):
            table.add_row(str(idx), entry.path, entry.get_size_str())

        self.console.print(table)

        if len(matching) > 20:
            self.console.print(f"[dim]... and {len(matching) - 20} more files[/dim]")

        # Calculate total size
        total_size = sum(e.size for e in matching)
        size_str = f"{total_size:,} bytes"
        if total_size > 1024 * 1024:
            size_str = f"{total_size / (1024 * 1024):.1f} MB"
        elif total_size > 1024:
            size_str = f"{total_size / 1024:.1f} KB"
        self.console.print(f"\n[cyan]Total size: {size_str}[/cyan]")

        # Ask for extraction
        action = Prompt.ask(
            "\nAction",
            choices=["extract", "list", "cancel"],
            default="extract"
        )

        if action == "cancel":
            return

        if action == "list":
            # Show full list
            for entry in matching:
                print(f"[F] {entry.path} ({entry.get_size_str()})")
            Prompt.ask("\nPress Enter to continue")
            return

        # Extract
        output_dir = Prompt.ask("Output directory", default="./extracted")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console
        ) as progress:
            task = progress.add_task("Extracting...", total=len(matching))
            success = 0
            failed = 0

            for entry in matching:
                output_path = os.path.join(output_dir, entry.path)
                os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
                if self.reader.extract_file(entry, output_path):
                    success += 1
                else:
                    failed += 1
                progress.advance(task)

        self.console.print(f"\n[green]Extracted {success} files[/green]")
        if failed > 0:
            self.console.print(f"[red]Failed: {failed} files[/red]")

    def run(self, pk2_path: str = None):
        """Main application loop"""
        self.clear_screen()
        self.print_header()

        # Get PK2 file path
        if not pk2_path:
            pk2_path = Prompt.ask("\n[cyan]Enter PK2 file path[/cyan]")

        if not os.path.exists(pk2_path):
            self.console.print(f"[red]Error: File not found: {pk2_path}[/red]")
            return

        # Open PK2 file
        self.console.print(f"\n[yellow]Opening {pk2_path}...[/yellow]")

        try:
            self.reader = PK2Reader(pk2_path)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                progress.add_task("Parsing archive...", total=None)
                self.reader.open()

            self.console.print(f"[green]Loaded {self.reader.get_entry_count()} entries[/green]")

        except Exception as e:
            self.console.print(f"[red]Error opening PK2 file: {e}[/red]")
            return

        # Set initial folder
        self.current_folder = self.reader.root

        # Main loop
        while True:
            self.clear_screen()
            self.print_header()
            self.show_folder_contents()
            self.show_menu()

            try:
                cmd = Prompt.ask("\n[bold cyan]>[/bold cyan]").strip()

                if not cmd:
                    continue

                # Quit
                if cmd.lower() == 'q':
                    if Confirm.ask("Are you sure you want to quit?"):
                        break
                    continue

                # Tree view
                if cmd.lower() == 't':
                    self.clear_screen()
                    self.print_header()
                    depth = IntPrompt.ask("Tree depth", default=3)
                    self.show_tree(self.current_folder, depth)
                    Prompt.ask("\nPress Enter to continue")
                    continue

                # Search
                if cmd.lower().startswith('s '):
                    query = cmd[2:].strip()
                    self.search_files(query)
                    Prompt.ask("\nPress Enter to continue")
                    continue

                # Filter and extract
                if cmd.lower() == 'f':
                    self.clear_screen()
                    self.print_header()
                    self.filter_and_extract()
                    Prompt.ask("\nPress Enter to continue")
                    continue

                # Extract all
                if cmd.lower() == 'ea':
                    output_dir = Prompt.ask("Output directory", default="./extracted")
                    self.extract_entry(self.current_folder, output_dir)
                    Prompt.ask("\nPress Enter to continue")
                    continue

                # Extract specific
                if cmd.lower().startswith('e '):
                    try:
                        idx = int(cmd[2:].strip())
                        children = sorted(self.current_folder.children,
                                        key=lambda x: (not x.is_folder(), x.name.lower()))

                        if 1 <= idx <= len(children):
                            entry = children[idx - 1]
                            output_dir = Prompt.ask("Output directory", default="./extracted")
                            self.extract_entry(entry, output_dir)
                            Prompt.ask("\nPress Enter to continue")
                    except ValueError:
                        self.console.print("[red]Invalid number[/red]")
                    continue

                # Navigate by number
                if cmd.isdigit():
                    idx = int(cmd)

                    if idx == 0:
                        self.navigate_up()
                        continue

                    children = sorted(self.current_folder.children,
                                     key=lambda x: (not x.is_folder(), x.name.lower()))

                    if 1 <= idx <= len(children):
                        entry = children[idx - 1]
                        if entry.is_folder():
                            self.navigate_to(entry)
                        else:
                            # Show file info
                            self.console.print(f"\n[cyan]File:[/cyan] {entry.name}")
                            self.console.print(f"[cyan]Path:[/cyan] {entry.path}")
                            self.console.print(f"[cyan]Size:[/cyan] {entry.get_size_str()}")

                            if Confirm.ask("Extract this file?"):
                                output_dir = Prompt.ask("Output directory", default="./extracted")
                                self.extract_entry(entry, output_dir)

                            Prompt.ask("\nPress Enter to continue")

            except KeyboardInterrupt:
                if Confirm.ask("\nAre you sure you want to quit?"):
                    break
            except Exception as e:
                self.console.print(f"[red]Error: {e}[/red]")
                Prompt.ask("\nPress Enter to continue")

        # Cleanup
        if self.reader:
            self.reader.close()

        self.console.print("\n[green]Goodbye![/green]")


# ============================================================================
# Main Entry Point
# ============================================================================

def main():
    """Main entry point"""
    import argparse
    import re
    import fnmatch

    parser = argparse.ArgumentParser(
        description="PK2 Extractor - Extract files from PK2 archives",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Extract all files
  python pk2_extractor.py file.pk2 -e ./output

  # Extract files matching regex pattern
  python pk2_extractor.py file.pk2 -e ./output -p ".*\\.txt$"

  # Extract files by extension
  python pk2_extractor.py file.pk2 -e ./output --ext .ddj .dds

  # Extract files containing substring
  python pk2_extractor.py file.pk2 -e ./output --contains icon

  # Extract files matching glob pattern (like *.txt)
  python pk2_extractor.py file.pk2 -e ./output --glob "*.txt"

  # List files matching pattern (without extracting)
  python pk2_extractor.py file.pk2 -l -p "config.*"
        """
    )
    parser.add_argument("pk2_file", nargs="?", help="Path to PK2 file")
    parser.add_argument("-e", "--extract", help="Extract to directory")
    parser.add_argument("-l", "--list", action="store_true", help="List contents only")
    parser.add_argument("-p", "--pattern", help="Regex pattern to match file paths")
    parser.add_argument("--ext", nargs="+", help="File extensions to extract (e.g., .txt .ddj)")
    parser.add_argument("--contains", help="Extract files containing this substring")
    parser.add_argument("--glob", help="Glob pattern to match (e.g., *.txt, icon_*.ddj)")
    parser.add_argument("-i", "--ignore-case", action="store_true", help="Case-insensitive matching")

    args = parser.parse_args()

    def matches_filter(entry, args):
        """Check if entry matches the filter criteria"""
        if not entry.is_file():
            return False

        path = entry.path
        name = entry.name

        if args.ignore_case:
            path = path.lower()
            name = name.lower()

        # Regex pattern
        if args.pattern:
            pattern = args.pattern
            if args.ignore_case:
                pattern = re.compile(pattern, re.IGNORECASE)
            else:
                pattern = re.compile(pattern)
            if not pattern.search(entry.path):
                return False

        # Extension filter
        if args.ext:
            exts = [ext.lower() if args.ignore_case else ext for ext in args.ext]
            # Ensure extensions start with dot
            exts = [ext if ext.startswith('.') else f'.{ext}' for ext in exts]
            file_ext = os.path.splitext(name)[1]
            if args.ignore_case:
                file_ext = file_ext.lower()
            if file_ext not in exts:
                return False

        # Contains substring
        if args.contains:
            substr = args.contains.lower() if args.ignore_case else args.contains
            if substr not in path:
                return False

        # Glob pattern
        if args.glob:
            glob_pattern = args.glob.lower() if args.ignore_case else args.glob
            if not fnmatch.fnmatch(name, glob_pattern):
                return False

        return True

    # Check if any filter is specified
    has_filter = args.pattern or args.ext or args.contains or args.glob

    # Command-line extraction mode
    if args.pk2_file and args.extract:
        console = Console()
        console.print(f"[yellow]Opening {args.pk2_file}...[/yellow]")

        try:
            reader = PK2Reader(args.pk2_file)
            reader.open()
            console.print(f"[green]Loaded {reader.get_entry_count()} entries[/green]")

            # Filter entries if pattern specified
            if has_filter:
                matching_entries = [e for e in reader.all_entries if matches_filter(e, args)]
                console.print(f"[cyan]Matched {len(matching_entries)} files[/cyan]")

                if not matching_entries:
                    console.print("[yellow]No files match the specified pattern[/yellow]")
                    reader.close()
                    sys.exit(0)

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console
                ) as progress:
                    task = progress.add_task("Extracting...", total=len(matching_entries))
                    success = 0
                    failed = 0

                    for entry in matching_entries:
                        output_path = os.path.join(args.extract, entry.path)
                        os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
                        if reader.extract_file(entry, output_path):
                            success += 1
                        else:
                            failed += 1
                        progress.advance(task)

            else:
                # Extract all files
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    console=console
                ) as progress:
                    files_count, _ = reader.count_files_in_folder(reader.root)
                    task = progress.add_task("Extracting...", total=files_count)

                    def update_progress(_filename):
                        progress.advance(task)

                    success, failed = reader.extract_folder(reader.root, args.extract, update_progress)

            console.print(f"\n[green]Extracted {success} files[/green]")
            if failed > 0:
                console.print(f"[red]Failed: {failed} files[/red]")

            reader.close()

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)

    # List mode
    elif args.pk2_file and args.list:
        console = Console()

        try:
            reader = PK2Reader(args.pk2_file)
            reader.open()

            # Filter entries if pattern specified
            if has_filter:
                entries = [e for e in reader.all_entries if matches_filter(e, args)]
                import sys as _sys
                print(f"Matched {len(entries)} files\n", file=_sys.stderr)
            else:
                entries = reader.all_entries

            for entry in entries:
                entry_type = "D" if entry.is_folder() else "F"
                print(f"[{entry_type}] {entry.path} ({entry.get_size_str()})")

            reader.close()

        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)

    # Interactive GUI mode
    else:
        gui = PK2ExtractorGUI()
        gui.run(args.pk2_file)


if __name__ == "__main__":
    main()
