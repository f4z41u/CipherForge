"""
CipherForge - Utility Functions
Helper functions for display, formatting, and user interaction
"""

import sys
import getpass
from colorama import Fore, Back, Style, init

# Initialize colorama for Windows support
init(autoreset=True)


class Colors:
    """Color constants for terminal output"""
    HEADER = Fore.CYAN + Style.BRIGHT
    SUCCESS = Fore.GREEN + Style.BRIGHT
    WARNING = Fore.YELLOW + Style.BRIGHT
    ERROR = Fore.RED + Style.BRIGHT
    INFO = Fore.BLUE + Style.BRIGHT
    HIGHLIGHT = Fore.MAGENTA + Style.BRIGHT
    RESET = Style.RESET_ALL
    DIM = Style.DIM


def print_banner():
    """Print the CipherForge ASCII art banner"""
    banner = f"""
{Fore.CYAN}{Style.BRIGHT}
   ██████╗██╗██████╗ ██╗  ██╗███████╗██████╗ ███████╗ ██████╗ ██████╗  ██████╗ ███████╗
  ██╔════╝██║██╔══██╗██║  ██║██╔════╝██╔══██╗██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝
  ██║     ██║██████╔╝███████║█████╗  ██████╔╝█████╗  ██║   ██║██████╔╝██║  ███╗█████╗  
  ██║     ██║██╔═══╝ ██╔══██║██╔══╝  ██╔══██╗██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝  
  ╚██████╗██║██║     ██║  ██║███████╗██║  ██║██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗
   ╚═════╝╚═╝╚═╝     ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
{Style.RESET_ALL}
{Fore.YELLOW}                    ⚔️  Advanced Encryption Tool with ChaCha20-Poly1305  ⚔️{Style.RESET_ALL}
{Fore.WHITE}{Style.DIM}                              Forge Your Security, Encrypt Your Future{Style.RESET_ALL}
{Fore.MAGENTA}{Style.DIM}                                      Created by Fazalu Rahman{Style.RESET_ALL}
    """
    print(banner)


def print_success(message: str):
    """Print a success message"""
    print(f"{Colors.SUCCESS}✓ {message}{Colors.RESET}")


def print_error(message: str):
    """Print an error message"""
    print(f"{Colors.ERROR}✗ {message}{Colors.RESET}", file=sys.stderr)


def print_warning(message: str):
    """Print a warning message"""
    print(f"{Colors.WARNING}⚠ {message}{Colors.RESET}")


def print_info(message: str):
    """Print an info message"""
    print(f"{Colors.INFO}ℹ {message}{Colors.RESET}")


def print_header(message: str):
    """Print a header message"""
    print(f"\n{Colors.HEADER}{'═' * 60}")
    print(f"  {message}")
    print(f"{'═' * 60}{Colors.RESET}\n")


def print_section(title: str):
    """Print a section title"""
    print(f"\n{Colors.HIGHLIGHT}▶ {title}{Colors.RESET}")


def format_bytes(size: int) -> str:
    """
    Format byte size as human-readable string
    
    Args:
        size: Size in bytes
        
    Returns:
        Formatted string (e.g., "1.5 MB")
    """
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def format_percentage(value: float) -> str:
    """
    Format a percentage value
    
    Args:
        value: Percentage value
        
    Returns:
        Formatted string (e.g., "45.67%")
    """
    return f"{value:.2f}%"


def print_file_stats(stats: dict):
    """
    Print file operation statistics
    
    Args:
        stats: Dictionary containing operation statistics
    """
    print_section("Operation Statistics")
    
    if 'original_size' in stats:
        print(f"  Original Size:  {format_bytes(stats['original_size'])}")
    
    if 'compressed_size' in stats and stats['compressed_size'] is not None:
        print(f"  Compressed:     {format_bytes(stats['compressed_size'])} ({format_percentage(stats['compression_ratio'])} reduction)")
    
    if 'encrypted_size' in stats:
        print(f"  Encrypted Size: {format_bytes(stats['encrypted_size'])}")
    
    if 'decrypted_size' in stats:
        print(f"  Decrypted Size: {format_bytes(stats['decrypted_size'])}")
    
    if 'was_compressed' in stats and stats['was_compressed']:
        print(f"  Compression:    {Colors.SUCCESS}Detected and decompressed{Colors.RESET}")


def prompt_password(prompt_text: str = "Enter password: ") -> str:
    """
    Securely prompt for password
    
    Args:
        prompt_text: Prompt message
        
    Returns:
        Password string
    """
    return getpass.getpass(f"{Colors.INFO}{prompt_text}{Colors.RESET}")


def prompt_confirm(message: str, default: bool = False) -> bool:
    """
    Prompt user for yes/no confirmation
    
    Args:
        message: Confirmation message
        default: Default value if user just presses Enter
        
    Returns:
        True if user confirms, False otherwise
    """
    default_str = "Y/n" if default else "y/N"
    response = input(f"{Colors.WARNING}{message} [{default_str}]: {Colors.RESET}").strip().lower()
    
    if not response:
        return default
    
    return response in ['y', 'yes']


def print_batch_results(results: list[dict]):
    """
    Print results from batch operations
    
    Args:
        results: List of result dictionaries
    """
    successful = [r for r in results if r.get('success', False)]
    failed = [r for r in results if not r.get('success', False)]
    
    print_section("Batch Operation Results")
    print(f"  Total Files:    {len(results)}")
    print(f"  {Colors.SUCCESS}Successful:     {len(successful)}{Colors.RESET}")
    
    if failed:
        print(f"  {Colors.ERROR}Failed:         {len(failed)}{Colors.RESET}")
        print_section("Failed Files")
        for result in failed:
            print(f"  {Colors.ERROR}✗{Colors.RESET} {result.get('input_file', 'unknown')}")
            print(f"    Error: {result.get('error', 'unknown error')}")


def create_progress_bar(total: int, desc: str = "Processing"):
    """
    Create a progress bar for long operations
    
    Args:
        total: Total number of items
        desc: Description for the progress bar
        
    Returns:
        tqdm progress bar instance
    """
    from tqdm import tqdm
    return tqdm(
        total=total,
        desc=f"{Colors.INFO}{desc}{Colors.RESET}",
        bar_format='{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]',
        colour='cyan'
    )


def print_key_generation_info():
    """Print information about key generation"""
    info = f"""
{Colors.HEADER}Key Generation Information:{Colors.RESET}

{Colors.INFO}•{Colors.RESET} A random 256-bit (32-byte) key will be generated
{Colors.INFO}•{Colors.RESET} Store this key file in a secure location
{Colors.INFO}•{Colors.RESET} Never share your key file with anyone
{Colors.INFO}•{Colors.RESET} Losing the key means losing access to encrypted data
{Colors.INFO}•{Colors.RESET} Consider backing up the key to a secure location
    """
    print(info)


def print_encryption_info():
    """Print information about the encryption method"""
    info = f"""
{Colors.HEADER}Encryption Details:{Colors.RESET}

{Colors.INFO}•{Colors.RESET} Algorithm:     ChaCha20-Poly1305 (AEAD)
{Colors.INFO}•{Colors.RESET} Key Size:      256 bits
{Colors.INFO}•{Colors.RESET} Authentication: Poly1305 MAC
{Colors.INFO}•{Colors.RESET} Key Derivation: Argon2id
{Colors.INFO}•{Colors.RESET} Nonce:         96 bits (random, per encryption)
{Colors.INFO}•{Colors.RESET} Security:      Military-grade encryption
    """
    print(info)


def handle_exception(e: Exception, context: str = "Operation"):
    """
    Handle and display exceptions in a user-friendly way
    
    Args:
        e: Exception to handle
        context: Context of the operation
    """
    from cryptography.exceptions import InvalidTag
    
    if isinstance(e, FileNotFoundError):
        print_error(f"{context} failed: File not found - {e}")
    elif isinstance(e, PermissionError):
        print_error(f"{context} failed: Permission denied - {e}")
    elif isinstance(e, InvalidTag):
        print_error(f"{context} failed: Authentication failed! The data may have been tampered with or the wrong password/key was used.")
    elif isinstance(e, ValueError):
        print_error(f"{context} failed: {e}")
    else:
        print_error(f"{context} failed: {type(e).__name__}: {e}")
    
    return 1  # Error exit code
