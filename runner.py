import ipaddress
import re
from dataclasses import dataclass
from typing import Optional
import shutil
import subprocess
import time

@dataclass
class ScanResult:
    target: str
    command: list[str]
    returncode: int
    stdout: str
    stderr: str 
    duration: float
    success: bool
    error: Optional[str] = None

HOSTNAME_RE = re.compile(
    r'^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)'
    r'(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$'
    )

def validate_target(target: str) -> bool:
    """Return True if target looks like a valid IP, CIDR range, or hostname."""
    target = target.strip()
    if not target:
        return False
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        pass
    return bool(HOSTNAME_RE.match(target))

def get_nmap_path() -> str:
    path = shutil.which("nmap")
    if path is None:
        raise RuntimeError("Nmap not found on PATH. Install nmap using 'sudo apt install nmap' ")
    return path 
DEFAULT_ARGS = ["-sV","-sC", "-T4", "--top-ports", "100", "-oX", "-"]

def run_scan(target: str, timeout: int = 120) -> ScanResult:
    if not validate_target(target):
        return ScanResult(
            target=target, command=[], returncode=-1,
            stdout="", stderr="", duration=0.0,
            success=False, error="Invalid target format"
        )
    
    nmap_path = get_nmap_path()
    command = [nmap_path, *DEFAULT_ARGS, target]

    start = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,

        )
        duration = time.monotonic() - start
        return ScanResult(
            target=target,
            command=command,
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            duration=duration,
            success=(proc.returncode == 0),
            error=None if proc.returncode == 0 else f"nmap exited with code {proc.returncode}"
        )
    except subprocess.TimeoutExpired as e:
        duration = time.monotonic() - start
        return ScanResult(
            target=target, command=command, returncode=-1,
            stdout=e.stdout or "", stderr=e.stderr or "",
            duration=duration, success=False,
            error=f"Scan timed out after {timeout}s"
        )
    except Exception as e:
        duration = time.monotonic() - start
        return ScanResult(
            target=target, command=command, returncode=-1,
            stdout="", stderr="", duration=duration, 
            success=False, error=f"Unexpected error: {e}"
        )
if __name__ == "__main__":
    result = run_scan("scanme.nmap.org")
    print("Success: ", result.success)
    print("Duration: ", result.duration)
    if result.success:
        print(result.stdout[:500])
    else:
        print("Error: ", result.error)
    
