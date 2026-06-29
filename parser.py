from runner import ScanResult
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Service:
    name: str
    product: Optional[str] = None
    version: Optional[str] = None
    extrainfo: Optional[str] = None

@dataclass
class Port:
    number: int
    protocol: str 
    state: str 
    service: Optional[Service] = None

@dataclass
class Host:
    ip: str
    hostname: Optional[str] = None
    status: str = "unknown"
    ports: list[Port] = field(default_factory=list)

def parse_scan(result: ScanResult) -> list[Host]:
    if not result.success:
        raise ValueError(f"Cannot parse a failed scan: {result.error}")
    
    xml_data = result.stdout