# Network Scanner Project

HNDNE251F-NDP-Course_work

A high-performance, multi-threaded TCP port scanner written in Python for scanning CIDR subnets and individual hosts.

## Features

- **CIDR Support**: Scan entire subnets using CIDR notation (e.g., 192.168.1.0/24)
- **Flexible Port Scanning**: Support for individual ports, port ranges, and combinations
- **Multi-threaded**: High-performance scanning using configurable thread pools.
- **Multiple Output Formats**: Save results to CSV or JSON files
- **Progress Tracking**: Real-time progress display during scanning
- **Banner Grabbing**: Attempt to retrieve service banners from open ports
- **Error Handling**: Graceful handling of network errors and interruptions.
- **Hostname Resolution**: Support for scanning hostnames (resolved to IP addresses)

## Requirements

- Python 3.6 or higher
- Standard library modules: `argparse`, `ipaddress`, `socket`, `csv`, `json`, `concurrent.futures`

## Installation

1. Ensure Python 3.6+ is installed on your system
2. Clone or download this repository
3. No additional dependencies required - uses only Python standard library

## Usage

### Basic Syntax

```bash
python scan.py <target> [options]
```

### Command Line Options

- `target`: Target IP, hostname, or CIDR block (required)
- `-p, --ports`: Ports to scan (default: "1-1024")
  - Examples: `22`, `22,80,443`, `1-1024`, `22,80,8000-8100`
- `-t, --threads`: Number of worker threads (default: 200)
- `-T, --timeout`: Socket timeout in seconds (default: 1.0)
- `-o, --output`: Save results to file (.csv or .json extension)
- `--no-progress`: Disable progress display
- `--version`: Show version information

### Examples

#### Scan a single host for common ports
```bash
python scan.py 192.168.1.100
```

#### Scan a subnet for specific ports
```bash
python scan.py 192.168.1.0/24 -p 22,80,443
```

#### Scan with custom timeout and thread count
```bash
python scan.py 10.0.0.0/8 -p 1-65535 -t 500 -T 0.5
```

#### Scan hostname and save to CSV
```bash
python scan.py example.com -p 80,443 -o results.csv
```

#### Scan port range and save to JSON
```bash
python scan.py 192.168.1.1 -p 20-25 -o scan_results.json
```

## Output Formats

### Console Output
- Open ports are displayed with `[OPEN]` prefix
- Service banners are shown when available
- Progress indicator shows completion status
- Final summary displays total open ports found

### CSV Output
Columns: `ip`, `port`, `open`, `banner`
```csv
ip,port,open,banner
192.168.1.1,22,yes,SSH-2.0-OpenSSH_8.2p1
192.168.1.1,80,yes,<html>
```

### JSON Output
```json
[
  {
    "ip": "192.168.1.1",
    "port": 22,
    "open": true,
    "banner": "SSH-2.0-OpenSSH_8.2p1"
  },
  {
    "ip": "192.168.1.1",
    "port": 80,
    "open": true,
    "banner": "<html>"
  }
]
```

## Performance Considerations

- **Thread Count**: Higher thread counts improve speed but may overwhelm the network or trigger rate limiting
- **Timeout**: Lower timeouts speed up scanning but may miss slow-responding services
- **Port Ranges**: Large port ranges (e.g., 1-65535) on large subnets can take significant time
- **Network Impact**: Scanning may be detected by intrusion detection systems

## Error Handling

- Invalid targets or port specifications are caught and reported
- Network errors during scanning are handled gracefully
- Keyboard interrupts (Ctrl+C) allow clean termination with partial results
- Hostname resolution failures are reported

## Security Notice

This tool is intended for authorized network reconnaissance and security testing only. Ensure you have permission to scan target networks. Unauthorized scanning may violate laws and terms of service.

## Troubleshooting

### Common Issues

1. **Permission Denied**: Run with appropriate privileges if scanning privileged ports (< 1024)
2. **No Targets Resolved**: Check target format and network connectivity
3. **Slow Scanning**: Reduce timeout or increase thread count
4. **False Negatives**: Increase timeout for slow networks/services

### Debug Tips

- Use `--no-progress` for cleaner output when redirecting
- Start with small port ranges and single hosts for testing
- Check firewall settings that may block connections

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Version

Network Scanner 1.0

...
