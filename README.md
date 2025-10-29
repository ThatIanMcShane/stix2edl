# STIX2EDL

**Version 1.1**

Convert TAXII threat intelligence feeds into firewall-consumable External Dynamic Lists (EDL).

## Important Notices

**THIS IS A PROOF OF CONCEPT TOOL**

This tool was developed as a proof of concept and is NOT intended for production use without proper security review. See Security Considerations section below for important details.

### Testing Environment
- Tested on: macOS 15.7.1, Ubuntu 22.04 LTS
- Testing scope: Functionality and security features
- Data source: Arctic Wolf Threat Feed (STIX2 format)

## Overview

STIX2EDL connects to TAXII 2.1 servers, fetches threat intelligence indicators, and serves them in EDL format for consumption by firewalls and security appliances. It supports multiple collections, persistent storage, automatic refresh, and provides a secure web interface for management.

## Features

### v1.1 Features
- **Password-Protected Access** - Session-based authentication with configurable timeout
- **Three-State Health Indicators** - Green (healthy), Amber (warning), Red (critical)
- **Auto-Refresh Scheduling** - Automatic periodic indicator updates
- **Collection Management** - Enable/disable collections individually

### Core Features
- **TAXII 2.1 Support** - Connects to any TAXII 2.1 compliant server
- **Multiple Collections** - Manage multiple threat feeds simultaneously
- **EDL Export** - Generates firewall-ready External Dynamic Lists
- **Web Interface** - Modern, responsive dashboard for management
- **Persistent Storage** - SQLite database with automatic deduplication
- **CSV Export** - Download indicators in CSV format
- **RESTful API** - Full API for automation and integration
- **Indicator Lifecycle Tracking** - First seen, last seen, and revocation tracking

## Quick Start

### Prerequisites

- Python 3.10 or higher
- pip

### Installation

1. Clone or download the repository:
```bash
cd stix2edl
```

2. Run the setup script:
```bash
chmod +x setup.sh
./setup.sh
```

This will:
- Install Python dependencies
- Create configuration template
- Set up the templates directory

3. Configure your TAXII collections:
```bash
cp config.yaml.example config.yaml
# Edit config.yaml with your TAXII server details and auth credentials
```

4. Run the application:
```bash
python3 taxii_threat_intel.py
```

5. Access the web interface:
```
http://localhost:5000
```

## Configuration

Edit `config.yaml` to configure your TAXII connections:

```yaml
# TAXII Server Authentication
username: "your-username"
password: "your-password"

# Collections to fetch
collections:
  - url: "https://taxii-server.com/taxii2/collections/abc123/objects/"
    name: "Malware Indicators"
    enabled: true
  
  - url: "https://taxii-server.com/taxii2/collections/def456/objects/"
    name: "Phishing URLs"
    enabled: true

# Maximum pages to fetch per collection (each page ~100 objects)
max_pages: 50
```

### Configuration Options

- **username/password** - TAXII server Basic Auth credentials
- **collections** - List of TAXII collection endpoints
  - **url** - Full URL to collection's `/objects/` endpoint
  - **name** - Friendly name for the collection
  - **enabled** - Set to `false` to disable a collection
- **max_pages** - Limit pages fetched per collection (prevents runaway queries)

## Usage

### Web Interface

The web dashboard provides:
- **Overall Status** - Total indicators, last update time
- **Collection Cards** - Individual collection health and stats
- **Refresh Actions** - Update all or individual collections
- **Export Options** - Download CSV or view EDL

### EDL API Endpoints

STIX2EDL provides External Dynamic List (EDL) feeds for firewall consumption:

#### All Indicators
```bash
GET /api/edl/all
```
Returns all indicators from all enabled collections in EDL format (one indicator per line).

**Example**:
```
http://your-server:5000/api/edl/all
```

#### Per-Collection Feeds
```bash
GET /api/edl/collection/<index>
```
Returns indicators from a specific collection by index (starting at 0).

**Examples**:
```
http://your-server:5000/api/edl/collection/0
http://your-server:5000/api/edl/collection/1
```

**Supported Indicator Types**:
- IPv4 addresses
- IPv6 addresses
- Domain names
- URLs
- File hashes (MD5, SHA-1, SHA-256)

## Firewall Integration

### Palo Alto Networks

1. Navigate to **Objects > External Dynamic Lists**
2. Create new list:
   - **Type**: URL
   - **Source**: `http://your-server:5000/api/edl/all`
   - **Check Interval**: Hourly
3. Use in security policies

### Fortinet FortiGate

1. Navigate to **Security Fabric > External Connectors**
2. Create Threat Feed:
   - **URI**: `http://your-server:5000/api/edl/all`
   - **Refresh Rate**: 60 minutes
3. Apply to policies

### Cisco Firepower

1. Navigate to **Objects > Object Management**
2. Add URL List:
   - **URL**: `http://your-server:5000/api/edl/all`
   - **Update Interval**: 3600 seconds
3. Use in access control policies

## EDL Format

External Dynamic List format is a simple text file with one indicator per line:

```
192.168.1.100
10.0.0.5
malicious.com
evil-site.net
http://phishing.example.com/login
5d41402abc4b2a76b9719d911017c592
```

**Supported Indicator Types:**
- IP addresses (IPv4/IPv6)
- Domain names
- URLs
- File hashes (MD5, SHA-1, SHA-256)

## Architecture

### Components

- **TAXII Client** - Connects to TAXII 2.1 servers
- **SQLite Database** - Stores indicators persistently
- **Flask Web Server** - Serves web UI and API
- **Background Initialization** - Non-blocking startup

### Data Flow

1. Application starts †’ Loads from database (if exists)
2. If no data †’ Fetches from TAXII servers
3. Indicators stored in SQLite with deduplication
4. Web UI and API serve indicators in various formats

## Development

### Project Structure

```
stix2edl/
””€”€ taxii_threat_intel.py    # Main application
””€”€ config.yaml               # Configuration
””€”€ requirements.txt          # Python dependencies
””€”€ templates/
   â”œâ”€â”€ index.html            # Dashboard
   â”œâ”€â”€ settings.html         # Settings page
   â””â”€â”€ login.html            # Login page
””€”€ indicators.db            # SQLite database (created on first run)
”””€”€ README.md
```

### Running Tests

Test your configuration:
```bash
python3 test_config.py
```

This validates:
- TAXII server connectivity
- Authentication credentials
- Collection accessibility
- STIX object parsing

## Troubleshooting

### Connection Refused on First Run

The application may take a few minutes to initialize on first run while fetching indicators. The web server starts immediately and shows a progress page.

### No Indicators in EDL

1. Check collections are enabled in `config.yaml`
2. Verify TAXII credentials are correct
3. Run `python3 test_config.py` to diagnose
4. Check logs for errors

### Collection Shows Failed

- Verify the collection URL is correct (must end with `/objects/`)
- Check authentication credentials
- Ensure network access to TAXII server
- Check TAXII server is online

### Database Reset

To clear all data and refetch:
```bash
rm indicators.db
python3 taxii_threat_intel.py
```

## Performance

- **Startup** - Fast (loads from database)
- **First Run** - Depends on indicator count (typically 1-5 minutes)
- **Refresh** - Depends on indicator count
- **EDL Generation** - Instant (served from cache)
- **Database Size** - ~1MB per 10,000 indicators

## Security Considerations

**WARNING: This is a proof of concept tool. Review security implications before deployment.**

### Authentication (v1.1)

- **Password Protection**: Web UI protected by session-based authentication
- **Login Password**: Stored in database (system_meta table)
- **Session Timeout**: Configurable (default 72 hours)
- **First-Time Setup**: Set password on first access

### TAXII Credentials

- **Storage**: TAXII credentials stored in `config.yaml` in plain text
- **Mitigation**:
  - Use dedicated credentials not used elsewhere
  - Read-only TAXII access
  - Restrict file system access
- **Production Alternatives**:
  - Environment variables
  - Secrets management (HashiCorp Vault, AWS Secrets Manager)
  - Encrypted configuration

### Deployment Security

**Recommended setup**:
```bash
# Allow only firewall to access EDL feeds
iptables -A INPUT -p tcp --dport 5000 -s <firewall-ip> -j ACCEPT
iptables -A INPUT -p tcp --dport 5000 -s 127.0.0.1 -j ACCEPT
iptables -A INPUT -p tcp --dport 5000 -j DROP

# Or use SSH tunnel for admin access
ssh -L 5000:localhost:5000 user@server
```

### Use at Your Own Risk

This software is provided as-is for testing and proof of concept purposes. The author assumes no liability for security issues, data breaches, or damages resulting from use of this software.

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## License

MIT License - see LICENSE file for details

## Support

- **Issues**: GitHub Issues
- **Documentation**: This README
- **Configuration Help**: See `config.yaml.example`

## Version History

- **v1.1** - Security, UI improvements, and health monitoring
  - Password-protected web UI with session management
  - Three-state health indicators (Green/Amber/Red)
  - Auto-refresh scheduling with persistence
  - Settings page for web-based configuration
  - Indicator lifecycle tracking (first seen, last seen)
  - Collection-level refresh control
  
- **v1.0** - Initial release
  - TAXII 2.1 support
  - Multiple collections
  - EDL export
  - Web interface
  - SQLite persistence

## Credits

Built with:
- Flask - Web framework
- taxii2-client - TAXII 2.1 client library
- SQLite - Database

---

**STIX2EDL v1.1** - Converting threat intelligence to actionable security
