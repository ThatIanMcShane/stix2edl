# STIX2EDL

**Version 1.0**

Convert TAXII threat intelligence feeds into firewall-consumable External Dynamic Lists (EDL).

## Important Notices

**THIS IS A PROOF OF CONCEPT TOOL**

This tool was developed as a proof of concept and is NOT intended for production use. See Security Considerations section below for important details.

### Testing Environment
- Tested on: macOS 15.7.1
- Testing scope: Functionality only
- Data source: Arctic Wolf Threat Feed (STIX2 format)

## Overview

STIX2EDL connects to TAXII 2.1 servers, fetches threat intelligence indicators, and serves them in EDL format for consumption by firewalls and security appliances. It supports multiple collections, persistent storage, and provides a clean web interface for management.

## Features

- **TAXII 2.1 Support** - Connects to any TAXII 2.1 compliant server
- **Multiple Collections** - Manage multiple threat feeds simultaneously
- **EDL Export** - Generates firewall-ready External Dynamic Lists
- **Web Interface** - Modern, responsive dashboard for management
- **Persistent Storage** - SQLite database for indicator persistence
- **Automatic Deduplication** - Prevents duplicate indicators
- **CSV Export** - Download indicators in CSV format
- **RESTful API** - Full API for automation and integration

## Quick Start

### Prerequisites

- Python 3.7+
- pip

### Installation

1. Clone the repository:
```bash
git clone https://github.com/ThatIanMcShane/stix2edl.git
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
# Edit config.yaml with your TAXII server details
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

### EDL Endpoints

#### All Indicators
```
http://localhost:5000/api/edl/all
```
Returns all indicators from all collections in EDL format.

#### Per-Collection
```
http://localhost:5000/api/edl/collection/0
http://localhost:5000/api/edl/collection/1
```
Returns indicators from a specific collection (by index).

### API Endpoints

#### Status
```bash
GET /api/status
```
Returns overall system status and indicator counts.

#### Collections
```bash
GET /api/collections
```
Lists all configured collections with metadata.

#### Refresh
```bash
POST /api/refresh
```
Fetches latest indicators from all collections.

```bash
POST /api/collection/0/refresh
```
Refreshes a specific collection.

#### Export
```bash
GET /api/indicators/csv
GET /api/collection/0/csv
```
Download indicators in CSV format.

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
```

**Supported Indicator Types:**
- IP addresses (IPv4/IPv6)
- Domain names
- URLs

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

### Database Schema

**indicators** - Threat indicators
- type, value, description, confidence
- collection_index (tracks source collection)
- Unique constraint on (type, value)

**collections** - Collection metadata
- name, url, status, last_updated

**system_meta** - System information
- last_updated timestamp

## Development

### Project Structure

```
stix2edl/
””€”€ taxii_threat_intel.py    # Main application
””€”€ config.yaml               # Configuration
””€”€ requirements.txt          # Python dependencies
””€”€ templates/
”‚   ””€”€ index.html           # Dashboard
”‚   ”””€”€ initializing.html    # First-run page
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

**WARNING: This is a proof of concept tool and should NOT be used in production environments.**

### Authentication

- **NOTE**: TAXII credentials are stored in `config.yaml` in plain text
- While this is not good security practice, the risk can be mitigated:
  - Use a dedicated credential that is not used anywhere else
  - This tool only retrieves data from TAXII servers (read-only operations)
  - If an attacker has local file access to poison this configuration, you likely have larger security concerns
- For production or higher-security environments, consider:
  - Environment variables
  - Secrets management systems (HashiCorp Vault, AWS Secrets Manager, etc.)
  - Encrypted configuration files
  - Service accounts with minimal privileges

### Network Security

- Run behind reverse proxy (nginx/apache) with HTTPS
- Restrict EDL endpoint access to firewall IPs only
- Implement authentication on web interface
- Do not expose to the public internet

### Rate Limiting

Consider implementing rate limits on refresh endpoints to prevent abuse.

### Use at Your Own Risk

This software is provided as-is for testing and proof of concept purposes only. The author assumes no liability for security issues, data breaches, or other damages resulting from the use of this software.

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

- **v1.1** - Settings page, auto-refresh persistence, full export
  - Web-based configuration management
  - Global credentials
  - Auto-refresh persists across restarts
  - Full CSV export (active + revoked indicators)
  
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
