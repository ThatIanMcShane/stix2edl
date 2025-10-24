#!/usr/bin/env python3
"""
TAXII Threat Intelligence Collector
Connects to TAXII servers, downloads STIX 2.1 indicators, and serves them via API
"""

import json
import csv
import io
import logging
import sqlite3
import threading
from datetime import datetime
from typing import List, Dict, Set
from pathlib import Path

from flask import Flask, jsonify, send_file, request, render_template, Response
from taxii2client.v21 import Server, Collection
import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

# Database file
DB_FILE = 'indicators.db'

# Initialization state
init_state = {
    'status': 'initializing',  # initializing, ready, error
    'message': 'Starting up...',
    'progress': 0
}

# Global storage for indicators (cache only)
indicators_cache = {
    'last_updated': None,
    'indicators': [],
    'collections': [],
    'collection_indicators': {}
}


def init_database():
    """Initialize SQLite database with required tables"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Indicators table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            indicator_types TEXT,
            name TEXT,
            description TEXT,
            created TEXT,
            modified TEXT,
            confidence INTEGER,
            labels TEXT,
            collection_index INTEGER,
            UNIQUE(type, value)
        )
    ''')
    
    # Create index for faster lookups
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_type_value ON indicators(type, value)
    ''')
    
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_collection ON indicators(collection_index)
    ''')
    
    # Collections metadata table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS collections (
            collection_index INTEGER PRIMARY KEY,
            name TEXT NOT NULL,
            url TEXT,
            status TEXT,
            last_updated TEXT,
            object_count INTEGER
        )
    ''')
    
    # System metadata table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info(f"Database initialized: {DB_FILE}")


def save_indicators_to_db(indicators: List[Dict], collection_index: int = None):
    """Save indicators to database, handling duplicates by updating collection_index"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    saved_count = 0
    updated_count = 0
    
    for indicator in indicators:
        ioc_type = indicator.get('type')
        value = indicator.get('value')
        
        if not ioc_type or not value:
            continue
        
        try:
            # Check if indicator already exists
            cursor.execute('SELECT id, collection_index FROM indicators WHERE type = ? AND value = ?', (ioc_type, value))
            existing = cursor.fetchone()
            
            if existing:
                # Indicator exists - update if it's from a different collection or update collection_index
                existing_id, existing_coll_idx = existing
                
                # If no collection_index specified or it's different, update the record
                if collection_index is not None and existing_coll_idx != collection_index:
                    # Keep the indicator but update collection_index to the latest
                    cursor.execute('''
                        UPDATE indicators 
                        SET collection_index = ?,
                            indicator_types = ?,
                            name = ?,
                            description = ?,
                            modified = ?,
                            confidence = ?,
                            labels = ?
                        WHERE id = ?
                    ''', (
                        collection_index,
                        indicator.get('indicator_types'),
                        indicator.get('name'),
                        indicator.get('description'),
                        indicator.get('modified'),
                        indicator.get('confidence'),
                        indicator.get('labels'),
                        existing_id
                    ))
                    updated_count += 1
                # else: same collection, skip
            else:
                # New indicator - insert it
                cursor.execute('''
                    INSERT INTO indicators 
                    (type, value, indicator_types, name, description, created, modified, confidence, labels, collection_index)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ioc_type,
                    value,
                    indicator.get('indicator_types'),
                    indicator.get('name'),
                    indicator.get('description'),
                    indicator.get('created'),
                    indicator.get('modified'),
                    indicator.get('confidence'),
                    indicator.get('labels'),
                    collection_index
                ))
                saved_count += 1
                
        except sqlite3.Error as e:
            logger.warning(f"Error saving indicator {ioc_type}:{value}: {e}")
            continue
    
    conn.commit()
    conn.close()
    
    logger.info(f"Saved {saved_count} new indicators, updated {updated_count} existing (collection {collection_index})")
    return saved_count + updated_count


def load_indicators_from_db(collection_index: int = None) -> List[Dict]:
    """Load indicators from database"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    if collection_index is not None:
        cursor.execute('SELECT * FROM indicators WHERE collection_index = ?', (collection_index,))
    else:
        cursor.execute('SELECT * FROM indicators')
    
    rows = cursor.fetchall()
    conn.close()
    
    indicators = []
    for row in rows:
        indicators.append({
            'type': row['type'],
            'value': row['value'],
            'indicator_types': row['indicator_types'],
            'name': row['name'],
            'description': row['description'],
            'created': row['created'],
            'modified': row['modified'],
            'confidence': row['confidence'],
            'labels': row['labels'],
            'collection_index': row['collection_index']
        })
    
    return indicators


def save_collection_metadata(collection_index: int, name: str, url: str, status: str, object_count: int):
    """Save collection metadata to database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        INSERT OR REPLACE INTO collections 
        (collection_index, name, url, status, last_updated, object_count)
        VALUES (?, ?, ?, ?, ?, ?)
    ''', (collection_index, name, url, status, datetime.now().isoformat(), object_count))
    
    conn.commit()
    conn.close()


def load_collections_metadata() -> List[Dict]:
    """Load collections metadata from database"""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute('SELECT * FROM collections ORDER BY collection_index')
    rows = cursor.fetchall()
    conn.close()
    
    collections = []
    for row in rows:
        collections.append({
            'index': row['collection_index'],
            'name': row['name'],
            'url': row['url'],
            'status': row['status'],
            'last_updated': row['last_updated'],
            'object_count': row['object_count']
        })
    
    return collections


def save_system_meta(key: str, value: str):
    """Save system metadata"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('INSERT OR REPLACE INTO system_meta (key, value) VALUES (?, ?)', (key, value))
    
    conn.commit()
    conn.close()


def load_system_meta(key: str) -> str:
    """Load system metadata"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('SELECT value FROM system_meta WHERE key = ?', (key,))
    row = cursor.fetchone()
    conn.close()
    
    return row[0] if row else None


def clear_collection_indicators(collection_index: int):
    """Clear indicators for a specific collection"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('DELETE FROM indicators WHERE collection_index = ?', (collection_index,))
    
    conn.commit()
    conn.close()
    logger.info(f"Cleared indicators for collection {collection_index}")


def load_cache_from_db():
    """Load all data from database into cache"""
    logger.info("Loading data from database into cache...")
    
    # Load all indicators (deduplicated by type+value in DB)
    all_indicators = load_indicators_from_db()
    
    # Load collections metadata
    indicators_cache['collections'] = load_collections_metadata()
    
    # Load per-collection indicators
    indicators_cache['collection_indicators'] = {}
    for collection in indicators_cache['collections']:
        idx = collection['index']
        indicators_cache['collection_indicators'][idx] = load_indicators_from_db(idx)
    
    # Use all_indicators directly (already deduplicated)
    indicators_cache['indicators'] = all_indicators
    
    # Load last updated timestamp
    last_updated = load_system_meta('last_updated')
    indicators_cache['last_updated'] = last_updated
    
    logger.info(f"Loaded {len(indicators_cache['indicators'])} unique indicators from database")


# Global storage for indicators (cache only)


class TaxiiCollector:
    """Handles TAXII server connection and STIX data collection"""
    
    def __init__(self, config_path: str = 'config.yaml'):
        self.config_path = config_path
        self.config = self._load_config()
        
    def _load_config(self) -> dict:
        """Load configuration from YAML file"""
        try:
            with open(self.config_path, 'r') as f:
                config = yaml.safe_load(f)
            logger.info(f"Configuration loaded from {self.config_path}")
            return config
        except FileNotFoundError:
            logger.error(f"Config file not found: {self.config_path}")
            raise
        except yaml.YAMLError as e:
            logger.error(f"Error parsing config file: {e}")
            raise
    
    def get_auth_params(self) -> tuple:
        """Get Basic authentication parameters from config"""
        username = self.config.get('username')
        password = self.config.get('password')
        
        if username and password:
            logger.info(f"Using Basic authentication with username: {username}")
            return (username, password)
        else:
            logger.warning("No authentication credentials configured")
            return None
    
    def fetch_stix_objects(self) -> List[Dict]:
        """Fetch STIX objects from all enabled collections"""
        collections = self.config.get('collections', [])
        
        if not collections:
            raise ValueError("No collections configured")
        
        # Get authentication parameters (single set for all collections)
        auth = self.get_auth_params()
        
        all_objects = []
        collection_stats = []
        collection_objects = {}  # Map collection index to its objects
        
        # Process each enabled collection
        for idx, collection_config in enumerate(collections):
            # Skip disabled collections
            if not collection_config.get('enabled', True):
                logger.info(f"Skipping disabled collection: {collection_config.get('name', 'Unknown')}")
                continue
            
            collection_url = collection_config.get('url')
            collection_name = collection_config.get('name', 'Unknown')
            
            if not collection_url:
                logger.warning(f"Skipping collection '{collection_name}': No URL provided")
                continue
            
            logger.info(f"=" * 70)
            logger.info(f"Processing collection: {collection_name}")
            logger.info(f"URL: {collection_url}")
            logger.info(f"=" * 70)
            
            try:
                objects = self._fetch_collection_objects(collection_url, collection_name, auth)
                all_objects.extend(objects)
                collection_objects[idx] = objects  # Store per-collection
                
                stats = {
                    'index': idx,
                    'name': collection_name,
                    'url': collection_url,
                    'object_count': len(objects),
                    'status': 'success'
                }
                collection_stats.append(stats)
                
                logger.info(f"✅ Successfully fetched {len(objects)} objects from '{collection_name}'")
                
            except Exception as e:
                logger.error(f"❌ Failed to fetch from '{collection_name}': {e}")
                stats = {
                    'index': idx,
                    'name': collection_name,
                    'url': collection_url,
                    'object_count': 0,
                    'status': 'failed',
                    'error': str(e)
                }
                collection_stats.append(stats)
                collection_objects[idx] = []
                # Continue with next collection instead of failing completely
                continue
        
        # Log summary
        logger.info(f"")
        logger.info(f"=" * 70)
        logger.info(f"COLLECTION SUMMARY")
        logger.info(f"=" * 70)
        logger.info(f"Total collections processed: {len(collection_stats)}")
        
        successful = [s for s in collection_stats if s['status'] == 'success']
        failed = [s for s in collection_stats if s['status'] == 'failed']
        
        logger.info(f"Successful: {len(successful)}")
        logger.info(f"Failed: {len(failed)}")
        logger.info(f"Total objects retrieved: {len(all_objects)}")
        
        for stat in collection_stats:
            if stat['status'] == 'success':
                logger.info(f"  ✅ {stat['name']}: {stat['object_count']} objects")
            else:
                logger.info(f"  ❌ {stat['name']}: {stat.get('error', 'Unknown error')}")
        
        logger.info(f"=" * 70)
        
        return all_objects, collection_stats, collection_objects
    
    def _fetch_collection_objects(self, collection_url: str, collection_name: str, auth: tuple) -> List[Dict]:
        """Fetch STIX objects from a single collection with pagination support"""
        all_objects = []
        page_count = 0
        max_pages = self.config.get('max_pages', 50)
        
        try:
            import requests
            
            # Prepare headers with TAXII 2.1 requirements
            headers = {
                'Accept': 'application/taxii+json;version=2.1',
                'Content-Type': 'application/taxii+json;version=2.1'
            }
            
            next_param = None
            
            # Paginate through results
            while page_count < max_pages:
                page_count += 1
                logger.info(f"[{collection_name}] Fetching page {page_count}...")
                
                # Build request parameters
                params = {}
                if next_param:
                    params['added_after'] = next_param
                
                # Make HTTP request
                response = requests.get(
                    collection_url,
                    params=params,
                    auth=auth,
                    headers=headers,
                    timeout=30
                )
                
                # Log the actual URL being requested for debugging
                logger.debug(f"[{collection_name}] Request URL: {response.url}")
                
                # Check response status
                if response.status_code == 400:
                    error_msg = f"Bad Request (400). The server rejected the request."
                    try:
                        error_data = response.json()
                        if 'title' in error_data:
                            error_msg += f" Server says: {error_data.get('title')}"
                        if 'description' in error_data:
                            error_msg += f" - {error_data.get('description')}"
                        if 'message' in error_data:
                            error_msg += f" - {error_data.get('message')}"
                    except:
                        error_msg += f" Response: {response.text[:200]}"
                    raise Exception(error_msg)
                elif response.status_code == 401:
                    raise Exception("Authentication failed (401 Unauthorized). Check your credentials.")
                elif response.status_code == 403:
                    raise Exception("Access forbidden (403 Forbidden). Check your permissions.")
                elif response.status_code == 404:
                    raise Exception("Collection not found (404 Not Found). Check your collection URL.")
                elif response.status_code != 200:
                    raise Exception(f"HTTP {response.status_code}: {response.reason}")
                
                response.raise_for_status()
                
                # Parse JSON response
                data = response.json()
                
                # TAXII 2.1 envelope response has 'objects' array
                if 'objects' in data:
                    objects = data['objects']
                    all_objects.extend(objects)
                    logger.info(f"[{collection_name}] Retrieved {len(objects)} objects from page {page_count} (total: {len(all_objects)})")
                else:
                    logger.warning(f"[{collection_name}] No 'objects' field in response")
                    break
                
                # Check for pagination
                has_more = data.get('more', False)
                next_param = data.get('next')
                
                if has_more and next_param:
                    logger.info(f"[{collection_name}] More data available. Next timestamp: {next_param}")
                else:
                    # No more pages
                    logger.info(f"[{collection_name}] No more pages available")
                    break
            
            if page_count >= max_pages:
                logger.warning(f"[{collection_name}] Reached maximum page limit ({max_pages}). There may be more data available.")
                    
        except requests.exceptions.RequestException as e:
            logger.error(f"[{collection_name}] HTTP request error: {e}")
            raise
        except Exception as e:
            logger.error(f"[{collection_name}] Error fetching from collection: {e}")
            raise
        
        logger.info(f"[{collection_name}] Fetching complete. Total objects retrieved: {len(all_objects)} across {page_count} page(s)")
        return all_objects
    
    def extract_indicators(self, stix_objects: List[Dict]) -> List[Dict]:
        """Extract indicators from STIX 2.1 objects"""
        indicators = []
        revoked_count = 0
        
        for obj in stix_objects:
            # Handle both dict and object types
            if hasattr(obj, '__dict__'):
                obj = obj.__dict__
            
            obj_type = obj.get('type', '')
            
            # Skip revoked indicators
            if obj.get('revoked', False):
                revoked_count += 1
                continue
            
            # Process indicator objects
            if obj_type == 'indicator':
                indicator_data = self._process_indicator(obj)
                if indicator_data:
                    indicators.append(indicator_data)
            
            # Process observable objects that might contain indicators
            elif obj_type == 'observed-data':
                obs_indicators = self._process_observed_data(obj)
                indicators.extend(obs_indicators)
        
        logger.info(f"Extracted {len(indicators)} active indicators (skipped {revoked_count} revoked)")
        return indicators
    
    def _process_indicator(self, indicator_obj: Dict) -> Dict:
        """Process a STIX indicator object"""
        pattern = indicator_obj.get('pattern', '')
        indicator_types = indicator_obj.get('indicator_types', [])
        
        # Extract the actual indicator value from the pattern
        indicator_value, indicator_type = self._parse_pattern(pattern)
        
        if not indicator_value:
            return None
        
        return {
            'type': indicator_type,
            'value': indicator_value,
            'indicator_types': ', '.join(indicator_types) if indicator_types else 'unknown',
            'name': indicator_obj.get('name', ''),
            'description': indicator_obj.get('description', ''),
            'created': indicator_obj.get('created', ''),
            'modified': indicator_obj.get('modified', ''),
            'confidence': indicator_obj.get('confidence', ''),
            'labels': ', '.join(indicator_obj.get('labels', []))
        }
    
    def _process_observed_data(self, obs_obj: Dict) -> List[Dict]:
        """Process observed-data objects for indicators"""
        indicators = []
        objects = obs_obj.get('objects', {})
        
        for obj_key, obj_val in objects.items():
            obj_type = obj_val.get('type', '')
            
            if obj_type == 'ipv4-addr' or obj_type == 'ipv6-addr':
                indicators.append({
                    'type': 'ip',
                    'value': obj_val.get('value', ''),
                    'indicator_types': 'observed',
                    'name': '',
                    'description': '',
                    'created': obs_obj.get('created', ''),
                    'modified': obs_obj.get('modified', ''),
                    'confidence': '',
                    'labels': ''
                })
            elif obj_type == 'domain-name':
                indicators.append({
                    'type': 'domain',
                    'value': obj_val.get('value', ''),
                    'indicator_types': 'observed',
                    'name': '',
                    'description': '',
                    'created': obs_obj.get('created', ''),
                    'modified': obs_obj.get('modified', ''),
                    'confidence': '',
                    'labels': ''
                })
            elif obj_type == 'url':
                indicators.append({
                    'type': 'url',
                    'value': obj_val.get('value', ''),
                    'indicator_types': 'observed',
                    'name': '',
                    'description': '',
                    'created': obs_obj.get('created', ''),
                    'modified': obs_obj.get('modified', ''),
                    'confidence': '',
                    'labels': ''
                })
            elif obj_type == 'file':
                hashes = obj_val.get('hashes', {})
                for hash_type, hash_value in hashes.items():
                    indicators.append({
                        'type': f'file-hash-{hash_type}',
                        'value': hash_value,
                        'indicator_types': 'observed',
                        'name': obj_val.get('name', ''),
                        'description': '',
                        'created': obs_obj.get('created', ''),
                        'modified': obs_obj.get('modified', ''),
                        'confidence': '',
                        'labels': ''
                    })
        
        return indicators
    
    def _parse_pattern(self, pattern: str) -> tuple:
        """Parse STIX pattern to extract indicator value and type"""
        # Simple pattern parsing for common indicator types
        if not pattern:
            return None, None
        
        pattern = pattern.strip("[]")
        
        # IPv4/IPv6
        if "ipv4-addr:value" in pattern or "ipv6-addr:value" in pattern:
            value = self._extract_value(pattern)
            return value, 'ip'
        
        # Domain
        elif "domain-name:value" in pattern:
            value = self._extract_value(pattern)
            return value, 'domain'
        
        # URL
        elif "url:value" in pattern:
            value = self._extract_value(pattern)
            return value, 'url'
        
        # File hash
        elif "file:hashes" in pattern:
            value = self._extract_value(pattern)
            if "MD5" in pattern:
                return value, 'file-hash-MD5'
            elif "SHA-1" in pattern:
                return value, 'file-hash-SHA-1'
            elif "SHA-256" in pattern:
                return value, 'file-hash-SHA-256'
            elif "SHA-512" in pattern:
                return value, 'file-hash-SHA-512'
            else:
                return value, 'file-hash'
        
        return None, None
    
    def _extract_value(self, pattern: str) -> str:
        """Extract the actual value from a STIX pattern"""
        # Look for value between quotes
        import re
        match = re.search(r"'([^']+)'", pattern)
        if match:
            return match.group(1)
        
        match = re.search(r'"([^"]+)"', pattern)
        if match:
            return match.group(1)
        
        return ""


# Flask API endpoints

@app.route('/')
def index():
    """Serve the web interface"""
    # If still initializing, show initialization page
    if init_state['status'] == 'initializing':
        return render_template('initializing.html')
    return render_template('index.html')


@app.route('/api/init-status')
def get_init_status():
    """Get initialization status"""
    return jsonify(init_state)


@app.route('/api/status')
def status():
    """Get status of indicator collection"""
    collections_config = []
    try:
        collector = TaxiiCollector()
        collections_config = collector.config.get('collections', [])
    except:
        pass
    
    collections_processed = len([c for c in indicators_cache.get('collections', []) if c.get('status') == 'success'])
    collections_total = len(collections_config)
    
    return jsonify({
        'last_updated': indicators_cache['last_updated'],
        'indicator_count': len(indicators_cache['indicators']),
        'collections_processed': collections_processed,
        'collections_total': collections_total,
        'collections_successful': len([c for c in indicators_cache.get('collections', []) if c.get('status') == 'success']),
        'collections_failed': len([c for c in indicators_cache.get('collections', []) if c.get('status') == 'failed']),
        'status': 'ready' if indicators_cache['indicators'] else 'no data'
    })


@app.route('/api/collections')
def get_collections():
    """Get list of configured collections with their status"""
    try:
        collector = TaxiiCollector()
        collections_config = collector.config.get('collections', [])
        
        result_collections = []
        for idx, coll_config in enumerate(collections_config):
            # Get indicator count for this collection
            coll_indicators = indicators_cache.get('collection_indicators', {}).get(idx, [])
            
            # Get metadata from cache
            coll_meta = None
            for meta in indicators_cache.get('collections', []):
                if meta.get('index') == idx:
                    coll_meta = meta
                    break
            
            result_collections.append({
                'index': idx,
                'name': coll_config.get('name', f'Collection {idx+1}'),
                'url': coll_config.get('url', ''),
                'enabled': coll_config.get('enabled', True),
                'indicator_count': len(coll_indicators),
                'last_updated': coll_meta.get('last_updated') if coll_meta else None,
                'status': coll_meta.get('status', 'unknown') if coll_meta else 'not loaded'
            })
        
        return jsonify({
            'collections': result_collections
        })
    except Exception as e:
        logger.error(f"Error getting collections: {e}")
        return jsonify({
            'error': str(e),
            'collections': []
        }), 500


@app.route('/api/indicators')
def get_indicators_json():
    """Get indicators in JSON format"""
    indicator_type = request.args.get('type')
    
    indicators = indicators_cache['indicators']
    
    # Filter by type if requested
    if indicator_type:
        indicators = [i for i in indicators if i['type'] == indicator_type]
    
    return jsonify({
        'last_updated': indicators_cache['last_updated'],
        'count': len(indicators),
        'indicators': indicators
    })


@app.route('/api/indicators/csv')
def get_indicators_csv():
    """Download all indicators as CSV file"""
    indicators = indicators_cache['indicators']
    
    # Create CSV in memory
    output = io.StringIO()
    
    if indicators:
        fieldnames = indicators[0].keys()
        writer = csv.DictWriter(output, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(indicators)
    
    # Convert to bytes for sending
    output.seek(0)
    
    return send_file(
        io.BytesIO(output.getvalue().encode('utf-8')),
        mimetype='text/csv',
        as_attachment=True,
        download_name=f'threat_indicators_all_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
    )


@app.route('/api/collection/<int:collection_index>/csv')
def get_collection_csv(collection_index):
    """Download indicators for a specific collection as CSV"""
    try:
        collector = TaxiiCollector()
        collections_config = collector.config.get('collections', [])
        
        if collection_index >= len(collections_config):
            return jsonify({'error': 'Collection not found'}), 404
        
        collection_name = collections_config[collection_index].get('name', f'Collection {collection_index+1}')
        indicators = indicators_cache.get('collection_indicators', {}).get(collection_index, [])
        
        # Create CSV in memory
        output = io.StringIO()
        
        if indicators:
            fieldnames = indicators[0].keys()
            writer = csv.DictWriter(output, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(indicators)
        
        # Convert to bytes for sending
        output.seek(0)
        
        safe_name = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' for c in collection_name)
        filename = f'indicators_{safe_name}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'
        
        return send_file(
            io.BytesIO(output.getvalue().encode('utf-8')),
            mimetype='text/csv',
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        logger.error(f"Error getting collection CSV: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/edl/all')
def get_edl_all():
    """Get all indicators in EDL (External Dynamic List) format"""
    indicators = indicators_cache['indicators']
    
    # EDL format: one indicator per line (IP, domain, URL)
    edl_lines = []
    seen = set()  # Avoid duplicates
    
    for indicator in indicators:
        ioc_type = indicator.get('type')
        value = indicator.get('value')
        
        if not value or value in seen:
            continue
        
        # EDL supports: IP addresses, domains, URLs
        if ioc_type in ['ip', 'ipv4', 'ipv6', 'domain', 'url']:
            edl_lines.append(value)
            seen.add(value)
    
    # Create text response
    edl_content = '\n'.join(edl_lines)
    
    return Response(
        edl_content,
        mimetype='text/plain',
        headers={
            'Content-Disposition': f'inline; filename=threat_intel_edl_{datetime.now().strftime("%Y%m%d")}.txt'
        }
    )


@app.route('/api/edl/collection/<int:collection_index>')
def get_edl_collection(collection_index):
    """Get indicators for a specific collection in EDL format"""
    try:
        collector = TaxiiCollector()
        collections_config = collector.config.get('collections', [])
        
        if collection_index >= len(collections_config):
            return Response('# Collection not found', mimetype='text/plain'), 404
        
        collection_name = collections_config[collection_index].get('name', f'Collection {collection_index+1}')
        indicators = indicators_cache.get('collection_indicators', {}).get(collection_index, [])
        
        # EDL format: one indicator per line
        edl_lines = []
        seen = set()
        
        for indicator in indicators:
            ioc_type = indicator.get('type')
            value = indicator.get('value')
            
            if not value or value in seen:
                continue
            
            # EDL supports: IP addresses, domains, URLs
            if ioc_type in ['ip', 'ipv4', 'ipv6', 'domain', 'url']:
                edl_lines.append(value)
                seen.add(value)
        
        # Create text response with header comment
        edl_content = f'# EDL for {collection_name}\n'
        edl_content += f'# Generated: {datetime.now().isoformat()}\n'
        edl_content += f'# Total entries: {len(edl_lines)}\n'
        edl_content += '\n'.join(edl_lines)
        
        safe_name = "".join(c if c.isalnum() or c in (' ', '-', '_') else '_' for c in collection_name)
        
        return Response(
            edl_content,
            mimetype='text/plain',
            headers={
                'Content-Disposition': f'inline; filename={safe_name}_edl_{datetime.now().strftime("%Y%m%d")}.txt'
            }
        )
    except Exception as e:
        logger.error(f"Error getting collection EDL: {e}")
        return Response(f'# Error: {str(e)}', mimetype='text/plain'), 500


@app.route('/api/refresh', methods=['POST'])
def refresh_indicators():
    """Refresh all indicators from TAXII server"""
    try:
        collector = TaxiiCollector()
        
        logger.info("Starting full indicator refresh...")
        stix_objects, collection_stats, collection_objects = collector.fetch_stix_objects()
        
        # Clear database
        logger.info("Clearing old indicators from database...")
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM indicators')
        cursor.execute('DELETE FROM collections')
        conn.commit()
        conn.close()
        
        # Process and save indicators per collection
        all_indicators = []
        total_saved = 0
        
        for idx, objects in collection_objects.items():
            # Extract indicators from this collection's objects
            indicators = collector.extract_indicators(objects)
            
            # Save with collection_index
            saved = save_indicators_to_db(indicators, collection_index=idx)
            total_saved += saved
            all_indicators.extend(indicators)
            
            logger.info(f"Collection {idx}: Extracted {len(indicators)} indicators")
        
        # Deduplicate all_indicators for reporting (database already deduped)
        seen = set()
        unique_count = 0
        duplicate_count = 0
        
        for indicator in all_indicators:
            key = (indicator.get('type'), indicator.get('value'))
            if key not in seen and key[0] and key[1]:
                seen.add(key)
                unique_count += 1
            else:
                duplicate_count += 1
        
        logger.info(f"Total: {unique_count} unique indicators ({duplicate_count} duplicates across collections)")
        
        # Save collection metadata
        collections_config = collector.config.get('collections', [])
        for idx, coll_config in enumerate(collections_config):
            if not coll_config.get('enabled', True):
                continue
            
            coll_name = coll_config.get('name', '')
            coll_url = coll_config.get('url', '')
            
            # Find stats for this collection
            coll_stats = None
            for stats in collection_stats:
                if stats.get('index') == idx:
                    coll_stats = stats
                    break
            
            if coll_stats:
                save_collection_metadata(
                    idx,
                    coll_name,
                    coll_url,
                    coll_stats.get('status', 'unknown'),
                    coll_stats.get('object_count', 0)
                )
        
        # Save system metadata
        last_updated = datetime.now().isoformat()
        save_system_meta('last_updated', last_updated)
        
        # Reload cache from database
        load_cache_from_db()
        
        logger.info(f"Refresh complete. {unique_count} unique indicators saved to database.")
        
        successful = len([s for s in collection_stats if s.get('status') == 'success'])
        
        return jsonify({
            'status': 'success',
            'message': f'Refreshed {unique_count} unique indicators from {successful} collections',
            'indicator_count': unique_count,
            'duplicates_removed': duplicate_count,
            'collections_processed': len(collection_stats),
            'last_updated': indicators_cache['last_updated']
        })
    
    except Exception as e:
        logger.error(f"Error refreshing indicators: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/collection/<int:collection_index>/refresh', methods=['POST'])
def refresh_collection(collection_index):
    """Refresh indicators from a specific collection"""
    try:
        collector = TaxiiCollector()
        collections_config = collector.config.get('collections', [])
        
        if collection_index >= len(collections_config):
            return jsonify({
                'status': 'error',
                'message': 'Collection not found'
            }), 404
        
        collection_config = collections_config[collection_index]
        
        if not collection_config.get('enabled', True):
            return jsonify({
                'status': 'error',
                'message': 'Collection is disabled'
            }), 400
        
        collection_url = collection_config.get('url')
        collection_name = collection_config.get('name', f'Collection {collection_index+1}')
        auth = collector.get_auth_params()
        
        logger.info(f"Refreshing collection: {collection_name}")
        
        # Fetch from single collection
        objects = collector._fetch_collection_objects(collection_url, collection_name, auth)
        indicators = collector.extract_indicators(objects)
        
        # Clear old indicators for this collection from database
        clear_collection_indicators(collection_index)
        
        # Save new indicators to database
        save_indicators_to_db(indicators, collection_index)
        
        # Save collection metadata
        save_collection_metadata(
            collection_index,
            collection_name,
            collection_url,
            'success',
            len(objects)
        )
        
        # Update system last_updated
        last_updated = datetime.now().isoformat()
        save_system_meta('last_updated', last_updated)
        
        # Reload cache from database
        load_cache_from_db()
        
        logger.info(f"Collection refresh complete. {len(indicators)} indicators from '{collection_name}'.")
        
        return jsonify({
            'status': 'success',
            'message': f'Refreshed collection: {collection_name}',
            'indicator_count': len(indicators),
            'collection_name': collection_name
        })
    
    except Exception as e:
        logger.error(f"Error refreshing collection: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


def initialize_app():
    """Initialize the application by loading indicators"""
    # Initialize database
    init_state['status'] = 'initializing'
    init_state['message'] = 'Initializing database...'
    init_state['progress'] = 10
    
    init_database()
    
    # Try to load from database first
    try:
        init_state['message'] = 'Loading existing data from database...'
        init_state['progress'] = 20
        
        logger.info("Loading existing data from database...")
        load_cache_from_db()
        
        if indicators_cache['indicators']:
            logger.info(f"Loaded {len(indicators_cache['indicators'])} indicators from database")
            init_state['status'] = 'ready'
            init_state['message'] = 'Ready'
            init_state['progress'] = 100
            return
        else:
            logger.info("No data in database, fetching from TAXII server...")
            init_state['message'] = 'No data in database, fetching from TAXII server...'
            init_state['progress'] = 30
    except Exception as e:
        logger.warning(f"Could not load from database: {e}")
        logger.info("Fetching fresh data from TAXII server...")
        init_state['message'] = 'Fetching fresh data from TAXII server...'
        init_state['progress'] = 30
    
    # If no data in database, fetch from TAXII
    try:
        init_state['message'] = 'Connecting to TAXII server...'
        init_state['progress'] = 40
        
        collector = TaxiiCollector()
        
        init_state['message'] = 'Fetching indicators from collections...'
        init_state['progress'] = 50
        
        stix_objects, collection_stats, collection_objects = collector.fetch_stix_objects()
        
        init_state['message'] = 'Processing and saving indicators...'
        init_state['progress'] = 70
        
        # Process and save indicators per collection
        for idx, objects in collection_objects.items():
            indicators = collector.extract_indicators(objects)
            save_indicators_to_db(indicators, collection_index=idx)
        
        init_state['progress'] = 80
        
        # Save collection metadata
        collections_config = collector.config.get('collections', [])
        for idx, coll_config in enumerate(collections_config):
            coll_name = coll_config.get('name', '')
            coll_url = coll_config.get('url', '')
            
            # Find stats for this collection
            coll_stats = None
            for stats in collection_stats:
                if stats.get('index') == idx:
                    coll_stats = stats
                    break
            
            if coll_stats:
                save_collection_metadata(
                    idx,
                    coll_name,
                    coll_url,
                    coll_stats.get('status', 'unknown'),
                    coll_stats.get('object_count', 0)
                )
        
        init_state['message'] = 'Finalizing...'
        init_state['progress'] = 90
        
        # Save system metadata
        save_system_meta('last_updated', datetime.now().isoformat())
        
        # Load into cache
        load_cache_from_db()
        
        init_state['status'] = 'ready'
        init_state['message'] = 'Ready'
        init_state['progress'] = 100
        
        logger.info(f"Initialization complete. {len(indicators_cache['indicators'])} indicators saved to database.")
    except Exception as e:
        logger.warning(f"Could not initialize indicators: {e}")
        logger.info("Application started without initial data. Use /api/refresh to load indicators.")
        init_state['status'] = 'error'
        init_state['message'] = f'Initialization failed: {str(e)}'
        init_state['progress'] = 0


if __name__ == '__main__':
    # Ensure templates directory exists
    import os
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    if not os.path.exists(template_dir):
        os.makedirs(template_dir)
        logger.warning(f"Created templates directory at {template_dir}")
    
    # Check if index.html exists
    index_path = os.path.join(template_dir, 'index.html')
    if not os.path.exists(index_path):
        logger.error(f"index.html not found at {index_path}")
        logger.error("Please copy index.html to the templates directory")
        logger.info("Web UI will not be available. API endpoints will still work.")
    
    # Start initialization in background thread
    def init_in_background():
        try:
            initialize_app()
        except Exception as e:
            logger.error(f"Background initialization failed: {e}")
            init_state['status'] = 'error'
            init_state['message'] = f'Failed: {str(e)}'
    
    init_thread = threading.Thread(target=init_in_background, daemon=True)
    init_thread.start()
    
    # Start Flask app immediately
    logger.info("Starting Flask application on http://localhost:5000")
    logger.info("Initialization running in background...")
    app.run(host='localhost', port=5000, debug=False, threaded=True)
