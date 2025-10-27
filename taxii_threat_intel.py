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
import time
from datetime import datetime, timedelta
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

# Auto-refresh state
auto_refresh_state = {
    'enabled': False,
    'interval_hours': 6,
    'next_refresh': None,
    'last_refresh': None,
    'thread': None,
    'stop_event': threading.Event()
}

# Refresh progress state
refresh_progress = {
    'in_progress': False,
    'stage': '',
    'message': '',
    'percent': 0,
    'current_collection': '',
    'collections_done': 0,
    'collections_total': 0
}
refresh_progress_lock = threading.Lock()


def update_refresh_progress(stage='', message='', percent=0, current_collection='', collections_done=0, collections_total=0):
    """Update refresh progress state"""
    with refresh_progress_lock:
        refresh_progress['in_progress'] = True
        refresh_progress['stage'] = stage
        refresh_progress['message'] = message
        refresh_progress['percent'] = percent
        refresh_progress['current_collection'] = current_collection
        refresh_progress['collections_done'] = collections_done
        refresh_progress['collections_total'] = collections_total


def clear_refresh_progress():
    """Clear refresh progress state"""
    with refresh_progress_lock:
        refresh_progress['in_progress'] = False
        refresh_progress['stage'] = ''
        refresh_progress['message'] = ''
        refresh_progress['percent'] = 0
        refresh_progress['current_collection'] = ''
        refresh_progress['collections_done'] = 0
        refresh_progress['collections_total'] = 0


def get_refresh_progress():
    """Get current refresh progress (thread-safe)"""
    with refresh_progress_lock:
        return refresh_progress.copy()



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
            first_seen TEXT,
            last_seen TEXT,
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
            object_count INTEGER,
            error TEXT
        )
    ''')
    
    # System metadata table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_meta (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    
    # Revoked indicators table (v1.1)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS revoked_indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            description TEXT,
            confidence INTEGER,
            collection_index INTEGER,
            first_seen TEXT,
            revoked_date TEXT NOT NULL,
            UNIQUE(type, value)
        )
    ''')
    
    # Indicator history table (v1.1)
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS indicator_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            indicators_active INTEGER DEFAULT 0,
            indicators_revoked INTEGER DEFAULT 0,
            indicators_added INTEGER DEFAULT 0,
            indicators_removed INTEGER DEFAULT 0,
            by_type TEXT,
            by_collection TEXT,
            UNIQUE(date)
        )
    ''')
    
    conn.commit()
    conn.close()
    logger.info(f"Database initialized: {DB_FILE}")


def migrate_database():
    """Migrate existing database to v1.1 schema"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    try:
        # Check if first_seen and last_seen columns exist
        cursor.execute("PRAGMA table_info(indicators)")
        columns = [column[1] for column in cursor.fetchall()]
        
        # Add first_seen column if it doesn't exist
        if 'first_seen' not in columns:
            logger.info("Adding first_seen column to indicators table")
            cursor.execute('ALTER TABLE indicators ADD COLUMN first_seen TEXT')
            # Initialize with current timestamp for existing indicators
            cursor.execute('''
                UPDATE indicators 
                SET first_seen = COALESCE(created, datetime('now'))
                WHERE first_seen IS NULL
            ''')
        
        # Add last_seen column if it doesn't exist
        if 'last_seen' not in columns:
            logger.info("Adding last_seen column to indicators table")
            cursor.execute('ALTER TABLE indicators ADD COLUMN last_seen TEXT')
            # Initialize with current timestamp for existing indicators
            cursor.execute('''
                UPDATE indicators 
                SET last_seen = COALESCE(modified, datetime('now'))
                WHERE last_seen IS NULL
            ''')
        
        # Check if collections table has error column
        cursor.execute("PRAGMA table_info(collections)")
        coll_columns = [column[1] for column in cursor.fetchall()]
        
        if 'error' not in coll_columns:
            logger.info("Adding error column to collections table")
            cursor.execute('ALTER TABLE collections ADD COLUMN error TEXT')
        
        conn.commit()
        logger.info("Database migration completed successfully")
        
    except Exception as e:
        logger.error(f"Database migration failed: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


def save_indicators_to_db(indicators: List[Dict], collection_index: int = None, is_refresh: bool = False):
    """
    Save indicators to database, handling duplicates and timestamps
    
    Args:
        indicators: List of indicator dicts
        collection_index: Which collection these came from
        is_refresh: If True, update last_seen; if False (new), set first_seen
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    saved_count = 0
    updated_count = 0
    now = datetime.now().isoformat()
    
    for indicator in indicators:
        ioc_type = indicator.get('type')
        value = indicator.get('value')
        
        if not ioc_type or not value:
            continue
        
        try:
            # Check if indicator already exists
            cursor.execute('SELECT id, collection_index, first_seen FROM indicators WHERE type = ? AND value = ?', (ioc_type, value))
            existing = cursor.fetchone()
            
            if existing:
                # Indicator exists - update last_seen and other fields
                existing_id, existing_coll_idx, existing_first_seen = existing
                
                cursor.execute('''
                    UPDATE indicators 
                    SET collection_index = ?,
                        indicator_types = ?,
                        name = ?,
                        description = ?,
                        modified = ?,
                        confidence = ?,
                        labels = ?,
                        last_seen = ?
                    WHERE id = ?
                ''', (
                    collection_index if collection_index is not None else existing_coll_idx,
                    indicator.get('indicator_types'),
                    indicator.get('name'),
                    indicator.get('description'),
                    indicator.get('modified'),
                    indicator.get('confidence'),
                    indicator.get('labels'),
                    now,  # Update last_seen
                    existing_id
                ))
                updated_count += 1
            else:
                # New indicator - insert with first_seen and last_seen
                cursor.execute('''
                    INSERT INTO indicators 
                    (type, value, indicator_types, name, description, created, modified, 
                     confidence, labels, collection_index, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    collection_index,
                    now,  # Set first_seen
                    now   # Set last_seen
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


def save_collection_metadata(collection_index: int, name: str, url: str, status: str, object_count: int, error: str = None):
    """Save collection metadata to database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    # Simplify error message if provided
    if error:
        error = simplify_error_message(error)
    
    cursor.execute('''
        INSERT OR REPLACE INTO collections 
        (collection_index, name, url, status, last_updated, object_count, error)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (collection_index, name, url, status, datetime.now().isoformat(), object_count, error))
    
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


def get_newest_indicator_date(collection_index: int = None) -> str:
    """Get the date of the newest indicator (most recent 'created' or 'modified' date)"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    if collection_index is not None:
        # Get newest for specific collection
        cursor.execute('''
            SELECT MAX(
                CASE 
                    WHEN modified IS NOT NULL AND modified != '' THEN modified
                    WHEN created IS NOT NULL AND created != '' THEN created
                    ELSE NULL
                END
            ) as newest_date
            FROM indicators
            WHERE collection_index = ?
        ''', (collection_index,))
    else:
        # Get newest across all collections
        cursor.execute('''
            SELECT MAX(
                CASE 
                    WHEN modified IS NOT NULL AND modified != '' THEN modified
                    WHEN created IS NOT NULL AND created != '' THEN created
                    ELSE NULL
                END
            ) as newest_date
            FROM indicators
        ''')
    
    result = cursor.fetchone()
    conn.close()
    
    return result[0] if result and result[0] else None


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
            
            # Update progress
            collections_done = len(collection_stats)
            percent = 15 + int((collections_done / len(collections)) * 20)  # 15-35%
            update_refresh_progress('fetching', f'Fetching {collection_name}...', percent,
                                  current_collection=collection_name,
                                  collections_done=collections_done,
                                  collections_total=len(collections))
            
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
    
    def extract_indicators(self, stix_objects: List[Dict]) -> tuple:
        """
        Extract indicators from STIX 2.1 objects
        
        Returns:
            tuple: (active_indicators, revoked_indicators)
        """
        active_indicators = []
        revoked_indicators = []
        
        for obj in stix_objects:
            # Handle both dict and object types
            if hasattr(obj, '__dict__'):
                obj = obj.__dict__
            
            obj_type = obj.get('type', '')
            is_revoked = obj.get('revoked', False)
            
            # Process indicator objects
            if obj_type == 'indicator':
                indicator_data = self._process_indicator(obj)
                if indicator_data:
                    if is_revoked:
                        revoked_indicators.append(indicator_data)
                    else:
                        active_indicators.append(indicator_data)
            
            # Process observable objects that might contain indicators
            elif obj_type == 'observed-data':
                obs_indicators = self._process_observed_data(obj)
                # Observable data doesn't have revoked flag, always active
                active_indicators.extend(obs_indicators)
        
        logger.info(f"Extracted {len(active_indicators)} active indicators, {len(revoked_indicators)} revoked indicators")
        return active_indicators, revoked_indicators
    
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

# ============================================================================
# Auto-Refresh Scheduler
# ============================================================================

def simplify_error_message(error_str):
    """Convert technical error messages to user-friendly ones"""
    error_lower = error_str.lower()
    
    # Network/DNS errors
    if 'failed to resolve' in error_lower or 'nodename nor servname' in error_lower:
        return 'Network error: Unable to resolve hostname (check internet connection)'
    if 'name resolution' in error_lower or 'getaddrinfo failed' in error_lower:
        return 'Network error: DNS lookup failed (check internet connection)'
    if 'max retries exceeded' in error_lower:
        return 'Network error: Connection timeout (check internet connection)'
    if 'connection refused' in error_lower:
        return 'Network error: Server refused connection'
    if 'timeout' in error_lower:
        return 'Network error: Request timed out'
    if 'connection reset' in error_lower or 'connection aborted' in error_lower:
        return 'Network error: Connection was interrupted'
    
    # Authentication errors
    if '401' in error_str or 'unauthorized' in error_lower:
        return 'Authentication failed: Check your credentials'
    if '403' in error_str or 'forbidden' in error_lower:
        return 'Access denied: Check your permissions'
    
    # Server errors
    if '404' in error_str:
        return 'Not found: Check your collection URL'
    if '500' in error_str or '502' in error_str or '503' in error_str:
        return 'Server error: Remote server is unavailable'
    
    # Certificate errors
    if 'certificate' in error_lower or 'ssl' in error_lower:
        return 'SSL/Certificate error: Check server certificate'
    
    # If we can't simplify it, return first 150 chars
    if len(error_str) > 150:
        return error_str[:147] + '...'
    
    return error_str


def auto_refresh_worker():
    """Background worker that runs scheduled refreshes"""
    logger.info("Auto-refresh worker started")
    
    while not auto_refresh_state['stop_event'].is_set():
        if auto_refresh_state['enabled'] and auto_refresh_state['next_refresh']:
            now = datetime.now()
            next_refresh = datetime.fromisoformat(auto_refresh_state['next_refresh'])
            
            if now >= next_refresh:
                logger.info("Auto-refresh triggered")
                try:
                    # Run refresh
                    perform_auto_refresh()
                    
                    # Schedule next refresh
                    schedule_next_refresh()
                    
                except Exception as e:
                    logger.error(f"Auto-refresh failed: {e}")
        
        # Check every minute
        auto_refresh_state['stop_event'].wait(60)
    
    logger.info("Auto-refresh worker stopped")


def perform_auto_refresh():
    """Perform a full refresh (called by scheduler)"""
    try:
        collector = TaxiiCollector()
        
        logger.info("Starting auto-refresh...")
        
        # Get current indicators snapshot
        current_indicators = get_current_indicators_snapshot()
        
        # Fetch new indicators from TAXII
        stix_objects, collection_stats, collection_objects = collector.fetch_stix_objects()
        
        # Check if refresh actually succeeded
        successful_collections = [s for s in collection_stats if s.get('status') == 'success']
        failed_collections = [s for s in collection_stats if s.get('status') == 'failed']
        
        if len(successful_collections) == 0:
            # ALL collections failed - abort
            logger.error("❌ Auto-refresh: All collections failed - aborting to prevent false revocations")
            
            # Get simplified error message
            simple_error = 'Unable to connect to TAXII servers'
            if failed_collections:
                first_error = failed_collections[0].get('error', '')
                simple_error = simplify_error_message(first_error)
            
            save_system_meta('last_refresh_status', 'failed')
            save_system_meta('last_refresh_error', simple_error)
            return
        
        # Some or all succeeded - proceed
        if len(failed_collections) > 0:
            logger.warning(f"⚠ Auto-refresh: {len(failed_collections)} collection(s) failed, proceeding with {len(successful_collections)}")
        
        save_system_meta('last_refresh_status', 'success')
        save_system_meta('last_refresh_error', '')
        
        # Process new indicators per collection
        new_indicators = {}
        server_revoked = []
        
        for idx, objects in collection_objects.items():
            # Skip failed collections
            collection_status = next((s for s in collection_stats if s['index'] == idx), None)
            if collection_status and collection_status.get('status') == 'failed':
                logger.info(f"Auto-refresh: Skipping failed collection {idx}")
                continue
            
            active, revoked = collector.extract_indicators(objects)
            new_indicators[idx] = active
            
            for indicator in revoked:
                indicator['collection_index'] = idx
                server_revoked.append(indicator)
        
        # Compare old vs new
        comparison = compare_indicators(current_indicators, new_indicators)
        
        # Handle removed indicators
        handle_removed_indicators(comparison['removed'])
        handle_removed_indicators(server_revoked)
        
        # Clear database
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM indicators')
        cursor.execute('DELETE FROM collections')
        conn.commit()
        conn.close()
        
        # Save new indicators
        for idx, objects in collection_objects.items():
            active, revoked = collector.extract_indicators(objects)
            save_indicators_to_db(active, collection_index=idx)
        
        # Save collection metadata
        collections_config = collector.config.get('collections', [])
        for idx, coll_config in enumerate(collections_config):
            if not coll_config.get('enabled', True):
                continue
            
            coll_name = coll_config.get('name', '')
            coll_url = coll_config.get('url', '')
            
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
                    coll_stats.get('object_count', 0),
                    coll_stats.get('error')
                )
        
        # Save system metadata
        last_updated = datetime.now().isoformat()
        save_system_meta('last_updated', last_updated)
        
        # Save daily stats
        save_daily_stats(comparison, new_indicators)
        
        # Reload cache
        load_cache_from_db()
        
        auto_refresh_state['last_refresh'] = last_updated
        
        logger.info(f"Auto-refresh complete: {comparison['added_count']} added, {comparison['removed_count']} removed")
        
    except Exception as e:
        logger.error(f"Auto-refresh error: {e}")
        import traceback
        traceback.print_exc()


def schedule_next_refresh():
    """Calculate and set next refresh time"""
    interval_hours = auto_refresh_state['interval_hours']
    next_time = datetime.now() + timedelta(hours=interval_hours)
    auto_refresh_state['next_refresh'] = next_time.isoformat()
    logger.info(f"Next auto-refresh scheduled for {next_time.strftime('%Y-%m-%d %H:%M:%S')}")


def start_auto_refresh(interval_hours=6):
    """Start the auto-refresh scheduler"""
    if auto_refresh_state['thread'] and auto_refresh_state['thread'].is_alive():
        logger.warning("Auto-refresh already running")
        return
    
    auto_refresh_state['enabled'] = True
    auto_refresh_state['interval_hours'] = interval_hours
    auto_refresh_state['stop_event'].clear()
    
    # Schedule first refresh
    schedule_next_refresh()
    
    # Start worker thread
    thread = threading.Thread(target=auto_refresh_worker, daemon=True)
    thread.start()
    auto_refresh_state['thread'] = thread
    
    logger.info(f"Auto-refresh started with {interval_hours} hour interval")


def stop_auto_refresh():
    """Stop the auto-refresh scheduler"""
    auto_refresh_state['enabled'] = False
    auto_refresh_state['stop_event'].set()
    
    if auto_refresh_state['thread']:
        auto_refresh_state['thread'].join(timeout=5)
    
    auto_refresh_state['next_refresh'] = None
    logger.info("Auto-refresh stopped")


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
    
    # Get last refresh status
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM system_meta WHERE key = ?', ('last_refresh_status',))
    refresh_status_row = cursor.fetchone()
    refresh_status = refresh_status_row[0] if refresh_status_row else 'unknown'
    
    cursor.execute('SELECT value FROM system_meta WHERE key = ?', ('last_refresh_error',))
    refresh_error_row = cursor.fetchone()
    refresh_error = refresh_error_row[0] if refresh_error_row else ''
    conn.close()
    
    return jsonify({
        'last_updated': indicators_cache['last_updated'],
        'indicator_count': len(indicators_cache['indicators']),
        'collections_processed': collections_processed,
        'collections_total': collections_total,
        'collections_successful': len([c for c in indicators_cache.get('collections', []) if c.get('status') == 'success']),
        'collections_failed': len([c for c in indicators_cache.get('collections', []) if c.get('status') == 'failed']),
        'status': 'ready' if indicators_cache['indicators'] else 'no data',
        'refresh_status': refresh_status,
        'refresh_error': refresh_error,
        'is_stale': refresh_status == 'failed'
    })


@app.route('/api/stats')
def get_stats():
    """Get comprehensive indicator statistics"""
    try:
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        
        stats = {}
        
        # Current active indicators by type
        cursor.execute('''
            SELECT type, COUNT(*) as count 
            FROM indicators 
            GROUP BY type
        ''')
        stats['by_type'] = dict(cursor.fetchall())
        
        # Current active indicators by collection
        cursor.execute('''
            SELECT collection_index, COUNT(*) as count 
            FROM indicators 
            GROUP BY collection_index
        ''')
        stats['by_collection'] = dict(cursor.fetchall())
        
        # Total active indicators
        cursor.execute('SELECT COUNT(*) FROM indicators')
        stats['total_active'] = cursor.fetchone()[0]
        
        # Total revoked indicators
        cursor.execute('SELECT COUNT(*) FROM revoked_indicators')
        stats['total_revoked'] = cursor.fetchone()[0]
        
        # Recent history (last 7 days)
        cursor.execute('''
            SELECT date, indicators_added, indicators_removed, indicators_active
            FROM indicator_history
            ORDER BY date DESC
            LIMIT 7
        ''')
        history_7d = []
        for row in cursor.fetchall():
            history_7d.append({
                'date': row[0],
                'added': row[1],
                'removed': row[2],
                'active': row[3]
            })
        stats['history_7d'] = history_7d
        
        # Recent history (last 30 days)
        cursor.execute('''
            SELECT date, indicators_added, indicators_removed, indicators_active
            FROM indicator_history
            ORDER BY date DESC
            LIMIT 30
        ''')
        history_30d = []
        for row in cursor.fetchall():
            history_30d.append({
                'date': row[0],
                'added': row[1],
                'removed': row[2],
                'active': row[3]
            })
        stats['history_30d'] = history_30d
        
        # Today's changes (if available)
        today = datetime.now().date().isoformat()
        cursor.execute('''
            SELECT indicators_added, indicators_removed
            FROM indicator_history
            WHERE date = ?
        ''', (today,))
        today_row = cursor.fetchone()
        if today_row:
            stats['today_added'] = today_row[0]
            stats['today_removed'] = today_row[1]
        else:
            stats['today_added'] = 0
            stats['today_removed'] = 0
        
        # Recently revoked (last 10)
        cursor.execute('''
            SELECT type, value, revoked_date
            FROM revoked_indicators
            ORDER BY revoked_date DESC
            LIMIT 10
        ''')
        recently_revoked = []
        for row in cursor.fetchall():
            recently_revoked.append({
                'type': row[0],
                'value': row[1],
                'revoked_date': row[2]
            })
        stats['recently_revoked'] = recently_revoked
        
        conn.close()
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/auto-refresh/status')
def auto_refresh_status():
    """Get auto-refresh status"""
    return jsonify({
        'enabled': auto_refresh_state['enabled'],
        'interval_hours': auto_refresh_state['interval_hours'],
        'next_refresh': auto_refresh_state['next_refresh'],
        'last_refresh': auto_refresh_state['last_refresh']
    })


@app.route('/api/auto-refresh/start', methods=['POST'])
def api_start_auto_refresh():
    """Start auto-refresh"""
    data = request.get_json() or {}
    interval_hours = data.get('interval_hours', 6)
    
    try:
        start_auto_refresh(interval_hours)
        return jsonify({
            'status': 'success',
            'message': f'Auto-refresh started with {interval_hours} hour interval',
            'next_refresh': auto_refresh_state['next_refresh']
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@app.route('/api/auto-refresh/stop', methods=['POST'])
def api_stop_auto_refresh():
    """Stop auto-refresh"""
    try:
        stop_auto_refresh()
        return jsonify({
            'status': 'success',
            'message': 'Auto-refresh stopped'
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


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
            
            # Get newest indicator date for this collection
            newest_date = get_newest_indicator_date(idx)
            
            result_collections.append({
                'index': idx,
                'name': coll_config.get('name', f'Collection {idx+1}'),
                'url': coll_config.get('url', ''),
                'enabled': coll_config.get('enabled', True),
                'indicator_count': len(coll_indicators),
                'last_updated': coll_meta.get('last_updated') if coll_meta else None,
                'status': coll_meta.get('status', 'unknown') if coll_meta else 'not loaded',
                'error': coll_meta.get('error') if coll_meta else None,
                'newest_indicator': newest_date
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


# ============================================================================
# Indicator Tracking and Comparison Functions (v1.1)
# ============================================================================

def get_current_indicators_snapshot():
    """Get a snapshot of current indicators in the database"""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    cursor.execute('''
        SELECT type, value, description, confidence, collection_index, 
               first_seen, last_seen, created, modified
        FROM indicators
    ''')
    
    indicators = {}
    for row in cursor.fetchall():
        key = (row[0], row[1])  # (type, value)
        indicators[key] = {
            'type': row[0],
            'value': row[1],
            'description': row[2],
            'confidence': row[3],
            'collection_index': row[4],
            'first_seen': row[5],
            'last_seen': row[6],
            'created': row[7],
            'modified': row[8]
        }
    
    conn.close()
    return indicators


def compare_indicators(current_indicators, new_indicators_by_collection):
    """
    Compare current indicators with new indicators from TAXII
    
    Args:
        current_indicators: dict of {(type, value): indicator_data}
        new_indicators_by_collection: dict of {collection_index: [indicators]}
    
    Returns:
        dict with 'added', 'removed', 'unchanged' lists and counts
    """
    # Flatten new indicators into a single dict with collection tracking
    new_indicators = {}
    for coll_idx, indicators in new_indicators_by_collection.items():
        for indicator in indicators:
            key = (indicator.get('type'), indicator.get('value'))
            if key[0] and key[1]:  # Valid key
                # Track which collection this indicator came from
                indicator['collection_index'] = coll_idx
                new_indicators[key] = indicator
    
    # Find what's added, removed, unchanged
    current_keys = set(current_indicators.keys())
    new_keys = set(new_indicators.keys())
    
    added_keys = new_keys - current_keys
    removed_keys = current_keys - new_keys
    unchanged_keys = current_keys & new_keys
    
    added = [new_indicators[key] for key in added_keys]
    removed = [current_indicators[key] for key in removed_keys]
    unchanged = [current_indicators[key] for key in unchanged_keys]
    
    return {
        'added': added,
        'removed': removed,
        'unchanged': unchanged,
        'added_count': len(added),
        'removed_count': len(removed),
        'unchanged_count': len(unchanged),
        'new_indicators': new_indicators  # For later use
    }


def handle_removed_indicators(removed_indicators):
    """
    Move removed indicators to revoked_indicators table
    
    Args:
        removed_indicators: list of indicator dicts that disappeared
    """
    if not removed_indicators:
        logger.info("No indicators to revoke")
        return
    
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    revoked_count = 0
    revoked_date = datetime.now().isoformat()
    
    for indicator in removed_indicators:
        try:
            cursor.execute('''
                INSERT OR REPLACE INTO revoked_indicators 
                (type, value, description, confidence, collection_index, first_seen, revoked_date)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                indicator.get('type'),
                indicator.get('value'),
                indicator.get('description'),
                indicator.get('confidence'),
                indicator.get('collection_index'),
                indicator.get('first_seen'),
                revoked_date
            ))
            revoked_count += 1
        except Exception as e:
            logger.error(f"Error moving indicator to revoked table: {e}")
    
    conn.commit()
    conn.close()
    
    logger.info(f"Moved {revoked_count} indicators to revoked_indicators table")


def save_daily_stats(comparison_result, new_indicators_by_collection):
    """
    Save daily statistics to indicator_history table
    
    Args:
        comparison_result: dict from compare_indicators()
        new_indicators_by_collection: dict of {collection_index: [indicators]}
    """
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    
    today = datetime.now().date().isoformat()
    
    # Count by type
    by_type = {}
    for indicator in comparison_result['new_indicators'].values():
        ioc_type = indicator.get('type')
        by_type[ioc_type] = by_type.get(ioc_type, 0) + 1
    
    # Count by collection
    by_collection = {}
    for coll_idx, indicators in new_indicators_by_collection.items():
        by_collection[str(coll_idx)] = len(indicators)
    
    # Get total active indicators (what will be in database after refresh)
    indicators_active = len(comparison_result['new_indicators'])
    
    # Get total revoked indicators
    cursor.execute('SELECT COUNT(*) FROM revoked_indicators')
    indicators_revoked = cursor.fetchone()[0]
    
    try:
        # Insert or update today's stats
        cursor.execute('''
            INSERT OR REPLACE INTO indicator_history
            (date, indicators_active, indicators_revoked, indicators_added, 
             indicators_removed, by_type, by_collection)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            today,
            indicators_active,
            indicators_revoked,
            comparison_result['added_count'],
            comparison_result['removed_count'],
            json.dumps(by_type),
            json.dumps(by_collection)
        ))
        
        conn.commit()
        logger.info(f"Saved daily stats for {today}: {indicators_active} active, "
                   f"{comparison_result['added_count']} added, "
                   f"{comparison_result['removed_count']} removed")
    except Exception as e:
        logger.error(f"Error saving daily stats: {e}")
        conn.rollback()
    finally:
        conn.close()


@app.route('/api/refresh/progress')
def get_refresh_progress_api():
    """Get current refresh progress"""
    return jsonify(get_refresh_progress())


@app.route('/api/refresh', methods=['POST'])
def refresh_indicators():
    """Refresh all indicators from TAXII server"""
    try:
        update_refresh_progress('starting', 'Initializing refresh...', 5)
        
        collector = TaxiiCollector()
        collections_config = collector.config.get('collections', [])
        enabled_collections = [c for c in collections_config if c.get('enabled', True)]
        total_collections = len(enabled_collections)
        
        logger.info("Starting full indicator refresh...")
        
        # STEP 1: Get current indicators snapshot
        update_refresh_progress('preparing', 'Loading current indicators...', 10)
        current_indicators = get_current_indicators_snapshot()
        logger.info(f"Current database has {len(current_indicators)} indicators")
        
        # STEP 2: Fetch new indicators from TAXII
        update_refresh_progress('fetching', 'Fetching from TAXII servers...', 15, 
                               collections_total=total_collections)
        stix_objects, collection_stats, collection_objects = collector.fetch_stix_objects()
        
        # STEP 2A: Check if refresh actually succeeded
        successful_collections = [s for s in collection_stats if s.get('status') == 'success']
        failed_collections = [s for s in collection_stats if s.get('status') == 'failed']
        
        if len(successful_collections) == 0:
            # ALL collections failed - network/server issue
            logger.error("❌ All collections failed to refresh - network or server issue")
            logger.error("Data is now stale but will NOT be modified")
            
            clear_refresh_progress()
            
            # Get simplified error message from first failure
            simple_error = 'Unable to connect to TAXII servers'
            if failed_collections:
                first_error = failed_collections[0].get('error', '')
                simple_error = simplify_error_message(first_error)
            
            # Mark data as stale in system metadata
            save_system_meta('last_refresh_status', 'failed')
            save_system_meta('last_refresh_error', simple_error)
            
            return jsonify({
                'status': 'error',
                'message': f'Refresh failed: {simple_error}',
                'details': 'Data is stale but unchanged. No indicators were modified.',
                'failed_collections': len(failed_collections)
            }), 503  # 503 Service Unavailable
        
        # Some or all collections succeeded - proceed with refresh
        if len(failed_collections) > 0:
            logger.warning(f"⚠ {len(failed_collections)} collection(s) failed, but {len(successful_collections)} succeeded")
            logger.warning("Proceeding with refresh using successful collections only")
        
        # Mark refresh as successful
        save_system_meta('last_refresh_status', 'success')
        save_system_meta('last_refresh_error', '')
        
        # Process new indicators per collection
        update_refresh_progress('processing', 'Processing indicators...', 40)
        new_indicators = {}
        server_revoked = []  # Track indicators marked as revoked by server
        
        collections_processed = 0
        for idx, objects in collection_objects.items():
            # Skip failed collections
            collection_status = next((s for s in collection_stats if s['index'] == idx), None)
            if collection_status and collection_status.get('status') == 'failed':
                logger.info(f"Skipping failed collection {idx}")
                continue
            
            # Get collection name for progress
            coll_name = collection_status.get('name', f'Collection {idx}') if collection_status else f'Collection {idx}'
            collections_processed += 1
            percent = 40 + int((collections_processed / total_collections) * 20)
            update_refresh_progress('processing', f'Processing {coll_name}...', percent,
                                  current_collection=coll_name,
                                  collections_done=collections_processed,
                                  collections_total=total_collections)
            
            active, revoked = collector.extract_indicators(objects)
            new_indicators[idx] = active
            
            # Mark server-revoked indicators with collection info
            for indicator in revoked:
                indicator['collection_index'] = idx
                server_revoked.append(indicator)
            
            logger.info(f"Collection {idx}: Fetched {len(active)} active, {len(revoked)} server-revoked indicators")
        
        # STEP 3: Compare old vs new
        update_refresh_progress('comparing', 'Comparing with existing data...', 65)
        comparison = compare_indicators(current_indicators, new_indicators)
        logger.info(f"Comparison: {comparison['added_count']} added, {comparison['removed_count']} removed, {comparison['unchanged_count']} unchanged")
        
        # STEP 4: Handle removed indicators (moved to revoked table)
        # This includes both indicators that disappeared AND server-revoked ones
        handle_removed_indicators(comparison['removed'])
        handle_removed_indicators(server_revoked)  # Add server-revoked to revoked table
        
        # STEP 5: Clear database (we'll rebuild it)
        update_refresh_progress('saving', 'Clearing old data...', 70)
        logger.info("Clearing old indicators from database...")
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('DELETE FROM indicators')
        cursor.execute('DELETE FROM collections')
        conn.commit()
        conn.close()
        
        # Process and save indicators per collection
        update_refresh_progress('saving', 'Saving new indicators...', 75)
        all_indicators = []
        total_saved = 0
        
        for idx, objects in collection_objects.items():
            # Extract indicators from this collection's objects
            active, revoked = collector.extract_indicators(objects)
            
            # Save only active indicators with collection_index
            saved = save_indicators_to_db(active, collection_index=idx)
            total_saved += saved
            all_indicators.extend(active)
            
            logger.info(f"Collection {idx}: Saved {len(active)} active indicators")
        
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
                    coll_stats.get('object_count', 0),
                    coll_stats.get('error')  # Pass error if collection failed
                )
        
        # Save system metadata
        update_refresh_progress('finalizing', 'Saving metadata...', 90)
        last_updated = datetime.now().isoformat()
        save_system_meta('last_updated', last_updated)
        
        # STEP 6: Save daily statistics
        save_daily_stats(comparison, new_indicators)
        
        # Reload cache from database
        update_refresh_progress('finalizing', 'Reloading cache...', 95)
        load_cache_from_db()
        
        logger.info(f"Refresh complete. {unique_count} unique indicators saved to database.")
        
        # Clear progress before returning
        clear_refresh_progress()
        
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
        clear_refresh_progress()
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
        
        # STEP 1: Get snapshot of current indicators for this collection only
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT type, value, description, confidence, collection_index, 
                   first_seen, last_seen
            FROM indicators
            WHERE collection_index = ?
        ''', (collection_index,))
        
        current_indicators = {}
        for row in cursor.fetchall():
            key = (row[0], row[1])
            current_indicators[key] = {
                'type': row[0],
                'value': row[1],
                'description': row[2],
                'confidence': row[3],
                'collection_index': row[4],
                'first_seen': row[5],
                'last_seen': row[6]
            }
        conn.close()
        
        logger.info(f"Collection {collection_index} currently has {len(current_indicators)} indicators")
        
        # STEP 2: Fetch new indicators from TAXII for this collection
        objects = collector._fetch_collection_objects(collection_url, collection_name, auth)
        active_indicators, revoked_indicators = collector.extract_indicators(objects)
        
        logger.info(f"Fetched {len(active_indicators)} active, {len(revoked_indicators)} server-revoked indicators")
        
        # STEP 3: Compare old vs new for this collection
        new_indicators_dict = {collection_index: active_indicators}
        comparison = compare_indicators(current_indicators, new_indicators_dict)
        
        logger.info(f"Collection {collection_index}: {comparison['added_count']} added, "
                   f"{comparison['removed_count']} removed, {comparison['unchanged_count']} unchanged")
        
        # STEP 4: Handle removed indicators (both disappeared and server-revoked)
        handle_removed_indicators(comparison['removed'])
        
        # Add server-revoked indicators to revoked table
        for indicator in revoked_indicators:
            indicator['collection_index'] = collection_index
        handle_removed_indicators(revoked_indicators)
        
        # STEP 5: Clear old indicators for this collection from database
        clear_collection_indicators(collection_index)
        
        # STEP 6: Save new active indicators to database
        save_indicators_to_db(active_indicators, collection_index)
        
        # STEP 7: Save collection metadata
        save_collection_metadata(
            collection_index,
            collection_name,
            collection_url,
            'success',
            len(objects),
            None  # No error on success
        )
        
        # STEP 8: Update system last_updated
        last_updated = datetime.now().isoformat()
        save_system_meta('last_updated', last_updated)
        
        # STEP 9: Reload cache from database
        load_cache_from_db()
        
        logger.info(f"Collection refresh complete. {len(active_indicators)} active indicators from '{collection_name}'.")
        
        return jsonify({
            'status': 'success',
            'message': f'Refreshed collection: {collection_name}',
            'indicator_count': len(active_indicators),
            'collection_name': collection_name,
            'added': comparison['added_count'],
            'removed': comparison['removed_count']
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
    
    # Run migration for existing databases
    try:
        migrate_database()
    except Exception as e:
        logger.error(f"Migration failed, but continuing: {e}")
    
    # Try to load from database first
    try:
        init_state['message'] = 'Loading existing data from database...'
        init_state['progress'] = 20
        
        logger.info("Loading existing data from database...")
        load_cache_from_db()
        
        if indicators_cache['indicators']:
            logger.info(f"Loaded {len(indicators_cache['indicators'])} indicators from database")
            
            # Set refresh status to success since we have data
            save_system_meta('last_refresh_status', 'success')
            save_system_meta('last_refresh_error', '')
            
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
            active, revoked = collector.extract_indicators(objects)
            save_indicators_to_db(active, collection_index=idx)
            
            # Track server-revoked indicators
            if revoked:
                for indicator in revoked:
                    indicator['collection_index'] = idx
                handle_removed_indicators(revoked)
                logger.info(f"Collection {idx}: Saved {len(active)} active, tracked {len(revoked)} server-revoked indicators")
        
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
                    coll_stats.get('object_count', 0),
                    coll_stats.get('error')
                )
        
        init_state['message'] = 'Finalizing...'
        init_state['progress'] = 90
        
        # Save system metadata
        save_system_meta('last_updated', datetime.now().isoformat())
        save_system_meta('last_refresh_status', 'success')
        save_system_meta('last_refresh_error', '')
        
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
