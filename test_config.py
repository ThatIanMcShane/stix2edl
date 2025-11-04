#!/usr/bin/env python3
"""
Configuration and Authentication Test Script
Tests your TAXII server connection and authentication setup
"""

import yaml
import sys
from taxii2client.v21 import Server

def load_config(config_path='config.yaml'):
    """Load configuration from YAML file"""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        print(f"❌ Config file not found: {config_path}")
        print(f"   Please create {config_path} or use config.examples.yaml as a template")
        return None
    except yaml.YAMLError as e:
        print(f"❌ Error parsing config file: {e}")
        return None

def test_connection(config):
    """Test TAXII collection connections"""
    print("=" * 70)
    print("TAXII Multi-Collection Connection Test")
    print("=" * 70)
    print()
    
    # Validate configuration
    collections = config.get('collections', [])
    if not collections:
        print("❌ No collections configured")
        print("   Add collections to config.yaml")
        return False
    
    username = config.get('username')
    password = config.get('password')
    
    print(f"Collections configured: {len(collections)}")
    print(f"Authentication: Basic HTTP")
    
    if not username or username == 'your-username':
        print("⚠️  Warning: No valid username configured")
    elif not password or password == 'your-password':
        print("⚠️  Warning: No valid password configured")
    else:
        print(f"✅ Basic auth configured (username: {username})")
    
    print()
    print("-" * 70)
    print("Testing collections...")
    print("-" * 70)
    print()
    
    import requests
    
    # Test each collection
    success_count = 0
    failed_count = 0
    disabled_count = 0
    
    for idx, collection_config in enumerate(collections, 1):
        collection_url = collection_config.get('url')
        collection_name = collection_config.get('name', f'Collection {idx}')
        enabled = collection_config.get('enabled', True)
        
        print(f"Collection {idx}: {collection_name}")
        print(f"  URL: {collection_url}")
        print(f"  Enabled: {enabled}")
        
        if not enabled:
            print(f"  ⏭️  Skipped (disabled)")
            disabled_count += 1
            print()
            continue
        
        if not collection_url:
            print(f"  ❌ No URL provided")
            failed_count += 1
            print()
            continue
        
        try:
            # Prepare authentication and headers
            auth = (username, password) if username and password else None
            headers = {
                'Accept': 'application/taxii+json;version=2.1',
                'Content-Type': 'application/taxii+json;version=2.1'
            }
            
            # Make HTTP request
            response = requests.get(
                collection_url,
                auth=auth,
                headers=headers,
                timeout=30
            )
            
            # Check status
            if response.status_code == 401:
                print(f"  ❌ Authentication failed (401)")
                failed_count += 1
            elif response.status_code == 403:
                print(f"  ❌ Access forbidden (403)")
                failed_count += 1
            elif response.status_code == 404:
                print(f"  ❌ Not found (404)")
                failed_count += 1
            elif response.status_code == 400:
                print(f"  ❌ Bad request (400)")
                failed_count += 1
            elif response.status_code != 200:
                print(f"  ❌ HTTP {response.status_code}: {response.reason}")
                failed_count += 1
            else:
                # Success - parse response
                data = response.json()
                
                if 'objects' in data:
                    objects = data['objects']
                    print(f"  ✅ Connected successfully")
                    print(f"  📊 Retrieved {len(objects)} objects")
                    
                    # Check pagination
                    has_more = data.get('more', False)
                    if has_more:
                        print(f"  📄 More data available (paginated)")
                    
                    # Show object types
                    types = {}
                    revoked = 0
                    for obj in objects:
                        obj_type = obj.get('type', 'unknown')
                        types[obj_type] = types.get(obj_type, 0) + 1
                        if obj.get('revoked', False):
                            revoked += 1
                    
                    if types:
                        print(f"  📋 Object types: {', '.join(f'{k}({v})' for k, v in sorted(types.items())[:3])}")
                        print(f"  🔄 Status: {len(objects) - revoked} active, {revoked} revoked")
                    
                    success_count += 1
                else:
                    print(f"  ⚠️  Connected but no objects found")
                    success_count += 1
                    
        except requests.exceptions.ConnectionError as e:
            print(f"  ❌ Connection error: {e}")
            failed_count += 1
        except requests.exceptions.Timeout:
            print(f"  ❌ Timeout")
            failed_count += 1
        except Exception as e:
            print(f"  ❌ Error: {e}")
            failed_count += 1
        
        print()
    
    # Summary
    print("=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"Total collections: {len(collections)}")
    print(f"  ✅ Successful: {success_count}")
    print(f"  ❌ Failed: {failed_count}")
    print(f"  ⏭️  Disabled: {disabled_count}")
    print("=" * 70)
    
    if success_count > 0 and failed_count == 0:
        print("✅ ALL TESTS PASSED")
        return True
    elif success_count > 0:
        print("⚠️  PARTIAL SUCCESS - Some collections failed")
        return True
    else:
        print("❌ ALL TESTS FAILED")
        return False

def main():
    """Main test function"""
    print()
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║  TAXII Threat Intelligence Collector - Configuration Test         ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print()
    
    # Load configuration
    config = load_config()
    if not config:
        sys.exit(1)
    
    # Test connection
    success = test_connection(config)
    
    print()
    if success:
        print("🎉 Your configuration is working correctly!")
        print("   You can now run: python3 taxii_threat_intel.py")
    else:
        print("💡 Fix the issues above and run this test again")
        print("   For help, see README.md or config.examples.yaml")
    print()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⚠️  Test interrupted by user")
        sys.exit(1)
