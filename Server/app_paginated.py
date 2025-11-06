#!/usr/bin/env python3
"""
cveBuster Flask API - Paginated Version
Demonstrates NextPageToken pagination for Microsoft Sentinel CCF testing
"""

from flask import Flask, jsonify, request
import json
import base64

app = Flask(__name__)

# Load vulnerability data
with open('cvebuster_data.json', 'r') as f:
    data = json.load(f)
    # Handle both array and object with 'vulnerabilities' key
    if isinstance(data, list):
        ALL_VULNERABILITIES = data
    else:
        ALL_VULNERABILITIES = data.get('vulnerabilities', data.get('data', []))

# Configuration - Real-world pagination settings
PAGE_SIZE = 50  # Standard API pagination size (typical: 25-100 records per page)
VALID_API_KEY = 'cvebuster-demo-key-12345'


def encode_cursor(offset):
    """Encode offset as a base64 cursor token"""
    return base64.b64encode(str(offset).encode()).decode()


def decode_cursor(cursor):
    """Decode base64 cursor token to offset"""
    try:
        return int(base64.b64decode(cursor).decode())
    except:
        return 0


@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """
    Paginated vulnerabilities endpoint
    
    Query Parameters:
    - next_token: Cursor for pagination (base64 encoded offset)
    
    Response Format:
    {
      "data": [...],           # Current page of vulnerabilities
      "next_token": "xyz",     # Token for next page (null if last page)
      "total_count": 10,       # Total records available
      "page_size": 5,          # Records per page
      "current_offset": 0      # Current offset (for debugging)
    }
    """
    # Authentication
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != VALID_API_KEY:
        return jsonify({'error': 'Unauthorized - Invalid API key'}), 401
    
    # Get pagination parameters
    next_token = request.args.get('next_token', None)
    
    # Decode cursor to get offset
    offset = decode_cursor(next_token) if next_token else 0
    
    # Calculate pagination
    total_count = len(ALL_VULNERABILITIES)
    end_offset = offset + PAGE_SIZE
    
    # Get current page of data
    page_data = ALL_VULNERABILITIES[offset:end_offset]
    
    # Determine if there's a next page
    has_next_page = end_offset < total_count
    next_page_token = encode_cursor(end_offset) if has_next_page else None
    
    # Build response
    response = {
        'data': page_data,
        'next_token': next_page_token,
        'total_count': total_count,
        'page_size': PAGE_SIZE,
        'current_offset': offset,
        'records_in_page': len(page_data)
    }
    
    # Log request for debugging
    print(f"[API] Request - Offset: {offset}, Page Size: {PAGE_SIZE}, Records Returned: {len(page_data)}, Has Next: {has_next_page}")
    
    return jsonify(response), 200


@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'cveBuster API - Paginated',
        'version': '2.0',
        'total_vulnerabilities': len(ALL_VULNERABILITIES),
        'page_size': PAGE_SIZE
    }), 200


@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Statistics endpoint (no auth required for demo)"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or auth_header != VALID_API_KEY:
        return jsonify({'error': 'Unauthorized - Invalid API key'}), 401
    
    severity_counts = {}
    for vuln in ALL_VULNERABILITIES:
        severity = vuln.get('Severity', 'Unknown')
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    return jsonify({
        'total_vulnerabilities': len(ALL_VULNERABILITIES),
        'severity_breakdown': severity_counts,
        'page_size': PAGE_SIZE,
        'total_pages': (len(ALL_VULNERABILITIES) + PAGE_SIZE - 1) // PAGE_SIZE
    }), 200


if __name__ == '__main__':
    print("=" * 70)
    print("cveBuster API Server - PAGINATED VERSION (Real-world Config)")
    print("=" * 70)
    print(f"📊 Dataset Statistics:")
    print(f"   Total Vulnerabilities: {len(ALL_VULNERABILITIES):,}")
    print(f"   Page Size: {PAGE_SIZE} records per page")
    print(f"   Total Pages: {(len(ALL_VULNERABILITIES) + PAGE_SIZE - 1) // PAGE_SIZE}")
    print(f"   API Key: {VALID_API_KEY}")
    print("=" * 70)
    print("\n🌐 Endpoints:")
    print("   GET /api/vulnerabilities?next_token=<token>  (paginated)")
    print("   GET /api/health")
    print("   GET /api/stats")
    print("\n📖 Pagination Flow (Real-world Example):")
    print("   1. First request: GET /api/vulnerabilities")
    print(f"      → Returns {PAGE_SIZE} records + next_token")
    print("   2. Next request: GET /api/vulnerabilities?next_token=<token>")
    print(f"      → Returns next {PAGE_SIZE} records + next_token")
    print("   3. Continue until next_token is null (last page)")
    print("\n💡 Typical real-world pagination: 25-100 records per page")
    print("=" * 70)
    print(f"\n🚀 Starting server on http://0.0.0.0:5000")
    print("Press Ctrl+C to stop\n")
    
    app.run(host='0.0.0.0', port=5000, debug=True)
