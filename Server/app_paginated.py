from flask import Flask, request, jsonify
import json
import base64
from datetime import datetime, timezone

app = Flask(__name__)

# API Key for authentication
API_KEY = "cvebuster-demo-key-12345"

def parse_iso_datetime(dt_str):
    """Parse ISO 8601 datetime string to datetime object."""
    try:
        # Handle both with and without 'Z' suffix
        if dt_str.endswith('Z'):
            dt_str = dt_str[:-1] + '+00:00'
        return datetime.fromisoformat(dt_str)
    except Exception as e:
        print(f"Error parsing datetime '{dt_str}': {e}")
        return None

def filter_by_time_range(vulnerabilities, start_time_str=None, end_time_str=None):
    """Filter vulnerabilities by LastModified time range."""
    if not start_time_str and not end_time_str:
        return vulnerabilities
    
    start_time = parse_iso_datetime(start_time_str) if start_time_str else None
    end_time = parse_iso_datetime(end_time_str) if end_time_str else None
    
    filtered = []
    for vuln in vulnerabilities:
        last_modified = parse_iso_datetime(vuln.get('LastModified', ''))
        if last_modified is None:
            continue
        
        # Check if within time range
        if start_time and last_modified <= start_time:
            continue
        if end_time and last_modified >= end_time:
            continue
        
        filtered.append(vuln)
    
    return filtered

@app.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    """
    Get vulnerabilities with pagination support.
    Supports both 'next_token' and 'nextToken' parameter names.
    Supports time filtering via createdAt__gt and createdAt__lt parameters.
    """
    # Check API key
    auth_header = request.headers.get('Authorization', '')
    if auth_header != API_KEY:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Load vulnerability data
    try:
        with open('cvebuster_data.json', 'r') as f:
            all_vulnerabilities = json.load(f)
    except FileNotFoundError:
        return jsonify({"error": "Data file not found"}), 500
    
    # Get time filter parameters (SentinelOne pattern)
    start_time = request.args.get('createdAt__gt')
    end_time = request.args.get('createdAt__lt')
    
    # Filter by time range if provided
    filtered_vulnerabilities = filter_by_time_range(all_vulnerabilities, start_time, end_time)
    
    # Get pagination parameters
    page_size = int(request.args.get('page_size', 50))
    next_token_param = request.args.get('next_token') or request.args.get('nextToken')
    
    # Decode offset from next_token (base64 encoded)
    if next_token_param:
        try:
            offset = int(base64.b64decode(next_token_param).decode('utf-8'))
        except:
            offset = 0
    else:
        offset = 0
    
    # Get paginated results
    start_idx = offset
    end_idx = offset + page_size
    page_vulnerabilities = filtered_vulnerabilities[start_idx:end_idx]
    
    # Calculate next token
    has_more = end_idx < len(filtered_vulnerabilities)
    next_token = base64.b64encode(str(end_idx).encode('utf-8')).decode('utf-8') if has_more else None
    
    # Log pagination details
    print(f"TimeFilter: {start_time} to {end_time}")
    print(f"Offset: {offset}, Filtered Records: {len(filtered_vulnerabilities)}, Returned: {len(page_vulnerabilities)}, Has Next: {has_more}")
    
    # Return response
    response = {
        "vulnerabilities": page_vulnerabilities,
        "next_token": next_token,
        "total_filtered": len(filtered_vulnerabilities),
        "page_size": page_size,
        "offset": offset
    }
    
    return jsonify(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
