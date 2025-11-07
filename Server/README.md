# cveBuster Flask API Server

This folder contains the mock vulnerability scanner API that demonstrates CCF pagination.

## Files

- **`app_paginated.py`** - Flask API server with pagination and time-based filtering
- **`generate_data.py`** - Test data generator (500 records, 30% recent/70% old)

## Quick Start

1. **Install dependencies:**
   ```bash
   pip install flask
   ```

2. **Generate test data:**
   ```bash
   python3 generate_data.py
   ```
   This creates `cvebuster_data.json` with 500 records.

3. **Run the API server:**
   ```bash
   python3 app_paginated.py
   ```
   Server runs on `http://0.0.0.0:5000`

4. **Test the API:**
   ```bash
   curl -H "Authorization: cvebuster-demo-key-12345" \
        "http://localhost:5000/api/vulnerabilities?page_size=50"
   ```

## API Endpoint

**GET** `/api/vulnerabilities`

**Headers:**
- `Authorization: cvebuster-demo-key-12345`

**Query Parameters:**
- `createdAt__gt` - Filter records after this ISO 8601 timestamp
- `createdAt__lt` - Filter records before this ISO 8601 timestamp
- `page_size` - Records per page (default: 50)
- `next_token` - Base64 encoded cursor for pagination

**Response:**
```json
{
  "vulnerabilities": [...],
  "next_token": "NTA=",
  "total_filtered": 168,
  "page_size": 50,
  "offset": 0
}
```

## How It Works

1. **Time Filtering**: Filters by `LastModified` field using `createdAt__gt` and `createdAt__lt`
2. **Pagination**: Returns 50 records per page with base64-encoded cursor
3. **Logging**: Prints pagination details to console for debugging

## Data Generation

The `generate_data.py` script creates:
- **500 total records**
- **30% recent** - LastModified within last 2 minutes
- **70% old** - LastModified 30-90 days ago

This distribution ensures that CCF's 5-minute polling window captures approximately 150 records, testing multi-page pagination (4 pages: 50+50+50+18).
