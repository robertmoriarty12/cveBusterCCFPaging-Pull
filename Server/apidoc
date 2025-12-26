# bustCVE API Documentation

## Overview

bustCVE is a REST API service that provides vulnerability scan data for integration with Microsoft Sentinel and other security platforms. The API returns comprehensive vulnerability information including CVE details, CVSS scores, asset information, patch availability, and exploit intelligence.

**API Base URL:** `http://20.12.242.149/api`

**Current Version:** 1.0.0

**Authentication:** API Key (Bearer Token)

---

## Table of Contents

1. [Authentication](#authentication)
2. [Core Endpoints](#core-endpoints)
3. [Data Models](#data-models)
4. [Query Parameters](#query-parameters)
5. [Pagination](#pagination)
6. [Time-Based Filtering](#time-based-filtering)
7. [Response Format](#response-format)
8. [Error Handling](#error-handling)
9. [Rate Limiting](#rate-limiting)
10. [Examples](#examples)

---

## Authentication

All requests to the bustCVE API require authentication via an API Key passed in the `Authorization` header.

### Header Format

```
Authorization: <API_KEY>
```

### Example

```bash
curl -H "Authorization: cvebuster-demo-key-12345" \
  http://20.12.242.149/api/vulnerabilities
```

### Error Response

```json
{
  "error": "Unauthorized"
}
```

**HTTP Status:** `401 Unauthorized`

---

## Core Endpoints

### GET /api/vulnerabilities

Retrieves vulnerability records with support for pagination and time-based filtering.

**Method:** `GET`

**URL:** `/api/vulnerabilities`

**Authentication:** Required

**Description:**
Returns a paginated list of vulnerability records from the bustCVE database. Each record represents a detected vulnerability on a scanned asset, including asset information, vulnerability details, and remediation status.

#### Request Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `page_size` | integer | No | Number of records to return per page. Default: `50`. Max: `1000`. |
| `next_token` | string | No | Pagination token for fetching the next page of results. Returned in previous response. |
| `createdAt__gt` | string (ISO 8601) | No | Return records modified after this timestamp (greater than). Format: `YYYY-MM-DDTHH:MM:SSZ` |
| `createdAt__lt` | string (ISO 8601) | No | Return records modified before this timestamp (less than). Format: `YYYY-MM-DDTHH:MM:SSZ` |

#### Response

**HTTP Status:** `200 OK`

```json
{
  "vulnerabilities": [
    {
      "MachineName": "ProdServer03",
      "HostId": "5e297337-1e4b-4115-8610-df6d2842ef50",
      "IPAddress": "172.16.2.128",
      "OSFamily": "SUSE Linux Enterprise 15",
      "Application": "Grafana",
      "AppFilePath": "/usr/share/grafana",
      "VulnId": "CVE-2021-3156",
      "VulnTitle": "Sudo Baron Samedit",
      "Severity": "High",
      "CVSS": 7.8,
      "ExploitAvailable": false,
      "ExploitedInWild": false,
      "PatchAvailable": true,
      "FirstSeen": "2025-09-20T19:37:20Z",
      "LastSeen": "2025-10-18T19:37:20Z",
      "LastScanTime": "2025-11-06T19:37:20Z",
      "LastModified": "2025-08-22T19:37:20Z",
      "AssetCriticality": "Critical",
      "BusinessOwner": "Database-Team",
      "Source": "cveBuster:demo"
    }
  ],
  "next_token": "MTA=",
  "total_filtered": 150,
  "page_size": 50,
  "offset": 0
}
```

---

## Data Models

### Vulnerability Object

Represents a single vulnerability finding on an asset.

| Field | Type | Description |
|-------|------|-------------|
| `MachineName` | string | Hostname or device name of the scanned asset. Example: `ProdServer03` |
| `HostId` | string | Unique identifier (UUID) for the host. Example: `5e297337-1e4b-4115-8610-df6d2842ef50` |
| `IPAddress` | string | IPv4 address of the scanned asset. Example: `172.16.2.128` |
| `OSFamily` | string | Operating system and version. Example: `Ubuntu 18.04`, `Windows Server 2019` |
| `Application` | string | Name of the vulnerable software/application. Example: `Grafana`, `Apache`, `OpenSSL` |
| `AppFilePath` | string | File system path where the vulnerable application is installed. Example: `/usr/share/grafana`, `C:\Program Files\Apache\Apache24` |
| `VulnId` | string | Common Vulnerabilities and Exposures identifier. Format: `CVE-YYYY-NNNNN`. Example: `CVE-2021-3156` |
| `VulnTitle` | string | Human-readable vulnerability name/description. Example: `Sudo Baron Samedit` |
| `Severity` | string | Vulnerability severity level. Valid values: `Critical`, `High`, `Medium`, `Low` |
| `CVSS` | number (float) | CVSS v3.1 base score. Range: `0.0` - `10.0`. Example: `7.8` |
| `ExploitAvailable` | boolean | Indicates if a public exploit or proof-of-concept is publicly available. |
| `ExploitedInWild` | boolean | Indicates if active exploitation in the wild has been detected or reported. |
| `PatchAvailable` | boolean | Indicates if a vendor patch or update is available. |
| `FirstSeen` | string (ISO 8601) | Timestamp when vulnerability was first detected on this asset. Format: `YYYY-MM-DDTHH:MM:SSZ` |
| `LastSeen` | string (ISO 8601) | Timestamp when vulnerability was most recently confirmed on this asset. Format: `YYYY-MM-DDTHH:MM:SSZ` |
| `LastScanTime` | string (ISO 8601) | Timestamp of the most recent vulnerability scan on this asset. Format: `YYYY-MM-DDTHH:MM:SSZ` |
| `LastModified` | string (ISO 8601) | Timestamp when this vulnerability record was last modified. Used for incremental synchronization. Format: `YYYY-MM-DDTHH:MM:SSZ` |
| `AssetCriticality` | string | Business criticality classification of the asset. Valid values: `Critical`, `High`, `Medium`, `Low` |
| `BusinessOwner` | string | Team or department responsible for the asset. Example: `Database-Team`, `Infrastructure`, `Platform-Team` |
| `Source` | string | Data source identifier. Example: `cveBuster:demo` |

---

## Query Parameters

### page_size

Controls the number of records returned in a single API response.

| Property | Value |
|----------|-------|
| **Type** | integer |
| **Default** | `50` |
| **Minimum** | `1` |
| **Maximum** | `1000` |
| **Description** | Number of vulnerability records to return per page. Larger page sizes reduce the number of API calls required but increase response payload size. |

**Example:**
```
GET /api/vulnerabilities?page_size=100
```

### next_token

Pagination token for retrieving subsequent pages of results.

| Property | Value |
|----------|-------|
| **Type** | string |
| **Format** | Base64-encoded offset value |
| **Description** | Opaque token returned in the previous API response. Pass this token to retrieve the next page of results. |

**Example:**
```
GET /api/vulnerabilities?next_token=MTA=&page_size=50
```

### createdAt__gt (Greater Than)

Filter to return only records modified after the specified timestamp.

| Property | Value |
|----------|-------|
| **Type** | string (ISO 8601 datetime) |
| **Format** | `YYYY-MM-DDTHH:MM:SSZ` |
| **Description** | Returns vulnerability records where `LastModified` timestamp is **greater than** the specified value. Useful for incremental/delta synchronization. |

**Example:**
```
GET /api/vulnerabilities?createdAt__gt=2025-11-06T10:00:00Z
```

### createdAt__lt (Less Than)

Filter to return only records modified before the specified timestamp.

| Property | Value |
|----------|-------|
| **Type** | string (ISO 8601 datetime) |
| **Format** | `YYYY-MM-DDTHH:MM:SSZ` |
| **Description** | Returns vulnerability records where `LastModified` timestamp is **less than** the specified value. |

**Example:**
```
GET /api/vulnerabilities?createdAt__lt=2025-11-06T15:00:00Z
```

### Combined Time Range Filter

Both `createdAt__gt` and `createdAt__lt` can be used together to query a specific time window.

**Example:**
```
GET /api/vulnerabilities?createdAt__gt=2025-11-06T10:00:00Z&createdAt__lt=2025-11-06T15:00:00Z&page_size=100
```

---

## Pagination

The bustCVE API uses cursor-based pagination via the `next_token` parameter, enabling efficient retrieval of large datasets.

### How Pagination Works

1. **Initial Request:** Call the API without a `next_token` parameter
2. **Response:** Receives `page_size` records plus a `next_token` for the next page
3. **Subsequent Requests:** Include the `next_token` in the next request
4. **End of Results:** When `next_token` is `null`, all pages have been retrieved

### Pagination Response Fields

| Field | Type | Description |
|-------|------|-------------|
| `vulnerabilities` | array | Array of vulnerability records for the current page. |
| `next_token` | string or null | Token for retrieving the next page. `null` when no more pages exist. |
| `total_filtered` | integer | Total number of records matching the query filters (across all pages). |
| `page_size` | integer | Number of records requested in this page. |
| `offset` | integer | Zero-based offset of the first record in the current page. |

### Example Pagination Flow

**Request 1 (First Page):**
```bash
curl -H "Authorization: cvebuster-demo-key-12345" \
  "http://20.12.242.149/api/vulnerabilities?page_size=50"
```

**Response 1:**
```json
{
  "vulnerabilities": [...50 records...],
  "next_token": "NTA=",
  "total_filtered": 500,
  "page_size": 50,
  "offset": 0
}
```

**Request 2 (Next Page):**
```bash
curl -H "Authorization: cvebuster-demo-key-12345" \
  "http://20.12.242.149/api/vulnerabilities?page_size=50&next_token=NTA="
```

**Response 2:**
```json
{
  "vulnerabilities": [...50 records...],
  "next_token": "MTAw",
  "total_filtered": 500,
  "page_size": 50,
  "offset": 50
}
```

---

## Time-Based Filtering

Time-based filtering enables incremental/delta synchronization, allowing you to query only records modified within a specific time window.

### Use Cases

- **Incremental Sync:** Poll the API every 5 minutes, requesting only changes since the last synchronization
- **Backfill:** Retrieve historical vulnerability data from a specific date range
- **Real-time Integration:** Stream new/updated vulnerabilities as they're discovered

### Filter Behavior

The API filters records based on the `LastModified` timestamp:

- **`createdAt__gt`:** Includes records where `LastModified > specified_time`
- **`createdAt__lt`:** Includes records where `LastModified < specified_time`

### Important Notes

⚠️ **Filter Logic:** Both filters use strict comparison (`>` and `<`), not inclusive (`>=`, `<=`). Records with timestamps exactly equal to the filter values are excluded.

⚠️ **LastModified Semantics:** The `LastModified` field represents when the vulnerability record was last updated in the system, not necessarily when the vulnerability was discovered.

### Example: 5-Minute Window Query

```bash
# Query for records modified in the past 5 minutes
START_TIME=$(date -u -d '5 minutes ago' '+%Y-%m-%dT%H:%M:%SZ')
END_TIME=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

curl -H "Authorization: cvebuster-demo-key-12345" \
  "http://20.12.242.149/api/vulnerabilities?createdAt__gt=$START_TIME&createdAt__lt=$END_TIME&page_size=100"
```

---

## Response Format

### Success Response

All successful responses return HTTP status `200 OK` with a JSON object containing:

```json
{
  "vulnerabilities": [
    {
      "MachineName": "...",
      "HostId": "...",
      ...
    }
  ],
  "next_token": "...",
  "total_filtered": 500,
  "page_size": 50,
  "offset": 0
}
```

### Content-Type

```
Content-Type: application/json
```

### Response Headers

```
Content-Type: application/json
Connection: keep-alive
```

---

## Error Handling

### Error Response Format

All error responses include a JSON object with an `error` field describing the issue:

```json
{
  "error": "Error message describing the issue"
}
```

### Common Error Scenarios

#### 401 Unauthorized

**Cause:** Missing or invalid API key

**HTTP Status:** `401`

**Response:**
```json
{
  "error": "Unauthorized"
}
```

**Resolution:** Verify the API key is correct and included in the `Authorization` header.

#### 400 Bad Request

**Cause:** Invalid query parameters (e.g., malformed datetime, invalid page_size)

**HTTP Status:** `400`

**Response:**
```json
{
  "error": "Invalid page_size parameter"
}
```

**Resolution:** Validate query parameter formats and values.

#### 500 Internal Server Error

**Cause:** Server-side error (e.g., data file not found)

**HTTP Status:** `500`

**Response:**
```json
{
  "error": "Data file not found"
}
```

**Resolution:** Contact API support and provide the timestamp of the request.

### Best Practices

- **Implement Retry Logic:** For 5xx errors, implement exponential backoff retry (3 retries recommended)
- **Validate Timestamps:** Ensure datetime parameters are in valid ISO 8601 format
- **Check Status Codes:** Always verify HTTP status before processing response body

---

## Rate Limiting

The bustCVE API implements rate limiting to ensure fair usage and service stability.

### Rate Limits

| Limit Type | Threshold | Window |
|------------|-----------|--------|
| Requests per Second | 10 | Per-IP |
| Concurrent Connections | 5 | Per-IP |

### Best Practices

- **Batch Requests:** Use larger `page_size` values to reduce the number of API calls
- **Implement Backoff:** If rate limited (429 response), wait 60 seconds before retrying
- **Cache Results:** Cache vulnerability data locally to minimize repeated queries
- **Pagination:** Use cursor-based pagination to efficiently retrieve large datasets

---

## Examples

### Example 1: Retrieve First Page of Vulnerabilities

**Request:**
```bash
curl -H "Authorization: cvebuster-demo-key-12345" \
  "http://20.12.242.149/api/vulnerabilities?page_size=10"
```

**Response:**
```json
{
  "vulnerabilities": [
    {
      "MachineName": "ProdServer03",
      "HostId": "5e297337-1e4b-4115-8610-df6d2842ef50",
      "IPAddress": "172.16.2.128",
      "OSFamily": "SUSE Linux Enterprise 15",
      "Application": "Grafana",
      "AppFilePath": "/usr/share/grafana",
      "VulnId": "CVE-2021-3156",
      "VulnTitle": "Sudo Baron Samedit",
      "Severity": "High",
      "CVSS": 7.8,
      "ExploitAvailable": false,
      "ExploitedInWild": false,
      "PatchAvailable": true,
      "FirstSeen": "2025-09-20T19:37:20Z",
      "LastSeen": "2025-10-18T19:37:20Z",
      "LastScanTime": "2025-11-06T19:37:20Z",
      "LastModified": "2025-08-22T19:37:20Z",
      "AssetCriticality": "Critical",
      "BusinessOwner": "Database-Team",
      "Source": "cveBuster:demo"
    }
  ],
  "next_token": "MTA=",
  "total_filtered": 500,
  "page_size": 10,
  "offset": 0
}
```

### Example 2: Retrieve Records with 5-Minute Time Window

**Request:**
```bash
curl -H "Authorization: cvebuster-demo-key-12345" \
  "http://20.12.242.149/api/vulnerabilities?createdAt__gt=2025-11-06T10:00:00Z&createdAt__lt=2025-11-06T10:05:00Z&page_size=50"
```

**Use Case:** Microsoft Sentinel REST API poller configured with 5-minute query window (queryWindowInMin: 5)

### Example 3: Iterate Through All Pages

**Pseudo-code:**
```python
import requests
import json

api_key = "cvebuster-demo-key-12345"
api_endpoint = "http://20.12.242.149/api/vulnerabilities"
all_records = []
next_token = None

while True:
    params = {"page_size": 100}
    if next_token:
        params["next_token"] = next_token
    
    headers = {"Authorization": api_key}
    response = requests.get(api_endpoint, params=params, headers=headers)
    
    if response.status_code != 200:
        print(f"Error: {response.json()['error']}")
        break
    
    data = response.json()
    all_records.extend(data["vulnerabilities"])
    
    next_token = data.get("next_token")
    if not next_token:
        break

print(f"Total records retrieved: {len(all_records)}")
```

### Example 4: Integration with Microsoft Sentinel CCF Connector

**REST API Poller Configuration:**
```json
{
  "kind": "RestApiPoller",
  "properties": {
    "connectorDefinitionName": "bustCveConnector",
    "dataType": "bustCVE Vulnerabilities",
    "request": {
      "apiEndpoint": "http://20.12.242.149/api/vulnerabilities",
      "httpMethod": "GET",
      "queryWindowInMin": 5,
      "queryTimeFormat": "yyyy-MM-ddTHH:mm:ssZ",
      "startTimeAttributeName": "createdAt__gt",
      "endTimeAttributeName": "createdAt__lt",
      "headers": {
        "Accept": "application/json",
        "User-Agent": "bustCVE-Sentinel-Connector/1.0"
      }
    },
    "paging": {
      "pagingType": "NextPageToken",
      "PageSize": 50,
      "PageSizeParameterName": "page_size",
      "NextPageTokenJsonPath": "$.next_token",
      "NextPageParaName": "next_token"
    },
    "response": {
      "eventsJsonPaths": [
        "$.vulnerabilities"
      ]
    }
  }
}
```

---

## Support & Feedback

For issues, questions, or feature requests, please contact:

- **Email:** support@bustcve.com
- **Documentation:** https://docs.bustcve.com
- **Status Page:** https://status.bustcve.com

---

## Changelog

### Version 1.0.0 (2025-11-06)

- Initial release of bustCVE API
- Vulnerability endpoint with pagination support
- Time-based filtering for incremental synchronization
- Support for Microsoft Sentinel REST API Poller integration

---

## License

bustCVE API is provided under the [MIT License](LICENSE).
