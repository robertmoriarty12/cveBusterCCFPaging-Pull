# cveBuster Microsoft Sentinel CCF Connector with Pagination

A production-ready Codeless Connector Framework (CCF) solution demonstrating NextPageToken pagination with time-based filtering for Microsoft Sentinel. This connector ingests vulnerability data from a REST API with automatic deduplication and multi-page handling.

## What This Project Demonstrates

This solution showcases the **SentinelOne pattern** for CCF connectors:
- ✅ **NextPageToken Pagination** - Handles large datasets (500+ records) across multiple pages
- ✅ **Time-Based Filtering** - Only fetches new/modified records using `startTimeAttributeName` and `endTimeAttributeName`
- ✅ **Automatic Deduplication** - Prevents duplicate ingestion on subsequent 5-minute polls
- ✅ **Production Architecture** - Data Collection Rules (DCR), custom Log Analytics table, proper error handling

**Proven Results:**
- Successfully pages through 168 records across 4 API calls (50+50+50+18)
- Time filters correctly to only fetch records modified in 5-minute query window
- Zero duplicates on subsequent polls

## Key Components

### 1. CCF Configuration (`Data Connectors/cveBusterVulnerabilitiesLogs_ccf/`)
- **cveBuster_PollerConfig.json** - Critical configuration with:
  ```json
  "request": {
    "startTimeAttributeName": "createdAt__gt",
    "endTimeAttributeName": "createdAt__lt",
    "queryWindowInMin": 5
  },
  "paging": {
    "pagingType": "NextPageToken",
    "NextPageParaName": "next_token",
    "PageSize": "50",
    "PageSizeParameterName": "page_size"
  }
  ```
- **cveBuster_connectorDefinition.json** - UI configuration
- **cveBuster_DCR.json** - Data Collection Rule with 19-field schema
- **cveBuster_Table.json** - Custom table definition

### 2. Flask API Server (`app_paginated.py`)
Mock API demonstrating proper pagination and time filtering:
- Returns JSON with `data`, `next_token`, `total_count`
- Supports `createdAt__gt`, `createdAt__lt`, `page_size`, `next_token` parameters
- Filters 500 vulnerability records by `LastModified` timestamp
- Base64-encoded cursor pagination

### 3. Data Generator (`generate_data.py`)
Creates test data with realistic distribution:
- 500 total vulnerability records
- 30% with `LastModified` in last 2 minutes (for testing)
- 70% with old `LastModified` timestamps (30-90 days ago)

## Quick Start

### Prerequisites
- Microsoft Sentinel workspace
- Azure subscription with Contributor permissions
- PowerShell with Az modules
- Python 3.x (for test API server)

### Deploy in 5 Steps

**1. Package the Solution**
```powershell
cd C:\GitHub\Azure-Sentinel\Tools\Create-Azure-Sentinel-Solution\V3
.\createSolutionV3.ps1 `
  -packageConfigPath "C:\GitHub\Azure-Sentinel\Solutions\cveBusterSolutionPagination\Data\Solution_cveBuster.json" `
  -outputFolderPath "C:\GitHub\Azure-Sentinel\Solutions\cveBusterSolutionPagination\Package"
```

**2. Deploy to Azure**
```powershell
New-AzResourceGroupDeployment `
  -ResourceGroupName "your-rg" `
  -TemplateFile "C:\GitHub\Azure-Sentinel\Solutions\cveBusterSolutionPagination\Package\mainTemplate.json" `
  -workspace "your-sentinel-workspace-name" `
  -apiEndpoint "http://YOUR_API:5000/api/vulnerabilities" `
  -apiKey "your-api-key"
```

**3. Start Test API Server** (optional for testing)
```bash
cd ~/cveBusterCCFPaging-Pull
python3 generate_data.py
python3 app_paginated.py
```

**4. Verify Data Flow**
Check Flask logs for pagination in action:
```
[API] Request - TimeFilter: 2025-11-07T00:46:35Z to 2025-11-07T00:51:35Z, Offset: 0, Page Size: 50, Filtered Records: 168, Returned: 50, Has Next: True
[API] Request - TimeFilter: 2025-11-07T00:46:35Z to 2025-11-07T00:51:35Z, Offset: 50, Page Size: 50, Filtered Records: 168, Returned: 50, Has Next: True
[API] Request - TimeFilter: 2025-11-07T00:46:35Z to 2025-11-07T00:51:35Z, Offset: 100, Page Size: 50, Filtered Records: 168, Returned: 50, Has Next: True
[API] Request - TimeFilter: 2025-11-07T00:46:35Z to 2025-11-07T00:51:35Z, Offset: 150, Page Size: 50, Filtered Records: 168, Returned: 18, Has Next: False
```

**5. Query in Sentinel**
```kql
cveBusterVulnerabilities_CL
| where TimeGenerated > ago(1h)
| summarize count() by Severity
```

## Implementation Details

### Critical Configuration: PollerConfig.json

The key to making pagination AND time-based filtering work together:

```json
{
  "request": {
    "apiEndpoint": "[[parameters('apiEndpoint')]",
    "queryWindowInMin": 5,
    "queryTimeFormat": "yyyy-MM-ddTHH:mm:ssZ",
    "startTimeAttributeName": "createdAt__gt",  // Critical!
    "endTimeAttributeName": "createdAt__lt",    // Critical!
    "httpMethod": "GET"
  },
  "paging": {
    "pagingType": "NextPageToken",
    "nextPageTokenJsonPath": "$.next_token",
    "NextPageParaName": "next_token",
    "PageSize": "50",
    "PageSizeParameterName": "page_size"
  }
}
```

**Important:** Use `startTimeAttributeName` / `endTimeAttributeName` instead of `queryParameters` for time filtering. This ensures CCF sends the time parameters correctly.

### API Response Format

Your API must return this structure:

```json
{
  "data": [...],           // Array of records
  "next_token": "NTA=",    // Base64 cursor, null on last page
  "total_count": 500,      // Total records available
  "page_size": 50,         // Records per page
  "records_in_page": 50    // Records in current page
}
```

### Data Schema (19 Fields)

The custom table includes vulnerability details, asset information, and timestamps for proper time-based filtering.

## Sample KQL Queries

**Find recent ingestions:**
```kql
cveBusterVulnerabilities_CL
| where TimeGenerated > ago(1h)
| summarize count() by Severity
```

**Critical vulnerabilities with exploits:**
```kql
cveBusterVulnerabilities_CL
| where Severity == "Critical" and ExploitAvailable == true
| project MachineName, VulnId, CVSS, LastModified
| order by CVSS desc
```

**Verify time-based filtering (no duplicates):**
```kql
cveBusterVulnerabilities_CL
| summarize count() by bin(TimeGenerated, 5m)
| render timechart
// Should show spikes only when data is modified, not every 5 minutes
```

## Troubleshooting

**No data appearing:**
- Check Flask server logs for incoming CCF requests
- Verify `startTimeAttributeName` and `endTimeAttributeName` are set (not `queryParameters`)
- Test API manually: `Invoke-RestMethod -Uri "http://YOUR_IP:5000/api/vulnerabilities" -Headers @{Authorization="your-key"}`

**Only getting 50 records (no pagination):**
- Check Flask logs - you should see multiple requests with different `next_token` values
- Verify API returns `next_token` in response JSON
- Ensure `NextPageParaName` matches your API's parameter name

**Getting duplicate data every 5 minutes:**
- This means time filtering isn't working
- Verify `startTimeAttributeName` and `endTimeAttributeName` are configured
- Check Flask logs show `TimeFilter:` in requests
- Make sure API filters by `LastModified` field before returning data

**Packaging errors:**
- Ensure `Solution_cveBuster.json` Name field matches folder name exactly
- Delete Package folder and rebuild from scratch
- Check all JSON files are valid

## How It Works: The SentinelOne Pattern

**Request Flow:**
1. CCF polls every 5 minutes with time window: `?createdAt__gt=START&createdAt__lt=END`
2. Flask API filters 500 records → finds records with `LastModified` in that window
3. Returns first 50 records + `next_token`
4. CCF automatically requests next page: `?createdAt__gt=START&createdAt__lt=END&next_token=NTA=`
5. Repeats until `next_token` is null
6. Next poll (5 min later) uses NEW time window → only fetches newly modified records

**Result:** No duplicates, efficient data transfer, production-ready! 🎯

## References

- [Microsoft CCF Documentation](https://learn.microsoft.com/en-us/azure/sentinel/create-codeless-connector)
- [CCF Paging Reference](https://learn.microsoft.com/en-us/azure/sentinel/data-connector-connection-rules-reference#paging-configuration)
- [SentinelOne Connector Example](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/SentinelOne)

## License

This is a demonstration project for educational purposes.

**How it works**:
1. Connector makes initial request to `/api/vulnerabilities`
2. API returns data with `next_token` field
3. Connector automatically requests `/api/vulnerabilities?next_token=xxx`
4. Process repeats until no `next_token` is returned
5. All records are ingested in a single polling cycle

## Key Differences from Manual Deployment

| Aspect | Manual (Your Current) | Documented CCF Process |
|--------|----------------------|------------------------|
| **File Structure** | Flat JSON files | Nested folder structure with naming conventions |
| **Packaging** | PowerShell script | Microsoft packaging tool (createSolutionV3.ps1) |
| **Deployment** | Custom ARM template | Generated mainTemplate.json |
| **Connector UI** | Manual API calls | Integrated in Sentinel Data Connectors gallery |
| **Updates** | Redeploy all | Incremental changes + packaging |
| **Publishing** | N/A | Can submit PR to Azure-Sentinel repo |

## Next Steps

1. **Create Analytics Rules** - Detect critical vulnerabilities
2. **Build Workbooks** - Visualize trends
3. **Set up Automation** - Auto-remediate with Logic Apps
4. **Submit to Content Hub** (Optional):
   - Commit changes to your branch
   - Push to your fork
   - Submit PR to Azure/Azure-Sentinel
   - Address technical validation feedback

## References

- [Microsoft Sentinel Codeless Connector Documentation](https://learn.microsoft.com/en-us/azure/sentinel/create-codeless-connector)
- [CCF Packaging Tool Guidance](https://github.com/Azure/Azure-Sentinel/blob/master/Tools/Create-Azure-Sentinel-Solution/V3/CCF_README.md)
- [SentinelOne Reference Connector](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions/SentinelOne)
- [Solutions Build Guide](https://github.com/Azure/Azure-Sentinel/tree/master/Solutions)

## Support

For issues or questions:
- Review the troubleshooting section above
- Check Azure Monitor DCR logs
- Test API connectivity from Azure Cloud Shell
- Review [Microsoft Sentinel Documentation](https://learn.microsoft.com/en-us/azure/sentinel/)

---

**Version**: 2.0.0 (Pagination-Enabled)  
**Last Updated**: November 5, 2025  
**Note**: This is a testing variant with pagination support. The production version is at `Solutions\cveBuster`
