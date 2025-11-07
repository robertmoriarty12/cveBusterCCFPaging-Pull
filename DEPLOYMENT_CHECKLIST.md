# Deployment Checklist - cveBuster CCF Connector (with Pagination)

Use this checklist to track your progress deploying the cveBuster connector with pagination support following the documented CCF process.

## Phase 1: Git Environment Setup

- [ ] **Fork Azure-Sentinel repository** on GitHub
  - Visit: https://github.com/Azure/Azure-Sentinel
  - Click "Fork" button
  - Fork to your personal/organization account

- [ ] **Clone your fork locally**
  ```powershell
  git clone https://github.com/YOUR_USERNAME/Azure-Sentinel.git C:\GitHub\Azure-Sentinel
  ```

- [ ] **Create feature branch**
  ```powershell
  cd C:\GitHub\Azure-Sentinel
  git checkout -b feature/cvebuster-connector
  ```

- [ ] **Verify branch**
  ```powershell
  git branch
  # Should show: * feature/cvebuster-connector
  ```

## Phase 2: Solution Preparation

- [x] **Solution already prepared** (cveBusterSolutionPagination is ready to use)

- [ ] **Update BasePath in Solution_cveBuster.json** (if needed)
  - Open: `C:\GitHub\Azure-Sentinel\Solutions\cveBusterSolutionPagination\Data\Solution_cveBuster.json`
  - Change `BasePath` to: `"C:\\GitHub\\Azure-Sentinel\\Solutions\\cveBusterSolutionPagination"`

- [ ] **Verify folder structure**
  ```
  C:\GitHub\Azure-Sentinel\Solutions\cveBusterSolutionPagination\
  ├── Data\
  │   └── Solution_cveBuster.json
  ├── Data Connectors\
  │   └── cveBusterVulnerabilitiesLogs_ccf\
  │       ├── cveBuster_connectorDefinition.json
  │       ├── cveBuster_PollerConfig.json  (WITH PAGINATION CONFIG)
  │       ├── cveBuster_DCR.json
  │       └── cveBuster_Table.json
  ├── Package\
  ├── SolutionMetadata.json
  ├── README.md
  ├── QUICKSTART.md
  └── IMPLEMENTATION_SUMMARY.md
  ```

- [ ] **Validate JSON files**
  - Use JSON validator to check all `.json` files
  - Ensure no syntax errors

## Phase 3: Packaging

- [ ] **Navigate to packaging tool**
  ```powershell
  cd C:\GitHub\Azure-Sentinel\Tools\Create-Azure-Sentinel-Solution\V3
  ```

- [ ] **Run packaging script**
  ```powershell
  .\createSolutionV3.ps1 `
    -solutionName "cveBuster" `
    -inputFolderPath "C:\GitHub\Azure-Sentinel\Solutions\cveBuster" `
    -outputFolderPath "C:\GitHub\Azure-Sentinel\Solutions\cveBuster\Package"
  ```

- [ ] **Verify packaging output**
  - Check that `Package\mainTemplate.json` was created
  - Check that `Package\createUiDefinition.json` was created
  - Review console output for any errors or warnings

- [ ] **Inspect generated mainTemplate.json**
  - Open `C:\GitHub\Azure-Sentinel\Solutions\cveBuster\Package\mainTemplate.json`
  - Verify it contains:
    - Data connector resources
    - DCR resources
    - Table resources
    - Parameters section

## Phase 4: Pre-Deployment Verification

- [ ] **Verify Flask API is running**
  ```powershell
  Invoke-RestMethod -Uri "http://20.84.144.179:5000/health"
  # Should return: {"status": "healthy", ...}
  ```

- [ ] **Test API with authentication**
  ```powershell
  Invoke-RestMethod -Uri "http://20.84.144.179:5000/api/vulnerabilities" `
    -Headers @{Authorization="cvebuster-demo-key-12345"}
  # Should return JSON with vulnerability data
  ```

- [ ] **Verify Azure connection**
  ```powershell
  Connect-AzAccount
  Get-AzContext
  # Should show your subscription
  ```

- [ ] **Check Sentinel workspace exists**
  ```powershell
  $workspace = Get-AzOperationalInsightsWorkspace `
    -ResourceGroupName "rg-mssentinel-lab1" `
    -Name "sentinel-mt425li7vpf6w"
  Write-Host "Workspace ID: $($workspace.CustomerId)"
  ```

## Phase 5: Deployment

### Option A: Azure Portal Deployment

- [ ] **Navigate to custom deployment**
  - Go to: https://portal.azure.com/#create/Microsoft.Template

- [ ] **Load template**
  - Click "Build your own template in the editor"
  - Click "Load file"
  - Select `C:\GitHub\Azure-Sentinel\Solutions\cveBuster\Package\mainTemplate.json`
  - Click "Save"

- [ ] **Configure parameters**
  - **Subscription**: Select your subscription
  - **Resource Group**: `rg-mssentinel-lab1`
  - **Region**: (auto-selected)
  - **Workspace**: `sentinel-mt425li7vpf6w`
  - **Workspace-location**: `eastus` (or your region)

- [ ] **Review and deploy**
  - Click "Review + create"
  - Review resources to be created
  - Click "Create"
  - Wait for deployment to complete (5-10 minutes)

- [ ] **Verify deployment succeeded**
  - Check deployment status: "Your deployment is complete"
  - Review deployment outputs
  - Check for any errors

### Option B: PowerShell Deployment

- [ ] **Set deployment variables**
  ```powershell
  $resourceGroup = "rg-mssentinel-lab1"
  $workspaceName = "sentinel-mt425li7vpf6w"
  $location = "eastus"
  $templateFile = "C:\GitHub\Azure-Sentinel\Solutions\cveBuster\Package\mainTemplate.json"
  ```

- [ ] **Deploy template**
  ```powershell
  New-AzResourceGroupDeployment `
    -ResourceGroupName $resourceGroup `
    -TemplateFile $templateFile `
    -workspace $workspaceName `
    -location $location `
    -Verbose
  ```

- [ ] **Verify deployment output**
  - Check for "ProvisioningState : Succeeded"
  - Note any warnings or errors

## Phase 6: Connector Configuration

- [ ] **Navigate to Sentinel Data Connectors**
  - Go to Azure Portal → Microsoft Sentinel
  - Select your workspace: `sentinel-mt425li7vpf6w`
  - Click "Data connectors" in left menu

- [ ] **Find cveBuster connector**
  - Search for "cveBuster" in the search box
  - Connector should appear with your branding

- [ ] **Open connector page**
  - Click on "cveBuster Vulnerability Scanner"
  - Click "Open connector page"

- [ ] **Configure connection**
  - **API Endpoint URL**: `http://20.84.144.179:5000/api/vulnerabilities`
  - **API Key**: `cvebuster-demo-key-12345`
  - Click "Connect"

- [ ] **Verify connection status**
  - Status should change to "Connected"
  - Note the timestamp

## Phase 7: Verification & Testing

- [ ] **Wait for initial data** (5-10 minutes)

- [ ] **Check table exists**
  ```kql
  cveBusterVulnerabilities_CL
  | getschema
  ```

- [ ] **Verify data ingestion**
  ```kql
  cveBusterVulnerabilities_CL
  | take 10
  ```

- [ ] **Check data freshness**
  ```kql
  cveBusterVulnerabilities_CL
  | summarize 
      RecordCount = count(),
      LatestRecord = max(TimeGenerated),
      EarliestRecord = min(TimeGenerated)
  ```

- [ ] **Validate field mappings**
  ```kql
  cveBusterVulnerabilities_CL
  | project MachineName, VulnId, Severity, CVSS, TimeGenerated
  | take 5
  ```

- [ ] **Test sample queries from connector page**
  - Run each sample query provided
  - Verify results are as expected

- [ ] **Check Health Monitoring**
  - Sentinel → Settings → Health monitoring
  - Look for cveBuster connector
  - Verify no errors

- [ ] **Verify continuous polling**
  - Wait 5 minutes
  - Run query again
  - Check for new records with recent TimeGenerated

## Phase 8: Advanced Testing

- [ ] **Test severity filtering**
  ```kql
  cveBusterVulnerabilities_CL
  | summarize Count = count() by Severity
  | render piechart
  ```

- [ ] **Test exploit detection**
  ```kql
  cveBusterVulnerabilities_CL
  | where ExploitAvailable == true
  | project MachineName, VulnId, VulnTitle, CVSS
  ```

- [ ] **Test asset criticality analysis**
  ```kql
  cveBusterVulnerabilities_CL
  | summarize VulnCount = count() by MachineName, AssetCriticality
  | order by VulnCount desc
  ```

- [ ] **Verify DCR metrics**
  - Go to Azure Monitor → Data Collection Rules
  - Find cveBusterVulnerabilitiesDCR
  - Check "Metrics" for ingestion statistics

- [ ] **Check DCE logs**
  - Go to Azure Monitor → Data Collection Endpoints
  - Find the DCE created for cveBuster
  - Review activity logs

## Phase 9: Documentation

- [ ] **Document deployment date and version**
  - Record: Deployed on [DATE] - Version 1.0.0

- [ ] **Save configuration details**
  - API endpoint used
  - Workspace name
  - Resource group
  - Deployment method used

- [ ] **Create operational runbook**
  - How to refresh data
  - How to update connector
  - Troubleshooting steps

- [ ] **Document any issues encountered**
  - What went wrong
  - How it was resolved
  - Lessons learned

## Phase 10: Optional - Git Commit & PR

- [ ] **Stage changes**
  ```powershell
  git add Solutions/cveBuster/
  git status
  ```

- [ ] **Commit solution**
  ```powershell
  git commit -m "Add cveBuster CCF connector for vulnerability management"
  ```

- [ ] **Push to your fork**
  ```powershell
  git push origin feature/cvebuster-connector
  ```

- [ ] **Create Pull Request**
  - Go to your fork on GitHub
  - Click "Pull requests" → "New pull request"
  - Base: Azure/Azure-Sentinel main
  - Compare: YOUR_USERNAME/Azure-Sentinel feature/cvebuster-connector
  - Fill in PR template
  - Submit for review

- [ ] **Address review feedback**
  - Respond to technical validation comments
  - Make requested changes
  - Update PR

## Success Metrics

Mark as complete when ALL of the following are true:

- [ ] Connector appears in Sentinel Data Connectors gallery
- [ ] Configuration UI is functional and user-friendly
- [ ] Data successfully ingests every 5 minutes
- [ ] All 19 vulnerability fields populate correctly
- [ ] Sample queries return expected results
- [ ] Health monitoring shows no errors
- [ ] Documentation is complete and accurate
- [ ] Solution can be deployed to fresh workspace without issues

---

## Troubleshooting Reference

### Issue: Packaging fails
**Check:**
- BasePath in Solution_cveBuster.json
- JSON syntax in all files
- File naming matches CCF conventions

### Issue: Deployment fails
**Check:**
- Workspace name and resource group are correct
- You have Contributor permissions
- Template is valid ARM JSON
- No resource name conflicts

### Issue: Connector doesn't appear
**Check:**
- Deployment succeeded without errors
- Refresh Data connectors page
- Check resource deployment in Azure Portal

### Issue: No data appears
**Check:**
- API is accessible from Azure
- API key is correct
- DCR and DCE were created
- Table exists
- Wait full 10 minutes for initial data

---

## Completion Date

**Started**: _______________  
**Completed**: _______________  
**Deployed By**: _______________  
**Workspace**: _______________  
**Status**: ☐ Success  ☐ Partial  ☐ Failed

---

**Notes:**

____________________________________________

____________________________________________

____________________________________________

____________________________________________

____________________________________________
