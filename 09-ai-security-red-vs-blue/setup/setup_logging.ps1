# Creates the log pipeline from the assistant to Microsoft Sentinel:
#   1. Custom table AIAssistant_CL in the Log Analytics workspace
#   2. Data Collection Rule (DCR) with its own logs ingestion endpoint
#   3. "Monitoring Metrics Publisher" role for your account on the DCR (permission to send logs)
#   4. Adds the endpoint and DCR id to .env
#
# Run from the project folder after `az login`:
#   .\setup\setup_logging.ps1

param(
    [string]$ResourceGroup = "rg-ai-secure-lab",
    [string]$Workspace = "ai-secure-lab-resource-logs",
    [string]$DcrName = "dcr-ai-assistant",
    [string]$Location = "swedencentral"
)

$Table = "AIAssistant_CL"
$Stream = "Custom-AIAssistant"

function Check($step) {
    if ($LASTEXITCODE -ne 0) { Write-Host "FAILED: $step" -ForegroundColor Red; exit 1 }
}

function Put-Json($url, $body) {
    # Write the body without BOM and send it with az rest
    $file = [System.IO.Path]::GetTempFileName()
    [System.IO.File]::WriteAllText($file, ($body | ConvertTo-Json -Depth 10))
    az rest --method put --url $url --body "@$file" --output none
    $code = $LASTEXITCODE
    Remove-Item $file
    $global:LASTEXITCODE = $code
}

# Columns of the table. Log Analytics tables use "dateTime", DCR streams use "datetime".
$columns = @(
    @{ name = "TimeGenerated";     type = "datetime" },
    @{ name = "Mode";              type = "string" },
    @{ name = "UserName";          type = "string" },
    @{ name = "Question";          type = "string" },
    @{ name = "RetrievedDocs";     type = "dynamic" },
    @{ name = "Answer";            type = "string" },
    @{ name = "Blocked";           type = "boolean" },
    @{ name = "BlockedBy";         type = "string" },
    @{ name = "DefensesTriggered"; type = "dynamic" },
    @{ name = "Leaks";             type = "dynamic" }
)
$tableColumns = $columns | ForEach-Object {
    @{ name = $_.name; type = $(if ($_.type -eq "datetime") { "dateTime" } else { $_.type }) }
}

Write-Host "1/4 Finding the Log Analytics workspace..." -ForegroundColor Cyan
$workspaceId = az monitor log-analytics workspace show -g $ResourceGroup -n $Workspace --query id -o tsv
Check "workspace $Workspace not found in $ResourceGroup"

Write-Host "2/4 Creating table $Table..." -ForegroundColor Cyan
$tableUrl = "https://management.azure.com$workspaceId/tables/${Table}?api-version=2022-10-01"
Put-Json $tableUrl @{
    properties = @{ schema = @{ name = $Table; columns = @($tableColumns) } }
}
Check "create table"
# Table creation runs in the background; the DCR needs the table to exist
for ($i = 0; $i -lt 30; $i++) {
    $state = az rest --method get --url $tableUrl --query "properties.provisioningState" -o tsv
    if ($state -eq "Succeeded") { break }
    Start-Sleep -Seconds 5
}

Write-Host "3/4 Creating data collection rule $DcrName..." -ForegroundColor Cyan
$subscriptionId = az account show --query id -o tsv
$dcrId = "/subscriptions/$subscriptionId/resourceGroups/$ResourceGroup/providers/Microsoft.Insights/dataCollectionRules/$DcrName"
$dcrUrl = "https://management.azure.com${dcrId}?api-version=2023-03-11"
Put-Json $dcrUrl @{
    location   = $Location
    kind       = "Direct"
    properties = @{
        streamDeclarations = @{ $Stream = @{ columns = @($columns) } }
        destinations       = @{ logAnalytics = @(@{ workspaceResourceId = $workspaceId; name = "law" }) }
        dataFlows          = @(@{
            streams      = @($Stream)
            destinations = @("law")
            transformKql = "source"
            outputStream = "Custom-$Table"
        })
    }
}
Check "create data collection rule"
$immutableId = az rest --method get --url $dcrUrl --query "properties.immutableId" -o tsv
$endpoint = az rest --method get --url $dcrUrl --query "properties.endpoints.logsIngestion" -o tsv
Check "read data collection rule"

Write-Host "4/4 Giving your account permission to send logs (Monitoring Metrics Publisher)..." -ForegroundColor Cyan
$userId = az ad signed-in-user show --query id -o tsv
Check "read signed-in user"
az role assignment create --assignee-object-id $userId --assignee-principal-type User `
    --role "Monitoring Metrics Publisher" --scope $dcrId --output none
Check "role assignment"

if (-not (Select-String -Path .env -Pattern "LOGS_INGESTION_ENDPOINT" -Quiet)) {
    Add-Content -Path .env -Value "LOGS_INGESTION_ENDPOINT=$endpoint"
    Add-Content -Path .env -Value "LOGS_DCR_IMMUTABLE_ID=$immutableId"
}

Write-Host ""
Write-Host "Done. Added to .env:" -ForegroundColor Green
Write-Host "  LOGS_INGESTION_ENDPOINT=$endpoint"
Write-Host "  LOGS_DCR_IMMUTABLE_ID=$immutableId"
Write-Host "The role can take up to 30 minutes to become active."
