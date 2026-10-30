Write-Host "================================================================" -ForegroundColor Yellow
Write-Host "  🛡️  AIndigo v1.00.00-beta | Enterprise Security & FinOps Suite" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Yellow

# Ensure clean start
& "D:\aindigo\stop-beta.ps1"
Start-Sleep -Seconds 1

Write-Host "☁️  Starting Cloud Control Plane on Port 3000..." -ForegroundColor Cyan
Start-Job -Name "AIndigoControlPlane" -ScriptBlock {
    Set-Location "D:\aindigo"
    $env:CLUSTER_SYNC_SECRET="aindigo-cluster-hmac-secret-key-2026-enterprise-verified"
    npx tsx packages\control-plane\src\index.ts
} | Out-Null

Start-Sleep -Seconds 2

Write-Host "⚡ Starting Local Data Plane Proxy on Port 8080..." -ForegroundColor Cyan
Start-Job -Name "AIndigoDataPlane" -ScriptBlock {
    Set-Location "D:\aindigo"
    $env:DATA_PLANE_MASTER_KEY="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    $env:CONTROL_PLANE_URL="http://127.0.0.1:3000"
    $env:CLUSTER_SYNC_SECRET="aindigo-cluster-hmac-secret-key-2026-enterprise-verified"
    npx tsx packages\data-plane\src\index.ts
} | Out-Null

Start-Sleep -Seconds 3

Write-Host "`n✅ AIndigo Beta Stack is LIVE:" -ForegroundColor Green
Write-Host "   • Control Plane UI & SIEM Center : http://127.0.0.1:3000" -ForegroundColor White
Write-Host "   • Data Plane AI Agent Proxy      : http://127.0.0.1:8080/v1" -ForegroundColor White
Write-Host "   • Stop All Services              : .\stop-beta.ps1`n" -ForegroundColor Gray
