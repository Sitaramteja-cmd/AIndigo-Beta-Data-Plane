Write-Host "🛑 Stopping AIndigo Beta processes..." -ForegroundColor Yellow
Get-Job -Name "AIndigo*" -ErrorAction SilentlyContinue | Stop-Job -PassThru | Remove-Job -Force -ErrorAction SilentlyContinue

foreach ($port in @(3000, 8080)) {
    $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    foreach ($c in $conns) {
        if ($c.OwningProcess -gt 4) {
            Stop-Process -Id $c.OwningProcess -Force -ErrorAction SilentlyContinue
            Write-Host "   • Released Port $port (PID $($c.OwningProcess))" -ForegroundColor Gray
        }
    }
}
Write-Host "✅ All AIndigo processes stopped cleanly." -ForegroundColor Green
