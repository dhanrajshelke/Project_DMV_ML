# CyberSleuth Full-Stack PowerShell Launcher
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host " 🛡️ Starting CyberSleuth Full-Stack Platform" -ForegroundColor Green
Write-Host " React (5173) + Java Spring Boot (8085) + Python ML (5000)" -ForegroundColor White
Write-Host "=====================================================================" -ForegroundColor Cyan

$env:JAVA_HOME = "C:\Program Files\Java\jdk1.8.0_481"
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"

Write-Host "[1/3] Starting Python ML & DMV Microservice on Port 5000..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "python ml-service\app.py"

Start-Sleep -Seconds 3

Write-Host "[2/3] Starting Java Spring Boot Backend on Port 8085..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "`$env:JAVA_HOME='C:\Program Files\Java\jdk1.8.0_481'; Set-Location server; mvn spring-boot:run"

Start-Sleep -Seconds 5

Write-Host "[3/3] Starting React Vite Frontend on Port 5173..." -ForegroundColor Yellow
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location client; npm.cmd run dev"

Write-Host ""
Write-Host "🚀 All services launched in separate windows!" -ForegroundColor Green
Write-Host "Open React App: http://localhost:5173" -ForegroundColor Cyan
