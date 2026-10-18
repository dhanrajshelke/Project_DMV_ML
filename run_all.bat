@echo off
TITLE CyberSleuth Full-Stack Launcher (React + Java + Python ML)

echo =====================================================================
echo  🛡️ Launching CyberSleuth Full-Stack Platform
echo  1. Python ML & DMV Service (Port 5000)
echo  2. Java Spring Boot Backend (Port 8085)
echo  3. React Vite Frontend (Port 5173)
echo =====================================================================

:: Set Java Home to JDK 1.8
set "JAVA_HOME=C:\Program Files\Java\jdk1.8.0_481"
set "PATH=%JAVA_HOME%\bin;%PATH%"

echo [*] Starting Python ML & DMV Microservice...
start "CyberSleuth-Python-ML" cmd /k "python ml-service\app.py"

timeout /t 3 /nobreak >nul

echo [*] Starting Java Spring Boot Backend...
start "CyberSleuth-Java-Backend" cmd /k "cd server && mvn spring-boot:run"

timeout /t 5 /nobreak >nul

echo [*] Starting React Frontend...
start "CyberSleuth-React-UI" cmd /k "cd client && npm run dev"

echo.
echo =====================================================================
echo  🚀 All 3 Services Initialized!
echo  React Frontend:  http://localhost:5173
echo  Java REST API:   http://localhost:8085/api/health
echo  Python ML API:   http://localhost:5000/api/ml/health
echo =====================================================================
