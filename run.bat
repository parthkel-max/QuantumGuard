@echo off
title QuantumGuard Server
color 0B

echo.
echo  ==========================================
echo   QUANTUMGUARD - Post-Quantum Scanner
echo  ==========================================
echo.

java -version >nul 2>&1
if %errorlevel% neq 0 (
    echo  [ERROR] Java not found. Download Java 17+ from https://adoptium.net
    pause & exit /b
)

if not exist "lib\bcprov-jdk18on-1.83.jar" (
    echo  [ERROR] Missing: lib\bcprov-jdk18on-1.83.jar
    pause & exit /b
)
if not exist "lib\json-20240303.jar" (
    echo  [ERROR] Missing: lib\json-20240303.jar
    pause & exit /b
)
if not exist "src\rules.json" (
    echo  [ERROR] Missing: src\rules.json
    pause & exit /b
)
if not exist "src\index.html" (
    echo  [ERROR] Missing: src\index.html
    pause & exit /b
)

if not exist "bin" mkdir bin

echo  [1/2] Compiling...
javac -cp ".;lib\bcprov-jdk18on-1.83.jar;lib\json-20240303.jar" src\ScannerService.java src\QuantumGuardServer.java -d bin

if %errorlevel% neq 0 (
    echo.
    echo  [ERROR] Compilation failed. See error above.
    pause & exit /b
)

echo  [2/2] Starting server...
echo.
echo  ==========================================
echo   Open: http://localhost:8080
echo   Press Ctrl+C to stop
echo  ==========================================
echo.

java -cp "bin;lib\bcprov-jdk18on-1.83.jar;lib\json-20240303.jar" QuantumGuardServer
pause