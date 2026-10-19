@echo off
REM =========================================================
REM  PhishGuard - Start All Services
REM  Double-click this file from ANYWHERE to start the project.
REM  It always finds the correct folder automatically.
REM =========================================================

REM Move to the folder where this .bat file lives (project root)
cd /d "%~dp0"

echo.
echo =========================================================
echo   PhishGuard - Starting Services
echo   Project folder: %~dp0
echo =========================================================
echo.

REM --- Check venv exists ---
if not exist "venv\Scripts\python.exe" (
    echo [ERROR] Virtual environment not found.
    echo.
    echo Please run these commands ONCE to set it up:
    echo   python -m venv venv
    echo   venv\Scripts\pip install -r ml-service\requirements.txt
    echo   venv\Scripts\pip install -r ml\requirements.txt
    echo   cd backend ^&^& npm install ^&^& cd ..
    echo.
    pause
    exit /b 1
)

REM --- Check model exists ---
if not exist "ml\models\phishing_model.pkl" (
    echo [ERROR] Trained model not found.
    echo.
    echo Train the model first (takes ~5 min):
    echo   venv\Scripts\python ml\train.py
    echo.
    pause
    exit /b 1
)

REM --- Check uvicorn ---
venv\Scripts\python.exe -c "import uvicorn" >nul 2>&1
if errorlevel 1 (
    echo [ERROR] uvicorn not installed. Installing now...
    venv\Scripts\pip install uvicorn fastapi
)

REM --- Check node_modules ---
if not exist "backend\node_modules" (
    echo [INFO] Installing Node.js dependencies...
    cd backend
    npm install
    cd ..
)

echo [1/2] Starting ML Service on http://localhost:8000 ...
start "PhishGuard ML Service" cmd /k "cd /d "%~dp0" && venv\Scripts\python.exe -m uvicorn ml-service.app:app --host 0.0.0.0 --port 8000"

echo     Waiting 4 seconds for ML service to load...
timeout /t 4 /nobreak >nul

echo [2/2] Starting Backend on http://localhost:3001 ...
start "PhishGuard Backend" cmd /k "cd /d "%~dp0" && node backend\server.js"

echo.
echo =========================================================
echo   Both services are starting in separate windows.
echo =========================================================
echo.
echo   Verify they are up (open in browser):
echo     ML Service : http://localhost:8000/health
echo     Backend    : http://localhost:3001/api/health
echo.
echo   To load the Chrome extension:
echo     1. Open Chrome - go to chrome://extensions
echo     2. Turn ON Developer mode (top-right toggle)
echo     3. Click "Load unpacked"
echo     4. Select this folder: %~dp0extension
echo     5. Pin the PhishGuard icon to the toolbar
echo =========================================================
echo.
pause
