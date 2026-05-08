@echo off
echo Setting up Phishing URL Detection Project...
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo Python is not installed or not in PATH. Please install Python first.
    pause
    exit /b
)

echo Installing required packages...
pip install -r requirements.txt

echo.
echo Starting the application...
echo Please open your browser and go to http://127.0.0.1:5000
echo.
python app.py

pause
