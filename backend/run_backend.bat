@echo off
echo ============================================
echo  Django RAG Chatbot Backend Startup
echo ============================================

cd /d "%~dp0"

REM Check if virtual environment exists
if not exist "venv" (
    echo Creating virtual environment...
    python -m venv venv
)

REM Activate virtual environment
echo Activating virtual environment...
call venv\Scripts\activate.bat

REM Install/update requirements
echo Installing dependencies...
pip install -r requirements.txt

REM Check if .env exists
if not exist ".env" (
    echo ❌ ERROR: .env file not found!
    echo Please create a .env file with your API keys
    pause
    exit /b 1
)

REM Start the Flask server
echo.
echo Starting Django RAG Chatbot Backend...
echo Backend will be available at: http://localhost:5000
echo.
python app.py

pause
