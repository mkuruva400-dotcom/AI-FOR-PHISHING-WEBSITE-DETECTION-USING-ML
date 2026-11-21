@echo off
title AI for Phishing Website Detection System
echo ======================================================================
echo    AI FOR PHISHING WEBSITE DETECTION USING ML & DEEP LEARNING
echo    Final-Year Engineering Capstone Project
echo ======================================================================
echo.

echo [1/3] Checking Python installation...
python --version
if errorlevel 1 (
    echo [ERROR] Python is not installed or not in PATH.
    pause
    exit /b
)

echo.
echo [2/3] Checking / Initializing database and models...
if not exist "instance\phishing_history.db" (
    echo Initializing database...
    python core\database.py
)

if not exist "ml_engine\saved_models\random_forest.pkl" (
    echo Training AI models (first-time setup)...
    python ml_engine\train_models.py
)

echo.
echo [3/3] Starting Flask Cybersecurity Application Server...
echo ----------------------------------------------------------------------
echo Access the Web Interface at: http://127.0.0.1:5000
echo ----------------------------------------------------------------------
echo.
python app.py

pause
