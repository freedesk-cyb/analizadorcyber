@echo off
title AI Web Security Analyzer - Centro de Mando de Ciberseguridad
echo =====================================================================
echo           AI WEB SECURITY ANALYZER - CENTRO DE CIBERDEFENSA
echo =====================================================================
echo.
echo [*] Iniciando servidor FastAPI en http://127.0.0.1:8000 ...
echo.

if exist "C:\Users\OMAR\AppData\Local\Python\bin\python.exe" (
    "C:\Users\OMAR\AppData\Local\Python\bin\python.exe" main.py
) else (
    python main.py
)

pause
