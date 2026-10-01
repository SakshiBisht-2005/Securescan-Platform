@echo off
cd /d "%~dp0"
echo Starting SecureScan (website + API + Cloudflare). Do not run cloudflared yourself.
python start.py
pause
