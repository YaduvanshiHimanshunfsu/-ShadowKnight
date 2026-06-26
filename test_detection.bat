@echo off
echo Testing ShadowNet Detection...
echo Running wevtutil command...
wevtutil qe Application /c:1 /f:text
echo.
echo Command executed. Check ShadowNet for detection!
pause
