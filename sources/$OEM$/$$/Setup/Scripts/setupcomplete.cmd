cd /d %~dp0
if exist setupcomplete.ps1 start /wait powershell -ex bypass -nol -noni -nop -f setupcomplete.ps1
(goto) 2>nul & del "%~f0"