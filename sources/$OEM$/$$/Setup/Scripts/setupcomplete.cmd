:: :: :::::::::::::::::::: :: :: ::::::::::
: : WINDOWS 11 CLEAN INSTALL : : :::::::::
:::::::::::::::::::::::::::::::::::::::::::
 ::::::: packaged by d3ad connection :::::

:: Run setupcomplete.ps1
cd /d %~dp0
if exist setupcomplete.ps1 start /wait powershell -ex bypass -nol -noni -nop -f setupcomplete.ps1

:: Delete self
(goto) 2>nul & del "%~f0"
