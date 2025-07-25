@echo off
set archive=http://ftp.hosteurope.de/mirror/archive.mariadb.org//mariadb-%DB%/winx64-packages/mariadb-%DB%-winx64.msi
set last=http://mirror.i3d.net/pub/mariadb//mariadb-%DB%/winx64-packages/mariadb-%DB%-winx64.msi

curl -fLsS -o server.msi %archive%

if %ERRORLEVEL% == 0 goto end

curl -fLsS -o server.msi %last%
if %ERRORLEVEL% == 0  goto end

echo Failure Reason Given is %errorlevel%
exit /b %errorlevel%

:end
echo "File found".
