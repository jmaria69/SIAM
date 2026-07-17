@echo off
setlocal enabledelayedexpansion
title SIEM: PANEL DE CONTROL

REM Nota (2026-07-06): docker-compose corre SIEMPRE via WSL (wsl.exe -e bash
REM -lc "cd ~/proyectosIA/SIAM && docker compose ..."), nunca directo desde
REM cmd.exe. Motivo, ya sufrido y corregido en GWS/CLEO_MENU.bat: el proyecto
REM vive en una ruta UNC (\\wsl.localhost\...) y el volumen ".:/app" de
REM docker-compose.yml es un bind-mount -- si docker-compose se lanza desde
REM cmd.exe, Docker Desktop no puede traducir esa ruta (falla con
REM "mkdir Z:\...: no se puede encontrar la ruta"). Lanzándolo desde dentro
REM de WSL, docker-compose ve la ruta nativa /home/jmari/... y no hay
REM traducción que hacer.

:MENU
cls
color 0B
echo.
echo ==============================================================
echo                  [ SIEM - PANEL DE CONTROL ]
echo ==============================================================
echo.
echo   [1] Iniciar / Actualizar (build + up)
echo   [2] Detener
echo   [3] Reiniciar (sin rebuild -- solo si NO tocaste codigo)
echo   [4] Ver logs en vivo
echo   [5] Ver estado
echo   [6] Salir
echo.
echo ==============================================================
set /p opt="Selecciona una opcion (1-6): "

if "%opt%"=="1" goto START
if "%opt%"=="2" goto STOP
if "%opt%"=="3" goto RESTART
if "%opt%"=="4" goto LOGS
if "%opt%"=="5" goto STATUS
if "%opt%"=="6" goto EOF

goto MENU

:START
cls
color 0A
echo.
echo ==============================================================
echo        INICIANDO SIEM (build + up -d)
echo ==============================================================
echo.
REM Bug real evitado a proposito (visto en GWS/siam-x, 2026-07-06):
REM "up -d --force-recreate" SIN --build reutiliza la imagen ya construida,
REM aunque el Dockerfile o el codigo hayan cambiado -- el contenedor puede
REM quedar corriendo codigo viejo durante dias sin que nadie lo note. Por
REM eso este menu SIEMPRE reconstruye la imagen antes de levantar, no solo
REM la primera vez.
wsl.exe -e bash -lc "cd ~/proyectosIA/SIAM && docker compose build siem_backend && docker compose up -d --force-recreate siem_backend"
echo.
echo       [OK] Si no salio ningun error arriba, SIEM esta arriba.
echo       Comprueba con la opcion [5] o con:
echo         curl -sD - http://localhost:8001/v1/monitoring/overview
echo.
pause
goto MENU

:STOP
cls
color 0C
echo.
echo ==============================================================
echo        DETENIENDO SIEM
echo ==============================================================
echo.
wsl.exe -e bash -lc "cd ~/proyectosIA/SIAM && docker compose down"
echo       [OK] Contenedor detenido.
echo.
pause
goto MENU

:RESTART
cls
color 0A
echo.
echo ==============================================================
echo        REINICIANDO SIEM (sin reconstruir imagen)
echo ==============================================================
echo.
echo [!] Esto NO recoge cambios de codigo nuevos -- si has tocado .py,
echo     usa la opcion [1] en su lugar.
echo.
wsl.exe -e bash -lc "cd ~/proyectosIA/SIAM && docker compose restart siem_backend"
echo       [OK] Reiniciado.
echo.
pause
goto MENU

:LOGS
cls
color 0B
echo.
echo ==============================================================
echo        LOGS EN VIVO (Ctrl+C para volver al menu)
echo ==============================================================
echo.
wsl.exe -e bash -lc "cd ~/proyectosIA/SIAM && docker compose logs -f --tail 100"
goto MENU

:STATUS
cls
color 0B
echo.
echo ==============================================================
echo        ESTADO
echo ==============================================================
echo.
wsl.exe -e bash -lc "docker ps -a --filter name=siem_backend"
echo.
echo Catalogo de amenazas (deberia ser 30):
wsl.exe -e bash -lc "curl -s http://localhost:8001/v1/threats | grep -o '\"id\":' | wc -l"
echo Escenarios del simulador (deberia ser 9):
wsl.exe -e bash -lc "curl -s http://localhost:8001/v1/monitoring/scenarios | grep -o '\"id\":' | wc -l"
echo.
pause
goto MENU

:EOF
endlocal
exit
