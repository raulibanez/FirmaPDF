@echo off
echo ============================================
echo  Empaquetando FirmaPDF como .exe
echo ============================================
echo.

call pip install pyinstaller
echo.

python -m PyInstaller --onefile --windowed --name "FirmaPDF" FirmaPDF.py

echo.
echo ============================================
echo  El ejecutable esta en: dist\FirmaPDF.exe
echo ============================================
pause
