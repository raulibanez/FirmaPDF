@echo off
echo ============================================
echo  Empaquetando FirmaPDF como .exe
echo ============================================
echo.

call pip install pyinstaller
echo.

python -m PyInstaller ^
    --onefile ^
    --windowed ^
    --noupx ^
    --name "FirmaPDF" ^
    --exclude-module torch ^
    --exclude-module tensorflow ^
    --exclude-module keras ^
    --exclude-module numpy ^
    --exclude-module scipy ^
    --exclude-module pandas ^
    --exclude-module matplotlib ^
    --exclude-module cv2 ^
    --exclude-module sklearn ^
    --exclude-module transformers ^
    --exclude-module accelerate ^
    --exclude-module sentencepiece ^
    FirmaPDF.py

echo.
echo ============================================
echo  El ejecutable esta en: dist\FirmaPDF.exe
echo ============================================
pause
