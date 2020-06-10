pip install virtualenv
virtualenv venv
venv\Scripts\pip.exe install -r requirements.txt
venv\Scripts\pip.exe install pyinstaller
venv\Scripts\pyinstaller.exe -F main.py --hiddenimport pkg_resources.py2_warn
del /F /S /Q venv
