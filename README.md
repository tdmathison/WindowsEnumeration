# WindowsEnumeration
Scripts to enumerate and collect information on a Windows machine

## WinEnum
### Prerequisites
- Python 3 (3.5 if using PyInstaller)
- PyWin32
- PyInstaller
- AccessChk commandline tool

### Usage
To simply run through python
```bash
python WinEnum.py --exepath accesschk64.exe
```

To compile with PyInstaller
```
pyinstaller --onefile WinEnum.py
```
