# Enable script execution
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser -Force

#These paths will be unique for every user. User must provide their local python installation and the location where GUI.py is
$targetPath = "C:\Users\johng\AppData\Local\Microsoft\WindowsApps\python3.11.exe"
$scriptPath = "C:\Users\johng\Documents\M.S. PROJECT\GUI.py"

#$command = """$targetPath"" ""$scriptPath"" ""%1"""
$commandKey = "EncryptDecryptCommand"
$commandValue = "Encrypt/Decrypt"

$sendToFolderPath = [Environment]::GetFolderPath('SendTo')

# Create the SendTo folder if it doesn't exist
if (-not (Test-Path -Path $sendToFolderPath)) {
    $null = New-Item -ItemType Directory -Path $sendToFolderPath
}

# Create the command key
$commandKeyPath = "HKCU:\Software\Classes\Directory\shell\$commandKey"
New-Item -Path $commandKeyPath -Force | Out-Null

# Set the command value
Set-ItemProperty -Path $commandKeyPath -Name "(default)" -Value $commandValue

# Create the command subkey
$commandSubKeyPath = "HKCU:\Software\Classes\Directory\shell\$commandKey\command"
New-Item -Path $commandSubKeyPath -Force | Out-Null

# Set the command subkey value
$commandSubKeyValue = """$targetPath"" ""$scriptPath"" ""%1"""
Set-ItemProperty -Path $commandSubKeyPath -Name "(default)" -Value $commandSubKeyValue

# Create the SendTo shortcut
$shortcutFilePath = Join-Path -Path $sendToFolderPath -ChildPath "EncryptDecrypt.lnk"

$WshShell = New-Object -ComObject WScript.Shell
$shortcut = $WshShell.CreateShortcut($shortcutFilePath)
$shortcut.TargetPath = $targetPath
$shortcut.Arguments = $scriptPath
$shortcut.Save()
