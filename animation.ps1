#supprimer animation lors du 1er logon
$RegKey="HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$RegKeyName="EnableFirstLogonAnimation"
$RegKeyValue="0"
set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
#/v EnableFirstLogonAnimation /d 0 /t REG_DWORD /f
