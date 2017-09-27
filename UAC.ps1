#Get-ExecutionPolicy
#Set-ExecutionPolicy
#desactiver UAC
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
#voir niveau uac
Get-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system
(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA
#reactiver uac
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 1 -Force
net user Administrateur /active:yes
#desactiver lockscreen
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Force
set-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Value 1 -Force
pause
