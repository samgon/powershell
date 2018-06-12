#Samuel GONZALES
#version 3.141 du 30-10-2017
#
write-host "Activation de l'exécution des scripts "
set-executionPolicy Unrestricted
#
#Variables du poste
#
#Nom du poste et utilisateurs
#
$RNE="0670123A"
$ADMINPWD="toutou"
$USER="toto" 
$USERPWD="toto"
$NOMPOSTE=$RNE.substring(3)+"-"+$USER
#
$IP_HORUS="10.67.A.B"
#
#On renomme le poste et on le met dans le groupe ETAB si ce n est pas deja fait
if ( ! ((Get-WmiObject -Class Win32_ComputerSystem).Workgroup -eq "ETAB" ) )
{Add-Computer -WorkgroupName ETAB
Write-Host "L'ordi est dans le groupe ETAB."}
else
{write-host "L'ordi est déjà dans le groupe ETAB"}
if ( ! ((Get-WmiObject -Class Win32_ComputerSystem).name -eq $NOMPOSTE ) )
{Rename-Computer -NewName $NOMPOSTE
Write-Host "L'ordi est renommé $NOMPOSTE"}
else
{write-host "L'ordi est déjà nommé $NOMPOSTE"}
#
#On crée l'utilisateur avec le mdp et on le met dans le groupe administrateurs
$UserSecurePWD=(ConvertTo-SecureString -Force -AsPlainText -String $UserPWD)
#On regarde si user existe
if ( ! ((Get-LocalUser).name -contains $user ) )
{
#user n'existe pas
write-host "Création de l'utilisateur $user."
New-LocalUser -name $user -Password $UserSecurePWD -AccountNeverExpires -PasswordNeverExpires -Description "Compte de $user"
Add-LocalGroupMember -Group "Administrateurs" -Member $user
write-host "Utilisateur $user crée."
}
else {
#user existe
write-host "L'utilisateur existe, mise à jour des données."
set-LocalUser -name $user -Password $UserSecurePWD -AccountNeverExpires -PasswordNeverExpires 1 -Description "Compte de $user"
if ( ! ((get-LocalGroupMember -Group "Administrateurs").name -contains "$env:COMPUTERNAME\$user") )
{
write-host "$user n'est pas dans le groupe Administrateurs."
Add-LocalGroupMember -Group "Administrateurs" -Member $user
Write-Host "$user a été ajouté au groupe Administrateurs."
} 
else {
write-host "$user est déjà dans le groupe Administrateurs."
}
#commandes à des fins de test pour suprimer l'utilisateur
#
#remove-LocalGroupMember -Group "Administrateurs" -Member $user
#Remove-LocalUser -Name $user
#set-LocalUser -name $user -AccountNeverExpires -PasswordNeverExpires 0 -Description "Le mdp de $user expire"
#
}
write-host "Fin de la création du compte $user."
#On active le compte Administrateur et on modifie le mdp
Enable-LocalUser -Name Administrateur
$SecurePWD = ConvertTo-SecureString -Force -AsPlainText -String $ADMINPWD
Set-LocalUser Administrateur -Password $SecurePWD  -AccountNeverExpires -PasswordNeverExpires 1 
#
#On vérifie si tout va bien
Write-Host "Vérification du compte $user :"
Get-Localuser $user 
write-host "Liste des membres du groupe Administrateurs :"
(Get-LocalGroupMember -Name Administrateurs).name
#UAC
#voir niveau uac
Write-host "Niveau actuel UAC"
(Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System).EnableLUA
write-host "Modification UAC"
New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 0 -Force
pause
#reactiver uac
#New-ItemProperty -Path HKLM:Software\Microsoft\Windows\CurrentVersion\policies\system -Name EnableLUA -PropertyType DWord -Value 1 -Force
#
#desactiver lockscreen
Write-host "Désactivation du LockScreen"
New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Force
set-ItemProperty -path HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization -Name NoLockScreen -Value 1 -Force
Write-host "Fait!"
#
#Samba domain
#
write-host "Configuration accès au domaine Samba"
$RegKey="HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters"
$RegKeyName="DNSNameResolutionRequired"
$RegKeyValue="0"
set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
$RegKeyName="DomainCompatibilityMode"
$RegKeyValue="1"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
write-host "Fait!"
#
#win10 accès netlogon
#
write-host "Accès au netlogon Win10"
$RegKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
$RegKeyName="\\*\NETLOGON"
$RegKeyValue="RequireMutualAuthentication=0,RequireIntegrity=0"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
$RegKeyName="\\*\SYSVOL"
$RegKeyValue="RequireMutualAuthentication=0,RequireIntegrity=0,RequirePrivacy=0"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
$RegKey="HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
$RegKeyName="\\*\NETLOGON"
$RegKeyValue="RequireMutualAuthentication=0,RequireIntegrity=0"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
$RegKeyName="\\*\SYSVOL"
$RegKeyValue="RequireMutualAuthentication=0,RequireIntegrity=0,RequirePrivacy=0"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
#
#Verrouillage numlock
#
write-host "Verrouillage Numlock"
$RegKey="HKCU:\Control Panel\Keyboard"
$RegKeyName="InitialKeyboardIndicators"
$RegKeyValue="2"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
$RegKey="HKU:\.DEFAULT\Control Panel\Keyboard"
$RegKeyName="InitialKeyboardIndicators"
$RegKeyValue="2"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
write-host "Fait!"
#
#Creation dossier bureau assistance
#
write-host "Création du dossier assistance"
New-Item -Path "C:\Users\Public\Desktop\@ASSISTANCE"  -ItemType Directory
#supression
#remove-Item -Path "C:\Users\Public\Desktop\@ASSISTANCE"
write-host "Copie des elements sur le bureau public"
#
Copy-Item -Recurse -Path "c:\RAIP\@ASSISTANCE\*" -Destination "C:\Users\Public\Desktop\@ASSISTANCE" -Verbose
write-host "Fait!"
#
#Création du raccourci Eteindre
#
$Shell = New-Object -ComObject WScript.Shell
write-host "Création du raccourci Eteindre"
$Shortcut = $Shell.CreateShortcut("C:\Users\Public\Desktop\Eteindre.lnk")
#$Link = $shell.CreateShortcut("C:\windows\System32\shutdown.exe")
$Shortcut.TargetPath = "C:\windows\System32\shutdown.exe"
$Shortcut.Arguments = "-s -t 0 -f"
$Shortcut.IconLocation = "$env:SystemRoot\System32\SHELL32.dll,27"
$Shortcut.save()
write-host "Fait!"
#
#Création du raccourci redémarrer
#
write-host "Création du raccourci Redémarrer"
$RestartSh = $Shell.CreateShortcut("C:\Users\Public\Desktop\Redémarrer.lnk")
$RestartSh.TargetPath = "C:\windows\System32\shutdown.exe"
$RestartSh.Arguments = "-r -t 0 -f"
$RestartSh.IconLocation = "$env:SystemRoot\System32\SHELL32.dll,238"
write-host "Fait..."
$RestartSh.save()
#
#Creation du reseau.bat
#
write-host "Accès aux lecteurs réseau"
Add-Content -Path "C:\Windows\reseau.bat" -Value "@echo off`r`n
cls`r`n
ECHO ************************************************************************`r`n
ECHO *           Suppression des anciennes connexions au reseau             *`r`n
ECHO ************************************************************************`r`n
net use * /delete /yes`r`n
ECHO ************************************************************************`r`n
ECHO *                Test de presence du serveur HORUS                     *`r`n
ECHO ************************************************************************`r`n
ping $IP_HORUS -n 1`r`n
\\$IP_HORUS\netlogon\scripts\groups\DomainUsers.bat`r`n
:fin`r`n
ECHO ************************************************************************`r`n
ECHO *                        Erreur de NETLOGON                            *`r`n
ECHO ************************************************************************`r`n
exit
"
#
#reseau.bat a l ouverture de session
#
$RegKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$RegKeyName="Reseau"
$RegKeyValue="c:\windows\reseau.bat"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
write-host "Réseau.bat ajouté à  l'ouverture de session"
#
#supprimer animation lors du 1er logon
#
write-host "Je supprime l'animation lors du premier logon"
$RegKey="HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
$RegKeyName="EnableFirstLogonAnimation"
$RegKeyValue="0"
set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
write-host "Fait!"
#
#Cortana remplacé par winsearch
#
write-host "Je remplace Cortana par WindowsSearch"
$RootPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\"
$CortanaPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
if (!(Test-Path -Path $CortanaPath)) {
New-Item -Path $RootPath -Name "Windows Search"
}
Set-ItemProperty $CortanaPath -Name "AllowCortana" -Value 0 #mettre la valeur à  1 pour réactiver cortana
Stop-Process -Name explorer
write-host "Fait!"
Read-Host "Fin du script, appuyer sur ENTREE pour continuer"
