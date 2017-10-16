#Variables du poste
#
#Nom du poste et utilisateurs
#
$RNE="067XXXX"
$ADMINPWD="toto"
$USER="cpe"
$USERPWD="titi"
$NOMPOSTE=$RNE.substring(3)+"-"+$USER
$IP_HORUS="10.67.A.B"
#
#On renomme le poste et on le met dans le groupe ETAB
Rename-Computer -NewName $NOMPOSTE
Add-Computer -WorkgroupName ETAB
#
#On crée l'utilisateur avec le mdp et on le met dans le groupe administrateurs
net user $USER $USERPWD /ADD
Add-LocalGroupMember -Group "Administrateurs" -Member $user
set-LocalUser $user -Description "Compte $user" -AccountNeverExpires
#
#On active le compte Administrateur et on modifie le mdp
Enable-LocalUser -Name Administrateur
$SecurePWD = ConvertTo-SecureString -Force -AsPlainText -String $ADMINPWD
Set-LocalUser Administrateur -Password $SecurePWD
#
#On vérifie si tout va bien
Write-Host "Vérification du compte $user :"
Get-Localuser $user 
write-host "Liste des membres du groupe Administrateurs :"
(Get-LocalGroupMember -Name Administrateurs).name
#
#Samba domain
#
$RegKey="HKLM:\System\CurrentControlSet\Services\LanManWorkstation\Parameters"
$RegKeyName="DNSNameResolutionRequired"
$RegKeyValue="0"
set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
$RegKeyName="DomainCompatibilityMode"
$RegKeyValue="1"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
#
#Verrouillage numlock
#
$RegKey="HKCU:\Control Panel\Keyboard"
$RegKeyName="InitialKeyboardIndicators"
$RegKeyValue="2"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
New-PSDrive -PSProvider Registry -Name HKU -Root HKEY_USERS
$RegKey="HKU:\.DEFAULT\Control Panel\Keyboard"
$RegKeyName="InitialKeyboardIndicators"
$RegKeyValue="2"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
#
#win10 accès netlogon
#
$RegKey="HKLM:\SOFTWARE\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
$RegKeyName="\\\\*\\NETLOGON"
$RegKeyValue="RequireMutualAuthentication=0,RequireIntegrity=0"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
$RegKeyName="\\\\*\\SYSVOL"
$RegKeyValue="RequireMutualAuthentication=0,RequireIntegrity=0,RequirePrivacy=0"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
$RegKey="HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\NetworkProvider\HardenedPaths"
$RegKeyName="\\\\*\\NETLOGON"
$RegKeyValue="RequireMutualAuthentication=0,RequireIntegrity=0"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
$RegKeyName="\\\\*\\SYSVOL"
$RegKeyValue="RequireMutualAuthentication=0,RequireIntegrity=0,RequirePrivacy=0"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
#
#Creation dossier bureau assistance
#
New-Item -Path "C:\Users\Public\Desktop\@ASSISTANCE"  -ItemType Directory
#supression
#remove-Item -Path "C:\Users\Public\Desktop\@ASSISTANCE"
#
#Creation du reseau.bat
#
Add-Content -Path "C:\Windows\reseau.bat" -Value "@echo off
cls
ECHO ************************************************************************
ECHO *           Suppression des anciennes connexions au reseau             *
ECHO ************************************************************************
net use * /delete /yes
ECHO ************************************************************************
ECHO *                Test de presence du serveur HORUS                     *
ECHO ************************************************************************
ping $IP_HORUS -n 1


\\$IP_HORUS\netlogon\scripts\groups\DomainUsers.bat


:fin
ECHO ************************************************************************
ECHO *                        Erreur de NETLOGON                            *
ECHO ************************************************************************
exit
"
#
#reseau.bat a l ouverture de session
#
$RegKey="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
$RegKeyName="Reseau"
$RegKeyValue="c:\\windows\\reseau.bat"
Set-ItemProperty $RegKey -Name $RegKeyName -Value $RegKeyValue
write-host "Réseau.bat ajouté à l'ouverture de session"
#
#copie des elements sur le bureau public
#
Copy-Item -Recurse -Path .\seven\bureau\users\Public\Desktop\* -Destination "C:\Users\Public\Desktop" -Verbose
Get-PSDrive
pwd
Read-Host
