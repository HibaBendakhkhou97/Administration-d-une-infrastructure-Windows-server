Import-Module serverManager

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

Import-Module -Name ADDSDeployment
$pwd=ConvertTo-SecureString -String "Password@123" -AsPlainText -Force
Install-ADDSForest -DomainName "AuTaza2.ma" -SafeModeAdministratorPassword $pwd -InstallDns -DomainMode WinThreshold -ForestMode WinThreshold -Force -NoRebootOnCompletion

Remove-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "10.0.0.5" 
Get-NetIPAddress -InterfaceAlias "Ethernet" 
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress "10.0.0.1" -PrefixLength 24

$pwdUsers=ConvertTo-SecureString -String "P@$$w0rd" -AsPlainText -Force

Get-ADObject -Filter * -SearchBase "OU=InfoDep,DC=AuTaza2,DC=ma"

New-ADUser -Name "Hiba Bendakhkhou" -GivenName "Hiba" -SurName "Bendakhkhou" -SamAccountName "HibaBendakhkhou" -UserPrincipalName "HibaBendakhkhou@AuTaza2.ma" -AccountPassword @pwdUsers -PasswordNeverExpires $true -Enabled $true
get-ADUser -Filter *
Move-ADObject -Identity "CN=Hiba Bendakhkhou,CN=Users,DC=AuTaza2,DC=ma" -TargetPath "OU=InfoDep,DC=AuTaza2,DC=ma"

Get-ADOrganizationalUnit  -Filter *

New-ADOrganizationalUnit -Name "InfoDep" 
New-ADOrganizationalUnit -Name "NewOU" 

#create new  group :
New-ADGroup -Name "InfoG1" -GroupScope DomainLocal -GroupCategory Security -Path "OU=InfoDep,DC=AuTaza2,DC=ma"


#Mov group to NewOU
Move-ADObject -Identity "CN=InfoG1,OU=InfoDep,DC=AuTaza2,DC=ma" -TargetPath "OU=NewOU,DC=AuTaza2,DC=ma" 

#Add a user to a group
ADD-ADGroupMember -Identity "InfoG1" -Members "HibaBendakhkhou"
Get-ADGroupMember -Identity "InfoG1"

#Get Objecs inside OU(InfoDep)
Get-ADObject -Filter * -SearchBase "OU=InfoDep,DC=AuTaza2,DC=ma"

Get-Help New-LocalGroup


$pwdUsers=ConvertTo-SecureString -String "P@$$w0rd" -AsPlainText -Force

$AllUsers=@(@("AhmediAhmedi","Ahmedi","Ahmedi","AhmediAhmedi@AuTaza2.ma","Ahmedi Ahmedi"),
            @("ImanIman","Iman","Iman","ImanIman@AuTAza2.ma","Iman Iman"),
            @("KarimaKarima","Karima","Karima","KarimaKarima@AuTaza2.ma","Karima Karima")),

          @(@("AhmedoAhmedo","Ahmedo","Ahmedo","AhmedoAhmedo@AuTaza2.ma","Ahmedo Ahmedo"),
            @("SaidSaid","Said","Said","SaidSaid@AuTAza2.ma","Said Said"),
            @("KarimKarimi","Karim","Karimi","KarimKarimi@AuTaza2.ma","Karimi Karimi")),

 @(@("AhmedAhmedo","Ahmed","Ahmedo","AhmedAhmedo@AuTaza2.ma","Ahmed Ahmedo"),
            @("SaidaSaid","Saida","Said","SaidaSaid@AuTAza2.ma","Saida Said"),
            @("KarimaKarimi","Karima","Karimi","KarimaKarimi@AuTaza2.ma","Karima Karimi")
)
              

$Ous=@("Finance","Urbanisme","RH")
$Groups=@("Finance1","Urbanisme1","RH1")

#Get-ADUser -Filter *
$i=0
Foreach ($OU in $Ous ){
New-ADOrganizationalUnit -Name $OU
  New-ADGroup -Name $Groups[$i] -GroupScope DomainLocal -GroupCategory Security -Path "OU=$OU,DC=AuTaza2,DC=ma"
  Foreach ($Usr in $AllUsers[$i])
   {
   New-ADUser -Name $Usr[4] -GivenName $Usr[1] -SurName $Usr[2] -SamAccountName $Usr[0] -UserPrincipalName $Usr[3]  -AccountPassword @pwdUsers -PasswordNeverExpires $true -Enabled $true -Path "OU=$OU,DC=AuTaza2,DC=ma"
   ADD-ADGroupMember -Identity $Groups[$i] -Members $Usr[0]
   }
  $i++ 
}

 Remove-ADOrganizationalUnit -Identity "OU=Urbanisme,DC=AuTaza2,DC=ma"
 $ou= Get-ADOrganizationalUnit -Filter *
 foreach ($p in $ou){
 $p | Set-ADObject -ProtectedFromAccidentalDeletion $false
 
 } 


 #GPO

$Target = Get-ADOrganizationalUnit -Filter {Name -like "InfoDep"}

$GPOs = ("ControlPannel","UsbReading","BackgroundChanging","CmdUse")

for($i=0;$i -lt $GPOs.Length;$i++){

New-GPO -Name $GPOs[$i] 
New-GPLink -Name $GPOs[$i] -Target $Target
}

$GPOs = ("ControlPannel","UsbReading","BackgroundChanging","CmdUse")
$Ous=@("Finance","Urbanisme","RH")


Foreach($OU in $OUs){
 Foreach ($GPO in $GPOs){
 New-GPLink -Name $GPO -Target "OU=$OU,DC=AuTaza2,DC=ma"
 }
}

#GPO_BackgroundChanging

Set-GPRegistryValue -Name $GPOs[2] -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\System" -ValueName "Wallpaper" -Type String -Value "C:\Windows\Web\Wallpaper\Windows\img0.jpg"


#GPO_ControlPanel


Set-GPRegistryValue -Name $GPOs[0] -Key "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -ValueName "NoControlPanel" -Type DWord -Value 1


#GPO_CmdUse

Set-GPRegistryValue -Name $GPOs[3] -Key "HKCU\Software\Policies\Microsoft\Windows\System" -ValueName "DisableCMD" -Type DWord -Value 1


#GPO_UsbReading

Set-GPRegistryValue -Name $GPOs[1] -Key "HKCU\Software\Policies\Microsoft\Windows\RemovableStorageDevices" -ValueName "Deny_Read" -Type DWord -Value 1


#NICTeaming

Get-NetIPAddress

Remove-NetIPAddress -InterfaceAlias "Ethernet*"

$interfaces = Get-NetAdapter

New-NetLbfoTeam -Name "EthernetsTeam" -TeamMembers $interfaces[0].Name ,$interfaces[1].Name , $interfaces[2].Name
Get-NetLbfoTeam
New-NetIPAddress -InterfaceAlias "EthernetsTeam" -IPAddress "10.0.0.1" -PrefixLength 24

Get-NetAdapter | Select Name ,Speed


#StoragePool

$disks = Get-PhysicalDisk
$disks
Get-StorageSubSystem 
New-StoragePool -FriendlyName "mnVStoragePool" -PhysicalDisks $disks[1] ,$disks[2] -StorageSubsystemFriendlyName "Windows Storage on SScript"  -ResiliencySettingName Mirror
Get-StoragePool -FriendlyName "mnVStoragePool"
 #CreateNewVirtualDiskForStoragePool
New-VirtualDisk -StoragePoolFriendlyName "mnVStoragePool" -FriendlyName "NMVolum" -ResiliencySettingName Mirror -UseMaximumSize
Get-VirtualDisk -FriendlyName "NMVolum"
 #CreatingNewPartition&Volume&DoFormat
Get-Disk |Select *
Initialize-Disk -Number 3 -PartitionStyle GPT
New-Partition -DiskNumber 3 -UseMaximumSize -AssignDriveLetter 
Format-Volume -DriveLetter E -FileSystem NTFS -NewFileSystemLabel "MNVolum_"

#FileSharing
 
$Deps=@("Finance","Urbanisme","RH")
foreach ($Dep in $Deps)
{
 New-Item -ItemType Directory -Path "C:\Users\Administrator\Desktop" -Name $Dep
 $GName = $Dep +"1"
 New-SmbShare -Name $Dep -Path "C:\Users\Administrator\Desktop\$Dep" -fullAccess "AuTaza2\$GName"
 $Grant = $GName + ":(OI)(CI)F" 
 icacls "C:\Users\Administrator\Desktop\$Dep" /grant $Grant /T
}
Get-ChildItem  -Path "C:\Users\Administrator\Desktop" -Directory |Select *
Get-SmbShare  


#No.txt Files for RH Shared Folder

Install-WindowsFeature -Name FS-Resource-Manager

Import-Module FileServerResourceManager

New-FsrmFileGroup -Name "TxtFiles" -IncludePattern "*.txt" 

New-FsrmFileScreenTemplate -Name "NoTxtFilesTemplate" -IncludeGroup @("TxtFiles") -Active

New-FsrmFileScreen -Path "C:\Users\Administrator\Desktop\RH" -Template "NoTxtFilesTemplate" -Active


#No .exe fils for Finance Shared Folder

New-FsrmFileGroup -Name "Exe"  -IncludePattern "*.exe"

New-FsrmFileScreenTemplate -Name "NoExe" -IncludeGroup @('Exe') -Active

New-FsrmFileScreen -Path "C:\Users\Administrator\Desktop\Finance" -Template "NoExe" -Active

#Configuration dhcp

Install-WindowsFeature -Name DHCP -IncludeManagementTools

Import-Module DhcpServer

Add-DhcpServerv4Scope -Name "AuTaza2Scope" -StartRange "10.0.0.10" -EndRange "10.0.0.100" -SubnetMask "255.255.255.0" -State Active

Set-DhcpServerv4OptionValue -ScopeId "10.0.0.10"   -DnsServer "10.0.0.1" 


#Configuration WDS (update and OS installation )

Install-WindowsFeature -Name WDS -IncludeManagementTools

Import-Module Wds

#Initialize-WdsServer -ServerName "." -RemInstPath "C:\RemoteInstall"
$res = wdsutil /initialize-server /reminst:"C:\RemoteInstall"

$res | select -Last 1
Start-Service -Name WDS


Import-WdsBootImage -Path "H:\sources\boot.wim" 
 
Import-WdsInstallImage -Path "H:\sources\install.wim"

#Roaming profiles (RH) (A global UserAccount Over the network (no local userAccount for each PC )

New-Item -Name "Profiles" -ItemType Directory -Path "C:\" 
$RhUsers =Get-ADUser -Filter * -SearchBase "OU=RH,DC=AuTaza2,DC=ma" 
Foreach ($user in $RhUsers){
Set-ADUser -Identity $user.SamAccountName -ProfilePath "C:\Profiles\$user"
}
Get-ADUser -Filter * -SearchBase "OU=RH,DC=AuTaza2,DC=ma" -Properties ProfilePath | Select-Object SameAccountName, ProfilePath





