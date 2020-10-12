$PSVersionTable

Update-Help
Save-Help #Save help files down for machines that do not connect Online
Update-Help -SourcePath \\LON-LT-HP049\Test\
Help Get-EVentLog -Online
Help Get-EventLog -ShowWindow #Opens help in separate window
Help Get-EventLog -Examples

Get-EventLog Application -computer (Get-Content names.txt)
# [] Optional Parameters if command and value enclosed in brackets
# Just the Parameter name enclosed in brackets is Positional - can provide a value without typing the parameter’s name, provided you put that value in the correct position (parameter name needed if typing out of position)
# <string[]> Square brackets signifies an array is acceptable

#Lab 3
Get-Service | ConvertTo-Html -As LIST > services.htm
get-command -Verb Out
Out-File -FilePath c:\
Get-Content C:\Test.txt | Out-Printer
get-command -Noun process
get-command -verb write
Write-EventLog
get-command -noun alias
Start-Transcript
Get-EventLog -LogName Security -Newest 100
Get-Service -ComputerName LON-LT-HP049
Get-Process -ComputerName LON-LT-HP049
Help out-file [80 characters for the width]
-NoClobber
Get-Alias
GSV -computerName LON-LT-HP049
get-command *object
Help *array*


show-Command get-service

Get-Alias -Definition Get-Service #Find alias for a cmdlet
(get-command get-eventlog | select -ExpandProperty parameters).computername.aliases #Discover alias of a cmdlet parameter

#Lab 4

Get-process
Get-EventLog -LogName Application -Newest 100
Get-Command -CommandType Cmdlet
Get-Alias
New-Alias -Name "np" notepad
Get-Service -Name M*
Get-Service -DisplayName M*
Get-Command get-netfirewall*
Get-NetFirewallRule
Get-NetFirewallRule -Direction Inbound

#Providers - An adapter designed to take some kind of storage and make it look like a disk. For the most part, the cmdlets you use with a PSDrive have the word Item somewhere in their noun
Get-Command -Noun *item*
New-Item TestDirectory -ItemType Directory
Get-ChildItem # -LiteralPath doesnt accept wildcards -Path accepts wildcards - * stands in for several characters and ? stands in for 1.

Set-Location -Path HKCU:
Set-Location -Path Software
Get-ChildItem
Set-Location Microsoft
Set-Location .\Windows
Set-ItemProperty -Path dwm -Name EnableAeroPeek -Value 0

#Lab 5
set-location -Path software\microsoft\Windows\currentversion\explorer
Get-ChildItem
Set-ItemProperty -Path Advanced -Name DontPrettyPath -Value 0
New-Item -Path C:\Labs -ItemType Directory
New-Item -Path C:\Labs -Name Test.txt -ItemType File
Set-Item -Path C:\Labs\Test.txt

$ENV:Temp
Get-Item env:temp

# Include and Exclude must be used with –Recurse or if querying a container. Filter uses the PSProvider’s filter capability, which not all providers support. For example, you could use DIR –filter in the filesystem but not in the Registry—
# although you could use DIR –include in the Registry to achieve almost the
# same type of filtering result.

Get-Process | Export-Csv process.csv
Import-Csv process.csv

Get-Process | Export-Clixml process.xml
Import-Clixml process.xml

#Compare processes on one machine with another by name
Get-Process | Export-Clixml Reference.xml
Diff -ReferenceObject (Import-Clixml Reference.xml) -DifferenceObject (Get-Process) -Property Name

# > is an alias for Out-File but with fewer parameters

get-service | Out-GridView

Get-Service | ConvertTo-Html | Out-File HTMLTest.html

Get-Process -Name notepad | Stop-Process
Get-Process -Name notepad | Stop-Process -Confirm
Get-Process -Name notepad | Stop-Process -WhatIf
$ConfirmPreference

#Use get-content for reading in a text file otherwise use respective import- commands (e.g import-csv for CSV files).

#Lab 6

"I a believer" | Out-File File3.txt 
Diff -ReferenceObject (Get-Content Test1.txt) -DifferenceObject (Get-Content Test2.txt)
Get-Service | Export-Csv Services.csv | Out-File #Doesnt Work as no location or file name specified for output
Get-Service | Export-Csv Services.csv
get-process | Export-Csv -Path "processes.csv" -Delimiter "|"
get-process | Export-Csv -Path "processes.csv" -NoTypeInformation
Get-Process | Export-Clixml "processes.xml" -NoClobber
Get-Process | Export-Clixml "processes.xml" -Confirm
get-process | Export-Csv -Path "processes.csv" -UseCulture 

get-pssnapin –registered
Get-PSProvider
get-command -pssnapin [snapin name] # Show the commands added from a snapin
$env:PSModulePath #PS Module path shows the locations to look to modules to autoload into PS
Remove-PSSnapin or Remove-Module # Unload an extension

Get-PSRepository
Register-PSRepository # Add a repo for PS to use
Install-Module
Update-Module 

help *dns*
import-module -Name DnsClient
Get-Command -Module DnsClient
help Clear-DnsClientCache
Clear-DnsClientCache -Verbose

#Save Powershell State (with PSSnapins loaded)
Export-Console c:\myshell.psc
%windir%\system32\WindowsPowerShell\v1.0\powershell.exe -noexit -psconsolefile c:\myshell.psc #Create shortcut

#Lab 7
help *troubleshooting
help Get-TroubleshootingPack -examples
Get-TroubleshootingPack -Path "C:\Windows\Diagnostics\System\Networking" | Invoke-TroubleshootingPack
or
$network = Get-TroubleshootingPack -Path "C:\Windows\diagnostics\system\Networking"
Invoke-TroubleshootingPack -Pack $network

Get-Command -noun *troubleshooting* 

#Object = a table row, Property = a table column, Method = an action related to a single object and makes it do something, Collection = entire set of objects (table)

Get-Member #Learn more about an object GM alias
Get-Process | Sort-Object -property VM, ID -Descending
Get-process | ConvertTo-Html | Out-File Test1.HTML
Get-Process | Select-Object -Property Name,ID,VM,PM | Convertto-HTML | Out-File Test2.HTML
Get-Process | Sort-Object VM -descending | Select-Object Name,ID,VM

#Select-Object to choose the properties (or columns) you want to see
#Where-Object removes or filters objects out of the pipeline based on criteria specified

#Remember that the PowerShell help files don’t contain information on objects’ properties. You’ll need to pipe the objects to Gm (Get-Member) to see a list of properties.
#Remember that you can add Gm to the end of any pipeline that typically produces results. A command line such as Get-Process -name Notepad | Stop-Process doesn’t usually produce results, so tacking | Gm onto the end won’t produce anything either.
#Remember that the pipeline can contain various types of objects at each step. Think about what type of object is in the pipeline, and focus on what the next command will do to that type of object.


#Lab 8

Get-Command *Random
Get-Random
Get-Command *Date
Get-Date
Get-date | get-member #System.DateTime
Get-Date | Select-Object -Property DayofWeek
Get-HotFix
Get-Hotfix | Sort-Object -Property InstalledOn | Select-Object InstalledOn,InstalledBy,HotFixID
Get-Hotfix | Sort-Object -Property Description | Select-Object Description,HotFixID,InstalledOn | ConvertTo-Html | Out-File HotFix1.HTML
Get-HotFix | Sort Description | Select Description,InstalledOn,InstalledBy,HotFixID | ConvertTo-Html -Title "Name of Document" | Out-File HotFixReport.htm
Get-EventLog -LogName Security -Newest 50 | Sort-Object -Property TimeGenerated,Index | Select-Object Index,TimeGenerated,Source | Out-File EventLogNewest50.txt

#Command A = Get-Process Command B = Stop-Process
#Pipeline parameter binding - how PS figures out which parameter of command B will accept output of Command A. ByPropertyName (Property Name match to Parameter Name) or ByValue (TypeName matching Parameter Value)
get-process -name * | Get-Member
Help Stop-Process -Full
#InputObject matches between the 2 commands (Process and accept pipeline input ByValue)

get-service -name s* | stop-process
import-csv .\aliases.csv | New-Alias

import-csv .\newusers.csv |
>> select-object -property *,
>> @{name='samAccountName';expression={$_.login}},
>> @{label='Name';expression={$_.login}},
>> @{n='Department';e={$_.Dept}} |
>> New-AdUser

get-content .\computers.txt | get-wmiobject -class win32_bios
#If parameter doesnt accept output from Pipeline, use parentheses instead as above
Get-WmiObject -Class Win32_Bios -ComputerName (Get-Content .\Computers.txt)
 

 get-adcomputer -filter * -searchbase "ou=domain controllers,dc=company,dc=pri"
 get-adcomputer -filter * -searchbase "ou=domain controllers,dc=testitlabs,dc=co,dc=uk" | gm
 Get-Service -computerName (Get-ADComputer -filter * -searchbase "ou=domain controllers,dc=testitlabs,dc=co,dc=uk" | Select-Object -expand name) #-Expand Name goes into the Name property and extracts its values, resulting in simple strings being returned from the command.

#Lab 9
Get-Hotfix -computerName (Get-ADComputer -filter * | Select-Object -expand name)
This should work because the expand Name takes the String value of Names for the computers which is acceptable to use in -computername of Get-Hotfix.
#This should work, because the nested Get-ADComputer expression will return a collection of computer names and the –Computername parameter can accept an array of values.

Get-ADComputer -filter * | Get-HotFix
This wouldnt work. Hotfix isnt a parameter returned as part of the initial Get-ADComputer query.
#This won’t work, because Get-Hotfix doesn’t accept any parameters by value. It will accept –Computername by property name, but this command isn’t doing that.

Get-ADComputer -filter * | Select-Object @{l='computername';e={$_.name}} | Get-Hotfix
This wouldnt work. The command changes the label of computer name but still doesnt generate the correct properties to pipe to Get-Hotfix.
Get-Service -computerName (Get-ADComputer -filter * -searchbase "ou=domain controllers,dc=testitlabs,dc=co,dc=uk" | Select-Object -expand name) #-Expand Name goes into the Name property and extracts its values, resulting in simple strings being returned from the command.

#Answers

Get-Hotfix -computerName (Get-ADComputer -filter * | Select-Object -expand name)
#This should work because of the nester "Name" property for Get-Hotfix (its a String that matches to expanded "Name" property of Get-ADComputer.

Get-ADComputer -filter * | Get-HotFix
#This wont work. Get-Hotfix doesnt know what to do with the ADComputer object type output from Get-ADComputer.

Get-ADComputer -filter * | Select-Object @{l='computername';e={$_.name}} | Get-Hotfix
#This should work as the property name is converted to something that Get-Hotfix can work with from its own property list.

Get-adcomputer -filter * | Select-Object @{l='computername';e={$_.name}} | Get-Process

Get-Service -computerName (Get-ADComputer -filter * | Select-Object -expand name)


 Get-Service | Sort-Object Status | Format-Table -groupBy Status
 Get-Service | Format-Table Name,Status,DisplayName -autoSize -wrap
 Get-Service | Fl * #Format-List will show properties of a list and the values
 Get-Process | Format-Wide name -col 6

 Get-Service | Format-Table @{name='ServiceName';expression={$_.Name}},Status,DisplayName
 Get-Process | Format-Table Name, @{name='VM(MB)';expression={$_.VM / 1MB -as [int]}} -autosize
 Get-Process | Format-Table Name, @{name='VM(MB)';expression={$_.VM};formatstring='F2';align='right'} -autosize
Get-Service | Select Name,DisplayName,Status | Format-Table | ConvertTo-HTML | Out-File services.html 

#Format as far right as possible with only Out- commands after it (except for Out-GridView which doesnt work)

#Lab 10 Start#
Get-Process | Format-Table Name,ID,Responding -AutoSize -Wrap
Get-Process | Format-Table ProcessName,ID,@{name='VM(MB)';expression={$_.VM / 1MB -as [int]}},@{name='PM(MB)';expression={$_.PM / 1MB -as [int]}} -autosize
Get-EventLog -List | Format-Table @{name='LogName';expression={$_.LogDisplayName}},@{name='RetDays';expression={$_.MinimumRetentionDays}}
Get-Service | Sort-Object Status -Descending | Format-Table -GroupBy Status
Dir | Format-Wide -Property Name -Column 4
Get-Item -Path C:\* -Include *.exe | Format-List Name,VersionInfo,@{name='Size';expression={$_.Length}} #Below is another way of doing this
dir c:\*.exe | Format-list Name,VersionInfo,@{Name="Size";Expression={$_.length}}

Get-Process | Select-Object Name,ID,Responding | Format-Table -AutoSize -Wrap
#get-process | format-table Name,ID,Responding -autosize -Wrap

Get-Process | Select-Object Name,ID,@{name='VM(MB)';expression={$_.VM / 1MB -as [int]}},@{name='PM(MB)';expression={$_.PM / 1MB -as [int]}} | Format-Table -AutoSize
#get-process | format-table Name,ID,@{l='VirtualMB';e={$_.vm/1mb}},@{l='PhysicalMB';e={$_.workingset/1MB}} -autosize

Get-Eventlog -List | Get-Member
Get-EventLog -List | Select-Object LogDisplayName,MinimumRetentionDays
Get-EventLog -List | Select-Object @{name='LogName';expression={$_.LogDisplayName}},@{name='RetDays';expression={$_.MinimumRetentionDays}}

Get-Service | Sort-Object Status -Descending | Format-Table -GroupBy Status

Get-ChildItem C:\ | Format-Wide -Column 4
Get-ChildItem C:\ -Attributes Directory | Format-Wide -Column 4

Get-ChildItem C:\Windows\*.exe | Select Name,VersionInfo,@{name='Size';expression={$_.Length}} | Format-List
#dir c:\windows\*.exe | Format-list Name,VersionInfo,@{Name="Size";Expression={$_.length}}

#Lab 10 End#

#Early filtering - retrieve only what is specified
#Interative - use a 2nd cmdlet to filter out things you dont want.

Get-ADComputer -filter "Name -like '*DC'" #Filter left technique - criteria as far left as possible
Get-Service | Where-Object -filter { $_.Status -eq 'Stopped' }
Get-Service | Where Status -eq 'Stopped' #Simplified syntax for above command - can be used for single comparison
get-service | where-object {$_.status -eq 'running' -AND $_.StartType -eq 'Manual'}

Get-Process | Where-Object -FilterScript {$_.Name -notlike 'Powershell*'} | Sort-Object VM -Descending | Select -First 10 | Measure-Object -Property VM -Sum
# Get processes. Get rid of everything that’s PowerShell. Sort the processes by virtual memory. Keep only the top 10 or bottom 10, depending on how you sort them. Add up the virtual memory for whatever is left.

Get-Service -computername (Get-Content c:\names.txt | Where-Object -filter { $_ -notlike '*dc' }) | Where-Object -filter { $_.Status -eq 'Running' }

#Start of Lab 11 #

Get-NetAdapter -Physical
Get-NetAdapter | Where-Object {$_.virtual -eq $False} 
Get-DnsClientCache -Type A,AAAA
Dir C:\Windows\System32\*.exe | Where-Object {$_.Length -gt 5MB} 
Get-Hotfix -Description "Security*" 
Get-Hotfix -Description "Security*" | Where-Object {$_.installedby -match "system"}

Get-Process | Where-Object {$_.ProcessName -eq "conhost" -or $_.ProcessName -eq "Svchost"} 
Get-Process -Name Conhost,Svchost

Get-NetAdapter | Where-Object -FilterScript { $_.Virtual -eq $False }
#get-netadapter -physical
 
Get-DnsClientCache -Type A,AAAA | Sort-Object Type

Get-ChildItem c:\Windows\System32\*.exe -Recurse | Where-Object -FilterScript { $_.Length -ge 5 MB }
Get-ChildItem c:\Windows\System32\*.exe | Where-Object -FilterScript { $_.Length -ge 5MB }

Get-HotFix -Description "Security Update"

Get-Hotfix | Where-Object -FilterScript { $_.Installedby -eq 'NT Authority\System' -AND $_.Description -eq 'Security Update' }
#get-hotfix -Description Update | where {$_.InstalledBy -eq "NT Authority\System"}

Get-Process | Where-Object -FilterScript {$_.Name -eq 'Conhost' -or $_.Name -eq 'svchost'}
#get-process -name svchost,conhost

# End of Lab 11 #


#Step 1 - Find The Commands
get-command *privilege
help *privilege*
Find-Module *privilege* | Format-Table -AutoSize #Searched Powershell Gallery Online
install-module -Name PoshPrivilege #Install relevant module found online
Get-Command -Module PoshPrivilege | format-table -AutoSize
Help Add-Privilege -full
Get-privilege

Add-Privilege -AccountName administrators -Privilege SeDenyBatchLogonRight
Get-Privilege -Privilege SeDenyBatchLogonRight

#Start of Lab 12#

mkdir -Name Labs -Path C:\
New-SmbShare -Name Labs -Path C:\Labs -ChangeAccess Everyone -FullAccess Administrators -CachingMode Documents  

#create the folder
New-item -Path C:\Labs -Type Directory | Out-Null
#create the share
$myShare = New-SmbShare -Name Labs -Path C:\Labs\ `
-Description "MoL Lab Share" -ChangeAccess Everyone `
-FullAccess Administrators -CachingMode Documents
#get the share permissions
$myShare | Get-SmbShareAccess


help *share
help New-SmbShare -full
get-smbshare -Name Labs | fl -Property *


MKDIR C:\Labs

$myshare = New-SMBShare -Name Labs -Path C:\Labs -FullAccess Administrators -ChangeAccess Everyone -CachingMode Documents -Verbose

$myshare | Get-SmbShareAccess

#End of Lab 12#

#PS uses WS-MAN as comms protocol for remoting (HTTP/HTTPS - 5985 & 5986) via WinRM service.
#From Objects to XML (Serialisation) & From XML to Objects (Deserialisation)

Enable-PSRemoting
Enter-PSSession -computerName Server-R2 #1to1 session with a device
Exit-PSSession

# Your permissions and privileges carry over across the remote connection. Your copy of
# PowerShell will pass along whatever security token it’s running under (it does this with
# Kerberos, so it doesn’t pass your username or password across the network). Any command
# you run on the remote computer will run under your credentials, so you’ll be
# able to do anything you’d normally have permission to do. It’s as if you logged into
# that computer’s console and used its copy of PowerShell directly.

Invoke-Command -computerName Server-R2,Server-DC4,Server12 -command { Get-EventLog Security -newest 200 | Where { $_.EventID -eq 1212 }} #1toMany
Get-EventLog Security -newest 200 -computerName Server-R2,Server-DC4,Server12 | Where { $_.EventID -eq 1212 } #Same result as above but computers contact sequentially, this runs on local machines and pulls information across network to it!

Invoke-Command -computerName localhost -command { Get-EventLog Security -newest 200 | Where { $_.EventID -eq 1212 }}
Invoke-Command -command { dir } -computerName (Get-Content webservers.txt)

Invoke-Command -command { dir } -computerName (Get-ADComputer -filter * -searchBase "ou=Sales,dc=company,dc=pri" | Select-Object -expand Name )

Enter-PSSession -ComputerName DONJONESE408 -SessionOption (New-PSSessionOption -SkipCNCheck)[DONJONESE408]: PS C:\Users\donjones\Documents>

#Lab 13

Enter-PSSession -ComputerName LON-LT-HP049`
Notepad.exe #Notepad opens as a process on the remote computer, not on the machine i am running the session on.

Invoke-Command -ComputerName PC1 -command { Get-Service | Where-Object {$_.Status -eq "Stopped"}} | Format-Wide -AutoSize
#Invoke-Command –scriptblock {get-service | where {$_.status -eq "stopped"}} -computername Server01,Server02 | format-wide -Column 4

Invoke-Command -ComputerName PC1 -Command { Get-Process | Sort-Object VM -Descending | Select -First 10}
#Invoke-Command -scriptblock {get-process | sort VM -Descending | Select-first 10} –computername Server01,Server02

Invoke-Command -ComputerName (Get-content C:\Computers.txt) -Command {Get-EventLog -LogName Application -Newest 100}
#Invoke-Command -scriptblock {get-eventlog -LogName Application - Newest 100} -ComputerName (Get-Content computers.txt)

Invoke-Command -ComputerName PC1 -Command { Get-ItemProperty -Path "Registry::HKEY_Local_Machine\SOFTWARE\Microsoft\Windows NT\CurrentVersion" | Select-Object ProductName,EditionID,CurrentVersion }
# Invoke-command –scriptblock{get-itemproperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\' | Select ProductName,EditionID,CurrentVersion} -computername Server01, Server02

#End of Lab 13#

Get-CimInstance -Namespace root\securitycenter2 -ClassName antispywareproduct
Get-WmiObject -Namespace root\CIMv2 -list | where name -like '*dis*'
Get-WmiObject -namespace root\cimv2 -list
Get-WmiObject -namespace root\cimv2 -class win32_desktop
Get-WmiObject win32_desktop
Get-WmiObject antispywareproduct -namespace root\securitycenter2
Get-WmiObject win32_operatingsystem | gm
gwmi -class win32_desktop -filter "name='COMPANY\\Administrator'"
Gwmi Win32_BIOS | Format-Table SerialNumber,Version -auto

#Wildcard is % rather than usual *

gwmi -class win32_bios -computer server-r2,localhost |
format-table @{label='ComputerName';expression={$_.__SERVER}},
@{label='BIOSSerial';expression={$_.SerialNumber}},
@{label='OSBuild';expression={
gwmi -class win32_operatingsystem -comp $_.__SERVER |
select-object -expand BuildNumber}
} -autosize

Get-CimInstance -ClassName Win32_LogicalDisk
invoke-command -ScriptBlock { Get-CimInstance -ClassName win32_process } -ComputerName WIN8 -Credential DOMAIN\Administrator

#Start of Lab 14 #

Get-CimClass win32_networkadapterconfiguration | select -expand methods | where Name -match "dhcp"

get-wmiobject win32_operatingsystem | Select BuildNumber,Caption,
@{l='Computername';e={$_.__SERVER}},
@{l='BIOSSerialNumber';e={(gwmi win32_bios).serialnumber }} | ft
-auto

get-ciminstance win32_operatingsystem | Select BuildNumber,Caption,
@{l='Computername';e={$_.CSName}},
@{l='BIOSSerialNumber';e={(get-ciminstance win32_bios).serialnumber
}} | ft -auto

get-wmiobject win32_service | Select Name,State,StartMode,StartName
get-ciminstance win32_service | Select Name,State,StartMode,StartName

get-cimclass -namespace root/SecurityCenter2 -ClassName *product
get-ciminstance -namespace root/SecurityCenter2 -ClassName
AntiSpywareProduct

Get-WmiObject -Namespace root\CIMv2 -list | where name -like '*network*'
Get-WmiObject Win32_NetworkAdapterConfiguration | gm
Get-WmiObject Win32_NetworkAdapterConfiguration | Select-Object DNSHostname,Description,IPAddress
ReleaseDHCPLease

Get-WmiObject Win32_bios -ComputerName Localhost | gm

Get-WmiObject Win32_bios -ComputerName Localhost |
Format-Table @{label='ComputerName';expression={$_.__SERVER}},
@{label='OSBuild';expression={gwmi -class win32_operatingsystem -comp $_.__SERVER | select-object -expand BuildNumber}},
@{label='OSDescription';expression={$_.Caption}},
@{label='BIOSSerial';expression={$_.SerialNumber}} -AutoSize
# get-wmiobject win32_operatingsystem | Select BuildNumber,Caption,@{l='Computername';e={$_.__SERVER}},@{l='BIOSSerialNumber';e={(gwmi win32_bios).serialnumber }} | ft -auto

get-wmiobject win32_quickfixengineering

get-wmiobject win32_service | fl *
get-wmiobject win32_service | Select-Object Name,State,StartMode,StartName
# get-ciminstance win32_service | Select Name,State,StartMode,StartName

Get-CimClass -Namespace root\securitycenter2 -ClassName *product*

Get-CimInstance -Namespace root\securitycenter2 -ClassName antivirusproduct

#End of Lab 14 #

start-job -scriptblock { dir C:\} #Use Absolute paths otherwise you may get inconsistent results
start-job -scriptblock {get-eventlog security -computer LON-LT-HP049} #Job runs locally on the machine but PSRemoting needs to be enabled for subject machine
get-wmiobject win32_operatingsystem -computername (get-content Computers.txt) –asjob #-AsJob moves this sequential task into background job
invoke-command -command { get-process } -computername (get-content .\computers.txt ) -asjob -jobname MyRemoteJob
Get-Job 
get-job -id 1 | format-list *
Receive-Job -Id 1
Receive-Job -Id 1 -Keep #Receive job and keep information cached in memory (Will clear otherwise)
Receive-job -name myremotejob | sort-object PSComputerName | Format-Table -groupby PSComputerName
Start-Job -script { Get-Service }
get-job -id 1 | select-object -expand childjobs
get-job | where { -not $_.HasMoreData } | remove-job #Remove jobs

Register-ScheduledJob -Name DailyProcList -ScriptBlock {Get-Process} -Trigger (New-JobTrigger -Daily -At 2am) -ScheduledJobOption (New-ScheduledJobOption -WakeToRun -RunElevated)

#Start of Lab 15 *

start-job -ScriptBlock {Get-ChildItem c:\*.ps1 -Recurse}
#Start-Job {dir c:\ -recurse –filter '*.ps1'}

invoke-command -command {Get-ChildItem c:\*.ps1 -Recurse} -computername (get-content .\computers.txt ) -asjob -jobname MyRemoteJob
#Invoke-Command –scriptblock {dir c:\ -recurse –filter *.ps1} –computername (get-content computers.txt) -asjob

Register-ScheduledJob -Name EventLogs -ScriptBlock {Get-EventLog -Logname System} -Trigger (New-JobTrigger -DaysOfWeek -At 6am) -ScheduledJobOption (New-ScheduledJobOption -WakeToRun -RunElevated) | Export-Clixml Events.xml

$Trigger=New-JobTrigger -At "6:00AM" -DaysOfWeek "Monday",
"Tuesday","Wednesday","Thursday","Friday" –Weekly
$command={ Get-EventLog -LogName System -Newest 25 -EntryType Error
| Export-Clixml c:\work\25SysErr.xml}
Register-ScheduledJob -Name "Get 25 System Errors" -ScriptBlock
$Command -Trigger $Trigger
#check on what was created
Get-ScheduledJob | Select *

Receive-Job -Id -keep

#End of Lab 15#

#Batch CMDLETS - The Preferred Way
Get-Service -name BITS,Spooler,W32Time | Set-Service -startuptype Automatic #Batch CMDLET example
Get-Service -name BITS,Spooler,W32Time -computer Server1,Server2,Server3 | -Service -startuptype Automatic #No Output
Get-Service -name BITS -computer Server1,Server2,Server3 | Start-Service -passthru | Out-File NewServiceStatus.txt #Shows output of command to determine success

#CIM/WMI Invoking Method
gwmi win32_networkadapterconfiguration -filter "description like '%intel%'"
gwmi win32_networkadapterconfiguration -filter "description like '%intel%'" | gm
gwmi win32_networkadapterconfiguration -filter "description like '%intel%'" | Invoke-WmiMethod -name EnableDHCP
Get-CimInstance -classname win32_networkadapterconfiguration -filter "description like '%intel%'" | Invoke-CimMethod -methodname EnableDHCP

Get-WmiObject Win32_Service -filter "name = 'BITS'" | ForEach-Object -process { $_.change($null,$null,$null,$null,$null,$null,$null,"P@ssw0rd") }
# gwmi win32_service -fi "name = 'BITS'" | % {$_.change($null,$null,$null,$null,$null,$null,$null,"P@ssw0rd") }

Get-Service -name *B* | Stop-Service #Batch CMDLET
Get-Service -name *B* | ForEach-Object { $_.Stop()} #For-Each Object
Get-WmiObject Win32_Service -filter "name LIKE '%B%'" | Invoke-WmiMethod -name StopService #WMI
Get-WmiObject Win32_Service -filter "name LIKE '%B%'" | ForEach-Object { $_.StopService()} #WMI and For-Each Object
Stop-Service -name *B* #Stop Service

You can never pipe anything to a method. You can pipe only from one cmdlet to
another. If a cmdlet doesn’t exist to do what you need, but a method does, then you
pipe to ForEach-Object and have it execute the method.
For example, suppose you retrieve something by using a Get-Something cmdlet. You
want to delete that something, but there’s no Delete-Something or Remove-Something
cmdlet. But the Something objects do have a Delete method. You can do this:

#Get-Something | ForEach-Object { $_.Delete() }


#Start of Lab 16 #

Get-Service | gm
Pause method
#get-service | Get-Member -MemberType Method

Get-Process | gm
Kill method
#get-process | Get-Member -MemberType Method

Get-WmiObject -Class Win32_Process -list | fl *
Terminate method
#Get-CimClass win32_process | select -ExpandProperty method

Get-Process -ProcessName notepad | Stop-Process #Batch CMDLET
Get-Process -ProcessName notepad | ForEach-Object { $_.Kill()} #For-Each Object
Stop-Process -ProcessName Notepad #Stop Service

Get-WmiObject -Namespace root\CIMv2 -list | where name -like '*process*'
Get-WmiObject Win32_Process | gm
Get-WmiObject Win32_process -filter {name = 'notepad.exe'}  | ForEach-Object { $_.Terminate()}#WMI and For-Each Object
Get-WmiObject Win32_process -filter {name = 'notepad.exe'} | Invoke-WmiMethod -name Terminate #WMI

Get-content computers.txt | foreach {$_.ToUpper()}

#End of Lab 16

#Execution Policy - This machine-wide setting governs the scripts that PowerShell will execute

Get-ExecutionPolicy #Use Restricted on non script machines and Remote Signed for machines running scripts
Set-AuthenticodeSignature #Apply a digital certificate to a script

#Lab 17

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

#Use {} To contain a variable with a space in the name
$var = "LON-LT-HP049"
get-wmiobject win32_computersystem -comp $var
$var = 'What does $var contain?'

$computername = 'LON-LT-HP049'
$phrase = "The computer name is $computername"

$computername = 'SERVER-R2'
$phrase = "`$computername contains $computername" # ` preceding the work changes the variable to literal

$computername = 'SERVER-R2'
$phrase = "`$computername`ncontains`n$computername" #`n creates a new line (about_escape)

$computers = 'SERVER-R2','SERVER1','localhost'
$computers[0]
$computers[1]
$computers[2]
$computers[-1] #Access last variable on list

$computers.count
$computername.toupper()
$computername.tolower()

$computers[1] = $computers[1].replace('SERVER','CLIENT') #Version 2 Powershell

$computers = $computers | ForEach-Object { $_.ToLower()}
$computers
$computers | select-object length

$services = get-service
$firstname = "The first name is $($services[0].name)"
$firstname

$number = Read-Host "Enter a number"
$number = $number * 10 #Doesnt work as the |gm is a string and not integer
$number
$number | gm

[int]$number = Read-Host "Enter a number"
$number = $number * 10 #Works as its an integer
$number

#[int] - Numbers
#[Single] & [double] - Numbers with a decimal portion
#[string] - Characters
#[char] - Exactly one character
#[xml] - XML document
#[adsi] - AD Service Interface query e.g. [adsi]$user = "WinNT:\\MYDOMAIN\Administrator,user"

#Lab 18

invoke-command {get-wmiobject win32_bios} –computername LON-LT-HP049,$env:computername –asjob
Get-Job
$results=Receive-Job 8 –keep
$results
$results | export-clixml bios.xml


read-host "Enter a computer name"
$computername = read-host "Enter a computer name"

#Create a graphical input box
[void][System.Reflection.Assembly]::LoadWithPartialName('Microsoft.VisualBasic') #Void means "throw the result away like Out-Null
$computername = [Microsoft.VisualBasic.Interaction]::InputBox('Enter a computer name','Computer Name','localhost')

write-host "COLORFUL!" -fore yellow -back magenta

write-output "Hello" | where-object { $_.length -gt 10 }#Doesnt output as the Hello text is dropped by the pipeline
write-host "Hello" | where-object { $_.length -gt 10 } #Write-Host outputs directly to the screen, ignoring the pipeline

#Lab 19

100*10 | Write-Output
#Write-Output (100*10)

100*10 | write-host
#Write-Host (100*10)

$computername = read-host "Enter a computer name" 
write-host $computername -fore yellow

$name = read-host "Enter a name"
write-output $name | where-object { $_.length -gt 10 }
#Read-Host "Enter a name" | where {$_.length -gt 5}


new-pssession -computername server-r2,server17,dc5
Get-PSSession
Remove-PSSession

$iis_servers = new-pssession -comp web1,web2,web3 -credential WebAdmin
$s_server1,$s_server2 = new-pssession -computer server-r2,dc01 #Create separate sessions within the same variable.

$sessions = New-PSSession -ComputerName LON-LT-HP049,localhost
enter-pssession -session $sessions[0]
enter-pssession -session ($sessions | where { $_.computername -eq 'LON-LT-HP049' })
enter-pssession -session (get-pssession -computer LON-LT-HP049)
Get-PSSession -ComputerName LON-LT-HP049 | Enter-PSSession
Disconnect-PSSession -Id 4
Get-PSSession -computerName COMPUTER2 | Connect-PSSession

invoke-command -command { get-wmiobject -class win32_process } -session $sessions
invoke-command -command { get-wmiobject -class win32_process } -session (get-pssession –comp server1,server2,server3)

#Lab 20

Get-PSSession | Remove-PSSession

$Session = New-PSSession -ComputerName Server2012
Enter-PSSession -Session $Session

Enter-PSSession -Session $Session[0]
Get-Process
Exit

Invoke-Command -command { Get-Service } -Session $Session

invoke-command -command { get-eventlog -LogName Security -newest 20 } -session (get-pssession –comp LON-LT-HP049)

Invoke-Command -command { import-module ServerManager } -Session $Session

$Session = New-PSSession -ComputerName Server2012
Invoke-Command -command { Import-Module ServerManager } -Session $Session
Import-PSSession -Session $Session -Module ServerManager -Prefix rem

Get-remWindowsFeature

Remove-PSSession -Session $session



Get-WmiObject -class Win32_LogicalDisk -computername localhost -filter "drivetype=3" | 
Sort-Object -property DeviceID | 
Format-Table -property DeviceID,
@{label='FreeSpace(MB)';expression={$_.FreeSpace / 1MB -as [int]}}, 
@{label='Size(GB)';expression={$_.Size / 1GB -as [int]}},
@{label='%Free';expression={$_.FreeSpace / $_.Size * 100 -as [int]}}

Get-PSSessionConfiguration

#Creating Session Configuration
New-PSSessionConfigurationFile -Path C:\HelpDeskEndpoint.pssc -ModulesToImport NetAdapter -SessionType RestrictedRemoteServer -CompanyName "Our Company" -Author "Don Jones"`
-Description "Net adapter commands for use by help desk" -PowerShellVersion '3.0'

#Registering the session
Register-PSSessionConfiguration -Path .\HelpDeskEndpoint.pssc -RunAsCredential COMPANY\HelpDeskProxyAdmin -ShowSecurityDescriptorUI -Name HelpDesk

Enable-WSManCredSSP -Role Server #Run on Computer B first before running the below
Enable-WSManCredSSP -Role Client -DelegateComputer [computername] #Allows multihop delegation of credentials (computer A login to work on Computer C from B)

#Lab 23

New-PSSessionConfigurationFile -Path C:\SMBShareEndpoint.pssc -ModulesToImport SMBShare -SessionType RestrictedRemoteServer -CompanyName "My Company" -Author "Author Name"`
-Description "restricted SMBShare Endpoint" -PowerShellVersion '3.0'

Register-PSSessionConfiguration -Path C:\SMBShareEndpoint.pssc -Name TestPoint

Enter-PSSession -ComputerName localhost -ConfigurationName TestPoint
get-command
exit-pssession




 #Yes because -Expand Name is feeding string output to the -ComputerName parameter as required.
 #No because you cant feed the output Type (ADComputer) into any parameter of Get-Hotfix which expects a String for the ComputerName.
 #Yes
 Get-Service –Computername (get-adcomputer -filter * | Select-Object –expandproperty name)
 
 Get-ADComputer -filter * | Select-Object @{l='computername';e={$_.name}} | Get-Process 
 Get-Service -ComputerName (Get-ADComputer -filter *)
 
 $NetAdapterName = Get-NetAdapter -Name Ethernet | Select MacAddress
 Get-ComputerInfo | Select-Object -Property BiosSeralNumber,CSDnsHostName,{Get-NetAdapter -Name Ethernet | Select MacAddress}



#Commands I Have Built

Get-ADComputer -Filter * -SearchBase "DC=grace-eyre,DC=org" -properties * | Sort-Object OperatingSystem | FT Name,OperatingSystem,LastLogonDate,Description -AutoSize | Out-File C:\Computers.csv


[PSCustomObject]@{
    BiosSerialNumber = (Get-CimInstance -ClassName Win32_BIOS).SerialNumber
    CsDNSHostName    = $ENV:COMPUTERNAME
    MacAddress       = Get-NetAdapter -Name * | Select-Object -ExpandProperty MacAddress
}

$cutoffdate = [datetime]"02-01-2020";
Get-MailboxStatistics -Server Exchange2010 |
    where lastlogontime -gt $cutoffdate |
        select DisplayName,LastLogonTime,LastLogoffTime,ItemCount,TotalItemSize,DatabaseName |
            Export-CSV C:\Temp\Test.csv -NoTypeInformation

#Get Last Logon Time to Exchange Mailbox 
Get-MailboxStatistics -Server Exchange2010 | sort LastLogonTime -Descending | Export-CSV c:\Temp\Mailboxes1.csv -NoTypeInformation