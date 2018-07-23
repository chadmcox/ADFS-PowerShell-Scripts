#requires -version 4.0
<#PSScriptInfo

.VERSION 0.1

.GUID 1b77c367-a9b9-4182-b671-1ca70b9f95e1

.AUTHOR Chad.Cox@microsoft.com
    https://blogs.technet.microsoft.com/chadcox/
    https://github.com/chadmcox

.COMPANYNAME 

.COPYRIGHT This Sample Code is provided for the purpose of illustration only and is not
intended to be used in a production environment.  THIS SAMPLE CODE AND ANY
RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER
EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF
MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE.  We grant You a
nonexclusive, royalty-free right to use and modify the Sample Code and to
reproduce and distribute the object code form of the Sample Code, provided
that You agree: (i) to not use Our name, logo, or trademarks to market Your
software product in which the Sample Code is embedded; (ii) to include a valid
copyright notice on Your software product in which the Sample Code is embedded;
and (iii) to indemnify, hold harmless, and defend Us and Our suppliers from and
against any claims or lawsuits, including attorneys` fees, that arise or result
from the use or distribution of the Sample Code..

.TAGS AD Domain Controllers Windows

.DESCRIPTION 
 This script generates a list of membership from a csv file. 

#> 
Param($reportpath = "$env:userprofile\Documents\ADFSLogs")

#region functions
function CollectEventLogs{
    [cmdletbinding()]
    param()
    process{
    
        foreach ($eventLogName in $eventLogNames)
        {
            write-host "collect Event logs $eventLogName"
            $_event_log_from = (Get-Date) - (New-TimeSpan -Day 60)
            $defaultFile = $reportpath + "\" + $env:computername + "_evt_" + $($eventLogName -replace "/","_") + ".csv"
            #Get-EventLog $eventLogName -After ((Get-Date).date).addDays(-60) | Select-Object TimeGenerated, MachineName, EventID, Source, EntryType, @{n= "Message";e={ ($_.Message -Replace “`r`n|`r|`n”,” ”).Trim() }} | Export-Csv $defaultFile -NoTypeInformation 
            Get-WinEvent -FilterHashTable @{LogName=$eventLogName; StartTime=$_event_log_from} -ErrorAction SilentlyContinue | Select-Object Machinename, TimeCreated, ID, UserId,LevelDisplayName,ProviderName, @{n= "Message";e={ ($_.Message -Replace “`r`n|`r|`n”,” ”).Trim() }} | Export-Csv $defaultFile -NoTypeInformation 
        }
    }
}
function CollectRegistryValues{
    [cmdletbinding()]
    param()

    write-host "Gathering registry data"
    $defaultFile = "$reportpath\$($env:computername)_reg_policies.txt"
    reg export HKEY_LOCAL_MACHINE\Software\Policies $defaultFile
    $defaultFile = "$reportpath\$($env:computername)_reg_schannel_protocols.txt"
    reg export HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols $defaultFile
    $defaultFile = "$reportpath\$($env:computername)_reg_tcpip.txt"
    reg export HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\Tcpip $defaultFile
    
    $defaultFile = "$reportpath\$($env:computername)_reg_symantec.txt"
    reg export HKEY_LOCAL_MACHINE\SOFTWARE\Symantec $defaultFile
    $defaultFile = "$reportpath\$($env:computername)_reg_windows_defender.txt"
    reg export HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows Defender\Exclusions $defaultFile

    $defaultFile = "$reportpath\$($env:computername)_reg_system_currentcontrolset_services.txt"
    reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa /s | out-file $defaultFile -append
    reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NTDS /s | out-file $defaultFile -append
    reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\AFD /s | out-file $defaultFile -append
    reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\NetBt /s | out-file $defaultFile -append
    reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer /s | out-file $defaultFile -append
    reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Netlogon /s | out-file $defaultFile -append
    reg query HKEY_LOCAL_MACHINE\System\CurrentControlSet\Services\LDAP /s | out-file $defaultFile -append

    $defaultFile = "$reportpath\$($env:computername)_reg_Image_File_Execution_Options.txt"
    reg query 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' /s | out-file $defaultFile -append

    $defaultFile = "$reportpath\$($env:computername)_reg_run.txt"
    reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run /s | out-file $defaultFile
    reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run /s | out-file $defaultFile -append
    reg query HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce /s | out-file $defaultFile -append
    reg query HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce /s | out-file $defaultFile -append
}
function CollectWindowsServerDetails{
    [cmdletbinding()]
    param()
    process{
        write-host "collect patches"
        $defaultFile = "$reportpath\$($env:computername)_hotfix.csv"
        get-hotfix | select PSComputerName,InstalledOn,Description,HotFixID,InstalledBy | sort InstalledOn | export-csv $defaultFile -NoTypeInformation

        write-host "Collect gpresult"
        $defaultFile = "$reportpath\$($env:computername)_gpresult.htm"
        gpresult /h $defaultFile
        $defaultFile = "$reportpath\$($env:computername)_gpresult.txt"
        gpresult /V | out-file $defaultFile

        write-host "gather services"
        $defaultFile = "$reportpath\$($env:computername)_services_results.csv"
        #get-service | select name, displayname, status | export-csv $defaultFile -NoTypeInformation
        Get-WmiObject win32_service | select name, displayname, description, startname, startmode, state | export-csv $defaultFile -NoTypeInformation

        write-host "gather drivers"
        $defaultFile = "$reportpath\$($env:computername)_windows_drivers.csv"
        Get-WindowsDriver -Online -All | export-csv $defaultFile -NoTypeInformation

        write-host "get netstat info"
        $defaultFile = "$reportpath\$($env:computername)_netstat.csv"
        If ($(Try{get-command -name Get-NetTCPConnection -ErrorAction SilentlyContinue}Catch{$false})){
            Get-NetTCPConnection | Group-Object -Property State, OwningProcess | Select `
                -Property Count, Name, @{Name="ProcessName";Expression={(Get-Process -PID ($_.Name.Split(',')[-1].Trim(' '))).Name}} | Sort Count -Descending | export-csv $defaultFile -NoTypeInformation 
        }else{
            get-netstat
        }

        write-host "System Info"
        $defaultFile = "$reportpath\$($env:computername)_systeminfo.txt"
        systeminfo | out-file $defaultFile

        write-host "whoami"
        $defaultFile = "$reportpath\$($env:computername)_whoami.txt"
        whoami /all | out-file $defaultFile


        write-host "time data"
        $defaultFile = "$reportpath\$($env:computername)_time.txt"
        w32tm /query /configuration | out-file $defaultFile

        write-host "gatheering processes"
        $defaultFile = "$reportpath\$($env:computername)_process.csv"
        get-process -includeusername | select name,description,Id,path,ProcessName,fileversion,Handles,NPM,PM,WS,VM,CPU | export-csv $defaultFile -NoTypeInformation 
        
        write-host "gathering file versions"
        $defaultFile = "$reportpath\$($env:computername)_file_dll.csv"
        get-childitem C:\windows\system32 -recurse |  where {$_.extension -eq ".dll"} | `
            select Directory,name,extension, @{name='fileversion';expression={($_.versioninfo).fileversion}},`
                @{name='productversion';expression={($_.versioninfo).productversion}} | export-csv $defaultFile -NoTypeInformation
        $defaultFile = "$reportpath\$($env:computername)_file_sys.csv"
        get-childitem C:\windows\system32 -recurse |  where {$_.extension -eq ".sys"} |`
             select Directory,name,extension, @{name='fileversion';expression={($_.versioninfo).fileversion}},`
                @{name='productversion';expression={($_.versioninfo).productversion}} | export-csv $defaultFile -NoTypeInformation

        write-host "gathering filter drivers"  
        $defaultFile = "$reportpath\$($env:computername)_filter_drivers.txt"
        Fltmc instances | out-file $defaultFile
    
        write-host "gathering Power Scheme"  
        $defaultFile = "$reportpath\$($env:computername)_Power_Schemes.txt"
        Powercfg /list | out-file $defaultFile

        write-host "gathering Schedule Task"
        $defaultFile = "$reportpath\$($env:computername)_Schedule_Task.csv"
        Get-Scheduledtask | select taskpath,taskname,state,actions,execute, arguments, workingdirectory | export-csv $defaultFile

        write-host "gathering drive data"
        $defaultFile = "$reportpath\$($env:computername)_Drive.csv"
        GET-WMIOBJECT –query “SELECT * from win32_logicaldisk” | export-csv $defaultFile
        $defaultFile = "$reportpath\$($env:computername)_disk.csv"
        Get-PhysicalDisk | export-csv $defaultFile
        $defaultFile = "$reportpath\$($env:computername)_disk_reliability_counter.csv"
        Get-PhysicalDisk | Get-StorageReliabilityCounter | export-csv $defaultFile
    }
}
function CollectServerPerformance{
    write-host "gathering performance data"
    ($_perf_counters | Get-Counter -MaxSamples 5 -ErrorAction SilentlyContinue).countersamples | `
        select-object -Property timestamp, Path, InstanceName, CookedValue | foreach{
    ##this calls to a custom function
    format-perf -countersample $_
    
}
}
function MaxNumOfTcpPorts{  #helper function to retrive number of ports per address
param 
    (
        [parameter(Mandatory=$true)]
         $tcpParams
    )
    #  Returns the maximum number of ports per TCP address
    #  Check for Windows Vista and later
    $IsVistaOrLater = Get-WmiObject -Class Win32_OperatingSystem | %{($_.Version -match "6\.\d+")}
    if($isVistaOrLater)
    {
        # Use netsh to retrieve the number of ports and parse out the string of numbers after "Number of Ports : "
        $maxPorts = netsh int ip show dynamicport tcp |
            Select-String -Pattern "Number of Ports : (\d*)"|
            %{$_.matches[0].Groups[1].Value}
        # Convert string to integer
        $maxPorts = [int32]::Parse($maxPorts)
        #  modify the PSCustomObject to simulate the MaxUserPort value for printout
        Add-Member -InputObject $tcpParams -MemberType NoteProperty -Name MaxUserPort -Value $maxPorts 
    }
    else  # this is Windows XP or older
    {
        # check of emphermal ports modified in registry
        $maxPorts = $($tcpParams | Select-Object MaxUserPort).MaxUserPort
        if($maxPorts -eq $null)
        {
            $maxPorts = 5000 - 1kb    #Windows Default range is from 1025 to 5000 inclusive
            Add-Member -InputObject $tcpParams -MemberType NoteProperty -Name MaxUserPort -Value $maxPorts
        }
    }
    return $maxPorts
}
function New-Port{  # helper function to track number of ports per IP address
    Param
    (
        [string] $IPAddress = [String]::EmptyString,
        [int32] $PortsWaiting = 0,
        [int32] $MaxUserPort = 3976
    )

    $newPort = New-Object PSObject

    Add-Member -InputObject $newPort -MemberType NoteProperty -Name IPAddress -Value $IPAddress
    Add-Member -InputObject $newPort -MemberType NoteProperty -Name PortsUsed -Value 1
    Add-Member -InputObject $newPort -MemberType ScriptProperty -Name PercentUsed -Value {$this.PortsUsed / $this.MaxUserPort}
    Add-Member -InputObject $newPort -MemberType NoteProperty -Name PortsWaiting -Value $portsWaiting
    Add-Member -InputObject $newPort -MemberType ScriptProperty -Name PercentWaiting -Value {$this.PortsWaiting / [Math]::Max(1,$this.PortsUsed)}
    Add-Member -InputObject $newPort -MemberType NoteProperty -Name MaxUserPort -Value $maxUserPort
    return $newPort
}
Function get-netstat{

    $defaultFile = "$reportpath\$($env:computername)_netstat.csv"
        ######################### Beginning of the main routine ##########################

    # Store MaxUserPort for percentage used calculations
    $tcpParams = Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\services\Tcpip\Parameters
    $maxPorts = MaxNumOfTcpPorts($tcpParams)   # call function to return max # ports as per OS version
    $tcpTimedWaitDelay = $($tcpParams | Select-Object TcpTimedWaitDelay).TcpTimedWaitDelay

    if($tcpTimedWaitDelay -eq $Null)           #Value wasn't configured in registry
    {
        $tcpTimedWaitDelay = 240               #Default Value if registry value doesn't exist
        Add-Member -InputObject $tcpParams -MemberType NoteProperty -Name TcpTimedWaitDelay -Value $tcpTimedWaitDelay  #fake reg value for output
    }
    # display current date and time
    #Write-Host -Object $(Get-Date)

    # Display the MaxUserPort and TcpTimedWaitDelay settings in the registry if available
    #$tcpParams | Format-List MaxUserPort,TcpTimedWaitDelay

    # collection of IP Address and port counts
    [System.Collections.HashTable] $ports = New-Object System.Collections.HashTable

    [int32] $intWait = 0

    netstat -an | 
    Select-String "TCP\s+.+\:.+\s+(.+)\:(\d+)\s+(\w+)" | 
    ForEach-Object {
        $key = $_.matches[0].Groups[1].value      # use the IP address as hash key
        $Status = $_.matches[0].Groups[3].value   # Last group contains port status
        if("TIME_WAIT" -like $Status)
        {
            $intWait = 1                          # incr count
        }
        else
        {
            $intWait = 0                          # don't incr count
        }
        if(-not $ports.ContainsKey($key))         #IP Address not yet counted
        {
            $port = New-Port -IPAddress $key -PortsWaiting $intWait -MaxUserPort $maxPorts    #intialize new tracking object
            $ports.Add($key,$port)                #Add the tracking object to hashtable
        }
        else                                      #otherwise a tracking object exists for this IP
        {
            $port = $ports[$key]                  #retrieve the tracking object
            $port.PortsUsed ++                    # increment the port count (PortsUsed)
            $port.PortsWaiting += $intWait        # increment PortsWaiting if status is TIME_WAIT
        }
    }

    $ports | Select -expand Values | Sort-Object -Property PortsUsed, PortsWaiting -Descending | select -Property IPAddress,PortsWaiting,
        @{Name='%Waiting';Expression ={"{0:P}" -f $_.PercentWaiting}},
        PortsUsed,
        @{Name='%Used';Expression ={"{0:P}" -f $_.PercentUsed}} | Export-Csv -path $defaultFile

}
function collectADFSStuff{
    $defaultFile = "$reportpath\$($env:computername)_ADFS_Config.txt"
    #collect dns info
    "<---------------------Resolve Hostname ---------------------------------------------------------------------------->" | out-file $defaultFile -Append
    Resolve-DnsName (Get-AdfsProperties).hostname | out-file $defaultFile -Append

    #Collect ADFS General Properties
    "<---------------------General ADFS Config ------------------------------------------------------------------------->" | out-file $defaultFile -Append
    Get-AdfsProperties | out-file $defaultFile -Append

    #Collect info about the Replying Party Trust
    "<---------------------Relying Party Trust - Microsoft Office 365 Identity Platform Settings------------------------>" | out-file $defaultFile -Append
    Get-AdfsRelyingPartyTrust –Name "Microsoft Office 365 Identity Platform" | out-file $defaultFile -Append

    #collect supported browser info
    "<---------------------Supported Browsers--------------------------------------------------------------------------->" | out-file $defaultFile -Append
    Get-AdfsProperties | select -ExpandProperty WIASupportedUserAgents | out-file $defaultFile -Append

    #Collect Certificate information
    "<---------------------Certificate Info----------------------------------------------------------------------------->" | out-file $defaultFile -Append
    Get-AdfsSslCertificate | out-file $defaultFile -Append
    Get-AdfsCertificate | out-file $defaultFile -Append

    #Collect Hotfixes
    "<---------------------Installed Hotfix----------------------------------------------------------------------------->" | out-file $defaultFile -Append
    get-hotfix | out-file $defaultFile -Append

    #collect services
    "<---------------------Services State------------------------------------------------------------------------------->" | out-file $defaultFile -Append
    Get-WmiObject win32_service | select name,startname,state | out-file $defaultFile -Append

    #collect service account spn info
    "<---------------------Services Account SPN------------------------------------------------------------------------->" | out-file $defaultFile -Append
    $adfssn = (Get-WmiObject win32_service | where {$_.name -eq "adfssrv"}).startname
    setspn -l $adfssn | out-file $defaultFile -Append

    $recoveryfile = "$reportpath\restorescript-$env:computername-$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).ps1_bak"

    $customIAR = (Get-AdfsRelyingPartyTrust –Name "Microsoft Office 365 Identity Platform").IssuanceAuthorizationRules
    "Get-AdfsRelyingPartyTrust –Name 'Microsoft Office 365 Identity Platform' | Set-ADFSRelyingPartyTrust -IssuanceAuthorizationRules '$customIAR'" | out-file $recoveryFile -append

    $customITR = (Get-AdfsRelyingPartyTrust –Name "Microsoft Office 365 Identity Platform").IssuanceTransformRules
    "Get-AdfsRelyingPartyTrust –Name 'Microsoft Office 365 Identity Platform' | Set-ADFSRelyingPartyTrust -IssuanceTransformRules '$customITR'" | out-file $recoveryFile -append

    $customAAR = (Get-AdfsRelyingPartyTrust –Name "Microsoft Office 365 Identity Platform").AdditionalAuthenticationRules
    "Get-AdfsRelyingPartyTrust –Name 'Microsoft Office 365 Identity Platform' | Set-ADFSRelyingPartyTrust -AdditionalAuthenticationRules '$customAAR'" | out-file $recoveryFile -append
}
Function format-perf{
    [cmdletbinding()]
    param($countersample)
    $pattern = '(?<srv>\\\\[^\\]*)?\\(?<obj>[^\(^\)]*)(\((?<inst>.*(\(.*\))?)\))?\\(?<ctr>.*\s?(\(.*\))?)'
    $defaultFile = $reportpath + "\" + $env:computername + "_perf_counter.csv"
                
    If ($Countersample.path -match $pattern)
    {         
        $oCtr = New-Object psobject
        $oCtr | add-member -membertype NoteProperty -name 'TimeStamp' -Value $Countersample.timestamp
        $oCtr | Add-Member -MemberType NoteProperty -Name 'Computer' -Value $($matches["srv"] -replace "\\","")
        $oCtr | Add-Member -MemberType NoteProperty -Name 'InstanceName' -Value $matches["inst"]
        $oCtr | Add-Member -MemberType NoteProperty -Name 'Counter' -Value $matches["ctr"]
        $oCtr | Add-Member -MemberType NoteProperty -Name 'Object' -Value $matches["obj"]
        $oCtr | Add-Member -MemberType NoteProperty -Name 'Value' -Value $Countersample.cookedvalue
        if($Countersample.cookedvalue -gt 0){
            $oCtr | select-object -Property TimeStamp,Computer,object,counter,InstanceName,Value | export-csv $defaultFile -append -NoTypeInformation 
        }
    }Else{
        Return $null
    }
}
function archive_results{
    [cmdletbinding()]
    param($source,$destination)
    Process{
        $source
        $destination
        Add-Type -assembly "system.io.compression.filesystem"
        [io.compression.zipfile]::CreateFromDirectory($source, $destination) 
    }
}
#endregion


$_perf_counters = "\AD FS Proxy\*","\AD FS Proxy\*","\Memory\*","\PhysicalDisk(*)\*","\Process(*)\*","\Processor(*)\*","\TCPv4\*"
$eventLogNames = "Application", "Security","System","Windows PowerShell","AD FS/Admin","Microsoft-Windows-PowerShell/Operational","Microsoft-Windows-CAPI2/Operational"

write-host "Creating folder structure"



If (!($(Try { Test-Path $reportpath } Catch { $true }))){
    new-Item $reportpath -ItemType "directory"  -force
}

$DebugPreference = "Continue"

if($(try{(Get-WindowsFeature -Name ADFS-Federation).installed -eq $true}catch{$false})){
    
    CollectRegistryValues
    CollectWindowsServerDetails
    CollectServerPerformance
    collectADFSStuff
    CollectEventLogs
    $archive = "$env:userprofile\Documents\$($env:computername)-ARCHIVE-$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).zip"
    archive_results -source $reportpath -destination $archive

    write-host "Report Can be found here $_archive"
}
