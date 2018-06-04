#Requires -Version 4
<#PSScriptInfo

.VERSION 0.11

.GUID 211b41f9-0d95-413c-920f-50b53b33633d

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

.TAGS 

.LICENSEURI 

.PROJECTURI 

.ICONURI 

.EXTERNALMODULEDEPENDENCIES 

.REQUIREDSCRIPTS 

.EXTERNALSCRIPTDEPENDENCIES 

.RELEASENOTES


.DESCRIPTION 
 the goal will be to set up a schedule task to run this hourly

#> 
Param(
    $reportpath = "c:\ADFSEventCollection")


If (!($(Try { Test-Path  $reportpath } Catch { $true }))){
    new-Item  $reportpath -ItemType "directory"  -force
}


function CollectSecurity516Events{
    $_time_filter = (Get-Date).AddHours(-1)
    $_xml_lockout_adfs = "<QueryList><Query Id=""0"" Path=""Security""><Select Path=""Security"">*[System[Provider[@Name='AD FS Auditing'] and (EventID=516)]]</Select></Query></QueryList>"
    
    $events = @()
    $results = Get-WinEvent -FilterXml $_xml_lockout_adfs | where {$_.TimeCreated -ge $_time_filter}
    $results | foreach {
        $useragentString = $null
        if($($_.Properties[0].Value) -ne "00000000-0000-0000-0000-000000000000"){
            $_operation_id_adfs = $_.Properties[0].Value
            $_xml_lockout_adfs_useragent = "<QueryList><Query Id=""0"" Path=""Security""><Select Path=""Security"">*[System[Provider[@Name='AD FS Auditing'] and (EventID=403)]] and *[ EventData[ Data and (Data='$_operation_id_adfs') ] ]</Select></Query></QueryList>"
            $useragentString = (Get-WinEvent -FilterXml $_xml_lockout_adfs_useragent -MaxEvents 1).Properties[8].Value
        }
        $_ip = $_.Properties[2].Value
        $_ip = $_ip.split(",")
        $_ip = $_ip[0]
        if($_ip -match "\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"){
             $events += $_ | select `
                @{name='Account';expression={$($_.Properties[1].Value)}},`
                @{name='ExternalIP';expression={$_ip}},`
                @{name='ClassBSubnet';expression={"$((($_ip).split("."))[0]).$((($_ip).split("."))[1]).0.0"}},`
                @{name='DateTime';expression={"$($_.Properties[4].Value)"}},`
                @{name='TimeCreated';expression={$_.TimeCreated}},`
                @{name='Activity';expression={$($_.Properties[0].Value)}},`
                @{name='UserAgentString';expression={$useragentString}}
        }
    }
    $events
}
Function format-perf{
    [cmdletbinding()]
    param($countersample)
    $pattern = '(?<srv>\\\\[^\\]*)?\\(?<obj>[^\(^\)]*)(\((?<inst>.*(\(.*\))?)\))?\\(?<ctr>.*\s?(\(.*\))?)'
    $_default_log = $_default_report_path + "\" + $env:computername + "_perf_counter.csv"
                
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
            $oCtr | select-object -Property TimeStamp,Computer,object,counter,InstanceName,Value
        }
    }Else{
        Return $null
    }
}

function CollectADFSPerf{
    $_counters = "\AD FS\*"
    $_sample = 5
    ($_counters | Get-Counter -MaxSamples $_sample -ErrorAction SilentlyContinue).countersamples | `
        select-object -Property timestamp, Path, InstanceName, CookedValue | foreach{
    ##this calls to a custom function
    format-perf -countersample $_}
}

CollectSecurity516Events | export-csv "$reportpath\516Events.csv" -Append -NoTypeInformation
CollectADFSPerf | export-csv "$reportpath\adfsperfcounters.csv" -append -NoTypeInformation

import-csv "$reportpath\516Events.csv" | group Account | select name,count | `
    export-csv "$reportpath\userlockoutsummary.csv" -NoTypeInformation
import-csv "$reportpath\516Events.csv" | group ClassBSubnet | select name,count | `
    export-csv "$reportpath\subnetlockoutsummary.csv" -NoTypeInformation
import-csv "$reportpath\516Events.csv" | group DateTime | select name,count | `
    export-csv "$reportpath\datelockoutsummary.csv" -NoTypeInformation
