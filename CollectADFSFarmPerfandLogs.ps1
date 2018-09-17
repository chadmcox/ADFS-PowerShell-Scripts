#sample code


$_default_log = $env:userprofile + "\Documents\perf-collection.csv"

$DebugPreference = "Continue"

$_event_Logs = "Application", "System", "AD FS/Admin", "DRS/Admin"
$_event_log_from = (Get-Date) - (New-TimeSpan -Day 75)
#$_servers = "s1","s2","s3"
$_servers = "corp-adfs1"

$_counters = "\Processor(_total)\% Processor Time","\Memory\Available MBytes","\AD FS\*","\LogicalDisk(_total)\*","Netlogon(*)\*","\TCPv4\*"
$_sample = 5

write-host "Collecting Performance Counters for $_sample seconds"

Function CounterPathToObject{
    param($countersample)
    $pattern = '(?<srv>\\\\[^\\]*)?\\(?<obj>[^\(^\)]*)(\((?<inst>.*(\(.*\))?)\))?\\(?<ctr>.*\s?(\(.*\))?)'
                
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
            $oCtr | select-object -Property TimeStamp,Computer,object,counter,InstanceName,Value | export-csv $_default_log -append -NoTypeInformation 
        }
    }Else{
        Return $null
    }
}

if ($PSVersionTable.PSVersion.Major -gt 3){
    #Parsing the path based on function "Borrowed" from Clint Huffman :) example
    $_counters | Get-Counter -computername $_servers -ErrorAction SilentlyContinue -MaxSamples $_sample | foreach {
        $_time_stamp = $_.timestamp
        #($_).CounterSamples | select-object -Property @{name='timestamp';expression={$_time_stamp}}, Path, InstanceName, CookedValue
        ($_).CounterSamples | select-object -Property @{name='timestamp';expression={$_time_stamp}}, Path, InstanceName, CookedValue | foreach {
        CounterPathToObject -countersample $_
        }
   }
    $_event_Logs | foreach {
            $_el = $_
            $_event_log_csv = $env:userprofile + "\Documents\" + $($_el -replace "/","_") + ".csv"
            $_servers | foreach { write-host "Grabbing $_el log from $_"
                Get-WinEvent -computername $_ -FilterHashTable @{LogName=$_el; StartTime=$_event_log_from} -ErrorAction SilentlyContinue | Select-Object Machinename, TimeCreated, ID, LevelDisplayName, @{n= "Message";e={ ($_.Message -Replace “`r`n|`r|`n”,” ”).Trim() }} | Export-Csv $_event_log_csv -append -NoTypeInformation 
            }
        }

    write-host "Reports Can be found here $_default_log"
}else{
    write-host "Please install the latest version of powershell before running this script"
}




