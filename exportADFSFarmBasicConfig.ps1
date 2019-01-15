#
    This code is Copyright (c) 2016 Microsoft Corporation.

    All rights reserved.
    THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, 
    INCLUDING BUT NOT LIMITED To THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
    PARTICULAR PURPOSE.'

    IN NO EVENT SHALL MICROSOFT AND/OR ITS RESPECTIVE SUPPLIERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR 
    CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
    WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
    WITH THE USE OR PERFORMANCE OF THIS CODE OR INFORMATION.

.SYNOPSIS

  Example of how to capture adfs settings.

.DESCRIPTION
    <Brief description of script>

.PARAMETER <Parameter_Name>
    <Brief description of parameter input required. Repeat this attribute if required>

.INPUTS
    None

.NOTES
  Version:        0.1
  Author:         Chad Cox Microsoft
  Creation Date:  10/11
  Purpose/Change: Initial script development. This script is a sample of how I would set up a daily task to collect configuration data from the server for troubleshooing purposes.
  The goal is to collect things in relation to the Office 365 Relying Party Trust.
  This script will create a new log file each time it is ran after 10 logs are create it will compress those logs into a zip and will keep 5 zip files around for validation.

.EXAMPLE

#>

#---------------------------------------------------------[Initializations]--------------------------------------------------------

#Set Error Action to Silently Continue
$DebugPreference = "Continue"
Import-Module ADFS

cls
#----------------------------------------------------------[Declarations]----------------------------------------------------------
#Script Version
$sScriptVersion = "0.1"

$defaultreportpath = 'C:\ADFSConfig'
If (!($(Try { Test-Path $defaultreportpath } Catch { $true }))){
    new-Item $defaultreportpath -ItemType "directory"  -force
}

$reportpath = $defaultreportpath + '\Results'
If (!($(Try { Test-Path $reportpath } Catch { $true }))){
    new-Item $reportpath -ItemType "directory"  -force
} 

$defaultFile = $reportpath + "\" + $env:computername + "-$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).txt"
$compressedfile = $defaultreportpath + "\" + $env:computername + "-ARCHIVE-$((Get-Date).ToString('MM-dd-yyyy_hh-mm-ss')).zip"

$CompressAchivetokeep = 5
$txtfilecount = 10

#-----------------------------------------------------------[Functions]------------------------------------------------------------
Function do-archiving{
    Param()

    Process{

        $compressachivecount = (Get-ChildItem $defaultreportpath *.zip).count - $compressAchivetokeep
        if($compressachivecount -gt 0){
            Get-ChildItem $defaultreportpath *.zip  | Sort CreationTime | Select -first $compressachivecount | Remove-Item -force
        }
        $txtachivecount = (Get-ChildItem $reportpath *.txt).count - $txtfilecount
        if($txtachivecount -gt 0){
            Add-Type -assembly "system.io.compression.filesystem"
            [io.compression.zipfile]::CreateFromDirectory($reportpath, $compressedfile)  
            Get-ChildItem $reportpath *.txt  | Remove-Item -force
            Get-ChildItem $reportpath *.ps1_bak  | Remove-Item -force
        }
    }
}

#-----------------------------------------------------------[Execution]------------------------------------------------------------

#perform existing log clean up
do-archiving

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
