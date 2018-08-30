#enable Test Page
#https://blogs.technet.microsoft.com/rmilne/2017/06/20/how-to-enable-idpinitiatedsignon-page-in-ad-fs-2016/
Set-AdfsProperties –EnableIdpInitiatedSignonPage $True
Get-AdfsProperties | Select-Object EnableIdpInitiatedSignonpage

#make sure chrome and firefox is supported
$list = (get-ADFSProperties).WIASupportedUserAgents
$list += "Mozilla/5.0"
Set-ADFSProperties -WIASupportedUserAgents $list
(get-ADFSProperties).WIASupportedUserAgents

#optional increase the duration for token-signing and token-decryption cert
get-adfsproperties | select certificateduration
$days = 365 * 5
Set-AdfsProperties -Certificateduration $days
get-adfsproperties | select certificateduration

#Enable expiry claim
#https://blogs.msdn.microsoft.com/samueld/2015/05/13/adfs-2012-r2-now-supports-password-change-not-reset-across-all-devices/
#enable password change endpoint
Get-AdfsEndpoint -AddressPath /adfs/portal/updatepassword/ | Enable-AdfsEndpoint
Get-AdfsEndpoint -AddressPath /adfs/portal/updatepassword/

#add password expiry claim
$rptName = "Microsoft Office 365 Identity Platform"
if(Get-AdfsRelyingPartyTrust $rptName){
    $msolId = "urn:federation:MicrosoftOnline" 
    $rptRules = (Get-AdfsRelyingPartyTrust -Identifier $msolId).IssuanceTransformRules 
    $newRule = '@RuleName = "Issue Password Expiry Claims" c1:[Type == "http://schemas.microsoft.com/ws/2012/01/passwordexpirationtime"] => issue(store = "_PasswordExpiryStore", types = ("http://schemas.microsoft.com/ws/2012/01/passwordexpirationtime", "http://schemas.microsoft.com/ws/2012/01/passwordexpirationdays", "http://schemas.microsoft.com/ws/2012/01/passwordchangeurl"), query = "{0};", param = c1.Value);'
    $rptRules = $rptRules + $newRule 
    Set-AdfsRelyingPartyTrust -TargetName $rptName -IssuanceTransformRules $rptRules
}
#validate
(Get-AdfsRelyingPartyTrust $rptName).IssuanceTransformRules

#enable MFA Claim on O365 
#https://blogs.technet.microsoft.com/cloudpfe/2017/03/15/multiple-mfa-prompts-connecting-to-office-365/
$rptName = "Microsoft Office 365 Identity Platform"
if(Get-AdfsRelyingPartyTrust $rptName){
    $msolId = "urn:federation:MicrosoftOnline" 
    $rptRules = (Get-AdfsRelyingPartyTrust -Identifier $msolId).IssuanceTransformRules 
    $newRule = '@RuleName = '@RuleTemplate = "PassThroughClaims" @RuleName = "Pass Through MFA Claims" c:[Type == "http://schemas.microsoft.com/claims/authnmethodsreferences"] => issue(claim = c);'
    $rptRules = $rptRules + $newRule 
    Set-AdfsRelyingPartyTrust -TargetName $rptName -IssuanceTransformRules $rptRules
}
#validate
(Get-AdfsRelyingPartyTrust $rptName).IssuanceTransformRules

#enable Logging
# This will Add the audit settings to your existing settings
set-AdfsProperties -LogLevel ((Get-AdfsProperties).LogLevel+'SuccessAudits','FailureAudits')
# Or just add all the logging
Set-ADFSProperties -LogLevel Verbose,Errors,Warnings,Information,SuccessAudits,FailureAudits
#validate SuccessAudit and FailureAudits is set
(Get-AdfsProperties).loglevel
 
#Make Sure the Security Audit Policy is enabled
auditpol.exe /set /subcategory:"Application Generated" /failure:enable /success:enable
#validate
auditpol.exe /get /subcategory:"Application Generated"

#enable Extranet Smart Lockout
#The lockout Threshold is the number of failed password attempts that must occur from a unfamiliar location
#before the account gets locked out from the ADFS Side.
Set-AdfsProperties -ExtranetLockoutThreshold 10
#the observation window is the amount of time that must pass before the extranet lockout
#automatically unlocks
Set-AdfsProperties -ExtranetObservationWindow ( new-timespan -minutes 15 )
#enable extranet lockout mode of enforce
Set-AdfsProperties -ExtranetLockoutMode AdfsSmartLockoutEnforce
Restart-service adfssrv
#enable Extranet Lockout
Set-AdfsProperties -EnableExtranetLockout $true
#Validate
get-AdfsProperties | select *lock*,bannediplist | fl
