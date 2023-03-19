<#
  DESCRIPTION:
 you can use this script to:
     - create a new GPO , enable ASR rules and populate it with all ASR rules GUIDs and set the value to: Block-Audit-Warn-Disabled
     - Modify ASR Rules in an existing GPO
     - specifiy one or more ASR rules to Configure in Audit Mode
     - List the Current Configured ASR rules in a GPO and their Values

  EXAMPLES:
  PS> .\asr-gpo.ps1 -gpoName "MDE-ASR-Rules" -mode Block
  PS> .\asr-gpo.ps1 -gpoName "MDE-ASR-Rules" -mode warn -auditRules "56a863a9-875e-4185-98a7-b882c64b5ce5","d4f940ab-401b-4efc-aadc-ad5f3c50688a"
  PS> .\asr-gpo.ps1 -gpoName "MDE-ASR-Rules" -ModifyExistentGPO -auditRules "56a863a9-875e-4185-98a7-b882c64b5ce5"
  PS> .\asr-gpo.ps1 -gpoName "MDE-ASR-Rules" -List


#>

param (
    [Parameter(Mandatory = $true,
        HelpMessage = 'Enter the desired GPO name')]
    [string] $GPOName,
    [Parameter(Mandatory = $false,
        HelpMessage = 'set ASR rules Mode')]
    [string][validateset('Block', 'Audit', 'Warn', 'Disable')] $mode,
    [Parameter(Mandatory = $false)]
    [Switch] $ModifyExistentGPO,
    [Parameter(Mandatory = $false)]
    [string[]] $AuditRules,
    [Parameter(Mandatory = $false)]
    [Switch] $list
	
)

# validate Parameters set
if(!$PSBoundParameters.mode -and (!$PSBoundParameters.auditrules -and !$PSBoundParameters.list)){
  Write-Host "Can't use the provided Paramter(s)set."
  exit
}

if($PSBoundParameters.list -and ($PSBoundParameters.auditrules -or $PSBoundParameters.mode)){
  Write-Host -ForegroundColor Cyan "Note:Only List switch Will be used"
 
}

#All available ASR rule
$ASRRules = @{

    "56a863a9-875e-4185-98a7-b882c64b5ce5" = "Block abuse of exploited vulnerable signed drivers"
    "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c" = "Block Adobe Reader from creating child processes"
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a" = "Block all Office applications from creating child processes"
    "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" = "Block credential stealing from the Windows local security authority subsystem (lsass.exe)"
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550" = "Block executable content from email client and webmail"
    "01443614-cd74-433a-b99e-2ecdc07bfc25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc" = "Block execution of potentially obfuscated scripts"
    "d3e037e1-3eb8-44c8-a917-57927947596d" = "Block JavaScript or VBScript from launching downloaded executable content"
    "3b576869-a4ec-4529-8536-b80a7769e899" = "Block Office applications from creating executable content"
    "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84" = "Block Office applications from injecting code into other processes"
    "26190899-1602-49e8-8b27-eb1d0a1ce869" = "Block Office communication application from creating child processes"
    "e6db77e5-3df2-4cf1-b95a-636979351e5b" = "Block persistence through WMI event subscription"
    "d1e49aac-8f56-4280-b9ba-993a6d77406c" = "Block process creations originating from PSExec and WMI commands"
    "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4" = "Block untrusted and unsigned processes that run from USB"
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b" = "Block Win32 API calls from Office macros"
    "c1db55ab-c21a-4637-bb3f-a12568109d35" = "Use advanced protection against ransomware"
}
#Validate provided Rule GUIDS
if ($AuditRules){
 $validGUIDS=$ASRRules.Keys
  foreach ($AR in $AuditRules)
  {
      if($AR -notin $validGUIDS){
         Write-host -ForegroundColor Red "Invalid Rule GUID(s)"
         exit
      }
  }
}
#list all ASR rules that are currently configured in the GPO and exit
if ($list) {
    $configuredRules = @()
    try {
        $rules = Get-GPRegistryValue -Name $GPOName -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ErrorAction stop
        if ($rules.length -ne 0) {
            foreach ($rule in $rules) {
                $configuredRule = [PSCustomObject]@{
                    RuleName = $ASRRules[$rule.valuename]
                    Value    = $rule.value
                
                }
                $configuredRules += $configuredRule
            }
        }

        else {
     
            Write-Host "NO ASR rules are configured"
        }

    }

    catch {

        Write-Host "NO GPO with the specified name was found"
    }

    finally {
        $actions = @{"1" = "Block"; "2" = "Audit"; "6" = "Warn"; "0" = "Disabled" }
        foreach ($CR in $configuredRules) {
            switch ($CR.value) {
                "1" { Write-Host -ForegroundColor Green -Object "$($CR.RuleName) is in Block Mode"; break }
                "2" { Write-Host -ForegroundColor Gray -Object "$($CR.RuleName) is in Audit Mode"; break }
                "6" { Write-Host -ForegroundColor DarkYellow -Object "$($CR.RuleName) is in Warn"; break }
                "0" { Write-Host -ForegroundColor Red -Object "$($CR.RuleName) is in Disabled"; break }
            }
        }
     
        exit
    }
}

#create a new GPO and return it to the caller
function createGPO ($GPOname) {
    #check if a GPO with the same name already exists
    if (Get-GPO -All | where { $_.DisplayName -eq "$GPOname" }) {
        Write-Host -ForegroundColor Red "A GPO with the same name is already configured.use " -NoNewline; Write-Host -ForegroundColor White  "-ModifyExistentGPO" -NoNewline; Write-Host -ForegroundColor red " to modify an existent GPO"
        exit   
    }
    else {
        New-GPO -Name $GPOname
    }
}

#get an existing GPO and return it to the caller
function ModifyExistentGPO ($GPOname) {
    $GPO = Get-GPO -All | where { $_.DisplayName -eq "$GPOname" }
    if ($GPO) {
        return $GPO
    }

    else {

        Write-Error "Couldn't Find a GPO with this name !"
        exit
    }
}

#populate a target GPO with Rules
function setRules ($rules, $mode, $targetGP) {
    foreach ($GUID in $rules) {
        Set-GPRegistryValue -Guid $targetGP.Id -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules" -ValueName $GUID -Type String -Value $mode
    }
}


###-----the GPO that will be used for all the configuration------###
if ($ModifyExistentGPO) {
    $GPO = ModifyExistentGPO -GPOname $GPOName
}

else {
    $GPO = createGPO -GPOname $GPOName
 
}


#ensure that "configure Attack Surface Reduction Rules" value is  enabled
Set-GPRegistryValue -Guid $GPO.Id -Key "HKLM\Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR" -ValueName "ExploitGuard_ASR_Rules" -Type Dword -Value 1
#get the Mode numeric value based on Selected mode
$ModeValue = switch ($mode) {
    "block" { 1; break }
    "audit" { 2; break }
    "warn" { 6; break }
    "disable" { 0; break }
}
#set ASR rules based on specified mode
if ($mode) {
    setRules -rules $ASRRules.Keys -mode $ModeValue -targetGP $GPO
}

#set Specific ASR rule(s) to audit mode
if ($AuditRules) {
    setRules -rules $AuditRules -mode 2 -targetGP $GPO
}
