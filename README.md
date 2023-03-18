# ASR Rules GPO
### Description
Manually Managing ASR rules in a GPO configuration/deployment can be tedious and not the best experience. this script Automate the whole process of ASR Rules Creation ,modifications and listing.
you can:
* create a new GPO , enable ASR rules and populate it with all ASR rules GUIDs and set the value to: Block-Audit-Warn-Disabled
* Modify ASR Rules in an existing GPO
* specifiy one or more ASR rules to Configure in Audit Mode
* List the Current Configured ASR rules in a GPO and their Values

### Usage
you can use the script on a DC or a machine with Group policy Managemment tools installed with a user that has the required Privileges to create or modify GPOs
### examples
* create a new GPO "MDE-ASR-Rules", populate it with all ASR rules and set them in "Block" Mode
<div class="highlight highlight-source-shell"><pre>
  PS> .\asr-gpo.ps1 -gpoName "MDE-ASR-Rules" -mode Block
</pre></div>

* create a new GPO "MDE-ASR-Rules" set all ASR Rules in "Warn" mode except two Rules will be in "Audit" mode
 <div class="highlight highlight-source-shell"><pre>
  PS> .\asr-gpo.ps1 -gpoName "MDE-ASR-Rules" -mode warn -auditRules "56a863a9-875e-4185-98a7-b882c64b5ce5","d4f940ab-401b-4efc-aadc-ad5f3c50688a"
</pre></div>

* modify an existent GPO to set a specific ASR rule in "Audit Mode"
<div class="highlight highlight-source-shell"><pre>
  PS> .\asr-gpo.ps1 -gpoName "MDE-ASR-Rules" -ModifyExistentGPO -auditRules "56a863a9-875e-4185-98a7-b882c64b5ce5"
</pre></div>

* List all ASR rules names and their Current values
<div class="highlight highlight-source-shell"><pre>
  PS> .\asr-gpo.ps1 -gpoName "MDE-ASR-Rules" -List
</pre></div>


 

