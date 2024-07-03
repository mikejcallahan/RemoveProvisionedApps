
function StartRemoteOp {
  param([array]$pclist)

  invoke-command -ComputerName $pclist -credential $creds -ScriptBlock {
<#----------------------------------------------------
.DESCRIPTION
removes selected appx packages from machine 
and individual users if already installed.
-----------------------------------------------------#>

$ProvisionedKillList = @(
"DellInc.DellDigitalDelivery",
"DellInc.DellCustomerConnect",
"DellInc.DellMobileConnect"
"DellInc.DellPowerManager",
#"DellInc.DellUpdate", < one we don't want. test before uncommenting
"DellInc.DellPrecisionOptimizer",
"DellInc.DellSupportAssistforPCs",
"DellInc.PartnerPromo",
"DellInc.Peripheral",
#"DellInc.DellCommandUpdate", Windows Universal?
"HONHAIPRECISIONINDUSTRYCO.DellWatchdogTimer"
"Microsoft.549981C3F5F10",          #Cortana
"Microsoft.BingWeather",
"Microsoft.Microsoft3DViewer",
"Microsoft.MicrosoftOfficeHub",
"Microsoft.MicrosoftSolitaireCollection",
"Microsoft.MixedReality.Portal",
"Microsoft.Office.OneNote",
#"Microsoft.People_8wekyb3d8bbwe",
"microsoft.microsoftskydrive",      #this is extra OneDrive with old name
"Microsoft.SkypeApp",
"Microsoft.Wallet",
"microsoft.windowscommunicationsapps",     # Windows Mail app
"Microsoft.WindowsFeedbackHub",
"Microsoft.WindowsMaps",
"Microsoft.XboxApp",
"Microsoft.XboxGameOverlay",
"Microsoft.XboxGamingOverlay",
"Microsoft.XboxIdentityProvider",
"Microsoft.XboxSpeechToTextOverlay",
"Microsoft.Xbox.TCUI",
"Microsoft.YourPhone",
#"Microsoft.ZuneMusic", eh?
#"Microsoft.ZuneVideo",
"MSWP.DellTypeCStatus")

write-host @" 
**********************************************************************************"
  Commands: Remove-AppxPackage
            Remove-AppxProvisionedPackage                
                                                                         
      Keys: HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\  
                         
  Comments: Profiles with active sessions will be skipped.                                                            
            Removal finishes for a user when they log in next.                                                                      
                                                                                 
"@
#$ProvisionedKillList          
write-host @"                                                                    
**********************************************************************************"
"@
start-sleep -seconds 4
#set-executionpolicy -executionpolicy remotesigned -scope process -force
<#----------------------------------------------------
Add package shortnames below. These names can differ from MSI installed names 
(dell often does both appx and msi for same program so it's that much harder to get rid of) 
-----------------------------------------------------#>

<#------------------------
NonRemovable (for reference)
#-------------------------
Microsoft.BioEnrollment
Microsoft.Windows.CloudExperienceHost
1527c705-839a-4832-9118-54d4Bd6a0c89
c5e2524a-ea46-4f67-841f-6a9465d9d515
F46D4000-FD22-4DB4-AC8E-4E1DDDE828FE
E2A4F912-2574-4A75-9BB0-0D023378592B
Microsoft.AccountsControl
Microsoft.AsyncTextService
Microsoft.LockApp
Microsoft.ECApp
Microsoft.Windows.AssignedAccessLockApp
Microsoft.Windows.OOBENetworkCaptivePortal
Microsoft.Windows.OOBENetworkConnectionFlow
Microsoft.Windows.SecureAssessmentBrowser
Microsoft.Windows.ShellExperienceHost
Microsoft.Windows.ContentDeliveryManager
Microsoft.Windows.PeopleExperienceHost
windows.immersivecontrolpanel
Microsoft.CredDialogHost
Windows.PrintDialog
MicrosoftWindows.UndockedDevKit
Microsoft.XboxGameCallableUI
Microsoft.Windows.CallingShellApp
MicrosoftWindows.Client.CBS
Microsoft.Windows.SecHealthUI
Microsoft.Windows.PinningConfirmationDialog
Microsoft.Windows.ParentalControls
Microsoft.Windows.CapturePicker
Microsoft.Windows.Search
Microsoft.Windows.NarratorQuickStart
Microsoft.Windows.XGpuEjectDialog
Microsoft.Windows.Apprep.ChxApp
Microsoft.Win32WebViewHost
NcsiUwpApp
Microsoft.MicrosoftEdgeDevToolsClient
Microsoft.MicrosoftEdge
Microsoft.Windows.StartMenuExperienceHost
Windows.CBSPreview
Microsoft.AAD.BrokerPlugin
#>


 function getUserProfiles {
 <#-------------------------------------------------------------------------------------------------------
 .DESCRIPTION 
 Get's profiles from registry. Compares subkeys (names are SIDs in this case) against "Name" property. 
 .OUTPUTS
 Returns [ArrayList] profileListSIDValid -
 Sets [ArrayList] global:ProfileListValid -
 -------------------------------------------------------------------------------------------------------#>
  $profileListImgPath = [System.Collections.Arraylist]`
   @(gci 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' | ForEach { $_.GetValue('ProfileImagePath') })
  $profileListSID = [System.Collections.Arraylist]`
   @((gci 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' | select Name).Name)
  $tempList = [System.Collections.Arraylist]@()      
  $profileListSIDValid = new-object -Typename 'System.collections.arraylist'
#---------------------------------------------------------------------------------
   for($i=0;$i-lt($profileListSID.count);$i++) {
    $p = $profileListImgPath[$i].tolower()
    $s = $profileListSID[$i]
     if (!($p.Contains("c:\windows"))){
      $pValid = ($p.replace("c:\users\",''))
      $tempList += $pValid
      $profileListSIDValid += ($s.replace('HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\','')) 
      $userCount++
   }}
  [System.Collections.Arraylist]$global:profileListValid = $tempList   
  write-host ("$($env:COMPUTERNAME) $userCount USERS:")                 #will need to invoke commands for remote sessions
  Write-Host $profileListValid -Separator "`n"
  write-host "------------------------------------------------------"
 return $profileListSIDValid
} 
 

 function RemoveUserPackages {
 <#------------------------------------------------------------
 .DESCRIPTION
 Takes array of SIDs for user profiles then initializes removal for each. Logon required to complete removal.
 -------------------------------------------------------------#>
  [CmdletBinding(SupportsShouldProcess)]
  param([Parameter(Mandatory = $true)] [array]$validUserList)

 #approximate current user - running apps can't be removed
  [string]$ExplorerOwner = (Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" |
  ForEach-Object { $_.GetOwner() } |
  Select-Object -Unique -Expand User) 

  for($y=0;$y-lt($validUserList.count);$y++) {
    [string]$profile = $profileListValid[$y]
    $user = $validUserList[$y]
    if(($profile -eq $ExplorerOwner) -or ($profile -eq $env:USERNAME)){       #active users estimation
     write-host "[SKIP ACTIVE USER ] $profile" 
     write-host "------------------------------------------------------"
      continue
     }else{ 
      write-host "[REMOVING FROM USER] $profile" 
      start-sleep -Seconds .5
     }
    $appsObj = [System.Collections.Arraylist]@(Get-AppXPackage -package All -user $user)
    $userApps = [System.Collections.Arraylist]@(($appsObj | ForEach-Object {$_}| select PackageFullName).PackageFullName)
    #$userApps = [System.Collections.Arraylist]@((Get-AppXPackage -package All -user $user | select PackageFullName).PackageFullName)
    $appsPending = [System.Collections.Arraylist]@(($appsObj |
     where-Object { ($_.Status -like "Modified, NeedsRemediation") -or ($_.Status -like "Modified, DependencyIssue, NeedsRemediation") } |
     select PackageFullName).PackageFullName)
    $LastMealPrep = $false
    $PkgDeathRow = [System.Collections.Arraylist]@() #* $userApps.count
    [int]$did = 0

    if($appsPending.Count -gt 1){    #clunky - PS treats .NET arraylist as always having count =1 even when empty.
     $total = ($appsPending.count)
     write-host "[PENDING USER LOGON] $total packages"
    }
    foreach($kill in $ProvisionedKillList){
     for($x =0;$x-lt($userApps.count);$x++){
      if((!($appsPending -contains $userApps[$x])) -and (($userApps[$x].contains($kill)))) {  
       $LastMealPrep = $true         
       $PkgDeathRow += $userApps[$x]
    }}}   
    if($LastMealPrep -eq $true){
     forEach($target in $PkgDeathRow){
      write-host "[REMOVAL STARTED] $target"         
      try{
       Remove-AppxPackage -package $target -user $user -ErrorAction stop -WarningAction Inquire 
       start-sleep .5  
      }catch [Exception]{
       write-host '[EXCEPTION]' 
       write-host $error
      continue
    }}}elseif($appsPending.count -lt 2) { 
     write-host "[CLEAN]"
     }
 write-host "------------------------------------------------------"
 }}
 

 function removePackages {
 <#----------------------------------------------------------------
 .DESCRIPTION
 Removes selected provisioned software from machine. 
 -----------------------------------------------------------------#>
  write-host `r`n "[REMOVING PROVISIONED PACKAGES]" `r`n
  $appsExist = $false
  $provisionedPkg = @((Get-AppxProvisionedPackage -Online | select PackageName).PackageName)
  $did = 0
  foreach ($pkg in $provisionedPkg) { foreach ($kill in $ProvisionedKillList) { 
   if ($pkg.contains($kill)) { 
    $appsExist = $true 
    try { 
     if(Remove-AppxProvisionedPackage -online -PackageName $pkg -erroraction stop) { 
      write-host "[REMOVED] $pkg" 
     }
    }catch [Exception] { write-host ("[NOT REMOVED] $pkg") 
     continue 
  }}}}
  if(!($appsExist)) { write-host `r`n "[CLEAN]" `r`n }else{ write-host "[SELECTED PACKAGES REMOVED]"
 }}



 function testElevation {
 <#-----------------------------------------------------------------
 .DESCRIPTION
 Checks currentUser role. Evaluates false if not running as admin
 -------------------------------------------------------------------#>
 param([switch]$Elevated)
  $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
} 

<#------(Start)-[script body args]---------------
Relaunches as admin then starts calling sequence.
-------------------------------------------------#>
if (!(testElevation)){if ($elevated) {write-host 'elevation confirmed'} else {
 try {Start-Process powershell.exe -Verb RunAs -erroraction stop -ArgumentList (' -noprofile -ExecutionPolicy bypass -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
}catch {read-host `r`n "Elevation Required." `r`n} exit }}



#Main (execution sequence)-------------------------
$sids = getUserProfiles
 if ($sids.count -gt 0) {removeUserPackages -validUserList $sids}

#write-host  `r`n "[REMOVING PROVISIONED APPX PACKAGES MACHINE-WIDE]" `r`n
start-sleep -seconds 2
removePackages

#write-host  `r`n "[CONTINUE FOR MSI UNINSTALLS]" `r`n
#$Midol = "$PSScriptRoot\_\RemoveBloat-v2.exe"
#---------------------------------------------------------------------MSI stuff below
set-location -path $PSScriptRoot

#----------------------cannot do dot sourcing to call another scipt when compiling to exe. So just copying
#..\RemoveBloat-v2.ps1
#Initialize
<#
try {Start-Process powershell  -wait -erroraction stop -ArgumentList ('"$myinvocation" -executionpolicy bypass -file ".\RemoveBloat-v2.ps1"' -f ($myinvocation.MyCommand.Definition)) -passthru
}catch {write-host "MSI removal didn't launch"}
#>
#start-process "powershell.exe" -credential -wait -args {$Midol; Initialize} -PassThru
#exit


$killList = @(
"SupportAssist",
"Dell Power",
"Dell Digital Delivery",
"Dell Pair",
"Dell Peripheral",
"OS Recovery Plugin",
"Dell Optimizer"
)
<#---------------------------------#>
$WorkingDir = "$env:USERPROFILE\appdata\local\PBSIT"
<#--------------------------------#>
write-host @"
**********************************************************************************"
msiexec.exe removal (/x strings. The easy ones)                                  
                                                                                 
   Usage: "Initialize"                                                           
                                                                                 
 Strings: HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall  
          HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\             
                                                                                 
    Logs: $WorkingDir                                                            
                                                                                 
KillList:                                                                        
                                                                                 
"@
$KillList          
write-host @"                                                                    
**********************************************************************************"
"@
start-sleep -seconds 4
 function CommandHandler {
 [CmdletBinding(SupportsShouldProcess)]
  param(
  [Parameter(Mandatory = $false)] [array]$names,
  [Parameter(Mandatory = $false)] [array]$xmsi,
  [Parameter(Mandatory = $false)] [array]$imsi,
  [Parameter(Mandatory = $false)] [array]$noMsi
  )
<# /x uninstall strings ---------------------------------------------------#>
   #function xRemover {
    write-host "[/X REMOVAL]"
    $names
    $i = 0
    foreach($block in $xmsi) {
     Start-Process "msiexec.exe" -Wait -ArgumentList $block -PassThru  #-NoNewWindow 
   }

 <#/i uninstall strings (not working yet - beloew does nothing but compare strings against another location where you can find the same id. Gotta be good for something ---------------------------------------------------#>
   function RemoverDraft {
    
    if($imsi -ne $null) {
     write-host "[MORE UNINSTALLS]"
     $targetId = @() * $imsi.count
     if($cimProduct -eq $null) { $global:cimProduct = @(Get-WmiObject -Class win32_Product)}
     else{
      foreach($str in $imsi) {
       for($i=0;$i-lt($cimProduct.count);$i++) { 
     
        if ($str.contains($cimProduct[$i].IdentifyingNumber)){
         write-host "igot - $str"
         $target = $cimProduct[$i]}}
         write-host $target
        }
       }
      }
     }
 <#---Calling----------#>
  #xRemover
   }
 


 function Initialize {
 <#-------------------------------------------------
 .DESCRIPTION
 gets software Name (= 'w32_Product.IdentifyingNumber) quickly from registry
 -------------------------------------#>
  $global:keys = @(gci 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\' )
  $global:keys2 = @(gci 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\')    # might need 2 "\\" for remote runs
  $imsi = [System.Collections.Arraylist]@()
  $xmsi = [System.Collections.Arraylist]@()
  $noMsi = [System.Collections.Arraylist]@()
  $intNotMsi = [System.Collections.Arraylist]@()

  $ustr = @(($keys| ForEach-Object {$_.GetValue('UninstallString')}))   #-------------------------
  $uname = @(($keys | ForEach-Object {$_.GetValue('DisplayName')}))     #  64 bit parallel set
  $suspect = ''                                                        <#------------------------- initialized for illustrative purpose  #>

  $ustr2 = @(($keys2| ForEach-Object {$_.GetValue('UninstallString')})) #-------------------------    
  $uname2 = @(($keys2 | ForEach-Object {$_.GetValue('DisplayName')}))   #  32 bit parallel set
  $suspect2 = ''                                                       <#------------------------- initialized for illustrative purpose  #>

  $xnames = [System.Collections.Arraylist]@()                           # collects /x strings
  $inames = [System.Collections.Arraylist]@()                           # collects /i strings
  $onames = [System.Collections.Arraylist]@()                           # collects the rest - includes exe strings with parameters

  

  <#-----Appologies for all the touppers I obviously forgot why I made a separate displayname variable in the first place (will fix)----------------#>


   #function SlaughterHouse
    foreach($kill in $killList){ 
     for($i=0;$i-lt($ustr.count);$i++) {
      [string]$suspect = $uname[$i]  
      #[string]$suspect2 = ($uname2[$i]).toupper()
                                                                         
# MSI uninstall strings prep and scriptblock creation. Plebeian code. Will make a constructor inner function later
#-------(/x)64 bit-----------------------------------------------
 
   if((($suspect).toupper()).contains(($kill).toUpper())) {
    if((([string]$ustr[$i]).toupper()).contains('MSIEXEC.EXE /X')) {
     $block = (((([string]$ustr[$i]).toUpper()).replace('MSIEXEC.EXE ','')).replace('/X','/X '))    

     [string]$time = (get-date -Format 'yyyyMMddhhmmss')
     $suspect = ($suspect.replace(" ",""))
     $deathCert = ("$suspect" + "$time")

     $block = ("$block /qn /l*v $WorkingDir\x$deathCert.log")
     $xmsi += $block
     $xnames += $suspect
    }
   }
   }
   }
#-------(/x)32 bit---------------------------------------------- 
   foreach($kill in $killList){ 
     for($i=0;$i-lt($ustr2.count);$i++) {  
      [string]$suspect2 = $uname2[$i]
      $suspect2 = ($suspect2.toupper())

   if(($suspect2).contains(($kill).toUpper())) {
    if((([string]$ustr2[$i]).toupper()).contains('MSIEXEC.EXE /X')) {
     $block2 = (((([string]$ustr2[$i]).toUpper()).replace('MSIEXEC.EXE ','')).replace('/X','/X '))  

     [string]$time = (get-date -Format 'yyyyMMddhhmmss')
     $suspect2 = ($suspect2.replace(" ",""))
     $deathCert2 = ("$suspect2" + "$time")
     
     $block2 = ("$block2 /qn /l*v $WorkingDir\x$deathCert2.log")
     $xmsi += $block2
     $xnames2 += $uname2[$i]
    }
   }
   }
   }                                                                     
#--------(/i)64bit----------------------------------------------- 
<#                                                                         
  if((([string]$ustr[$i]).toupper()).contains('MSIEXEC.EXE /I')) {                
     $imsi += (([string]$ustr[$i]).toUpper()).replace('MSIEXEC.EXE ','')
     $intImsi

    }else {
     $noMsi += $ustr[$i]
     $onames += $i
    }  
   }#>
 
 <#
 $xmsi += $xnames
 $imsi += $inames
 $noMsi += $onames
 #>

 $xnamesBoth = $xnames + $xnames2

 Write-Host "-----------/x strings-------"
 $xmsi

<#
  Write-Host "-----------/i strings-------"
  $imsi
   Write-Host "-----------other-------"
    $noMsi
#>

 CommandHandler -names $xnamesBoth -xmsi $xmsi

 }


 Initialize

}

}


<#______________________________________________________________________________________
OUTSIDE INVOKE BLOCK (LOCAL)
______________________________________________________________________________________#>


function PCListEdit {  

  set-location -path "$PSScriptRoot"                                    # Quotes needed in case there are spaces in path. PS handles this probably just being tidy
  #function getNotepad {
    if(!(test-path ".\PCList.txt")) { 
      new-item -ItemType file -Name "PCList.txt" -path . 
    }

    try { $pclist = @(Get-Content -Path ".\PCList.txt") 
          start-process notepad.exe -wait -argumentlist ".\PCList.txt"  # Start Notepad
          $pclist = @(Get-Content -Path ".\PCList.txt") }
    catch [exception] { $error[0] }

    return $pclist

}

function StartSequence {
if($null -eq $creds){ $global:creds = get-credential } 

  $pclist = PCListEdit

  StartRemoteOp -pclist $pclist

  read-host ("[FINISHED]
 
 PRESS ENTER TO LOOP OR EXIT PROGRAM
 
 ")

 StartSequence                           #looped run
}

StartSequence                            #initial run
