<#
.SYNOPSIS
Profile.ps1
.DESCRIPTION
This is the custom Profile loader to load this profile onto any machine
.OUTPUTS
Profile will go into the current users' documents folder

.NOTES
Written by: Matt Urbano

Change Log
V1.00, 09/08/20 - Initial version
#>
$Supported = "O365-Connect (Standard Office 365 Connection)
O365-MFAConnect (MFA O365 Connection)
WanIP (Get Current Machine's WAN IP)
Run-AsAdmin (Open a New Powershell Window as Admin)
Get-LatestCoreProfile (Update the Profile with the latest version)
Remove-Profile (To erase this profile from this Machine)
Test"
function CoreAuditLogCheck{
$AuditLogsEnabled = Get-AdminAuditLogConfig
                    if($AuditLogsEnabled -eq $null){sleep 2; $AuditLogsEnabled = Get-AdminAuditLogConfig }
                    $AuditLogVerify = $AuditLogsEnabled.AdminAuditLogEnabled
                    write-host "Found That Audit log enabled is set to:" -NoNewline
                    
                    if($AuditLogVerify -eq $true){write-host " $AuditLogVerify" -ForegroundColor Green}
                    elseif($AuditLogVerify -eq $False)
                        {
                            write-host " $AuditLogVerify" -ForegroundColor Red
                            write-host "O365 Audit Logs are detected as disabled Prompting for Enablement."
                            $Pop = new-object -comobject wscript.shell
		                    $AuditAnswer = $Pop.popup("Security Audit Logs are detected as not enabled.`nEnable Now?", `
				                    0, "O365 Audit Log Status", 4)
		                    
		                    If ($AuditAnswer -eq 6)
		                    {
			                    Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $true
                                write-host "Audit Logs now enabled, it may take up to 60 minutes to take effect."
		                    }
                            else
                            {
                                write-host "User did not wish to enable O365 Audit Logs"
                            }
                        }
}

function Get-LatestCoreProfile{
    iex ((New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/burn56/ToolBox-Addons/master/installprofile.ps1')) 
}

Function wanip{
function Write-ColorOutput
{
    [CmdletBinding()]
    Param(
         [Parameter(Mandatory=$False,Position=1,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][Object] $Object,
         [Parameter(Mandatory=$False,Position=2,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][ConsoleColor] $ForegroundColor,
         [Parameter(Mandatory=$False,Position=3,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][ConsoleColor] $BackgroundColor,
         [Switch]$NoNewline
    )    

    # Save previous colors
    $previousForegroundColor = $host.UI.RawUI.ForegroundColor
    $previousBackgroundColor = $host.UI.RawUI.BackgroundColor

    # Set BackgroundColor if available
    if($BackgroundColor -ne $null)
    { 
       $host.UI.RawUI.BackgroundColor = $BackgroundColor
    }

    # Set $ForegroundColor if available
    if($ForegroundColor -ne $null)
    {
        $host.UI.RawUI.ForegroundColor = $ForegroundColor
    }

    # Always write (if we want just a NewLine)
    if($Object -eq $null)
    {
        $Object = ""
    }

    if($NoNewline)
    {
        [Console]::Write($Object)
    }
    else
    {
        Write-Output $Object
    }

    # Restore previous colors
    $host.UI.RawUI.ForegroundColor = $previousForegroundColor
    $host.UI.RawUI.BackgroundColor = $previousBackgroundColor
}

#https://ipinfo.io/ 
Write-ColorOutput "WAN IP Information" Red

$ipinfo = Invoke-RestMethod http://ipinfo.io/json 

$ipinfo.ip 
$ipinfo.hostname 
$ipinfo.city 
$ipinfo.region 
$ipinfo.country 
$ipinfo.org
$ipinfo.name
$ipinfo.loc



} 
function O365-Connect { 
$UserCredential = Get-Credential
$Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
Import-PSSession $Session -DisableNameChecking
CoreAuditLogCheck
}
function Run-AsAdmin { 
    # Get the ID and security principal of the current user account 
    $myWindowsID=[System.Security.Principal.WindowsIdentity]::GetCurrent() 
    $myWindowsPrincipal=new-object System.Security.Principal.WindowsPrincipal($myWindowsID) 

    # Get the security principal for the Administrator role 
    $adminRole=[System.Security.Principal.WindowsBuiltInRole]::Administrator 

    # Check to see if we are currently running "as Administrator" 
    if ($myWindowsPrincipal.IsInRole($adminRole)) 
    { 
        # We are running "as Administrator" - so change the title and background color to indicate this 
        # $Host.UI.RawUI.WindowTitle = $myInvocation.MyCommand.Definition + "(Elevated)" 
        $Host.UI.RawUI.BackgroundColor = "DarkBlue" 
        clear-host 
    } 
    else 
    { 
        # We are not running "as Administrator" - so relaunch as administrator 

        # Create a new process object that starts PowerShell 
        $newProcess = new-object System.Diagnostics.ProcessStartInfo "PowerShell"; 

        # Indicate that the process should be elevated 
        $newProcess.Verb = "runas"; 

        # Start the new process 
        [System.Diagnostics.Process]::Start($newProcess); 

        # Exit from the current, unelevated, process 
        #exit 
    } 

}

function Remove-Profile {
$Scope = "CurrentUserAllHosts"
$profile_dir = Split-Path $PROFILE.$Scope
$profile_file = $profile.$Scope
$module_dir = "$profile_dir\Modules"
if((Test-Path $profile_file) -eq $true)
    {
        Remove-Item $profile_file -Force
        Remove-item $module_dir -Recurse -Force -ErrorAction SilentlyContinue
        if(test-path c:\temp\ExecutionPolicyOld.txt)
        {
            $OldPolicyRestore = gc c:\temp\ExecutionPolicyOld.txt
            Set-ExecutionPolicy $OldPolicyRestore -force
            Remove-Item c:\temp\ExecutionPolicyOld.txt
        }
    }


}

function Download-Unpack-Modules{
$Scope = "CurrentUserAllHosts"
$profile_dir = Split-Path $PROFILE.$Scope
$module_dir = "$profile_dir\Modules"
if(-not(test-path $module_dir))
    {
        New-Item -Path $module_dir -ItemType Directory | Out-Null
        $URL = 'https://github.com/burn56/ToolBox-Addons/raw/master/CreateExoPSSession.zip'
        $request = Invoke-WebRequest $URL -OutFile "$module_dir\ConnectEXO.zip"
        Expand-Archive -Path "$module_dir\ConnectEXO.zip" -DestinationPath "$module_dir"
        Remove-Item "$module_dir\ConnectEXO.zip" -Force
        Start-Process "Powershell.exe"
        exit
        
    }
Get-ChildItem "${module_dir}\*.ps1" -Recurse | %{.$_} 
import-module "$module_dir\CreateExoPSSession\CreateExoPSSession.ps1"
clear
}
Download-Unpack-Modules
function O365-MFAConnect{
$Scope = "CurrentUserAllHosts"
$profile_dir = Split-Path $PROFILE.$Scope
$module_dir = "$profile_dir\Modules"
Import-Module $((Get-ChildItem -Path $($module_dir+"\CreateExoPSSession") -Filter Microsoft.Exchange.Management.ExoPowershellModule.dll -Recurse ).FullName|?{$_ -notmatch "_none_"}|select -First 1)

try{ $EXOSession = New-ExoPSSession -ErrorAction stop
Import-PSSession $EXOSession -ErrorAction stop
CoreAuditLogCheck}
catch{
Write-Host "Connection was aborted" -ForegroundColor Red}
}
Write-Host "Coretelligent Powershell Profile Loaded"
Write-host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" -ForegroundColor Yellow    
Write-Host "Current Profile Supports: " -ForegroundColor DarkCyan
write-host "$Supported  " -ForegroundColor Green
Write-host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"-ForegroundColor Yellow
Write-host "Please use 'Remove-Profile' to remove this profile from the machine" -ForegroundColor Red
Write-host "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"-ForegroundColor Yellow

