
# Load PowerShell module for Active Directory
Import-Module ActiveDirectory
$DomainInfoVar = $null
# Custom function to scan specified AD domain and collect data
function Get-DomainInfo($DomainName)
    {
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        $DomainInfoVar +=  "`r`nCollecting Active Directory data..."

        # Start of data collection for specified domain by function
        $DomainInfo = Get-ADDomain $DomainName
        $DHCPServers = Get-DHCPServerInDC | Select -ExpandProperty DnsName

        # Variables definition
        $domainSID = $DomainInfo.DomainSID
        $domainDN = $DomainInfo.DistinguishedName
        $domain = $DomainInfo.DNSRoot
        $NetBIOS = $DomainInfo.NetBIOSName
        $dfl = $DomainInfo.DomainMode

        # Domain FSMO roles
        $FSMOPDC = $DomainInfo.PDCEmulator
        $FSMORID = $DomainInfo.RIDMaster
        $FSMOInfrastructure = $DomainInfo.InfrastructureMaster

        $DClist = $DomainInfo.ReplicaDirectoryServers
        $RODCList = $DomainInfo.ReadOnlyReplicaDirectoryServers

        $cmp_location = $DomainInfo.ComputersContainer
        $usr_location = $DomainInfo.UsersContainer

        $FGPPNo = "feature not supported"

        # Get Domain Controller with at least Windows Server OS 
        
        $DCListFiltered = Get-ADDomainController -Server $domain -Filter { operatingSystem -like "Windows Server 2008 R2*" -or operatingSystem -like "Windows Server 2012*" -or operatingSystem -like "Windows Server Technical Preview"  } | Select * -ExpandProperty Name
        $DCListFiltered | %{ $DCListFilteredIndex = $DCListFilteredIndex+1 }
       
        # End of 2008R2 DC list
        # if only one Windows Server Domain Controller exists
        if ( $DCListFilteredIndex -eq 1 )        
            {
                # Get information about Default Domain Password Policy
                $pwdGPO = Get-ADDefaultDomainPasswordPolicy -Server $DCListFiltered
                # check DFL and get Fine-Grained Password Policies
                if ( $dfl -like "Windows2008Domain" -or $dfl -like "Windows2008R2Domain" -or $dfl -like "Windows2012Domain" -or $dfl -like "Windows2012R2Domain" )

                    {        
                        $FGPPNo = (Get-ADFineGrainedPasswordPolicy -Server $DCListFiltered -Filter * | Measure-Object).Count               
                    }
                # End of Fine-Grained Password Policies section
                # Get information about built-in domain Administrator account
                $builtinAdmin = Get-ADuser -Identity $domainSID-500 -Server $DCListFiltered -Properties Name, LastLogonDate, PasswordLastSet, PasswordNeverExpires, whenCreated, Enabled
                # Get total number of Domain Administrator group members
                $domainAdminsNo = (Get-ADGroup -Identity $domainSID-512 -Server $DCListFiltered | Get-ADGroupMember -Recursive | Measure-Object).Count


            }
        # End main IF section
        # if there are more than one Windows Server 2008R2 Domain Controllers
        else
            {
                # Get information about Default Domain Password Policy from the first DC on the list
                $pwdGPO = Get-ADDefaultDomainPasswordPolicy -Server $DCListFiltered[0]
                # check DFL and get Fine-Grained Password Policies
                if ( $dfl -like "Windows2008Domain" -or $dfl -like "Windows2008R2Domain" -or $dfl -like "Windows2012Domain" -or $dfl -like "Windows2012R2Domain" )
                    {
                        $FGPPNo = (Get-ADFineGrainedPasswordPolicy -Server $DCListFiltered[0] -Filter * | Measure-Object).Count
                    }
                # End of Fine-Grained Password Policies section
                # Get information about built-in domain Administrator account
                $builtinAdmin = Get-ADuser -Identity $domainSID-500 -Server $DCListFiltered[0] -Properties Name, LastLogonDate, PasswordLastSet, PasswordNeverExpires, whenCreated, Enabled
                # Get total number of Domain Administrators group members
                $domainAdminsNo = (Get-ADGroup -Identity $domainSID-512 -Server $DCListFiltered[0] | Get-ADGroupMember -Recursive | Measure-Object).Count

            }
        # End main ELSE section


        $usr_objectsNo = 0
        $usr_active_objectsNo = 0
        $usr_inactive_objectsNo = 0
        $usr_locked_objectsNo = 0
        $usr_pwdnotreq_objectsNo = 0
        $usr_pwdnotexp_objectsNo = 0

        $grp_objectsNo = 0
        $grp_objects_localNo = 0
        $grp_objects_universalNo = 0
        $grp_objects_globalNo = 0

        $cmp_objectsNo = 0

        $cmp_os_2000 = 0
        $cmp_os_xp = 0
        $cmp_os_7 = 0
        $cmp_os_8 = 0
        $cmp_os_81 = 0
        $cmp_os_10 = 0

        $cmp_srvos_2000 = 0
        $cmp_srvos_2003 = 0
        $cmp_srvos_2008 = 0
        $cmp_srvos_2008r2 = 0
        $cmp_srvos_2012 = 0
        $cmp_srvos_2012r2 = 0
        $cmp_srvos_2016 = 0
        $cmp_srvos_2019 = 0

        # Get information about Active Directory objects
        $ou_objectsNo = (Get-ADOrganizationalUnit -Server $domain -Filter * | Measure-Object).Count

        $cmp_objects = Get-ADComputer -Server $domain -Filter * -Properties operatingSystem
        $cmp_objectsNo = $cmp_objects.Count

        $cmp_objects | %{ if ($_.operatingSystem -like "Windows 2000 Professional*") { $cmp_os_2000 = $cmp_os_2000 + 1 } }
        $cmp_objects | %{ if ($_.operatingSystem -like "Windows XP*") { $cmp_os_xp = $cmp_os_xp + 1 } }
        $cmp_objects | %{ if ($_.operatingSystem -like "Windows 7*") { $cmp_os_7 = $cmp_os_7 + 1 } }
        $cmp_objects | %{ if ($_.operatingSystem -like "Windows 8 *") { $cmp_os_8 = $cmp_os_8 + 1 } }
        $cmp_objects | %{ if ($_.operatingSystem -like "Windows 8.1*") { $cmp_os_81 = $cmp_os_81 + 1 } }
        $cmp_objects | %{ if ($_.operatingSystem -like "Windows 10*") { $cmp_os_10 = $cmp_os_10 + 1 } }

        $cmp_objects | %{ if ($_.operatingSystem -like "Windows 2000 Server*") { $cmp_srvos_2000 = $cmp_srvos_2000 + 1 } }
        $cmp_objects | %{ if ($_.operatingSystem -like "Windows Server 2003*") { $cmp_srvos_2003 = $cmp_srvos_2003 + 1 } }
        $cmp_objects | %{ if ( ($_.operatingSystem -like "Windows Server 2008*") -and ($_.operatingSystem -notlike "Windows Server 2008 R2*") ) { $cmp_srvos_2008 = $cmp_srvos_2008 + 1 } }
        $cmp_objects | %{ if ($_.operatingSystem -like "Windows Server 2008 R2*") { $cmp_srvos_2008r2 = $cmp_srvos_2008r2 + 1 } }
        $cmp_objects | %{ if ( ($_.operatingSystem -like "Windows Server 2012 *") -and ($_.operatingSystem -notlike "Windows Server 2012 R2*") ) { $cmp_srvos_2012 = $cmp_srvos_2012 + 1 } }
        $cmp_objects | %{ if ($_.operatingSystem -like "Windows Server 2012 R2*") { $cmp_srvos_2012r2 = $cmp_srvos_2012r2 + 1 } }
        $cmp_objects | %{ if ($_.operatingSystem -like "Windows Server 2016*") { $cmp_srvos_2016 = $cmp_srvos_2016 + 1 } }
        $cmp_objects | %{ if ($_.operatingSystem -like "Windows Server 2019*") { $cmp_srvos_2019 = $cmp_srvos_2019 + 1 } }

        $grp_objects = Get-ADGroup -Server $domain -Filter * -Properties GroupScope
        $grp_objectsNo = $grp_objects.Count
        $grp_objects | %{ if ($_.GroupScope -eq "DomainLocal") { $grp_objects_localNo = $grp_objects_localNo + 1 } }
        $grp_objects | %{ if ($_.GroupScope -eq "Universal") { $grp_objects_universalNo = $grp_objects_universalNo + 1 } }
        $grp_objects | %{ if ($_.GroupScope -eq "Global") { $grp_objects_globalNo = $grp_objects_globalNo + 1 } }

        $usr_objects = Get-ADUser -Server $domain -Filter * -Properties Enabled, LockedOut, PasswordNeverExpires, PasswordNotRequired
        $usr_objectsNo = $usr_objects.Count
        $usr_objects | %{ if ($_.Enabled -eq $True) { $usr_active_objectsNo = $usr_active_objectsNo + 1 } }
        $usr_objects | %{ if ($_.Enabled -eq $False) { $usr_inactive_objectsNo = $usr_inactive_objectsNo + 1 } }
        $usr_objects | %{ if ($_.LockedOut -eq $True) { $usr_locked_objectsNo = $usr_locked_objectsNo + 1 } }
        $usr_objects | %{ if ($_.PasswordNotRequired -eq $True) { $usr_pwdnotreq_objectsNo = $usr_pwdnotreq_objectsNo + 1 } }
        $usr_objects | %{ if ($_.PasswordNeverExpires -eq $True) { $usr_pwdnotexp_objectsNo = $usr_pwdnotexp_objectsNo + 1 } }

        # Display gathered domain details on the screen
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`nCurrent domain details:"
        
        $DomainInfoVar +=  "`r`n----------------------------------------------------------------"
        
        $DomainInfoVar +=  "`r`nDNS domain name"
        $DomainInfoVar +=  $domain
        
        $DomainInfoVar +=  "`r`n----------------------------------------------------------------"
        
        $DomainInfoVar +=  "`r`nNetBIOS domain name"
        $DomainInfoVar +=   $NetBIOS
        
        $DomainInfoVar +=  "`r`n----------------------------------------------------------------"

        $DomainInfoVar +=  "`r`nDHCP Servers in $domainName"
        $DHCPServers |Sort | %{ $DomainInfoVar +=  $_.TrimEnd($domain).toUpper() }

        $DomainInfoVar +=  "`r`n----------------------------------------------------------------"

        # Check and display DFL
        $DomainInfoVar +=  "`r`nDomain Functional Level"

        switch ($dfl)
        
            {
                Windows2000Domain { $DomainInfoVar +=  "`r`nWindows 2000 native" }
                Windows2003Domain { $DomainInfoVar +=  "`r`nWindows Server 2003" }
                Windows2008Domain { $DomainInfoVar +=  "`r`nWindows Server 2008" }
                Windows2008R2Domain { $DomainInfoVar +=  "`r`nWindows Server 2008 R2" }
                Windows2012Domain { $DomainInfoVar +=  "`r`nWindows Server 2012" }
                Windows2012R2Domain { $DomainInfoVar +=  "`r`nWindows Server 2012 R2" }
                Windows2016Domain { $DomainInfoVar +=  "`r`nWindows Server 2016" }
                Windows2019Domain { $DomainInfoVar +=  "`r`nWindows Server 2019" }
                default { $DomainInfoVar +=  "`r`nUnknown Domain Functional Level:$dfl" }
                
            }
            
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End DFL section

        # SYSVOL replication method
        $DomainInfoVar +=  "`r`nSYSVOL replication method"
        
        $FRSsysvol = "CN=Domain System Volume (SYSVOL share),CN=File Replication Service,CN=System,"+(Get-ADDomain $domain).DistinguishedName
        $DFSRsysvol = "CN=Domain System Volume,CN=DFSR-GlobalSettings,CN=System,"+(Get-ADDomain $domain).DistinguishedName

        $frs = Get-ADObject -Filter { distinguishedName -eq $FRSsysvol }
        $dfsr = Get-ADObject -Filter { distinguishedName -eq $DFSRsysvol } 

        if ( $frs -ne $nul ) { $DomainInfoVar +=  "`r`nFRS" }
        
            elseif ( $dfsr -ne $nul ) { $DomainInfoVar +=  "`r`nDFS-R" }
        
        else { $DomainInfoVar +=  "`r`n###########"
               $DomainInfoVar +=  "`r`nunknown"
               $DomainInfoVar +=  "`r`n###########"
             }

        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of SYSVOL replication section

        # List of Domain Controllers
        $DomainInfoVar +=  "`r`nList of Domain Controllers"
        
        $DCList | Sort | %{ $DomainInfoVar +=  $_.TrimEnd($domain).toUpper() }

        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"


        $DomainInfoVar +=  "`r`nList of Read-Only Domain Controllers"

        if ( $RODCList.Count -ne 0 )
            {
                $RODCList | %{ $DomainInfoVar +=  $_.TrimEnd($domain).toUpper() }
            }
        else
            {
                $DomainInfoVar +=  "`r`n(none)"
            }

        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of Domain Controllers list section

        # Global Catalogs in a domain
        $DomainInfoVar +=  "`r`nGlobal Catalog servers in the domain"
        
        $ForestGC | Sort | %{ if ( $_ -match $DomainName -and ((( $_ -replace $DomainName ) -split "\.").Count -eq 2 ))

            {
                $DomainInfoVar +=  ($_.TrimEnd($domain).toUpper()) }
            }
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of Global Catalogs section

        # Display information about domain objects

        # Domain computer objects location
        $DomainInfoVar +=  "`r`nDefault domain computer objects location"

        if ($cmp_location.Contains("CN=Computers"))
            {
                $DomainInfoVar +=  "`r`n$cmp_location (not redirected)"
            }
        else
            {
                $DomainInfoVar +=  "`r`n$cmp_location (redirected)"
            }
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of domain computer objects location


        # Domain user objects location
        $DomainInfoVar +=  "`r`nDefault domain user objects location"
        
            if ($usr_location.Contains("CN=Users"))
            
                {
                
                    $DomainInfoVar +=  "`r`n$usr_location (not redirected)"
                
                }
                
            else
            
                {
                
                    $DomainInfoVar +=  "`r`n$usr_location (redirected)"

                
                }
                
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of domain user objects location

        # Check if orphaned objects exist
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`nDomain objects statistic:"
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

        $orphaned = Get-ADObject -Filter * -SearchBase "cn=LostAndFound,$($domainDN)" -SearchScope OneLevel | Measure-Object

        if ($orphaned.Count -ne 0)
        
            {
                $DomainInfoVar +=  "`r`n$($orphaned.Count) orphaned objects have been found!"
            }
        else
            {
                $DomainInfoVar +=  "`r`nNo orphaned objects have been found"
            }
        # End of orphaned objects check

        # Check if lingering objects or conflict replication objects exist

        $lingConfRepl = Get-ADObject -LDAPFilter "(cn=*\0ACNF:*)" -SearchBase $domainDN -SearchScope SubTree | Measure-Object

        if ($lingConfRepl.Count -ne 0)
        
            {
                $DomainInfoVar +=  "`r`n$($lingConfRepl.Count) lingering or replication conflict objects have been found!"
            }
        else
            {
                $DomainInfoVar +=  "`r`nNo lingering or replication conflict objects have been found"
            }


        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of lingering objects check


        # Total number of Organizational Units
        $DomainInfoVar +=  "`r`nTotal number of Organizational Unit objects : $ou_objectsNo"
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`nTotal number of computer objects : $cmp_objectsNo"
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`n  Client systems"
        $DomainInfoVar +=  "`r`n  Windows 2000                   : $cmp_os_2000"
        $DomainInfoVar +=  "`r`n  Windows XP                     : $cmp_os_xp"
        $DomainInfoVar +=  "`r`n  Windows 7                      : $cmp_os_7"
        $DomainInfoVar +=  "`r`n  Windows 8                      : $cmp_os_8"
        $DomainInfoVar +=  "`r`n  Windows 8.1                    : $cmp_os_81"
        $DomainInfoVar +=  "`r`n  Windows 10                     : $cmp_os_10"
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`n  Server systems"
        $DomainInfoVar +=  "`r`n  Windows 2000 Server            : $cmp_srvos_2000" 
        $DomainInfoVar +=  "`r`n  Windows Server 2003            : $cmp_srvos_2003" 
        $DomainInfoVar +=  "`r`n  Windows Server 2008            : $cmp_srvos_2008" 
        $DomainInfoVar +=  "`r`n  Windows Server 2008R2          : $cmp_srvos_2008r2" 
        $DomainInfoVar +=  "`r`n  Windows Server 2012            : $cmp_srvos_2012" 
        $DomainInfoVar +=  "`r`n  Windows Server 2012R2          : $cmp_srvos_2012r2" 
        $DomainInfoVar +=  "`r`n  Windows Server 2016            : $cmp_srvos_2016" 
        $DomainInfoVar +=  "`r`n  Windows Server 2019            : $cmp_srvos_2019" 
        
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of total OUs number


        # Total number of domain users
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`nTotal number of user objects  : $usr_objectsNo" 
        $DomainInfoVar +=  "`r`n  Active                      : $usr_active_objectsNo" 
        $DomainInfoVar +=  "`r`n  Inactive                    : $usr_inactive_objectsNo" 
        $DomainInfoVar +=  "`r`n  Locked out                  : $usr_locked_objectsNo" 
        $DomainInfoVar +=  "`r`n  Password not required       : $usr_pwdnotreq_objectsNo" 
        $DomainInfoVar +=  "`r`n  Password never expires      : $usr_pwdnotexp_objectsNo" 
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of total domain users number


        # Total number of domain groups
        $DomainInfoVar +=  "`r`nTotal number of group objects : $grp_objectsNo" 
        $DomainInfoVar +=  "`r`n  Global                      : $grp_objects_globalNo" 
        $DomainInfoVar +=  "`r`n  Universal                   : $grp_objects_universalNo" 
        $DomainInfoVar +=  "`r`n  Domain Local                : $grp_objects_localNo" 
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of total domain groups number

        # Total number of domain administrators
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        

        $DomainInfoVar +=  "`r`nTotal number of Domain Administrators: $domainAdminsNo" 
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of total domain administrators number



        # Details about built-in domain Administrator account
        $DomainInfoVar +=  "`r`nBuilt-in Domain Administrator account details:"
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        $BuiltAd = $builtinAdmin.Name
        $DomainInfoVar +=  "`r`nAccount name: $BuiltAd"
                if ( $builtinAdmin.Enabled )
        
            {
            
                $BuiltAdStatus =  "enabled"
            
            }
            
        else

            {
            
                $BuiltAdStatus = "disabled"
            
            }
        $DomainInfoVar +=  "`r`nAccount status: $BuiltAdStatus" 
                if ( $builtinAdmin.PasswordNeverExpires )
        
            {
            
                $BuiltAdPass =  "yes"
            
            }
            
        else
        
            {
            
                $BuiltAdPass =  "no"
            
            }


        $DomainInfoVar +=  "`r`nPassword never expires: $BuiltAdPass" 
        


        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`nPromoted to domain account`r`n"
        $BuiltAdminCreate = $builtinAdmin.whenCreated

        $DomainInfoVar +=   $BuiltAdminCreate
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`nLast password change`r`n"
        $builtinAdminPasswordLastSet = $builtinAdmin.PasswordLastSet
        $DomainInfoVar +=   $builtinAdminPasswordLastSet
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`nLast logon date`r`n"
        $builtinAdminLastLogonDate = $builtinAdmin.LastLogonDate
        $DomainInfoVar +=   $builtinAdminLastLogonDate

        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of domain objects information section




        # FSMO roles for domain
        $DomainInfoVar +=  "`r`nFSMO roles details:"
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`nPDC Emulator master`r`n"
        $FSMOPDCUP = $FSMOPDC.toUpper()
        $DomainInfoVar +=   $FSMOPDCUP
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`nRID master`r`n"
        $FSMORIDUP = $FSMORID.toUpper()
        $DomainInfoVar +=   $FSMORIDUP
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`nInfrastructure master`r`n"
        $FSMOInfrastructureUP = $FSMOInfrastructure.toUpper()
        $DomainInfoVar +=   $FSMOInfrastructureUP
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of domain FSMO section



        # Check default domain policy existance
        $gpoDefaultDomain = Get-ADObject -Server $domain -LDAPFilter "(&(objectClass=groupPolicyContainer)(cn={31B2F340-016D-11D2-945F-00C04FB984F9}))"
        $gpoDefaultDomainController = Get-ADObject -Server $domain -LDAPFilter "(&(objectClass=groupPolicyContainer)(cn={6AC1786C-016F-11D2-945F-00C04fB984F9}))"

        $DomainInfoVar +=  "`r`nDefault Domain policies check:"
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

        if ($gpoDefaultDomain -ne $nul)
        
            {
            
                $DomainInfoVar +=  "`r`nDefault Domain policy             : " 
                $DomainInfoVar +=  "`r`nexists"
            
            }
            
        else
        
            {
            
                $DomainInfoVar +=  "`r`ndoes not exist"
            
            }


        if ($gpoDefaultDomainController -ne $nul)
        
            {
            
                $DomainInfoVar +=  "`r`nDefault Domain Controllers policy : " 
                $DomainInfoVar +=  "`r`nexists"
            
            }
            
        else
        
            {
            
                $DomainInfoVar +=  "`r`ndoes not exist"
            
            }

        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        # End of default domain policies check



        # Default Domain Password Policy details
        $DomainInfoVar +=  "`r`nDefault Domain Password Policy details:"
        
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`nMinimum password age: " 
        $DomainInfoVar +=   $pwdGPO.MinPasswordAge.days
        $DomainInfoVar += "day(s)"
        $DomainInfoVar +=  "`r`nMaximum password age: " 
        $DomainInfoVar +=   $pwdGPO.MaxPasswordAge.days
        $DomainInfoVar += "day(s)"
        $DomainInfoVar +=  "`r`nMinimum password length: " 
        $DomainInfoVar +=   $pwdGpo.MinPasswordLength
        $DomainInfoVar += "character(s)"
        $DomainInfoVar +=  "`r`nPassword history count: " 
        $DomainInfoVar +=   $pwdGPO.PasswordHistoryCount
        $DomainInfoVar += "unique password(s)"

        $DomainInfoVar +=  "`r`nPassword must meet complexity: " 
        
        if ( $pwdGPO.ComplexityEnabled )
        
            {
            
                $DomainInfoVar +=  "`r`nyes"
            
            }
            
        else
        
            {
            
                $DomainInfoVar +=  "`r`nno"
            
            }

        $DomainInfoVar +=  "`r`nPassword uses reversible encryption: " 
        
        if ( $pwdGPO.ReversibleEncryptionEnabled )
        
            {
            
                $DomainInfoVar +=  "yes"
            
            }
            
        else
        
            {
            
                $DomainInfoVar +=  "no"
            
            }

        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        
        $DomainInfoVar +=  "`r`nAccount lockout treshold: " 
        
        if ($pwdGPO.LockoutThreshold -eq 0 )
        
            {
            
                $DomainInfoVar +=  "Account never locks out"
            
            }
            
        else
        
            {
            
                $DomainInfoVar +=   $pwdGPO.LockoutThreshold
                $DomainInfoVar += "invalid logon attempts"
                $DomainInfoVar +=  "`r`nAccount lockout duration time: " 
                
                if ( $pwdGPO.LockoutDuration.days -eq 0 -and $pwdGPO.LockoutDuration.hours -eq 0 -and $pwdGPO.LockoutDuration.minutes -eq 0 )
                
                    {
                    
                        $DomainInfoVar +=  "Password may be unlocked by an administrator only"
                    
                    }
                    
                else
                
                    {
                    
                        $DomainInfoVar +=   $pwdGPO.LockoutDuration.days
                        $DomainInfoVar += "day(s) "
                        $DomainInfoVar += $pwdGPO.LockoutDuration.hours
                        $DomainInfoVar += "hour(s) "
                        $DomainInfoVar += $pwdGPO.LockoutDuration.minutes
                        $DomainInfoVar += "min(s)"
                        $DomainInfoVar +=  "`r`nAccount lockout counter resets after: " 
                        $DomainInfoVar +=   $pwdGPO.LockoutObservationWindow.days
                        $DomainInfoVar += "day(s) "
                        $DomainInfoVar += $pwdGPO.LockoutObservationWindow.hours
                        $DomainInfoVar += "hour(s) "
                        $DomainInfoVar += $pwdGPO.LockoutObservationWindow.minutes
                        $DomainInfoVar += "min(s)"
                    
                    }
                    
            }
            # End of Default Domain Password Policy details




            # Display total number of Fine-Grained Password Policies
            $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
            
            $DomainInfoVar +=  "`r`nFine-Grained Password Policies: " 
            $DomainInfoVar +=   $FGPPNo
            
            $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"


    }
    # End of custom Get-DomainInfo function




    # Main script section
    Clear-Host

    $DomainInfoVar +=  "`r`nCollecting Active Directory data..."

    # Checking if PowerShell script was executed with a parameter

    if ( $args.Length -gt 0 )
    
        {
        
            # Collecting information about specified Forest configuration
            $ForestInfo=Get-ADForest $args[0]
        
        }
        
    else
    
        {
        
            # Collecting information about current Forest configuration
            $ForestInfo=Get-ADForest
       
        }
    # End of parameter check





    # Forest variables definition
    $forest=$ForestInfo.RootDomain
    $allDomains=$ForestInfo.Domains

    $ForestGC=$ForestInfo.GlobalCatalogs
    $UPNsuffix=$ForestInfo.UPNSuffixes

    $ffl=$ForestInfo.ForestMode

    $FSMODomainNaming=$ForestInfo.DomainNamingMaster
    $FSMOSchema=$ForestInfo.SchemaMaster

    $forestDomainSID = Get-ADDomain (Get-ADForest).Name | Select domainSID


    $ADRecBinSupport="feature not supported"

    if ( $ffl -like "Windows2008R2Forest" -or $ffl -like "Windows2012Forest" -or $ffl -like "Windows2012R2Forest" )
    
        {
        
            $ADRecBin=(Get-ADOptionalFeature -Server $forest -Identity 766ddcd8-acd0-445e-f3b9-a7f9b6744f2a).EnabledScopes | Measure-Object

            if ( $ADRecBin.Count -ne 0 )
            
                {
                
                    $ADRecBinSupport="Enabled"
                
                }
                
            else
            
                {
                
                    $ADRecBinSupport="Disabled"
                
                }

        }
    # End of forest variables section




    # Define Schema partition variables
    
    $SchemaPartition = $ForestInfo.PartitionsContainer.Replace("CN=Partitions","CN=Schema")
    $SchemaVersion = Get-ADObject -Server $forest -Identity $SchemaPartition -Properties * | Select objectVersion
    
    # End of Schema partition variables definition


    $forestDN = $ForestInfo.PartitionsContainer.Replace("CN=Partitions,CN=Configuration,","")
    $configPartition = $ForestInfo.PartitionsContainer.Replace("CN=Partitions,","")



    # Display collected data
    Clear-Host
    $DomainInfoVar +=  "`r`nActive Directory report v0.2 by Krzysztof Pytko (iSiek)"

    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"


    # Display information about Forest
    $DomainInfoVar +=  "`r`nForest details:"
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    
    $DomainInfoVar +=  "`r`nForest name"
    $DomainInfoVar +=   $forest
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"




    # Determine and display schema version
    $DomainInfoVar +=  "`r`nActive Directory schema version"

    switch ($SchemaVersion.objectVersion)

        {
        
            13 { $DomainInfoVar +=   $SchemaVersion.objectVersion+"- Windows 2000 Server" }
            30 { $DomainInfoVar +=   $SchemaVersion.objectVersion+"- Windows Server 2003"  }
            31 { $DomainInfoVar +=   $SchemaVersion.objectVersion+"- Windows Server 2003 R2" }
            44 { $DomainInfoVar +=   $SchemaVersion.objectVersion+"- Windows Server 2008" }
            47 { $DomainInfoVar +=   $SchemaVersion.objectVersion+"- Windows Server 2008 R2" }
            51 { $DomainInfoVar +=   $SchemaVersion.objectVersion+"- Windows Server 8 Developers Preview" }
            52 { $DomainInfoVar +=   $SchemaVersion.objectVersion+"- Windows Server 8 Beta" }
            56 { $DomainInfoVar +=   $SchemaVersion.objectVersion+"- Windows Server 2012" }
            69 { $DomainInfoVar +=   $SchemaVersion.objectVersion+"- Windows Server 2012 R2" }
            72 { $DomainInfoVar +=   $SchemaVersion.objectVersion+"- Windows Server Technical Preview" }
            default { $DomainInfoVar +=  "`r`nunknown - "+$SchemaVersion.objectVersion }
       
        }
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    # End of schema version section



    # Determine and display Exchange version
    # Need to update exchange versions with latests releases
    $DomainInfoVar +=  "`r`nMicrosoft Exchange version"

    $ExchangeSystemObjects = Get-ADObject -Server $forest -LDAPFilter "(&(objectClass=container)(name=Microsoft Exchange System Objects))" -SearchBase $forestDN -Properties objectVersion
    $ExchangeSchemaVersion = Get-ADObject -Server $forest -LDAPFilter "(&(objectClass=attributeSchema)(name=ms-Exch-Schema-Version-Pt))" -SearchBase $SchemaPartition -Properties rangeUpper

    $ExchangeSchema = $ExchangeSystemObjects.objectVersion + $ExchangeSchemaVersion.rangeUpper

    if ($ExchangeSchemaVersion -ne $nul)
    
        {
        
            switch ($ExchangeSchema)
            
                {
                
                    13806  { $DomainInfoVar +=  "`r`nExchange Server 2003" }
                    21265 { $DomainInfoVar +=  "`r`nExchange Server 2007" }
                    22337 { $DomainInfoVar +=  "`r`nExchange Server 2007 Service Pack 1" }
                    25843 { $DomainInfoVar +=  "`r`nExchange Server 2007 Service Pack 2" }
                    25846 { $DomainInfoVar +=  "`r`nExchange Server 2007 Service Pack 3" }
                    27261 { $DomainInfoVar +=  "`r`nExchange Server 2010" }
                    27766 { $DomainInfoVar +=  "`r`nExchange Server 2010 Service Pack 1" }
                    27772 { $DomainInfoVar +=  "`r`nExchange Server 2010 Service Pack 2" }
                    27774 { $DomainInfoVar +=  "`r`nExchange Server 2010 Service Pack 3" }
                    28373 { $DomainInfoVar +=  "`r`nExchange Server 2013" }
                    28490 { $DomainInfoVar +=  "`r`nExchange Server 2013 Cumulative Update 1" }
                    28517 { $DomainInfoVar +=  "`r`nExchange Server 2013 Cumulative Update 2" }
                    28519 { $DomainInfoVar +=  "`r`nExchange Server 2013 Cumulative Update 3" }
                    28528 { $DomainInfoVar +=  "`r`nExchange Server 2013 Cumulative Update 4 - Service Pack 1" }
                    28536 { $DomainInfoVar +=  "`r`nExchange Server 2013 Cumulative Update 5" }
                    28539 { $DomainInfoVar +=  "`r`nExchange Server 2013 Cumulative Update 6" }
                    default {  $ExchangeSchemaVersionUP = $ExchangeSchemaVersion.rangeUpper ;$DomainInfoVar +=  "`r`nunknown - $ExchangeSchemaVersionUP" }
                    
                }

            $ExchOrganization = (Get-ADObject -Server $forest -Identity "cn=Microsoft Exchange,cn=Services,$configPartition" -Properties templateRoots).templateRoots
            $ExchOrgName = (Get-ADObject -Server $forest -Identity $($ExchOrganization -Replace "cn=Addressing," , "") -Properties name).name

            $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
            
            $DomainInfoVar +=  "`r`nMicrosoft Exchange Organization name`r`n"
            $DomainInfoVar +=   $ExchOrgName

        } #end if
        
    else
    
        {
        
            $DomainInfoVar +=  "`r`n(not present)"
        
        }
        
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    # End of Exchange version



    # Determine and display Lync version
    $DomainInfoVar +=  "`r`nMicrosoft Lync server version"

    $LyncSchemaVersion = Get-ADObject -Server $forest -LDAPFilter "(&(objectClass=attributeSchema)(name=ms-RTC-SIP-SchemaVersion))" -SearchBase $SchemaPartition -Properties rangeUpper

    if ($LyncSchemaVersion -ne $nul)
    
        {
        
            switch ($LyncSchemaVersion.rangeUpper)
            
                {
                
                    1006 { $DomainInfoVar +=  "`r`nLive Communications Server 2005" }
                    1007 { $DomainInfoVar +=  "`r`nOffice Communications Server 2007 Release 1" }
                    1008 { $DomainInfoVar +=  "`r`nOffice Communications Server 2007 Release 2" }
                    1100 { $DomainInfoVar +=  "`r`nLync Server 2010" }
                    1150 { $DomainInfoVar +=  "`r`nLync Server 2013" }
                    default {$LyncSchemaVersionUP= $LyncSchemaVersion.rangeUpper; $DomainInfoVar +=  "`r`nunknown - $LyncSchemaVersionUP" }
                
                }

        }# end if
        
    else
    
        {
        
            $DomainInfoVar +=  "`r`n(not present)"
        
        }
        
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    # End of Lync version



    # Determine and display FFL
    $DomainInfoVar +=  "`r`nForest Functional Level"
    
    switch ($ffl)
    
        {
        
            Windows2000Forest { $DomainInfoVar +=  "`r`nWindows 2000" }
            Windows2003Forest { $DomainInfoVar +=  "`r`nWindows Server 2003" }
            Windows2008Forest { $DomainInfoVar +=  "`r`nWindows Server 2008" }
            Windows2008R2Forest { $DomainInfoVar +=  "`r`nWindows Server 2008 R2" }
            Windows2012Forest { $DomainInfoVar +=  "`r`nWindows Server 2012" }
            Windows2012R2Forest { $DomainInfoVar +=  "`r`nWindows Server 2012 R2" }
            Windows2016Forest { $DomainInfoVar +=  "`r`nWindows Server 2016" }
            Windows2019Forest { $DomainInfoVar +=  "`r`nWindows Server 2019" }
            default { $DomainInfoVar +=  "`r`nUnknown Forest Functional Level:$ffl" }
        
        }
        
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    # End of FFL section



    # Forest tombstoneLifetime
    $tombstoneLifetime = (Get-ADobject -Server $forest -Identity "cn=Directory Service,cn=Windows NT,cn=Services,$configPartition" -Properties tombstoneLifetime).tombstoneLifetime
    
    $DomainInfoVar +=  "`r`nTombstone lifetime"
    
    if ($tombstoneLifetime -ne $nul)
    
        {
        
            $DomainInfoVar +=   "$tombstoneLifetime day(s)"
        
        }
        
    else
    
        {
        
            $DomainInfoVar +=  "`r`n60 days (default setting)"
        
        }
        
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    # End of forest tombstoneLifetime



    # AD Recycle Bin support
    
    $DomainInfoVar +=  "`r`nActive Directory Recycle Bin"
    $DomainInfoVar +=  "`r`n"
    $DomainInfoVar +=   $ADRecBinSupport
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    
    # End of AD Recycle Bin section




    # List of all Domains in a Forest
    
    $DomainInfoVar +=  "`r`nDomains in this forest"
    $DomainInfoVar +=   $allDomains | Sort | %{ $DomainInfoVar +=   $_ }
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    
    # End of list section




    # Trusts enumeration
    $DomainInfoVar +=  "`r`nList of trusts"
    
    $ADTrusts = Get-ADObject -Server $forest -Filter { objectClass -eq "trustedDomain" } -Properties CanonicalName,trustDirection

    if ($ADTrusts.Count -gt 0)
    
        {
        
            foreach ($Trust in $ADTrusts)

                {

                    switch ($Trust.trustDirection)
                    
                        {
                        
                            3 { $trustInfo=($Trust.CanonicalName).Replace("/System/","  <===>  ") }
                            2 { $trustInfo=($Trust.CanonicalName).Replace("/System/","  <----  ") }
                            1 { $trustInfo=($Trust.CanonicalName).Replace("/System/","  ---->  ") }
                        
                        }


                    $DomainInfoVar +=   $trustInfo

                }

        }

    else
    
        {
        
            $DomainInfoVar +=  "`r`n(none)"
        
        }
        
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    # End of trusts list




    # List of all partitions in a forest
    $partitions = Get-ADObject -Server $forest -Filter * -SearchBase $ForestInfo.PartitionsContainer -SearchScope OneLevel -Properties name,nCName,msDS-NC-Replica-Locations | Select name,nCName,msDS-NC-Replica-Locations | Sort-Object name
    
    $DomainInfoVar +=  "`r`nList of all partitions"
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    
    
    foreach ($part in $partitions)
        
        {
            $DomainInfoVar +=  "`r`n"
            $DomainInfoVar +=    $part.name
            $DomainInfoVar +=  "`r`n"
            $DomainInfoVar +=   $part.nCName
            
            $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
            $DomainInfoVar +=  "`r`n"
            $DNSServers = $part."msDS-NC-Replica-Locations" | Sort-Object
            
                       
            # If any DNS server holds partition
            if ($DNSServers -ne $nul)
                
                {
                    
                    $DomainInfoVar +=  "`r`nDNS servers"
                    
                    # Get DNS Servers for selected partition
                    foreach ($DNSServer in $DNSServers)
                    
                        {
                            $DomainInfoVar +=  "`r`n"
                            $DomainInfoVar +=  ( ($DNSServer -Split ",")[1] -Replace "CN=","")
                            
                        }
                        
                     # End of DNS servers list for selected partition
                        
                }
             # End IF section for DNS servers
             
            
            $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
            $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
            
        }
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    # End of list of all partitions in a forest
    
    
    $DomainInfoVar +=  "`r`nSites and Subnets information"
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"



    # Sites enumeration
    $ConfigurationPart = ($ForestInfo.PartitionsContainer -Replace "CN=Partitions,","")
    $AllSites = Get-ADObject -Server $forest -Filter { objectClass -eq "site" } -SearchBase $ConfigurationPart -Properties *

    # Loop for Sites and Subnets
    foreach ( $Site in $AllSites )
        
        {
            $SiteName = $Site.Name
            $DomainInfoVar +=  "`r`nSite:$SiteName"
            $DomainInfoVar += "`r`n"
            $DomainInfoVar +=  "`r`nServer(s) in site:"
            $DomainInfoVar += "`r`n"

            $ServersInSite = Get-ADObject -Server $forest -Filter { objectClass -eq "server" } -SearchBase $Site.distinguishedName -SearchScope Subtree -Properties Name | Select Name | Sort-Object Name

            # Loop for Domain Controller details
            foreach ($Server in $ServersInSite)
            
                {

                    # If any DC is in Site
                    if ( $Server -ne $nul )
                    
                        {
                            
                            $dcDetails = Get-ADDomainController $Server.Name

                            $dcDN = $dcDetails.ComputerObjectDN -Replace $dcDetails.Name,""
                            $dcDN = $dcDN -Replace "CN=,",""

                            $dcFRS = "CN=Domain System Volume (SYSVOL share),CN=NTFRS Subscriptions,$($dcdetails.computerobjectdn)"
                            $dcDFSR = "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,$($dcdetails.computerobjectdn)"


                            $dcFRSinfo = Get-ADObject -Filter { distinguishedName -eq $dcFRS } -Properties fRSRootPath
                            $dcDFSRinfo = Get-ADObject -Filter { distinguishedName -eq $dcDFSR } -Properties msDFSR-RootPath, msDFSR-RootSizeInMb


                            
                            # Display Domain Controller details
                            $DomainInfoVar +=  "`r`n$($Server.Name) ($($dcDN))"
                            $dcDetailsipv4address = $dcDetails.ipv4address
                            $DomainInfoVar +=  "`r`nIP address (v4)    : $dcDetailsipv4address"

                            # IPv6 address
                            if ($dcDetails.ipv6address -ne $nul)
                            
                                {
                                    $dcDetailsipv6address = $dcDetails.ipv6address
                                    $DomainInfoVar +=  "`r`nIP address (v6)    : $dcDetailsipv6address"
                                
                                }
                                
                            else
                            
                                {
                                
                                    $DomainInfoVar +=  "`r`nIP address (v6)    :  (none)"
                              
                                }
                            # End of IPv6 address section
                            
                            
                            
                            # Operating system type and its service pack level
                            $dcDetailsoperatingSystem = $dcDetails.operatingSystem
                            $DomainInfoVar +=  "`r`nOS type            : $dcDetailsoperatingSystem"

                            if ($dcDetails.operatingSystemServicePack -ne $nul)
                            
                                {
                                    $dcDetailsoperatingSystemServicePack = $dcDetails.operatingSystemServicePack
                                    $DomainInfoVar +=  "`r`nService Pack       : $dcDetailsoperatingSystemServicePack"
                                
                                }
                            # End of operating system and service pack level section
                            

                            
                            # SYSVOL replication method on DC
                            # SYSVOL FRS section
                            if ($dcFRSinfo -ne $nul)
                            
                                {
                                
                                    $DomainInfoVar +=  "`r`nSYSVOL replication :  FRS"
                                    $dcFRSinfoUP = $dcFRSinfo.fRSRootPath.toUpper()
                                    $DomainInfoVar +=  "`r`nSYSVOL location    : $dcFRSinfoUP"
                               
                                }
                            # End of SYSVOL FRS section


                            
                            # SYSVOL DFS-R section
                            if ($dcDFSRinfo -ne $nul)
                            
                                {
                                
                                    $DomainInfoVar +=  "`r`nSYSVOL replication :  DFS-R"
                                    $dcDFSRinfoUP = $dcDFSRinfo."msDFSR-RootPath".toUpper()
                                    $DomainInfoVar +=  "`r`nSYSVOL location    : $dcDFSRinfoUP"


                                    # SYSVOL size
                                    if ($dcDFSRinfo."msDFSR-RootSizeInMb" -ne $nul)
                                    
                                        {
                                            $dcDFSRinfomsDFSRRootSizeInMb = $dcDFSRinfo."msDFSR-RootSizeInMb"
                                            $DomainInfoVar +=  "`r`nSYSVOL quota       : $dcDFSRinfomsDFSRRootSizeInMb"
                                        
                                        }
                                        
                                    else
                                    
                                        {
                                        
                                            $DomainInfoVar +=  "`r`nSYSVOL quota       :  4GB (default setting)"
                                        
                                        }
                                    # End of SYSVOL size
                                    

                                }
                            # End of SYSVOL DFS-R section


                        }
                    # End of section where DC is in Site    
                    
                    
                    # If no DC in Site
                    else
    
                    {
                    
                        $DomainInfoVar +=  "`r`n(none)"
                    
                    }
                    # End of section where no DC in Site


                    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

                } # End of sub foreach for Domain Controllers details
                
                

        # List Subnets for selected Site
        $subnets = $Site.siteObjectBL

        $DomainInfoVar +=  "`r`nSubnets:`r`n"

        # If any Subnet assigned
        if ( $subnets -ne $nul )
                    
            {
            
                # List all Subnets for selected Site
                foreach ($subnet in $subnets)

                    {
                                
                        $SubnetSplit = $Subnet.Split(",")
                        $DomainInfoVar +=  $SubnetSplit[0].Replace("CN=","")
                        $DomainInfoVar +=  "`r`n"
                                
                    }
                # End of listing Subnets

            }
        # End of existing Subnets section
        
        
        # If no Subnets in Site
        else
                    
            {
                        
                $DomainInfoVar +=  "`r`n(none)"
                        
            }
        # End of no Subnets section
            
            
        
        # End of listing Subnets
       
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
        $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

        } # End of main foreach for Sites and Subnets
        
    # End of Sites section






    # Site Links enumeration

    $DomainInfoVar +=  "`r`nSite link(s) information:"
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

    $siteLinks = Get-ADObject -Server $forest -Filter { objectClass -eq "siteLink" } -SearchBase $ConfigurationPart -Properties name, cost, replInterval, siteList | Sort-Object replInterval

    foreach ($link in $siteLinks)
    
        {
            $linkname = $link.name
            $DomainInfoVar +=  "`r`nSite link name       : $linkname"
            $linkcost = $link.cost
            $DomainInfoVar +=  "`r`nReplication cost     : $linkcost" 
            $linkreplInterval = $link.replInterval
            $DomainInfoVar +=  "`r`nReplication interval : $linkreplInterval minutes"
            $DomainInfoVar +=  "`r`nSites included       : "

            foreach ($linkList in $link.siteList)
            
                {
                
                    $siteName = Get-ADObject -Identity $linkList -Properties Name
                    $siteNamename = $siteName.name
                    $DomainInfoVar +=   "$siteNamename; "
                
                }

            $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
            $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
            $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

        }


    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    # End of Site Links section




    # Get Global Catalogs in the forest
    
    $DomainInfoVar +=  "`r`nGlobal Catalog servers in the forest"
    $ForestGC | Sort | %{ $DomainInfoVar +=   "`r`n$_" }
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    
    # End of Global Catalogs section






    # Display additional suffixes
    $DomainInfoVar +=  "`r`nAdditional UPN suffixes"
    
    if ( $UPNSuffix.Count -ne 0 )
    
        {
        
        $UPNsuffix | Sort | %{ $DomainInfoVar +=   $_ }
        
        }
        
    else

        {
        
            $DomainInfoVar +=  "`r`n(none)"
        
        }

    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    # End of suffixes section





    # Forest FSMO roles display
    $DomainInfoVar +=  "`r`nFSMO roles details:"
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    
    $DomainInfoVar +=  "`r`nSchema master`r`n"
    $DomainInfoVar +=   $FSMOSchema.toUpper()
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    
    $DomainInfoVar +=  "`r`nDomain Naming master`r`n"
    $DomainInfoVar +=   $FSMODomainNaming.toUpper()

    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    # End of Forest FSMO section



    # Forest wide groups members
    $DomainInfoVar +=  "`r`nForest wide groups details:"
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    
    # Schema Administrators
    $schemaGroupID = ((Get-ADDomain(Get-ADForest).name).domainSID).value+"-518"
    $schemaAdminsNo = Get-ADGroup -Server $forest -Identity $schemaGroupID | Get-ADGroupMember -Recursive

    if ($schemaAdminsNo.Count -eq 2)
        {
        
            $DomainInfoVar +=  "`r`nTotal number of Schema Administrators     : "+$schemaAdminsNo.Count
            
        }
        
     else
     
        {
        
            $DomainInfoVar +=  "`r`nTotal number of Schema Administrators     : "+$schemaAdminsNo.Count
            
        }
        
        
    # Enterprise Admins
    $entGroupID = ((Get-ADDomain(Get-ADForest).name).domainSID).value+"-519"
    $enterpriseAdminsNo = Get-ADGroup -Server $forest -Identity $entGroupID | Get-ADGroupMember -Recursive

    if ($enterpriseAdminsNo.Count -eq 1)
        {
        
            $DomainInfoVar +=  "`r`nTotal number of Enterprise Administrators : "+$enterpriseAdminsNo.Count
            
        }
        
     else
     
        {
        
            $DomainInfoVar +=  "`r`nTotal number of Enterprise Administrators : "+$enterpriseAdminsNo.Count
            
        }
    
    
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    # End of forest wide groups members
    
    
    

    # Custom Get-DomainInfo function executed for every domain in the forest
    
    $allDomains | Sort | %{ Get-DomainInfo ($_) }
    
    # End of loop

    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"

    $DomainInfoVar +=  "`r`nThe end of Active Directory report"

    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    $DomainInfoVar +=  "`r`n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~"
    # End of data display

    $DomainInfoVar >> C:\temp\deployment\ADDirectoryInfo.txt
