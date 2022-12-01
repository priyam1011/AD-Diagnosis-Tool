 function Check-RunAsAdministrator()
{
  #Get current user context
  $CurrentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  
  #Check user is running the script is member of Administrator Group
  if($CurrentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator))
  {
       Write-host "Script is running with Administrator privileges!"
  }
  else
    {
       #Create a new Elevated process to Start PowerShell
       $ElevatedProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
 
       # Specify the current script path and name as a parameter
       $ElevatedProcess.Arguments = "& '" + $script:MyInvocation.MyCommand.Path + "'"
 
       #Set the Process to elevated
       $ElevatedProcess.Verb = "runas"
 
       #Start the new elevated process
       [System.Diagnostics.Process]::Start($ElevatedProcess)
 
       #Exit from the current, unelevated, process
       Exit
 
    }
}

function Separate-SPNsByIPAndHost {
    param(
        [string[]]$SQLServerSPNs
    )
    $SQLServerIPSPNs = @()
    $SQLServerHostSPNs = @()
    foreach ($SPN in $SQLServerSPNs) {
        try {
            $IPAddr = [IPAddress]$SPN
            $SQLServerIPSPNs += $IPAddr
        } catch {
            $SQLServerHostSPNs += $SPN
        }
    }

    return $SQLServerIPSPNs, $SQLServerHostSPNs
}

function Test-CheckAvailableDCs {
    param(
        [array]$OnPremIPAddresses
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    $AvailableDCs = @()
    $UnreachableDCs = @()
    $Status = ""
    foreach ($OnPremIPAddress in $OnPremIPAddresses) {
        $IsSuccess = Test-Connection -ComputerName $OnPremIPAddress -Quiet
        if ($IsSuccess) {
            $AvailableDCs += $OnPremIPAddress
        } else {
            $UnreachableDCs += $OnPremIPAddress
        }
    }
    
    if ($UnreachableDCs.Count -gt 0) {
        $Status = "WARNING"
        [void]$LogStringBuilder.AppendLine("Failed to ping domain controllers at following IP addresses: {0}" -f ($UnreachableDCs -join ', '))
    } else {
        $Status = "PASSED"
    }

    [void]$LogStringBuilder.Append('Status: {0}' -f $Status)
    
    return $AvailableDCs, $LogStringBuilder.ToString()
}

function Test-CheckPort {

[cmdletbinding(  
    DefaultParameterSetName = '',  
    ConfirmImpact = 'low'  
)]
    param(  
        [array]$OnPremIPAddresses,
        [array]$Ports,
        [string]$Protocol
    )
    Begin {
        $ErrorActionPreference = "SilentlyContinue"
        $ClosedPorts = @()
        $LogStringBuilder = [System.Text.StringBuilder]::new()
        $WarningState = $false
        $FailedState = $false
        $ConnectionTimeout = 1800
    }
    Process {
        ForEach ($IPAddress in $OnPremIPAddresses) {
            ForEach ($Port in $Ports) {
                If ($Protocol -eq "TCP") {
                    #Create object for connecting to port on computer
                    $TCPObject = new-Object system.Net.Sockets.TcpClient
                    #Connect to remote machine's port
                    $Connect = $TCPObject.BeginConnect($IPAddress,$Port,$null,$null)
                    #Configure a timeout before quitting
                    $Wait = $Connect.AsyncWaitHandle.WaitOne($ConnectionTimeout, $false)
                    #If timeout
                    If(!$Wait) {
                        #Close connection
                        $TCPObject.Close()
                        $ClosedPorts += $Port
                    } Else {
                        $Error.Clear()
                        $TCPObject.EndConnect($Connect) | out-Null
                        #If error
                        If($Error[0]){
                            $Failed = $true
                        }
                        #Close connection
                        $TCPObject.Close()
                        #If unable to query port due to failure  
                        If($Failed){
                            $ClosedPorts += $Port
                        }
                    }
                    #Reset failed value
                    $Failed = $null
                }
                If ($Protocol -eq "UDP") {
                    #Create object for connecting to port on computer  
                    $UDPObject = new-Object system.Net.Sockets.Udpclient
                    #Set a timeout on receiving message
                    $UDPObject.Client.ReceiveTimeout = $ConnectionTimeout
                    #Connect to remote machine's port
                    $UDPObject.Connect("$IPAddress",$Port)
                    #Sends a message to the host to which you have connected.
                    $Message = new-object system.text.asciiencoding
                    $Byte = $Message.GetBytes("$(Get-Date)")
                    [void]$UDPObject.Send($Byte,$Byte.length)
                    #IPEndPoint object will allow us to read datagrams sent from any source.
                    $RemoteEndpoint = New-Object system.net.ipendpoint([System.Net.IPAddress]::Any,0)
                    Try {
                        #Blocks until a message returns on this socket from a remote host.
                        Write-Verbose "Waiting for message return"
                        $ReceiveBytes = $UDPObject.Receive([ref]$RemoteEndpoint)
                        [string]$ReturnData = $Message.GetString($ReceiveBytes)
                        If ($ReturnData) {
                           #Connection Successful
                            $UDPObject.close()
                        }
                    } Catch {
                        If ($Error[0].ToString() -match "\bRespond after a period of time\b") {
                            #Close connection
                            $UDPObject.Close()
                            #Make sure that the host is online and not a false positive that it is open 
                            If (Test-Connection -comp $IPAddress -count 1 -quiet) {
                                #Connection Open
                            } Else { 
                                <# 
                                It is possible that the host is not online or that the host is online,  
                                but ICMP is blocked by a firewall and this port is actually open. 
                                #>
                                #Host maybe unavailable
                                $ClosedPorts += $Port
                            }
                        } ElseIf ($Error[0].ToString() -match "forcibly closed by the remote host" ) {
                            #Close connection
                            $UDPObject.Close()
                            #Connection Timeout
                            $ClosedPorts += $Port                        
                        } Else {                      
                            $UDPObject.close() 
                        } 
                    }
                }                               
            }

            # Generate logs for current on-prem domain controller
            if ($ClosedPorts.Count -gt 0) {
                [void]$LogStringBuilder.AppendLine("Protocol: {0}. IP Address: {1}. Closed/unreachable ports: {2}" -f ($Protocol, $IPAddress, ($ClosedPorts -join ', ')))
                $WarningState = $true
                foreach ($ClosedPort in $ClosedPorts) {
                    if (!($RPCPorts -Contains $ClosedPort)) {
                        $FailedState = $true
                        break
                    }
                }
            }

            # Reset closed ports for next on-prem domain controller's port check.
            $ClosedPorts = @()
        }

        [void]$LogStringBuilder.Append('Status ({0} port check): ' -f $Protocol)
        if ($FailedState) {
            [void]$LogStringBuilder.AppendLine('FAILED')
        } else {
            if ($WarningState) {
                [void]$LogStringBuilder.AppendLine('WARNING')
            } else {
                [void]$LogStringBuilder.AppendLine('PASSED')
            }
        }
    }
    End {
        return $LogStringBuilder.ToString()
    }
}

function Test-CheckDNS {
    param (
        [string[]]$OnPremIPAddresses
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    $Status = ""
    $DNSAddresses = Get-DnsClientServerAddress | Select-Object –ExpandProperty ServerAddresses
    # Check primary DNS
    $FoundPrimaryDNS = $false
    foreach ($OnPremIPAddress in $OnPremIPAddresses) {
        if ($DNSAddresses -contains $OnPremIPAddress) {
            $FoundPrimaryDNS = $true
            break
        }
    }

    # Check secondary DNS
    $FoundSecondaryDNS = $false
    if ($DNSAddresses -contains "127.0.0.1") {
        $FoundSecondaryDNS = $true
    }

    if ($FoundPrimaryDNS -and $FoundSecondaryDNS) {
        $Status = "PASSED"
    } else {
        $Status = "WARNING"
        [void]$LogStringBuilder.AppendLine(("Found Primary DNS server: {0}, Found Secondary DNS server (127.0.0.1): {1}" -f $FoundPrimaryDNS, $FoundSecondaryDNS))
    }

    [void]$LogStringBuilder.AppendLine('Status: {0}' -f $Status)

    return $LogStringBuilder.ToString()
}


function Test-CheckManagedADFQDN {
    param (
        [string]$ManagedADDomainName,
        [string[]]$OnPremIPAddresses
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    $Status = ""
    foreach ($OnPremIPAddress in $OnPremIPAddresses) {
        $DnsLookup = Resolve-DnsName -Name $ManagedADDomainName -Server $OnPremIPAddress -errorAction SilentlyContinue
        if ($DnsLookup -eq $null) {
            $Status = "FAILED"
            [void]$LogStringBuilder.AppendLine("Failed to resolve managed AD domain name from on-prem IP: {0}" -f $OnPremIPAddress)
        } else {
            $Status = "PASSED"
        }
    }

    [void]$LogStringBuilder.AppendLine('Status: {0}' -f $Status)

    return $LogStringBuilder.ToString()
}

function Test-CheckSQLServerFQDN {
    param (
        [string[]]$SQLServerSPNs,
        [string[]]$OnPremIPAddresses
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    $Status = ""
    foreach ($OnPremIPAddress in $OnPremIPAddresses) {
        foreach ($SPN in $SQLServerSPNs) {
            $SQLServerLookup = Resolve-DnsName -Name $SPN -Server $OnPremIPAddress -errorAction SilentlyContinue
            if ($SQLServerLookup -eq $null) {
                $Status = "FAILED"
                [void]$LogStringBuilder.AppendLine("Failed to resolve domain name: {0}" -f $SPN)
            } else {
                $Status = "PASSED"
            }
        }
    }

    [void]$LogStringBuilder.AppendLine('Status: {0}' -f $Status)

    return $LogStringBuilder.ToString()
}

function Test-CheckDCReplication {
    param (
        [string]$OnPremDomainName
    )
    $Status = ""
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    $ReplicationResults = Get-ADReplicationFailure -Target $OnPremDomainName -Scope Forest
    if ($ReplicationResults -eq $null) {
        $Status = "PASSED"
    } else {
        foreach ($Result in $ReplicationResults) {
            if ($Result.FailureCount -gt 0) {
                [void]$LogStringBuilder.AppendLine('Replication failures found on server: {0}' -f $Result.Server)
            }
        }
        $Status = "FAILED"
    }

    [void]$LogStringBuilder.Append('Status: {0}' -f $Status)

    return $LogStringBuilder.ToString()
}

function Test-CheckDNSForwarding {
    param (
        [string]$ManagedADDomainName
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    [void]$LogStringBuilder.Append('Status: ')
    $DNSForwarders = Get-DnsServerZone | Where-Object {($_.ZoneType -eq 'Forwarder') -and ($_.ZoneName -eq $ManagedADDomainName)}
    if ($DNSForwarders -ne $null) {
        [void]$LogStringBuilder.AppendLine('PASSED')
    } else {
        [void]$LogStringBuilder.AppendLine('FAILED')
    }
    return $LogStringBuilder.ToString()
}

function Test-CheckTrustSetup {
    param (
        [string]$ManagedADDomainName
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    $Status = ""
    $TrustDetails = Get-ADTrust -Filter "Target -eq '$ManagedADDomainName'"
    if ($TrustDetails -eq $null) {
        $Status = "FAILED"
    } else {
        $ForestTrustValue = 8
        if (($TrustDetails.TrustAttributes -band $ForestTrustValue) -ne 0) {
            $Status = "PASSED"
            if ($TrustDetails.Direction -like '*Disabled*') {
                [void]$LogStringBuilder.AppendLine('Trust is disabled with Managed AD domain: {0}. Please enable the trust.' -f $ManagedADDomainName)
                $Status = "FAILED"
            }
        } else {
            [void]$LogStringBuilder.AppendLine('Detected an external trust with Managed AD domain: {0}. Please use a forest trust instead.' -f $ManagedADDomainName)
            $Status = "FAILED"
        }
    }

    [void]$LogStringBuilder.Append('Status: {0}' -f $Status)

    return $LogStringBuilder.ToString()
}

function Test-CheckLocalSecurityPolicy {
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    [void]$LogStringBuilder.Append('Status: ')
    $CurrentPath = (Get-Location).Path
    $SecurityConfigExportPath = $CurrentPath + "\diagnose-ad-security-policy.cfg"
    secedit /export /cfg $SecurityConfigExportPath /quiet
    $NetworkNamedPipesConfig = Get-Content $SecurityConfigExportPath | Select-string -pattern "NullSessionPipes" -encoding unicode | Select -first 1
    $ConfigArray = $NetworkNamedPipesConfig.ToString().Split(",")
    $ExpectedValues = "netlogon", "samr", "lsarpc"
    $FoundConfig = 0
    foreach ($Value in $ExpectedValues) {
        if ($ConfigArray.Contains($Value)) {
            $FoundConfig += 1
        }
    }

    Remove-Item -Path $SecurityConfigExportPath
    if ($FoundConfig -eq 3) {
        [void]$LogStringBuilder.AppendLine('PASSED')
    } else {
        [void]$LogStringBuilder.AppendLine('FAILED')
    }

    return $LogStringBuilder.toString()
}

function Test-CheckNameSuffixRouting() {
    param (
        [string]$OnPremDomainName,
        [string]$ManagedADDomainName
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    [void]$LogStringBuilder.Append('Status: ')
    $NameSuffixes = netdom trust $OnPremDomainName /namesuffixes:$ManagedADDomainName
    $ExpectedString = "*.{0}, Name Suffix, Enabled" -f $ManagedADDomainName
    $FoundNameSuffix = $false
    foreach ($Line in $NameSuffixes) {
        if ($Line -like $ExpectedString) {
            $FoundNameSuffix = $true
        }
    }

    if($FoundNameSuffix) {
        [void]$LogStringBuilder.AppendLine('PASSED')
    } else {
        [void]$LogStringBuilder.AppendLine('FAILED')
    }

    return $LogStringBuilder.ToString()
}

function Test-CheckKerberosOnPremDomain {
    param (
        [string]$OnPremDomainName
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    $Status = ""
    $ListKerberosTicketResponse = klist
    $SPN = "krbtgt/{0}" -f $OnPremDomainName
    $GotTicket = Get-KerberosTicket -SPN $SPN -ListKerberosTicketResponse $ListKerberosTicketResponse
    if (!$GotTicket) {
        [void]$LogStringBuilder.AppendLine("Failed to get kerberos ticket for SPN: {0}" -f $SPN)
        $Status = "FAILED"
    } else {
        $Status = "PASSED"
    }

    [void]$LogStringBuilder.AppendLine('Status: {0}' -f $Status)

    return $LogStringBuilder.ToString()
}

function Test-CheckKerberosSQLServer {
    param (
        [string[]]$SQLServerIPSPNs,
        [string[]]$SQLServerHostSPNs
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    $Status = ""
    $ListKerberosTicketResponse = klist
    $TicketFailedForHost = $false
    $TicketFailedForIP = $false
    foreach ($SPN in $SQLServerHostSPNs) {
        $FullSQLServerSPN = "MSSQLSvc/{0}:1433" -f $SPN
        $GotTicket = Get-KerberosTicket -SPN $FullSQLServerSPN -ListKerberosTicketResponse $ListKerberosTicketResponse
        if (!$GotTicket) {
            $TicketFailedForHost = $true
            [void]$LogStringBuilder.AppendLine("Failed to get kerberos ticket for SPN: {0}" -f $SPN)
        }
    }

    # Try checking if IP is used in SPN since we failed to retrieve ticket with DNS-based host name.
    if ($TicketFailedForHost) {
        foreach ($SPN in $SQLServerIPSPNs) {
            $FullSQLServerSPN = "MSSQLSvc/{0}:1433" -f $SPN
            $GotTicket = Get-KerberosTicket -SPN $FullSQLServerSPN -ListKerberosTicketResponse $ListKerberosTicketResponse
            if (!$GotTicket) {
                $TicketFailedForIP = $true
                [void]$LogStringBuilder.AppendLine("Failed to get kerberos ticket for SPN: {0}" -f $SPN)
                # Check if registry value is set to allow use of IP address hostnames in SPN.
                $RegistryValue = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -ErrorAction SilentlyContinue).TryIPSPN
                if ($RegistryValue -eq $null -or $RegistryValue -ne 1) {
                    [void]$LogStringBuilder.AppendLine("Failed to find registry entry TryIPSPN with value equal to 1 at path HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters")
                }
            }
        }   
    }

    if ($TicketFailedForHost -or $TicketFailedForIP) {
        $Status = "FAILED"
    } else {
        $Status = "PASSED"
    }

    [void]$LogStringBuilder.Append('Status: {0}' -f $Status)


    return $LogStringBuilder.ToString()
}

function Get-KerberosTicket {
    param (
        [string]$SPN,
        [object[]]$ListKerberosTicketResponse
    )
    $ExpectedRegex = "*{0}*" -f $SPN
    if ($ListKerberosTicketResponse -like $ExpectedRegex) {
        return $true
    } else {
        $GetKerberosTicketResponse = klist get $SPN
        if ($GetKerberosTicketResponse -like "*klist failed with*") {
            return $false
        } else {
            return $true
        }
    }
}


Clear-Host

#Check Script is running with Elevated Privileges
#Check-RunAsAdministrator

$OnPremDomainName = Read-Host -Prompt 'Input your on-oprem domain name (Example: my-onprem-domain.com)'
$ManagedADDomainName = Read-Host -Prompt 'Input the Managed AD domain name from GCP (Example: my-managed-ad.com)'
$SQLServerSPNList = Read-Host -Prompt 'Input a comma-separated list of your SQL Server instance(s) SPN''s and IP address(es) from GCP (Example: <private|public|proxy>.<instance-name>.<region>.<project-name>.cloudsql.<managed-ad-domain>.com, 1.2.3.4, 4.5.6.7)'
$SQLServerSPNs = $SQLServerSPNList.Split(',').Trim()

$SQLServerIPSPNs, $SQLServerHostSPNs = Separate-SPNsByIPAndHost -SQLServerSPNs $SQLServerSPNs

# Get IP addresses for all on-prem domain controllers in the AD forest
$OnPremIPAddresses = $null
$OnPremIPAddresses = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $OnPremDomainName } | Select -ExpandProperty IPV4Address

if ($OnPremIPAddresses -eq $null) {
    Write-Output ("No on-prem domain controllers found in the given on-prem domain name. Verify that this script is running on a domain controller of the on-prem domain: {0}. Exiting..." -f $OnPremDomainName)
    Exit
}

# Check for available on-prem domain controllers
Write-Host -ForegroundColor Yellow "`n`nChecking for available on-prem domain controllers..."
$OnPremIPAddresses, $CheckDCResult = Test-CheckAvailableDCs -OnPremIPAddresses $OnPremIPAddresses
Write-Output $CheckDCResult
# End of check for available on-prem domain controllers

# Check for ports (Note: For TCP port check, the RPC port range is 49153 - 65534 but not all ports in this range are consistently open so only checking a few)
$RPCPorts = @(49153, (Get-Random -Minimum 49153 -Maximum 65534), 65534)
$TCPPorts = @(53, 88, 135, 389, 445, 464) + $RPCPorts
Write-Host -ForegroundColor Yellow "`n`nChecking TCP and UDP ports for on-prem domain controllers... (This operation can take up to 45sc)"
$TCPResult = Test-CheckPort -OnPremIPAddresses $OnPremIPAddresses -Ports $TCPPorts -Protocol "TCP"
Write-Output $TCPResult
$UDPResult = Test-CheckPort -OnPremIPAddresses $OnPremIPAddresses -Ports 53, 88, 389, 464 -Protocol "UDP"
Write-Output $UDPResult
# End of check for ports

# Check for Managed AD fully qualified domain name (FQDN)
Write-Host -ForegroundColor Yellow "`n`nChecking Managed AD domain lookup..."
$FQDNResult = Test-CheckManagedADFQDN -ManagedADDomainName $ManagedADDomainName -OnPremIPAddresses $OnPremIPAddresses
Write-Output $FQDNResult
# End of check for Managed AD fully qualified domain name

# Check for SQL Server fully qualified domain name (FQDN)
Write-Host -ForegroundColor Yellow "`n`nChecking SQL Server domain lookup..."
$FQDNResult = Test-CheckSQLServerFQDN -SQLServerSPNs $SQLServerHostSPNs -OnPremIPAddresses $OnPremIPAddresses
Write-Output $FQDNResult
# End of check for SQL Server fully qualified domain name

# Check DNS server setup
Write-Host -ForegroundColor Yellow "`n`nChecking domain controller DNS server setup..."
$DNSResult = Test-CheckDNS -OnPremIPAddresses $OnPremIPAddresses
Write-Output $DNSResult
# End of check for DNS setup

# Check for domain controller replication
if ($OnPremIPAddresses.Count -gt 1) {
    Write-Host -ForegroundColor Yellow "`n`nChecking domain controller replication..."
    $DCReplicationResult = Test-CheckDCReplication -OnPremDomainName $OnPremDomainName 
    Write-Output $DCReplicationResult
} else {
    Write-Host -ForegroundColor Yellow "`n`nSkipping domain controller replication check as only one available on-prem domain controller was found..."
}
# End of check for domain controller replication

# Check for DNS Forwarding
Write-Host -ForegroundColor Yellow "`n`nChecking DNS Forwarding setup..."
$DNSForwardingResult = Test-CheckDNSForwarding -ManagedADDomainName $ManagedADDomainName
Write-Output $DNSForwardingResult
# End of check for DNS Forwarding

# Check for trust setup
Write-Host -ForegroundColor Yellow "`n`nChecking trust setup with Managed AD domain..."
$TrustSetupResult = Test-CheckTrustSetup -ManagedADDomainName $ManagedADDomainName
Write-Output $TrustSetupResult
# End of check for trust setup

# Check for local security policy
Write-Host -ForegroundColor Yellow "`n`nChecking local security policy..."
$LocalSecurityPolicyResult = Test-CheckLocalSecurityPolicy
Write-Output $LocalSecurityPolicyResult
# End of check for local security policy

# Check for Name Suffix Routing
Write-Host -ForegroundColor Yellow "`n`nChecking name suffix routing is enabled..."
$NameSuffixRoutingResult = Test-CheckNameSuffixRouting -OnPremDomainName $OnPremDomainName -ManagedADDomainName $ManagedADDomainName
Write-Output $NameSuffixRoutingResult
# End of check for Name Suffix Routing

# Check for Kerberos ticket for on-prem domain
Write-Host -ForegroundColor Yellow "`n`nChecking Kerberos ticket retrieval for on-prem domain..."
$KerberosResult = Test-CheckKerberosOnPremDomain -OnPremDomainName $OnPremDomainName
Write-Output $KerberosResult
# End of check for Kerberos ticket for on-prem domain

# Check for Kerberos ticket for SQL Server
Write-Host -ForegroundColor Yellow "`n`nChecking Kerberos ticket retrieval for SQL Server domains..."
$KerberosResult = Test-CheckKerberosSQLServer -SQLServerIPSPNs $SQLServerIPSPNs -SQLServerHostSPNs $SQLServerHostSPNs
Write-Output $KerberosResult
# End of check for Kerberos ticket for SQL Server

Write-Host -ForegroundColor Yellow ("`n`nActive Directory diagnosis complete. Refer to the following doc on how to resolve any of the above failures - {0}" -f "go/ad-tool-public-doc") 
