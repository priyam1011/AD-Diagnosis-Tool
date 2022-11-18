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
    }  
    Process {
        $LogStringBuilder = [System.Text.StringBuilder]::new()
        [void]$LogStringBuilder.Append('{0} Port check: ' -f $Protocol)
        $ConnectionTimeout = 1800
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
                    Write-Verbose "Making UDP connection to remote server" 
                    $UDPObject.Connect("$IPAddress",$Port) 
                    #Sends a message to the host to which you have connected. 
                    Write-Verbose "Sending message to remote host" 
                    $Message = new-object system.text.asciiencoding 
                    $Byte = $Message.GetBytes("$(Get-Date)") 
                    [void]$UDPObject.Send($Byte,$Byte.length) 
                    #IPEndPoint object will allow us to read datagrams sent from any source.  
                    Write-Verbose "Creating remote endpoint" 
                    $RemoteEndpoint = New-Object system.net.ipendpoint([System.Net.IPAddress]::Any,0) 
                    Try { 
                        #Blocks until a message returns on this socket from a remote host. 
                        Write-Verbose "Waiting for message return" 
                        $ReceiveBytes = $UDPObject.Receive([ref]$RemoteEndpoint) 
                        [string]$ReturnData = $Message.GetString($ReceiveBytes)
                        If ($ReturnData) {
                           Write-Verbose "Connection Successful"
                            $UDPObject.close()   
                        }                       
                    } Catch { 
                        If ($Error[0].ToString() -match "\bRespond after a period of time\b") { 
                            #Close connection  
                            $UDPObject.Close()  
                            #Make sure that the host is online and not a false positive that it is open 
                            If (Test-Connection -comp $IPAddress -count 1 -quiet) { 
                                Write-Verbose "Connection Open"
                            } Else { 
                                <# 
                                It is possible that the host is not online or that the host is online,  
                                but ICMP is blocked by a firewall and this port is actually open. 
                                #> 
                                Write-Verbose "Host maybe unavailable"
                                $ClosedPorts += $Port                                 
                            }                         
                        } ElseIf ($Error[0].ToString() -match "forcibly closed by the remote host" ) { 
                            #Close connection  
                            $UDPObject.Close()  
                            Write-Verbose "Connection Timeout"  
                            $ClosedPorts += $Port                        
                        } Else {                      
                            $UDPObject.close() 
                        } 
                    }
                }                                  
            }  
        }
    }  
    End {  
        #Generate Report
        if ($ClosedPorts.Length -eq 0) {
            [void]$LogStringBuilder.AppendLine('PASSED')
        } else {
            [void]$LogStringBuilder.AppendLine('FAILED')
            [void]$LogStringBuilder.AppendLine('Refer to the following doc to enable required ports: https://cloud.google.com/managed-microsoft-ad/docs/create-trust?hl=en#opening-firewall')
        }
        return $LogStringBuilder.ToString()
    }
}

function Test-CheckDNS {
    param (
        [string[]]$OnPremIPAddresses
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    [void]$LogStringBuilder.Append('DNS server setup check: ')

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
        [void]$LogStringBuilder.AppendLine('PASSED')
    } else {
        [void]$LogStringBuilder.AppendLine('FAILED')
        [void]$LogStringBuilder.AppendLine(("Found Primary DNS server: {0}, Found Secondary DNS server (127.0.0.1): {1}" -f $FoundPrimaryDNS, $FoundSecondaryDNS))
        [void]$LogStringBuilder.AppendLine('Refer to the following doc (steps 15 through 18) for setup: https://cloud.google.com/architecture/deploy-fault-tolerant-active-directory-environment')
    }

    return $LogStringBuilder.ToString()
}


function Test-CheckFQDN {
    param (
        [string]$ManagedADDomainName
    )
    $DnsLookup = Resolve-DnsName -Name $ManagedADDomainName -errorAction SilentlyContinue
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    [void]$LogStringBuilder.Append('Managed AD domain lookup check: ')
    if ($DnsLookup -eq $null) {
        [void]$LogStringBuilder.AppendLine('FAILED')
        [void]$LogStringBuilder.AppendLine('Refer to the following doc for setup: https://cloud.google.com/managed-microsoft-ad/docs/create-trust?hl=en#creating-dns-forwarder')
    } else {
        [void]$LogStringBuilder.AppendLine('PASSED')
    }

    return $LogStringBuilder.ToString()
}

function Test-CheckDCReplication {
    param (
        [string]$OnPremDomainName
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    [void]$LogStringBuilder.Append('Domain controller replication check: ')
    $ReplicationFailures = Get-ADReplicationFailure -Target $OnPremDomainName -Scope Forest
    if ($ReplicationFailures -eq $null) {
        [void]$LogStringBuilder.AppendLine('PASSED')
    } else {
        [void]$LogStringBuilder.AppendLine('FAILED')
        [void]$LogStringBuilder.AppendLine('Refer to the following doc to create and validate replication setup: https://cloud.google.com/architecture/deploy-fault-tolerant-active-directory-environment#testing_the_installation')
    }

    return $LogStringBuilder.ToString()
}

function Test-CheckDNSForwarding {
    param (
        [string[]]$OnPremIPAddresses
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    [void]$LogStringBuilder.Append('DNS Forwarding check: ')
    # DNS forwarder IP address will be the default gateway IP if this script is running on the primary DC. 
    # Other DC's will have DNS forwarder IP as the address of the primary DC instead.
    $DefaultGatewayAddress = Get-NetRoute -DestinationPrefix "0.0.0.0/0" | Select-Object -ExpandProperty "NextHop"
    $FoundValidForwarder = $false
    $DNSForwarderAddresses = (Get-DnsServerForwarder).IPAddress.IPAddressToString
    foreach ($ForwarderAddress in $DNSForwarderAddresses) {
        foreach ($OnPremIPAddress in $OnPremIPAddresses) {
            if ($DefaultGatewayAddress -eq $ForwarderAddress -or $OnPremIPAddress -contains $ForwarderAddress) {
                $FoundValidForwarder = $true
                break
            }
        }
    }

    if ($FoundValidForwarder) {
        [void]$LogStringBuilder.AppendLine('PASSED')
    } else {
        [void]$LogStringBuilder.AppendLine('FAILED')
        [void]$LogStringBuilder.AppendLine('Refer to the following doc for conditional DNS forwarding setup: https://cloud.google.com/managed-microsoft-ad/docs/create-trust?hl=en#configuring-dns-forwarder')
    }

    return $LogStringBuilder.ToString()
}

function Test-CheckTrustSetup {
    param (
        [string]$ManagedADDomainName
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    [void]$LogStringBuilder.Append('Trust setup with Managed AD domain check: ')
    $TrustStatus = Get-ADTrust -Filter "Target -eq '$ManagedADDomainName'"
    if ($TrustStatus -eq $null) {
        [void]$LogStringBuilder.AppendLine('FAILED')
        [void]$LogStringBuilder.AppendLine('Refer to the following doc for trust setup with Managed AD domain: https://cloud.google.com/managed-microsoft-ad/docs/create-trust?hl=en#setting-up-trust')
    } else {
        [void]$LogStringBuilder.AppendLine('PASSED')
    }

    return $LogStringBuilder.ToString()
}

function Test-CheckLocalSecurityPolicy {
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    [void]$LogStringBuilder.Append('Local security policy check: ')
    $CurrentPath = (Get-Location).Path
    $SecurityConfigExportPath = $CurrentPath + "\diagnose-ad-security-policy.cfg"
    secedit /export /cfg $SecurityConfigExportPath /quiet
    $NetworkNamedPipesConfig = Get-Content $SecurityConfigExportPath | Select-string -pattern "NullSessionPipes" -encoding unicode | Select -first 1
    $ExpectedValues = "netlogon", "samr", "lsarpc"
    $FoundConfig = $true
    foreach ($Value in $ExpectedValues) {
        $RegexValue = "*" + $Value + "*"
        if (!($NetworkNamedPipesConfig -like $RegexValue)) {
            $FoundConfig = $false
        }
    }

    Remove-Item -Path $SecurityConfigExportPath
    if ($FoundConfig) {
        [void]$LogStringBuilder.AppendLine('PASSED')
    } else {
        [void]$LogStringBuilder.AppendLine('FAILED')
        [void]$LogStringBuilder.AppendLine('Refer to the following doc for local security policy setup: https://cloud.google.com/managed-microsoft-ad/docs/create-trust?hl=en#verifying-local-security-policy')
    }

    return $LogStringBuilder.toString()
}

function Test-CheckNameSuffixRouting() {
    param (
        [string]$OnPremDomainName,
        [string]$ManagedADDomainName
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    [void]$LogStringBuilder.Append('Name suffix routing check: ')
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
        [void]$LogStringBuilder.AppendLine('Refer to the following doc to refresh name suffix routing: https://cloud.google.com/managed-microsoft-ad/docs/manage-trusts#name-suffix-routing')
    }

    return $LogStringBuilder.ToString()
}

function Test-CheckKerberos {
    param (
        [string]$OnPremDomainName
    )
    $LogStringBuilder = [System.Text.StringBuilder]::new()
    [void]$LogStringBuilder.Append('Kerberos ticket check: ')
    $KerberosTicketStatus = klist
    $RegexValue = "*" + $OnPremDomainName + "*"
    if ($KerberosTicketStatus -like $RegexValue) {
        [void]$LogStringBuilder.AppendLine('PASSED')
    } else {
        [void]$LogStringBuilder.AppendLine('FAILED')
        [void]$LogStringBuilder.AppendLine('Refer to the following doc for obtaining a Kerberos ticket: https://docs.oracle.com/javase/7/docs/technotes/tools/windows/kinit.html')
    }

    return $LogStringBuilder.ToString()
}


#Inputs: 
# 1. On-prem domain name 
# 2. Managed AD domain name
<# TODO - Get input from user instead of setting the below two variables #>
Clear-Host
# Output logs to file.
$CurrentPath = (Get-Location).Path
$OutputLogPath = $CurrentPath + "\ad-diagnosis-log.txt"


$OnPremDomainName = "myonprem.com"
$ManagedADDomainName = "adprod3.com"
# Get IP addresses for all on-prem domain controllers in the AD forest
$OnPremIPAddresses = (Get-ADForest).Domains | %{ Get-ADDomainController -Filter * -Server $OnPremDomainName } | Select -ExpandProperty IPV4Address  #| Format-Table -Property Name,ComputerObjectDN,Domain,Forest,IPv4Address,OperatingSystem,OperatingSystemVersion


# Check for ports
Write-Host -ForegroundColor Yellow "`n`nChecking TCP and UDP ports for on-prem domain controllers... (This operation can take up to 45sc)"
$TCPResult = Test-CheckPort -OnPremIPAddresses $OnPremIPAddresses -Ports 53, 88, 135, 389, 445, 464, 49153, 50123, 65534 -Protocol "TCP"
$TCPResult | Out-File -FilePath $OutputLogPath
$UDPResult = Test-CheckPort -OnPremIPAddresses $OnPremIPAddresses -Ports 53, 88, 389, 445, 464 -Protocol "UDP"
$UDPResult | Out-File -FilePath $OutputLogPath -Append
Write-Host -ForegroundColor Yellow "`n`nCheck for TCP and UDP ports completed."
# End of check for ports


# Check for FQDN
Write-Host -ForegroundColor Yellow "`n`nChecking Managed AD domain lookup..."
$FQDNResult = Test-CheckFQDN -ManagedADDomainName $ManagedADDomainName  
$FQDNResult | Out-File -FilePath $OutputLogPath -Append
Write-Host -ForegroundColor Yellow "`n`nCheck for Managed AD domain lookup completed."
# End of check for FQDN


# Check DNS server setup
Write-Host -ForegroundColor Yellow "`n`nChecking domain controller DNS server setup..."
$DNSResult = Test-CheckDNS -OnPremIPAddresses $OnPremIPAddresses
$DNSResult | Out-File -FilePath $OutputLogPath -Append
Write-Host -ForegroundColor Yellow "`n`nCheck for DNS server setup completed."
# End of check for DNS setup

# Check for domain controller replication
if ($OnPremIPAddresses.Length > 1) {
    Write-Host -ForegroundColor Yellow "`n`nChecking domain controller replication..."
    $DCReplicationResult = Test-CheckDCReplication -OnPremDomainName $OnPremDomainName 
    $DCReplicationResult | Out-File -FilePath $OutputLogPath -Append
    Write-Host -ForegroundColor Yellow "`n`nCheck for DNS server setup completed."
} else {
    Write-Host -ForegroundColor Yellow "`n`nSkipping domain controller replication check as only one on-prem domain controller was found..."
} 
# End of check for domain controller replication

# Check for DNS Forwarding
Write-Host -ForegroundColor Yellow "`n`nChecking DNS Forwarding setup..."
$DNSForwardingResult = Test-CheckDNSForwarding -OnPremIPAddresses $OnPremIPAddresses
$DNSForwardingResult | Out-File -FilePath $OutputLogPath -Append
Write-Host -ForegroundColor Yellow "`n`nCheck for DNS forwarding setup completed."
# End of check for DNS Forwarding


# Check for trust setup
Write-Host -ForegroundColor Yellow "`n`nChecking trust setup with Managed AD domain..."
$TrustSetupResult = Test-CheckTrustSetup -ManagedADDomainName $ManagedADDomainName
$TrustSetupResult | Out-File -FilePath $OutputLogPath -Append
Write-Host -ForegroundColor Yellow "`n`nCheck for trust setup completed."
# End of check for trust setup

# Check for local security policy
Write-Host -ForegroundColor Yellow "`n`nChecking local security policy..."
$LocalSecurityPolicyResult = Test-CheckLocalSecurityPolicy
$LocalSecurityPolicyResult | Out-File -FilePath $OutputLogPath -Append
Write-Host -ForegroundColor Yellow "`n`nCheck for local security policy completed."
# End of check for local security policy


# Check for Name Suffix Routing
Write-Host -ForegroundColor Yellow "`n`nChecking if name suffix routing is enabled..."
$NameSuffixRoutingResult = Test-CheckNameSuffixRouting -OnPremDomainName $OnPremDomainName -ManagedADDomainName $ManagedADDomainName
$NameSuffixRoutingResult | Out-File -FilePath $OutputLogPath -Append
Write-Host -ForegroundColor Yellow "`n`nCheck for name suffix routing completed."
# End of check for Name Suffix Routing

# Check for Kerberos ticket
Write-Host -ForegroundColor Yellow "`n`nChecking Kerberos ticket..."
$KerberosResult = Test-CheckKerberos($OnPremDomainName)
$KerberosResult | Out-File -FilePath $OutputLogPath -Append
Write-Host -ForegroundColor Yellow "`n`nCheck for Kerberos ticket completed."
# End of check for Kerberos ticket

Write-Host -ForegroundColor Yellow ("`n`nActive Directory diagnosis complete. See results at - {0}" -f $OutputLogPath) 
