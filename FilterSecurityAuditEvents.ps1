# Check/request elevation
$MyWindowsID = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$MyWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($MyWindowsID)
$AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
If ($MyWindowsPrincipal.IsInRole($AdminRole)) {
    $Host.UI.RawUI.WindowTitle = $MyInvocation.MyCommand.Definition + "(Elevated)"
    $Host.UI.RawUI.BackgroundColor = "Black"
    Clear-Host
}
Else {
    $NewProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell";
    $NewProcess.Arguments = $MyInvocation.MyCommand.Definition;
    $NewProcess.Verb = "runas";
    [System.Diagnostics.Process]::Start($NewProcess);
    Trap {continue}
    Exit
}

# Get script path & folder path
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptDir = Split-Path -Path $ScriptPath

# Get user desktop & documents folder paths
$DesktopDir = Join-Path -Path $env:USERPROFILE -ChildPath "Desktop"
$DocumentsDir = Join-Path -Path $env:USERPROFILE -ChildPath "Documents"

# Text file export style - List/Table
$TextStyle = "Table"

# Title message colour
$TitleColour = "Cyan"

# Highlight colour
$HighlightColour = "Green"

# Result view text lookup
$ResultViewLookup = @{
    'C' = 'Chronological view'
    'S' = 'Summarised view'
}

###############################################################
# Please dont amend the below global settings manually unless #
# necessary - they are set from within the script itself      #
###############################################################

# Export folder global setting
$ExportDir = 'D:\Test'

# Result view global setting
$ResultView = 'S'

###############################################################

# Change export dir to script dir on execution if current one does not exist
If (!(Test-Path -Path $ExportDir -PathType Container)) {$ExportDir = $ScriptDir}

# Help text
$HelpText = @"
------------
Introduction
------------

This script has been designed as an interactive command line tool for use in an Active Directory domain environment.
It can be used to search Windows Event security logs for credential validation and logon events, by username or 
hostname, to find & summarise typical domain account activity. It has been designed as a simple tool of convenience
and should not be used where intensive forensic auditing/examination is required.

------------------------
Group Policy Information
------------------------

Two Group Policy options will need to be enabled in order for both searches to work, 
both of which can be found at the following location:

[Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Audit Policy]

Audit account logon events:

Required for the username search, both success & failure attempts need to be audited. This policy should be applied 
to all domain controllers and will create events for credential validation attempts of domain accounts only.

Enabling this policy will write the following events to the security log of a domain controller:
- ID 4768: A Kerberos authentication ticket (TGT) was requested
- ID 4769: A Kerberos service ticket was requested
- ID 4770: A Kerberos service ticket was renewed
- ID 4771: Kerberos pre-authentication failed
- ID 4774: An account was mapped for logon
- ID 4776: The domain controller attempted to validate the credentials for an account

Audit logon events:

Required for the computer search, both success & failure attempts need to be audited. This policy should be applied 
to all domain computers (or just the computers you want to be able to audit) and will create events for logon 
attempts of either local or domain accounts. 

Enabling this policy will write the following events to the security log of the local computer:
- ID 4624: An account was successfully logged on
- ID 4625: An account failed to log on
- ID 4648: A logon was attempted using explicit credentials
- ID 4634: An account was logged off
- ID 4647: User initiated logoff
- ID 4672: Special privileges assigned to new logon
- ID 4778: A session was reconnected to a Window Station

------------------
Search Information
------------------

There are two types of searches both of which are further subdivided between successful/unsuccessful:

---------------
Username Search
---------------

Option 1 - Successful credential validation

Searches all Domain Controllers for events with ID 4768 (generated when a Kerberos TGT is requested) which include
the keyword 'Audit Success'. Extracts the IP Address logged in each event and returns this with the DNS entry of 
the address if one can be found. Use this search to determine where a domain account has recently been used to 
log in successfully.

***IMPORTANT*** - Certain types of software (such as inventory or monitoring software) that require the use of a 
domain account can log many of these credential validation attempts in a short period of time. Searching for 
accounts used by this type of software may find a greater number of events, requiring much longer to retrieve and 
filter them (for example the built-in Domain Admin account).

Option 2 - Failed credential validation

Searches all Domain Controllers for events with ID 4768 (generated when a Kerberos TGT is requested) and ID 4771 
(generated when the KDC fails to issue a Kerberos TGT) which include the keyword 'Audit Failure'. Extracts the IP 
Address logged in each event and returns this with the DNS entry of the address if one exists, as well as the 
reason for the failure. Use this search to determine where a domain account has recently attempted to log in but 
failed to do so.

---------------
Computer Search
---------------

Option 1 - Successful logon

Searches the security log on the destination PC for events with ID 4624 (generated when a logon session is created)
on Windows Vista/Server 2008 or higher. Searches for event ID 528 & 540 on Windows XP/Server 2003. Extracts the 
username logged in each event and returns this along with Logon Type. Use this search to determine which local and
domain accounts have recently logged in successfully to the specified Computer.

***IMPORTANT*** - Computers sharing network resources with a high number of users (e.g. File Servers) can log 
thousands of these events in a couple of hours, potentially needing a lot more time to retrieve & filter them.

Option 2 - Failed logon attempt

Searches the security log on the destination PC for events with ID 4625 (generated when a logon is attempted but 
fails) on Windows Vista/Server 2008 or higher. Searches for event ID 529-537 & 539 on Windows XP/Server 2003. Extracts
the username logged in each event and returns this along with Logon Type & reason for the failure. Use this search to
determine which local and domain accounts have recently attempted but failed to login to the specified Computer.

A note about OS Versions:

Significant changes were made to the event IDs and event message format following Windows XP/2003. In order to
determine the correct method to search the security log on the target PC, WMI is used to find the OS Version. 
If this fails for whatever reason, the search will default to the method used for Windows Vista & later versions.

------------------
Result Information
------------------

Results for all searches can be displayed as one of two types:

Summarised view:

Displays results as a unique summary (i.e. eliminates duplicates) of all events found in the search, sorted in either
alphabetical or ascending order. Does not retrieve the time events were created. This is the default.

Chronological view:

Displays results as a collection of all events found, sorted in chronological order of their creation. If a high 
number of events are found it is likely this will create more output than space available in the Console.

-------------------------
Issues/Requirements/Other
-------------------------

- DC(s) for username search must be Server 2008 or higher
- PC(s) for computer search must be Windows 2000 or higher
- Requires at least Powershell v3 on the computer the script is run from
- Prompts for elevation - Some situations may not work without admin access (e.g. search against local PC)
- Uses several .NET static methods to retrieve AD info. and perform DNS lookups (faster than AD modules)
- Uses WMI to determine OS Version in computer search as pre-Vista security events were logged very differently.
  If WMI fails you can still continue which defaults to the method used for Vista & later.
- Manual filters in computer search will stop certain events being added to results. This is mainly to eliminate
  machine accounts, service accounts or events with empty results (change if needed).
- DNS lookups are done in real time on username search (i.e. on script execution) but the IP Address in the event
  message may have been reassigned via DHCP since event was logged - possibility the lookup could be inaccurate.
- If the script wont return a result against the local PC using the hostname please also try the IP Address
- There is a temptation to increase the security log size in order to cover a greater time period of events 
  logged. Bear in mind this is a balancing act, as increasing the log size will cause the searches to take longer.

-------------
Author's Note
-------------

There are quite a number of factors involved in this script meaning search times can vary dramatically. The vast 
majority of searches will be unlikely to need more than a few minutes to complete, but certain conditions may cause
the search parameters to find a lot of events (over 100,000) and in these situations the entire search/filtering 
process could take more than 30 minutes to finish. The only times I personally saw this was computers sharing network
resources with a large number of users (e.g. File Servers) or where a domain account was used a lot in specific types
of software (the built in Domain Admin account being used for inventory/monitoring software etc). Other factors can 
also potentially have an effect (e.g. log sizes, bandwidth, HDD speed, resource availability).
"@ -split "`n" | ForEach {$_.TrimEnd()}

# Check computer is domain joined
If ((Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain -eq $True) {

    # Check PS version is greater than 2
    If ($PSVersionTable["PSVersion"].Major -gt 2) {

        Write-Host -Object "Retrieving Active Directory information, one moment..."

        # Get all domain controllers, resolve and store
        $DCList = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers.Name
        $DCAddresses = @()
        $DCTable = @{}
        ForEach ($Server in $DCList) {
            $TempAddress = [System.Net.DNS]::GetHostAddresses("$Server").IPAddressToString
            $DCAddresses += $TempAddress
            $DCTable.Add("$Server","$TempAddress")
        }

        # Get all usernames in directory
        $UserSearch = New-Object System.DirectoryServices.DirectorySearcher([adsi]'')
        $UserSearch.Filter = '(&(objectCategory=Person)(objectClass=User))'
        $UserSearch.FindAll().GetEnumerator() | ForEach-Object {
        $UserList += $_.Properties.samaccountname}
        $FinalUserList = $UserList | Sort-Object -Unique

        # Get all computers in directory
        $PCSearch = New-Object System.DirectoryServices.DirectorySearcher([adsi]'')
        $PCSearch.Filter = '(&(objectCategory=Computer)(objectClass=Computer))'
        $PCSearch.FindAll().GetEnumerator() | ForEach-Object {
        $PCList += $_.Properties.name}
        $FinalPCList = $PCList | Sort-Object -Unique

        # List of variables to clear at end (to free memory)
        $Variables = @(
            "Events"
            "FinalResult"
            "Result"
            "OldestEvent"
            "ScriptContent"
        )

        # Hash tables for logon & kerberos code lookups
        $LogonResultCode = @{
            "0xC0000064" = "Username does not exist"
            "0xC000006A" = "Bad password"
            "0xC0000234" = "User account locked"
            "0xC0000072" = "User account disabled"
            "0xC000006F" = "Invalid logon hours"
            "0xC0000070" = "Workstation restriction"
            "0xC0000193" = "User account expired"
            "0xC0000071" = "Password expired"
            "0xC0000133" = "Clock out of sync with DC"
            "0xC0000224" = "Password change required"
            "0xC0000225" = "Weird Windows bug (good luck)"
            "0xc000015b" = "User not granted requested logon right"
        }

        $LogonResultCodeXP = @{
            "529" = "Unknown username/Bad password"
            "530" = "Invalid logon hours"
            "531" = "User account disabled"
            "532" = "User account expired"
            "533" = "User unauthorised to logon at this computer"
            "534" = "User not granted requested logon right"
            "535" = "Password expired"
            "536" = "Netlogon component inactive"
            "537" = "Other reason (possibly clock out of sync)"
            "539" = "User account locked"
        }

        $KerberosResultCode = @{
            "0x6" = "Client not found in Kerberos DB"
            "0x7" = "Server not found in Kerberos DB"
            "0x9" = "Client/Server has null key - Reset PW"
            "0xC" = "Workstation restriction"
            "0x12" = "Account disabled/expired/locked or invalid hours"
            "0x17" = "Password expired"
            "0x18" = "Bad password"
            "0x20" = "Kerberos Ticket expired"
            "0x25" = "Clock out of sync with DC"
            "0x26" = "Incorrect net address"
            "0x2E" = "Mutual authentication failed"
        }

        $LogonTypeTable = @{
            "2" = "Interactive"
            "3" = "Network"
            "4" = "Batch"
            "5" = "Service"
            "7" = "Unlock"
            "8" = "NetworkClearText"
            "9" = "NewCredentials"
            "10" = "RemoteInteractive"
            "11" = "CachedInteractive"
        }

        # Introduction/Description
        Clear-Host
        Write-Host -Object "Please note this script requires two group policy security audit options to be enabled" -ForegroundColor Yellow
        Write-Host -Object "in order to work. For further details please consult the help information." -ForegroundColor Yellow

        # Start of main script loop
        While ('NO','N' -notcontains $ExitPrompt) {

            # Main menu & search type choice
            $SearchChoice = $Null
            While ('1','2' -notcontains $SearchChoice) {
                Write-Host
                Write-Host -Object "---------" -ForegroundColor $TitleColour
                Write-Host -Object "Main Menu" -ForegroundColor $TitleColour
                Write-Host -Object "---------" -ForegroundColor $TitleColour
                Write-Host
                Write-Host -Object "Results are currently set to: " -NoNewline
                Write-Host -Object "[$($ResultViewLookup["$ResultView"])]" -ForegroundColor $HighlightColour
                Write-Host
                Write-Host -Object "Export folder: " -NoNewline
                Write-Host -Object "[$ExportDir]" -ForegroundColor $HighlightColour
                Write-Host
                Write-Host -Object "Please choose from the following options:"
                Write-Host
                Write-Host -Object "1) Search by Username (search DC for credential validation)"
                Write-Host -Object "2) Search by Computer (search specific PC for logon events)"
                Write-Host -Object "3) Change result view"
                Write-Host -Object "4) Change export folder"
                Write-Host -Object "5) View help information"
                Write-Host -Object "Q) " -NoNewline
                Write-Host -Object "Quit" -ForegroundColor $TitleColour
                Write-Host

                $SearchChoice = $Null
                While ('1','2','3','4','5','Q' -notcontains $SearchChoice) {$SearchChoice = (Read-Host -Prompt "Please enter your choice").ToUpper()}

                # Settings & help text
                If ('3','4','5','Q' -contains $SearchChoice) {
                    Switch ($SearchChoice) {
                        # Change view setting
                        '3' {
                            Write-Host
                            Write-Host -Object "-------------" -ForegroundColor $TitleColour
                            Write-Host -Object "View Settings" -ForegroundColor $TitleColour
                            Write-Host -Object "-------------" -ForegroundColor $TitleColour
                            Write-Host
                            Write-Host -Object "Results for all searches can be displayed as one of two types:"
                            Write-Host
                            Write-Host -Object "[S]ummarised view:" -ForegroundColor $TitleColour
                            Write-Host -Object "Displays results as a unique summary (eliminates duplicates) of all events."
                            Write-Host
                            Write-Host -Object "[C]hronological view:" -ForegroundColor $TitleColour
                            Write-Host -Object "Displays results as a collection of all events found, sorted in chronological"
                            Write-Host -Object "order of their creation."
                            Write-Host

                            # Prompt for new result view setting
                            $ResultView = $Null
                            While ('C','S' -notcontains $ResultView) {$ResultView = (Read-Host -Prompt "Please choose a view setting (C/S)").ToUpper()}

                            # Only attempt stateful setting change when running from an actual console and not ISE
                            If ((Get-Host).Name -eq "ConsoleHost") {
                                Try {
                                    # Attempt to change global view setting permanently by amending script
                                    $ScriptContent = Get-Content -Path $ScriptPath
                                    $InitialData = $ScriptContent | Select-String -Pattern '^\$ResultView = ' | Select-Object -Property @{N="LineIndex";E={$_.LineNumber - 1}},@{N="Value";E={($_.ToString() -split " = ")[1]}} -First 1
                                    $ScriptContent[$InitialData.LineIndex] = $ScriptContent[$InitialData.LineIndex] -replace "ResultView = $($InitialData.Value)","ResultView = '$ResultView'"
                                    Set-Content -Path $ScriptPath -Value $ScriptContent
                                }
                                Catch {
                                    # Error when attempting to save setting
                                    Write-Host
                                    Write-Warning -Message "One or more errors occured when trying to save settings permanently. The latest error in the stream is:"
                                    Write-Host
                                    Write-Output -InputObject $Error[0].Exception
                                }
                            }
                            Else {
                                # Not running script from actual PowerShell console (e.g. ISE)
                                Write-Host
                                Write-Warning -Message "Setting has only been changed temporarily - to save settings permanently please run this script from an actual PowerShell console (i.e. not ISE)"
                            }
                        }
                        # Change export dir
                        '4' {
                            Write-Host
                            Write-Host -Object "-------------" -ForegroundColor $TitleColour
                            Write-Host -Object "Export Folder" -ForegroundColor $TitleColour
                            Write-Host -Object "-------------" -ForegroundColor $TitleColour
                            Write-Host
                            Write-Host -Object "The following options are available:"
                            Write-Host
                            Write-Host -Object "1) Script Folder"
                            Write-Host -Object "2) Documents Folder"
                            Write-Host -Object "3) Desktop"
                            Write-Host -Object "4) Manual Path"
                            Write-Host -Object "Q) " -NoNewline
                            Write-Host -Object "Return to Main Menu" -ForegroundColor $TitleColour
                            Write-Host

                            # Prompt for new export folder setting
                            $ExportFolderChoice = $Null
                            While ('1','2','3','4','Q' -notcontains $ExportFolderChoice) {$ExportFolderChoice = Read-Host -Prompt "Please enter your choice"}


                            If ($ExportFolderChoice -ne 'Q') {

                                Switch ($ExportFolderChoice) {
                                    '1' {$ExportDir = $ScriptDir}
                                    '2' {$ExportDir = $DocumentsDir}
                                    '3' {$ExportDir = $DesktopDir}
                                    '4' {
                                        Write-Host
                                        Write-Host -Object "Please provide a new export folder path"
                                        Write-Host
                                        Do {
                                            $ValidDir = $False
                                            $ExportDir = $Null
                                            While ([string]::IsNullOrEmpty($ExportDir) -or ($ExportDir -match "^(\s+.+|\s+|.+\s+)$")) {
                                                $ExportDir = Read-Host -Prompt "New path"
                                                If ($ExportDir -match "^(\s+.+|\s+|.+\s+)$") {
                                                    Write-Host
                                                    Write-Warning -Message "Path cannot start/end with or contain only spaces"
                                                    Write-Host
                                                }
                                                ElseIf ([string]::IsNullOrEmpty($ExportDir)) {
                                                    Write-Host
                                                    Write-Warning -Message "Please provide a value"
                                                    Write-Host
                                                }
                                            }
                                            Try {
                                                $ValidDir = Test-Path -Path $ExportDir -PathType Container
                                                If (!$ValidDir) {
                                                    Write-Host
                                                    Write-Warning -Message "The supplied path is invalid or does not currently exist"
                                                    Write-Host
                                                }
                                            }
                                            Catch {
                                                Write-Host
                                                Write-Warning -Message "The supplied path is invalid"
                                                Write-Host
                                            }
                                        } Until ($ValidDir)
                                    }
                                }

                                # Only attempt stateful setting change when running from an actual console and not ISE
                                If ((Get-Host).Name -eq "ConsoleHost") {
                                    Try {
                                        # Attempt to change global export folder setting permanently by amending script using flaky regex
                                        $ScriptContent = Get-Content -Path $ScriptPath
                                        $InitialData = $ScriptContent | Select-String -Pattern '^\$ExportDir = ' | Select-Object -Property @{N="LineIndex";E={$_.LineNumber - 1}},@{N="Value";E={($_.ToString() -split " = ")[1] -replace "'" -replace "\\","\\"}} -First 1
                                        If ($InitialData.Value -match "^\$") {$ScriptContent[$InitialData.LineIndex] = $ScriptContent[$InitialData.LineIndex] -replace "\$($InitialData.Value)","'$ExportDir'"}
                                        Else {$ScriptContent[$InitialData.LineIndex] = $ScriptContent[$InitialData.LineIndex] -replace "$($InitialData.Value)","$ExportDir"}
                                        Set-Content -Path $ScriptPath -Value $ScriptContent
                                    }
                                    Catch {
                                        # Error when attempting to save setting
                                        Write-Host
                                        Write-Warning -Message "One or more errors occured when trying to save settings permanently. The latest error in the stream is:"
                                        Write-Host
                                        Write-Output -InputObject $Error[0].Exception
                                    }
                                }
                                Else {
                                    # Not running script from actual PowerShell console (e.g. ISE)
                                    Write-Host
                                    Write-Warning -Message "Setting has only been changed temporarily - to save settings permanently please run this script from an actual PowerShell console (i.e. not ISE)"
                                }
                            }
                        }
                        # Show help text
                        '5' {
                            Write-Host
                            Out-Host -InputObject $HelpText -Paging
                            Trap {continue}
                        }
                        # Quit
                        'Q' {exit}
                    }
                }
            }

            # Flag to track if a search has been initiated
            $SearchInitiated = $False

            # Perform search
            Switch ($SearchChoice) {
                # Start of Username search
                1 {
                    # Prompt for Username
                    Write-Host
                    $Username = $Null
                    While ([string]::IsNullOrEmpty($Username)) {$Username = (Read-Host -Prompt "Please enter an Active Directory username").ToLower()}

                    # Check Username
                    $UsernameChoice = $Null
                    While (($FinalUserList -notcontains $Username) -and ('1','4' -notcontains $UsernameChoice)) {
                        Write-Host
                        Write-Warning -Message "The account [$Username] does not appear to exist in Active Directory."
                        Write-Host
                        Write-Host -Object "What would you like to do?"
                        Write-Host
                        Write-Host -Object "1) Continue anyway"
                        Write-Host -Object "2) Change username"
                        Write-Host -Object "3) List usernames found in Directory"
                        Write-Host -Object "4) Quit"
                        Write-Host 

                        # Prompt for choice if username not found in AD
                        $UsernameChoice = $Null
                        While ('1','2','3','4' -notcontains $UsernameChoice) {$UsernameChoice = (Read-Host -Prompt "Please enter the number for your choice").ToUpper()}
                        Switch ($UsernameChoice) {
                            2 {
                                Write-Host
                                $Username = $Null
                                While ([string]::IsNullOrEmpty($Username)) {$Username = (Read-Host -Prompt "Please enter an Active Directory username").ToLower()}
                            }
                            3 {
                                Write-Host
                                Out-Host -InputObject $FinalUserList -Paging
                                Trap {continue}
                            }
                        }
                    }

                    # Go to exit prompt if option 4
                    If ($UsernameChoice -ne '4') {

                        Write-Host
                        Write-Host -Object "-----------" -ForegroundColor $TitleColour
                        Write-Host -Object "Search Type" -ForegroundColor $TitleColour
                        Write-Host -Object "-----------" -ForegroundColor $TitleColour
                        Write-Host
                        Write-Host -Object "1) Successful credential validation"
                        Write-Host -Object "2) Failed credential validation"
                        Write-Host

                        # Username search choice
                        $UserSearchChoice = $Null
                        While ('1','2' -notcontains $UserSearchChoice) {$UserSearchChoice = (Read-Host -Prompt "Please enter the number for your choice").ToUpper()}

                        Write-Host
                        Write-Host -Object "A search will now be initiated for the account " -NoNewline
                        Write-Host -Object "[$Username]" -ForegroundColor $HighlightColour
                        Write-Host -Object "across the following Domain Controllers:"
                        Write-Host
                        Write-Output -InputObject $DCList
                        Write-Host

                        # Confirmation prompt
                        $Confirm = $Null
                        While ('Y','N','YES','NO' -notcontains $Confirm) {$Confirm = (Read-Host -Prompt "Do you want to continue?(Y/N)").ToUpper()}

                        If ('Y','YES' -contains $Confirm) {

                            Write-Host
                            Write-Host -Object "Collecting and filtering events - be patient as this may take a long time"
                            Write-Host -Object "Please note if a large number of events are found (e.g. 10,000+) the"
                            Write-Host -Object "script can appear to hang whilst it retrieves all of them."
                            Write-Host

                            # Set flag
                            $SearchInitiated = $True

                            # Get search start time
                            $TimeStart = Get-Date

                            # Counter for total no. of events
                            $TotalCount = 0

                            # Declare some empty arrays
                            $Result,$EarliestEventTable,$OldestEventTable,$InvalidDNS = @(),@(),@(),@()

                            # Declare empty hash table to store successful reverse DNS lookups
                            $DNSReverseLookup = @{}

                            # Select XML query filter (success/failure) and string based on search choice
                            Switch ($UserSearchChoice) {
                                1 {
                                    $UserSearchStr = "Success"
                                    $XMLFilter = "<QueryList><Query><Select Path='Security'>*[System[band(Keywords,9007199254740992) and (EventID=4768)] and EventData[Data[@Name='TargetUserName']='$Username'] and EventData[Data[@Name='IpAddress']!='-']]</Select></Query></QueryList>"
                                }
                                2 {
                                    $UserSearchStr = "Failed"
                                    $XMLFilter = "<QueryList><Query><Select Path='Security'>*[System[band(Keywords,4503599627370496) and (EventID=4768 or EventID=4771)] and EventData[Data[@Name='TargetUserName']='$Username'] and EventData[Data[@Name='IpAddress']!='-']]</Select></Query></QueryList>"
                                }
                            }

                            # Loop through DCs querying each one for relevant security log events
                            ForEach ($DC in $DCList) {
                                # Reset event counter
                                $EventCounter = 0

                                # Get security events from DC using XML filter
                                Write-Host -Object "Checking for events on $DC..." -NoNewline
                                $Events = Get-WinEvent -FilterXml $XMLFilter -ComputerName "$DC" -ErrorAction SilentlyContinue
                                $TotalCount += $Events.Count
                                If ($Events.Count -gt 0) {
                                    $CountColour = "Green"
                                    If ($Event.Count -eq 1) {$EventStr = "event"}
                                    Else {$EventStr = "events"}
                                }
                                Else {
                                    $CountColour = "Red"
                                    $EventStr = "events"
                                }
                                Write-Host -Object "$($Events.Count) $EventStr found" -ForegroundColor $CountColour

                                # Get earliest event time from any retrieved and oldest in DC security log
                                $EarliestEventTable += ($Events.TimeCreated | Measure -Minimum).Minimum
                                $OldestEvent = (Get-WinEvent -LogName Security -ComputerName "$DC" -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue).TimeCreated
                                If ($OldestEvent.Count -gt 0) {
                                    $OldEvObj = New-Object PsObject
                                    $OldEvObj | Add-Member -MemberType NoteProperty -Name "DC" -Value $DC
                                    $OldEvObj | Add-Member -MemberType NoteProperty -Name "Time" -Value $OldestEvent
                                    $OldestEventTable += $OldEvObj
                                }

                                # Loop through events
                                ForEach ($WinEvent in $Events) {
                                    # Increment event counter for progress bar
                                    $EventCounter++
                        
                                    # Get IP address from message
                                    $IPAddress = (($WinEvent.Message -split '\r\n' | Select-String -Pattern 'Client Address:' -Context 0) -replace 'Client Address:','').Trim() -replace '^::ffff:',''

                                    # Get event time if chronological view selected
                                    Switch ($ResultView) {
                                        'S' {$EventTime = 'N/A'}
                                        'C' {$EventTime = $WinEvent.TimeCreated}
                                    }

                                    # Null DNS/reason in case we do not want to include the event in the results
                                    $DNSEntry,$FailureReason = $Null,$Null

                                    # We omit events where the client IP address is that of another DC. This is because the event data is not truly replicated amongst
                                    # DCs and only the logon server shows the actual client IP address, other DCs will show the IP address of the logon server
                                    If ($DCAddresses -notcontains $IPAddress) {
                            
                                        # Get the actual DC IP address if a local IPv4/IPv6 address
                                        If ('::1','127.0.0.1' -contains $IPAddress) {$IPAddress = $DCTable[$DC]}

                                        # Lookup failure reasons if applicable
                                        Switch ($UserSearchChoice) {
                                            1 {$FailureReason = 'N/A'}
                                            2 {
                                                Switch ($WinEvent.Id) {
                                                    4768 {$ResultString = 'Result Code:'}
                                                    4771 {$ResultString = 'Failure Code:'}
                                                }
                                                $ResultCode = (($WinEvent.Message -split '\r\n' | Select-String -Pattern $ResultString -Context 0) -replace $ResultString).Trim()
                                                $FailureReason = $KerberosResultCode[$ResultCode]
                                            }
                                        }

                                        # Check IP address exists
                                        If ($IPAddress.Count -gt 0) {

                                            # Get DNS entry from hash table if we have already successfully retrieved one for current IP address
                                            If ($DNSReverseLookup.ContainsKey($IPAddress)) {$DNSEntry = $DNSReverseLookup[$IPAddress]}
                                            # IP address has already failed on reverse lookup so assign no entry message for variable
                                            ElseIf ($InvalidDNS -contains $IPAddress) {$DNSEntry = 'NO ENTRY FOUND'}
                                            # Attempt a reverse DNS lookup if current IP address is unknown/not in invalid array
                                            Else {
                                                $Error.Clear()
                                                $DNSEntry = [System.Net.DNS]::GetHostEntry("$IPAddress").HostName
                                                Trap {continue}
                                                # Reverse lookup failed so assign no entry message and add to invalid array
                                                If ($Error.Count -gt 0) {
                                                    $DNSEntry = 'NO ENTRY FOUND'
                                                    $InvalidDNS += $IPAddress
                                                }
                                                # Reverse lookup was successful so store in hash table for further lookups
                                                Else {$DNSReverseLookup[$IPAddress] = $DNSEntry}
                                            }

                                            # Create new object and add to result array
                                            $Object = New-Object PsObject
                                            $Object | Add-Member -MemberType NoteProperty -Name "Username" -Value $Username
                                            $Object | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $IPAddress
                                            $Object | Add-Member -MemberType NoteProperty -Name "DNS Entry" -Value $DNSEntry
                                            $Object | Add-Member -MemberType NoteProperty -Name "Authorisation" -Value $UserSearchStr
                                            $Object | Add-Member -MemberType NoteProperty -Name "Failure Reason" -Value $FailureReason
                                            $Object | Add-Member -MemberType NoteProperty -Name "Logon Server" -Value $DC
                                            $Object | Add-Member -MemberType NoteProperty -Name "Time Created" -Value $EventTime
                                            $Result += $Object
                                        }
                                    }
                                    Write-Progress -Activity "Filtering events from [$DC] for [$Username]" -Status "Event $EventCounter of $($Events.Count)" -PercentComplete ($EventCounter/$Events.Count*100) -ErrorAction SilentlyContinue
                                }
                                Write-Progress -Activity "Filtering events from [$DC] for [$Username]" -Status "Event $EventCounter of $($Events.Count)" -Completed -ErrorAction SilentlyContinue
                            }
                            $EarliestEvent = ($EarliestEventTable | Measure -Minimum).Minimum
                        }
                        Else {Write-Host}
                    }
                    Else {Write-Host}
                } # End of Username search
                # Start of PC search
                2 {
                    # Prompt for PC name
                    Write-Host
                    $PCName = $Null
                    While ([string]::IsNullOrEmpty($PCName)) {$PCName = (Read-Host -Prompt "Please enter a PC Name or IP Address").ToUpper()}

                    # Check connection
                    Write-Host
                    Write-Host -Object "Testing connection to [$PCName]..." -NoNewline
                    $ConnectionOK = Test-Connection -ComputerName $PCName -Quiet -ErrorAction SilentlyContinue
                    If (!$ConnectionOK) {Write-Host -Object "FAILED!" -ForegroundColor Red}

                    $PCNameChoice = $Null
                    While (!$ConnectionOK -and ('1','4' -notcontains $PCNameChoice)) {
                        Write-Host
                        Write-Warning -Message "The PC [$PCName] is either not online or not configured to respond to ICMP."
                        Write-Host
                        Write-Host -Object "What would you like to do?"
                        Write-Host
                        Write-Host -Object "1) Continue anyway"
                        Write-Host -Object "2) Change PC Name/IP Address"
                        Write-Host -Object "3) List Computers found in Directory"
                        Write-Host -Object "4) Quit"
                        Write-Host

                        # Prompt for choice if unable to ping PC
                        $PCNameChoice = $Null
                        While ('1','2','3','4' -notcontains $PCNameChoice) {$PCNameChoice = (Read-Host -Prompt "Please enter the number for your choice").ToUpper()}
                        Switch ($PCNameChoice) {
                            2 {
                                Write-Host
                                $PCName = $Null
                                While ([string]::IsNullOrEmpty($PCName)) {$PCName = (Read-Host -Prompt "Please enter a PC Name or IP Address").ToUpper()}
                                Write-Host
                                Write-Host -Object "Testing connection to [$PCName]..." -NoNewline
                                $ConnectionOK = Test-Connection -ComputerName $PCName -Quiet -ErrorAction SilentlyContinue
                                If (!$ConnectionOK) {Write-Host -Object "FAILED!" -ForegroundColor Red}
                            }
                            3 {
                                Write-Host
                                Out-Host -InputObject $FinalPCList -Paging -ErrorAction SilentlyContinue
                                Trap {continue}
                            }
                        }
                    }

                    If ($ConnectionOK) {Write-Host -Object "OK!" -ForegroundColor $HighlightColour}

                    # Go to exit prompt if option 4
                    If ($PCNameChoice -ne '4') {

                        Write-Host
                        Write-Host -Object "-----------" -ForegroundColor $TitleColour
                        Write-Host -Object "Search Type" -ForegroundColor $TitleColour
                        Write-Host -Object "-----------" -ForegroundColor $TitleColour
                        Write-Host
                        Write-Host -Object "1) Successful logon"
                        Write-Host -Object "2) Failed logon attempt"
                        Write-Host

                        # PC search choice
                        $PCSearchChoice = $Null
                        While ('1','2' -notcontains $PCSearchChoice) {$PCSearchChoice = (Read-Host -Prompt "Please enter the number for your choice").ToUpper()}

                        # Check OS version using Wmi
                        Write-Host
                        Write-Host -Object "Checking OS Version..." -NoNewline
                        $Error.Clear()
                        $OSInfo = Get-WmiObject -Class Win32_OperatingSystem -ComputerName "$PCName" -ErrorAction SilentlyContinue
                        If ($Error.Count -gt 0) {
                            Write-Host -Object "FAILED!" -ForegroundColor Red
                            Write-Host
                            Write-Warning -Message "The specified entry [$PCName] is either not a Windows computer or an error occured when attempting to connect to WMI."
                            Write-Host
                            $Confirm = $Null
                            While ('Y','N','YES','NO' -notcontains $Confirm) {$Confirm = (Read-Host -Prompt "Do you want to continue anyway?(Y/N)").ToUpper()}
                        }
                        Else {
                            Write-Host -Object "$($OSInfo.Caption.Trim()) [$($OSInfo.Version)]" -ForegroundColor $HighlightColour
                            $Confirm = "Y"
                        }

                        # Go to exit prompt if error and 'N' selected
                        If ('Y','YES' -contains $Confirm) {

                            # Flag for operating system supported
                            $SupportedOS = $True

                            # Switch method, event ID, strings & context by search choice & OS
                            Switch ($PCSearchChoice) {
                                1 {
                                    $EntryType = 'SuccessAudit'
                                    If ($OSInfo.Version -match "^5") {
                                        $InstanceId = 528,540
                                        $ContextString = '^Successful'
                                        $Context = 0,8
                                        $UsernameString = 'User Name:'
                                        $DomainString = 'Domain:'
                                        $Method = 2
                                    }
                                    ElseIf (($OSInfo.Version -match "^(4|3|2|1)") -and ($OSInfo.Version -notmatch "^10")) {
                                        Write-Host
                                        Write-Warning -Message "$($OSInfo.Caption.Trim()) [$($OSInfo.Version)] is not a supported operating system"
                                        $SupportedOS = $False
                                    }
                                    Else {
                                        $InstanceId = 4624
                                        $ContextString = 'Logon Type:'
                                        $Context = 0,10
                                        $UsernameString = 'Account Name:'
                                        $DomainString = 'Account Domain:'
                                        $Method = 2
                                    }
                                }
                                2 {
                                    $EntryType = 'FailureAudit'
                                    If ($OSInfo.Version -match "^5") {
                                        $InstanceId = 529,530,531,532,533,534,535,536,537,539
                                        $ContextString = 'Reason:'
                                        $Context = 0,6
                                        $UsernameString = 'User Name:'
                                        $DomainString = 'Domain:'
                                        $ReasonString = 'Reason:'
                                        $Method = 2
                                    }
                                    ElseIf (($OSInfo.Version -match "^(4|3|2|1)") -and ($OSInfo.Version -notmatch "^10")) {
                                        Write-Host
                                        Write-Warning -Message "$($OSInfo.Caption.Trim()) [$($OSInfo.Version)] is not a supported operating system"
                                        $SupportedOS = $False
                                    }
                                    Else {
                                        $InstanceId = 4625
                                        $ContextString = 'Logon Type:'
                                        $Context = 0,10
                                        $UsernameString = 'Account Name:'
                                        $DomainString = 'Account Domain:'
                                        $ReasonString = 'Failure Reason:'
                                        $Method = 1
                                    }
                                }
                            }

                            # Go to exit prompt if OS not supported
                            If ($SupportedOS) {

                                Write-Host
                                Write-Host -Object "Collecting and filtering events - be patient as this may take a long time"
                                Write-Host -Object "Please note if a large number of events are found (e.g. 10,000+) the"
                                Write-Host -Object "script can appear to hang whilst it retrieves all of them."
                                Write-Host

                                # Set flag
                                $SearchInitiated = $True

                                # Get search start time
                                $TimeStart = Get-Date

                                # Counter for no. of events
                                $EventCounter = 0

                                # Empty array for results
                                $Result = @()

                                # Get security events from PC
                                Write-Host -Object "Checking for events on [$PCName]..." -NoNewline
                                $OldestEvent = (Get-WinEvent -LogName Security -ComputerName "$PCName" -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue).TimeCreated
                                Trap {continue}
                                Switch ($Method) {
                                    1 {
                                        $Events = Get-WinEvent -FilterXml "<QueryList><Query><Select Path='Security'>*[System[band(Keywords,4503599627370496) and (EventID='$InstanceId')]]</Select></Query></QueryList>" -ComputerName "$PCName" -ErrorAction SilentlyContinue
                                        Trap {continue}
                                        $EarliestEvent = ($Events.TimeCreated | Measure -Minimum).Minimum
                                    }
                                    2 {
                                        $Events = Get-EventLog -LogName Security -ComputerName "$PCName" -InstanceId $InstanceId -EntryType $EntryType -ErrorAction SilentlyContinue
                                        Trap {continue}
                                        $EarliestEvent = ($Events.TimeGenerated | Measure -Minimum).Minimum
                                    }
                                }
                                $TotalCount = $Events.Count
                                If ($Events.Count -gt 0) {
                                    $CountColour = "Green"
                                    If ($Event.Count -eq 1) {$EventStr = "event"}
                                    Else {$EventStr = "events"}
                                }
                                Else {
                                    $CountColour = "Red"
                                    $EventStr = "events"
                                }
                                Write-Host -Object "$TotalCount $EventStr found" -ForegroundColor $CountColour

                                # Loop through events retrieved
                                ForEach ($WinEvent in $Events) {
                                    # Increment event counter for progress bar
                                    $EventCounter++
                            
                                    # Split message according to search type and OS
                                    $FilterMessage = $WinEvent.Message -split '\r\n' | Select-String $ContextString -Context $Context

                                    # Get username and user logon domain
                                    $Account = (($FilterMessage -split '\r\n' | Select-String $UsernameString -Context 0) -replace $UsernameString -replace '\$$').Trim()
                                    $Domain = (($FilterMessage -split '\r\n' | Select-String $DomainString -Context 0) -replace $DomainString).Trim()

                                    # Get logon type code and search 
                                    $LogonTypeCode = (($FilterMessage -split '\r\n' | Select-String "Logon Type:" -Context 0) -replace 'Logon Type:' -replace '^>').Trim()
                                    $LogonType = $LogonTypeTable[$LogonTypeCode]

                                    # Get event time if chronological view selected
                                    Switch ($ResultView) {
                                        'S' {$EventTime = 'N/A'}
                                        'C' {
                                            Switch ($Method) {
                                                1 {$EventTime = $WinEvent.TimeCreated}
                                                2 {$EventTime = $WinEvent.TimeGenerated}
                                            }
                                        }
                                    }

                                    # Select failure reason if applicable
                                    Switch ($PCSearchChoice) {
                                        1 {$FailureReason = 'N/A'}
                                        2 {$FailureReason = (($FilterMessage -split '\r\n' | Select-String $ReasonString -Context 0) -replace $ReasonString -replace '^>').Trim()}
                                    }

                                    # Manual filters - remove computer accounts, service accounts etc or where the username/domain/logon type is empty
                                    If (($FinalPCList -notcontains $Account) -and ($Domain,$Account,$LogonType -notcontains '') -and ('-','NT AUTHORITY','Font Driver Host','Window Manager' -notcontains $Domain)) {
                                        $Object = New-Object PsObject
                                        $Object | Add-Member -MemberType NoteProperty -Name "Computer" -Value "$PCName"
                                        $Object | Add-Member -MemberType NoteProperty -Name "Account" -Value "$Domain\$Account"
                                        $Object | Add-Member -MemberType NoteProperty -Name "Logon Type" -Value $LogonType
                                        $Object | Add-Member -MemberType NoteProperty -Name "Failure Reason" -Value $FailureReason
                                        $Object | Add-Member -MemberType NoteProperty -Name "Time Created" -Value $EventTime
                                        $Result += $Object
                                    }
                                    Write-Progress -Activity "Filtering events from [$PCName]" -Status "Event $EventCounter of $($Events.Count)" -PercentComplete ($EventCounter/$Events.Count*100) -ErrorAction SilentlyContinue
                                }
                                Write-Progress -Activity "Filtering events from [$PCName]" -Status "Event $EventCounter of $($Events.Count)" -Completed -ErrorAction SilentlyContinue
                            }
                            Else {Write-Host}
                        }
                        Else {Write-Host}
                    }
                    Else {Write-Host}
                } # End of PC search
            }

            # If no events returned after search was initiated display times of earliest events retrieved
            If ($SearchInitiated -and ($Result.Count -eq 0)) {
                Write-Host
                Write-Warning -Message "No events were found for the specified criteria:"
                Switch ($SearchChoice) {
                    1 {
                        Write-Host
                        Write-Host -Object "Username: " -NoNewline
                        Write-Host -Object "[$Username]" -ForegroundColor $HighlightColour
                        Write-Host -Object "Auth Type: " -NoNewline
                        Switch ($UserSearchChoice) {
                            1 {Write-Host -Object "[Success]" -ForegroundColor $HighlightColour}
                            2 {Write-Host -Object "[Failure]" -ForegroundColor $HighlightColour}
                        }
                        If ($OldestEventTable.Count -gt 0) {
                            Write-Host
                            Write-Host -Object "At time of search the oldest event in the Security logs of each"
                            Write-Host -Object "domain controller were created at the following times:"
                            Write-Output -InputObject $OldestEventTable | FT -AutoSize
                        }
                        Else {Write-Host}
                    }
                    2 {
                        Write-Host
                        Write-Host -Object "IP or PC Name: " -NoNewline
                        Write-Host -Object "[$PCName]" -ForegroundColor $HighlightColour
                        Write-Host -Object "Logon Type: " -NoNewline
                        Switch ($PCSearchChoice) {
                            1 {Write-Host -Object "[Success]" -ForegroundColor $HighlightColour}
                            2 {Write-Host -Object "[Failure]" -ForegroundColor $HighlightColour}
                        }
                        If ($OldestEvent.Count -gt 0) {
                            Write-Host
                            Write-Host -Object "At time of search the oldest event in the Security log of the computer"
                            Write-Host -Object "[$PCName]" -ForegroundColor $HighlightColour -NoNewline
                            Write-Host -Object " was created at $OldestEvent"
                            Write-Host
                        }
                        Else {Write-Host}
                    }
                }
            }
            # Else if events were returned after search was initiated display the results
            ElseIf ($SearchInitiated -and ($Result.Count -gt 0)) {
                # Get search time of start -> finish
                $TimeDiff = (Get-Date) - $TimeStart

                # Determine properties to select and sorting order based on result view and search type
                Switch ($ResultView) {
                    'C' {
                        $FinalResult = $Result | Sort-Object -Property 'Time Created' -Descending
                        Switch ($SearchChoice) {
                            1 {
                                Switch ($UserSearchChoice) {
                                    1 {$DisplayedProperties = 'IP Address','DNS Entry','Time Created','Logon Server'}
                                    2 {$DisplayedProperties = 'IP Address','DNS Entry','Failure Reason','Time Created','Logon Server'}
                                }
                            }
                            2 {
                                Switch ($PCSearchChoice) {
                                    1 {$DisplayedProperties = 'Account','Logon Type','Time Created'}
                                    2 {$DisplayedProperties = 'Account','Logon Type','Failure Reason','Time Created'}
                                }
                            }
                        }
                    }
                    'S' {
                        Switch ($SearchChoice) {
                            1 {
                                $FinalResult = $Result | Select-Object -Property * -Unique | Sort-Object -Property 'IP Address','DNS Entry','Failure Reason','Time Created','Logon Server'
                                Switch ($UserSearchChoice) {
                                    1 {$DisplayedProperties = 'IP Address','DNS Entry','Logon Server'}
                                    2 {$DisplayedProperties = 'IP Address','DNS Entry','Failure Reason','Logon Server'}
                                }
                            }
                            2 {
                                $FinalResult = $Result | Select-Object -Property * -Unique | Sort-Object -Property 'Account','Logon Type','Failure Reason','Time Created'
                                Switch ($PCSearchChoice) {
                                    1 {$DisplayedProperties = 'Account','Logon Type'}
                                    2 {$DisplayedProperties = 'Account','Logon Type','Failure Reason'}
                                }
                            }
                        }
                    }
                }

                # Determine title string based on search type
                Switch ($SearchChoice) {
                    1 {$ResultTitleStr = "$($ResultViewLookup[$ResultView]) of $TotalCount events for the account [$Username]"}
                    2 {$ResultTitleStr = "$($ResultViewLookup[$ResultView]) of $TotalCount events for the computer [$PCName]"}
                }

                # Earliest event string
                $EarliestEventStr = "The earliest event retrieved was created at $EarliestEvent"

                # Search time string
                $SearchTimeStr = "Total Search Time (D:H:M:S) - $($TimeDiff.Days.ToString('00')):$($TimeDiff.Hours.ToString('00')):$($TimeDiff.Minutes.ToString('00')):$($TimeDiff.Seconds.ToString('00'))"

                # Get longest line length and create a hyphen line
                $MultiplyHyphen = ($ResultTitleStr,$EarliestEventStr,$SearchTimeStr | Measure -Property Length -Maximum).Maximum
                $HyphenLine = "-" * $MultiplyHyphen

                # Display results
                Write-Host
                Write-Host -Object $HyphenLine -ForegroundColor $TitleColour
                Write-Host -Object $ResultTitleStr -ForegroundColor $TitleColour
                Write-Host -Object $EarliestEventStr -ForegroundColor $TitleColour
                Write-Host -Object $HyphenLine -ForegroundColor $TitleColour
                Write-Output -InputObject $FinalResult | FT -Property $DisplayedProperties -AutoSize
                Write-Host -Object $HyphenLine -ForegroundColor $TitleColour
                Write-Host -Object $SearchTimeStr -ForegroundColor $TitleColour
                Write-Host -Object $HyphenLine -ForegroundColor $TitleColour
                Write-Host

                # Prompt to export file
                $FileExport = $Null
                While ('YES','Y','NO','N' -notcontains $FileExport) {$FileExport = (Read-Host -Prompt "Do you want to export a file?(Y/N)").ToUpper()}

                # Export file
                If ('YES','Y' -contains $FileExport) {
                    $ExportOK = $False
                    $ExportRetry = "Y"
                    While (!$ExportOK -and ("Y","YES" -contains $ExportRetry)) {
                        # Prompt for format
                        $FileFormat = $Null
                        Write-Host
                        While ('csv','txt' -notcontains $FileFormat) {$FileFormat = (Read-Host -Prompt "Format?(CSV/TXT)").ToLower()}

                        # Determine filename based on search type
                        Switch ($SearchChoice) {
                            1 {
                                Switch ($UserSearchChoice) {
                                    1 {$FileName = $Username.ToUpper() + "_AuthSuccess" + "_$($TimeStart.ToString('yyyy-MM-dd_HH-mm-ss'))" + ".$FileFormat"}
                                    2 {$FileName = $Username.ToUpper() + "_AuthFailure" + "_$($TimeStart.ToString('yyyy-MM-dd_HH-mm-ss'))" + ".$FileFormat"}
                                }
                            }
                            2 {
                                Switch ($PCSearchChoice) {
                                    1 {$FileName = $PCName.ToUpper() + "_LogonSuccess" + "_$($TimeStart.ToString('yyyy-MM-dd_HH-mm-ss'))" + ".$FileFormat"}
                                    2 {$FileName = $PCName.ToUpper() + "_LogonFailure" + "_$($TimeStart.ToString('yyyy-MM-dd_HH-mm-ss'))" + ".$FileFormat"}
                                }
                            }
                        }

                        Write-Host
                        Write-Host -Object "Attempting to export a file..." -NoNewline
                        Start-Sleep -Milliseconds 300

                        # Flag to check file exported
                        $ExportOK = $False

                        # Determine export path
                        $ExportPath = Join-Path -Path $ExportDir -ChildPath $FileName

                        # Attempt to export file to export path
                        Try {
                            Switch ($FileFormat) {
                                'txt' {
                                    If ($TextStyle -eq "Table") {$FinalResult | Format-Table -AutoSize | Out-File -FilePath $ExportPath -Force}
                                    Else {$FinalResult | Out-File -FilePath $ExportPath -Force}
                                }
                                'csv' {$FinalResult | Export-Csv -Path $ExportPath -Force -NoTypeInformation}
                            }
                            $ExportOK = $True
                            Write-Host -Object "OK!" -ForegroundColor $HighlightColour
                            Write-Host
                            Write-Host -Object "Export: " -NoNewline
                            Write-Host -Object "[$ExportPath]" -ForegroundColor $HighlightColour
                        }
                        Catch {
                            Write-Host -Object "FAILED!" -ForegroundColor Red
                            Write-Host
                            Write-Warning -Message "The following error occured whilst trying to export the file:"
                            Write-Host
                            Write-Output -InputObject $Error[0].Exception
                            Write-Host
                            $ExportRetry = $Null
                            While ('YES','Y','NO','N' -notcontains $ExportRetry) {$ExportRetry = (Read-Host -Prompt "Do you want to retry?(Y/N)").ToUpper()}
                        }
                    }
                    Write-Host
                }
                Else {Write-Host}
            }

            # Clear large variables and perform garbage collection to free up memory
            ForEach ($Item in $Variables) {Clear-Variable -Name $Item -ErrorAction SilentlyContinue}
            [System.GC]::Collect()
            Start-Sleep -Milliseconds 300

            # Prompt to exit
            $ExitPrompt = $Null
            While ('YES','Y','NO','N' -notcontains $ExitPrompt) {$ExitPrompt = (Read-Host -Prompt "Do you want to perform another search?(Y/N)").ToUpper()}
        }
    }
    # PS version is 2 or less
    Else {
        $LocalOS = Get-WmiObject -Class Win32_OperatingSystem

        Write-Warning -Message "This script requires at least PowerShell v3 to work correctly"
        Write-Host
        Write-Host -Object "OS Version: " -NoNewline
        Write-Host -Object "$($LocalOS.Caption.Trim()) [$($LocalOS.Version.Trim())]" -ForegroundColor Green
        Write-Host -Object "PS Version: " -NoNewline
        Write-Host -Object "$($PSVersionTable.PSVersion.ToString())" -ForegroundColor Green
        Write-Host

        $UrlRedirect = $Null
        While ("YES","Y","NO","N" -notcontains $UrlRedirect) {$UrlRedirect = (Read-Host -Prompt "Do you want to attempt to open the WMF upgrade webpage?(Y/N)").ToUpper()}

        If ("YES","Y" -contains $UrlRedirect) {Start-Process -FilePath "https://docs.microsoft.com/en-us/powershell/wmf/setup/install-configure"}
        Else {
            Write-Host
            Write-Host -Object "Please upgrade your PS version/WMF before running this script again"
            Write-Host
            Write-Host -Object "Exiting in " -NoNewline
            For ($Inc = 5; $Inc -gt 0; $Inc--) {
                Write-Host -Object "$Inc" -NoNewline -ForegroundColor Cyan
                Write-Host -Object ".." -NoNewline
                Start-Sleep -Seconds 1
            }
        }
    }
}
# Local computer is not domain joined
Else {
    Write-Warning -Message "This script is desgined to be used in an Active Directory Domain environment"
    Write-Host
    Write-Host -Object "Please ensure the local computer is joined to an AD domain then try running this script again"
    Write-Host
    Read-Host -Prompt "Press enter to exit"
}
