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
Write-Host "Retrieving Active Directory information, one moment..."
# Get all domain controllers, resolve and store
$DCList = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers.Name
$DCAddresses = @()
$DCTable = @{}
Foreach ($Server in $DCList) {
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
# List of all variables to clear at end
$Variables = "Account","Breakout","Confirm","ConnectionTest","Context","ContextString","Count","DC","DisplayedProperties","DNSEntry","Domain","DomainString","EarliestEvent","EarliestEventTable","EntryType","EventCounter","Events","EventTime","ExitPrompt","ExportRetry","FailureReason","FileChoice","FileExport","FileFormat","FileName","FilterMessage","FilterResult","FinalResult","InstanceId","IPAddress","LogonType","LogonTypeCode","Object","OldestEvent","OldestEventTable","OSVersion","PCName","PCNameChoice","PCSearchChoice","ReasonString","Result","ResultCode","ResultString","SearchChoice","SearchInitiated","TimeDays","TimeDiff","TimeEnd","TimeHours","TimeMinutes","TimeSeconds","TimeStart","TotalCount","Username","UsernameChoice","UsernameString","UserSearchChoice","WinEvent","XMLFilter"
# Hash tables
$LogonResultCode = @{"0xC0000064" = "Username does not exist";"0xC000006A" = "Bad password";"0xC0000234" = "User account locked";"0xC0000072" = "User account disabled";"0xC000006F" = "Invalid logon hours";"0xC0000070" = "Workstation restriction";"0xC0000193" = "User account expired";"0xC0000071" = "Password expired";"0xC0000133" = "Clock out of sync with DC";"0xC0000224" = "Password change required";"0xC0000225" = "Weird Windows bug (good luck)";"0xc000015b" = "User not granted requested logon right"}
$LogonResultCodeXP = @{"529" = "Unknown username/Bad password";"530" = "Invalid logon hours";"531" = "User account disabled";"532" = "User account expired";"533" = "User unauthorised to logon at this computer";"534" = "User not granted requested logon right";"535" = "Password expired";"536" = "Netlogon component inactive";"537" = "Other reason (possibly clock out of sync)";"539" = "User account locked"}
$KerberosResultCode = @{"0x6" = "Client not found in Kerberos DB";"0x7" = "Server not found in Kerberos DB";"0x9" = "Client/Server has null key - Reset PW";"0xC" = "Workstation restriction";"0x12" = "Account disabled/expired/locked or invalid hours";"0x17" = "Password expired";"0x18" = "Bad password";"0x20" = "Kerberos Ticket expired";"0x25" = "Clock out of sync with DC";"0x26" = "Incorrect net address";"0x2E" = "Mutual authentication failed"}
$LogonTypeTable = @{"2" = "Interactive";"3" = "Network";"4" = "Batch";"5" = "Service";"7" = "Unlock";"8" = "NetworkClearText";"9" = "NewCredentials";"10" = "RemoteInteractive";"11" = "CachedInteractive"}
# Introduction/Description
Clear-Host
Write-Host "Please note this script requires two security audit options to be"
Write-Host "enabled in group policy in order to work. For further information"
Write-Host "please consult the README text file."
$ResultView = 'S'
$ResultViewText = "Summarised view"
# Start of main script loop
While ('No','N' -notcontains $ExitPrompt) {
    Write-Host
    Write-Host "Results are currently set to: $ResultViewText"
    Write-Host
    Write-Host "Please choose from the following options:"
    Write-Host
    Write-Host "1) Search by Username (search DC for credential validation)"
    Write-Host "2) Search by Computer (search specific PC for logon events)"
    Write-Host "3) Change result view"
    Write-Host
    # Search type choice
    While ('1','2','Q' -notcontains $SearchChoice) {
        $SearchChoice = Read-Host "Please enter the number for your choice, or 'Q' to exit"
        If ($SearchChoice -eq '3') {
            Clear-Variable -Name ResultView,SearchChoice
            Write-Host
            Write-Host "Results for all searches can be displayed as one of two types:"
            Write-Host
            Write-Host "Summarised view:"
            Write-Host "Displays results as a unique summary (eliminates duplicates) of all events."
            Write-Host
            Write-Host "Chronological view:"
            Write-Host "Displays results as a collection of all events found, sorted in chronological"
            Write-Host "order of their creation."
            Write-Host
            While ('C','S' -notcontains $ResultView) {
            $ResultView = Read-Host "Please enter 'S' for Summarised or 'C' for Chronological view"}
            Switch ($ResultView) {
            'C' {$ResultViewText = "Chronological view"}
            'S' {$ResultViewText = "Summarised view"}}
            Write-Host
            Write-Host "Results are currently set to: $ResultViewText"
            Write-Host
            Write-Host "Please choose from the following options:"
            Write-Host
            Write-Host "1) Search by Username (search DC for credential validation)"
            Write-Host "2) Search by Computer (search specific PC for logon events)"
            Write-Host "3) Change result view"
            Write-Host
        }
    }
    Switch ($SearchChoice) {
        # Start of Username search
        1 {
            Write-Host
            $Username = ''
            While ($Username -eq [string]::empty) {$Username = Read-Host "Please enter an Active Directory username"}
            # Check Username
            While ($FinalUserList -notcontains $Username) {
                Write-Host
                Write-Host "The account $Username does not appear to exist in Active Directory."
                Write-Host "What would you like to do?"
                Write-Host
                Write-Host "1) Continue anyway"
                Write-Host "2) Change username"
                Write-Host "3) List usernames found in Directory"
                Write-Host "4) Quit"
                Write-Host 
                While ('1','2','3','4' -notcontains $UsernameChoice) {$UsernameChoice = Read-Host "Please enter the number for your choice"}
                Switch ($UsernameChoice) {
                    2 {
                        Write-Host
                        $Username = ''
                        While ($Username -eq [string]::empty) {$Username = Read-Host "Please enter an Active Directory username"}
                    }
                    3 {
                        Write-Host
                        Out-Host -InputObject $FinalUserList -Paging
                        Trap {continue}
                    }
                }
                If ('1','4' -contains $UsernameChoice) {break}
                Clear-Variable -Name UsernameChoice -ErrorAction SilentlyContinue
            }
            If ($UsernameChoice -eq '4') {break} # Break to Exit Prompt
            Write-Host
            Write-Host "The following options are available:"
            Write-Host
            Write-Host "1) Successful credential validation"
            Write-Host "2) Failed credential validation"
            Write-Host
            # Username search choice
            While ('1','2' -notcontains $UserSearchChoice) {$UserSearchChoice = Read-Host "Please enter the number for your choice"}
            Write-Host
            Write-Host "A search will now be initiated for the account $Username across"
            Write-Host "the following Domain Controllers:"
            Write-Host
            $DCList
            Write-Host
            While ('Y','N','Yes','No' -notcontains $Confirm) {$Confirm = Read-Host "Do you want to continue?(Y/N)"}
            If ('N','No' -contains $Confirm) {break} # Break to Exit Prompt
            Write-Host
            Write-Host "Collecting and filtering events - be patient as this may take a long time"
            Write-Host "Please note if a large number of events are found (e.g. 10,000+) the"
            Write-Host "script can appear to hang whilst it retrieves all of them."
            Write-Host
            # Start search & filter
            $SearchInitiated = '1'
            $TimeStart = Get-Date
            $TotalCount = 0
            $Result = @()
            $EarliestEventTable = @()
            $OldestEventTable = @()
            Switch ($UserSearchChoice) {
                1 {$XMLFilter = "<QueryList><Query><Select Path='Security'>*[System[band(Keywords,9007199254740992) and (EventID=4768)] and EventData[Data[@Name='TargetUserName']='$Username'] and EventData[Data[@Name='IpAddress']!='-']]</Select></Query></QueryList>"}
                2 {$XMLFilter = "<QueryList><Query><Select Path='Security'>*[System[band(Keywords,4503599627370496) and (EventID=4768 or EventID=4771)] and EventData[Data[@Name='TargetUserName']='$Username'] and EventData[Data[@Name='IpAddress']!='-']]</Select></Query></QueryList>"}
            }
            Foreach ($DC in $DCList) {
                $EventCounter = 0
                Write-Host "Checking for events on $DC..."
                $Events = Get-WinEvent -FilterXml $XMLFilter -ComputerName "$DC" -ErrorAction SilentlyContinue
                $Count = $Events.Count
                $TotalCount += $Count
                Write-Host "$Count event(s) found"
                $EarliestEventTable += ($Events.TimeCreated | Measure -Minimum).Minimum
                $OldestEvent = (Get-WinEvent -LogName Security -ComputerName "$DC" -MaxEvents 1 -Oldest -ErrorAction SilentlyContinue).TimeCreated
                If ($OldestEvent.Count -gt 0) {$OldestEventTable += "$DC - $OldestEvent"}
                Foreach ($WinEvent in $Events) {
                    Clear-Variable -Name IPAddress,DNSEntry,FailureReason,EventTime -ErrorAction SilentlyContinue
                    $IPAddress = (($WinEvent.Message -split '\r\n' | Select-String -Pattern 'Client Address:' -Context 0) -replace 'Client Address:','').Trim() -replace '^::ffff:',''
                    Switch ($ResultView) {
                        'S' {$EventTime = 'N/A'}
                        'C' {$EventTime = $WinEvent.TimeCreated}
                    }
                    If ($DCAddresses -notcontains $IPAddress) {
                        If ('::1','127.0.0.1' -contains $IPAddress) {
                            Clear-Variable -Name IPAddress -ErrorAction SilentlyContinue
                            $IPAddress = $DCTable.$DC
                        }
                        Switch ($UserSearchChoice) {
                            1 {$FailureReason = 'N/A'}
                            2 {
                                Switch ($WinEvent.Id) {
                                    4768 {$ResultString = 'Result Code:'}
                                    4771 {$ResultString = 'Failure Code:'}
                                }
                                $ResultCode = (($WinEvent.Message -split '\r\n' | Select-String -Pattern $ResultString -Context 0) -replace $ResultString,'').Trim()
                                $FailureReason = $KerberosResultCode.$ResultCode
                            }
                        }
                        If ($IPAddress.Count -gt 0) {
                            $Error.Clear()
                            $DNSEntry = [System.Net.DNS]::GetHostEntry("$IPAddress").HostName
                            Trap {continue}
                            If ($Error.Count -gt 0) {$DNSEntry = 'NO ENTRY FOUND'}
                            $Object = New-Object PsObject
                            $Object | Add-Member -MemberType NoteProperty -Name "IP Address" -Value $IPAddress
                            $Object | Add-Member -MemberType NoteProperty -Name "DNS Entry" -Value $DNSEntry
                            $Object | Add-Member -MemberType NoteProperty -Name "Failure Reason" -Value $FailureReason
                            $Object | Add-Member -MemberType NoteProperty -Name "Time Created" -Value $EventTime
                            $Result += $Object
                        }
                    }
                    $EventCounter = $EventCounter+1
                    Write-Progress -Activity "Filtering events from $DC for $Username" -Status "% Complete" -PercentComplete ($EventCounter/$Events.Count*100) -ErrorAction SilentlyContinue
                }
                Write-Progress -Activity "Filtering events from $DC for $Username" -Status "Completed" -Completed -ErrorAction SilentlyContinue
                Clear-Variable -Name EventCounter -ErrorAction SilentlyContinue
            }
            $EarliestEvent = ($EarliestEventTable | Measure -Minimum).Minimum
            $TimeEnd = Get-Date
        }
        # End of Username search
        # Start of PC search
        2 {
            Write-Host
            $PCName = ''
            While ($PCName -eq [string]::empty) {$PCName = Read-Host "Please enter a PC Name or IP Address"}
            Write-Host
            Write-Host "Testing connection to $PCName..."
            # Check connection
            $ConnectionTest = Test-Connection -ComputerName $PCName -Quiet -ErrorAction SilentlyContinue
            While ($ConnectionTest -ne $True) {
                Write-Host
                Write-Host "Unable to establish a connection with $PCName, or it is not configured"
                Write-Host "to respond to ping requests."
                Write-Host "What would you like to do?"
                Write-Host
                Write-Host "1) Continue anyway"
                Write-Host "2) Change PC Name/IP Address"
                Write-Host "3) List Computers in Directory"
                Write-Host "4) Quit"
                Write-Host
                While ('1','2','3','4' -notcontains $PCNameChoice) {$PCNameChoice = Read-Host "Please enter the number for your choice"}
                Switch ($PCNameChoice) {
                    2 {
                        Write-Host
                        $PCName = ''
                        While ($PCName -eq [string]::empty) {$PCName = Read-Host "Please enter a PC Name or IP Address"}
                        Write-Host
                        Write-Host "Testing connection to $PCName..."
                        $ConnectionTest = Test-Connection -ComputerName $PCName -Quiet -ErrorAction SilentlyContinue
                    }
                    3 {
                        Write-Host
                        Out-Host -InputObject $FinalPCList -Paging -ErrorAction SilentlyContinue
                        Trap {continue}
                    }
                }
                If ('1','4' -contains $PCNameChoice) {break}
                Clear-Variable -Name PCNameChoice -ErrorAction SilentlyContinue
            }
            If ($ConnectionTest -eq $True) {Write-Host "Success!"}
            If ($PCNameChoice -eq '4') {break} # Break to Exit Prompt
            Write-Host
            Write-Host "The following options are available:"
            Write-Host
            Write-Host "1) Successful logon"
            Write-Host "2) Failed logon attempt"
            Write-Host
            # PC search choice
            While ('1','2' -notcontains $PCSearchChoice) {$PCSearchChoice = Read-Host "Please enter the number for your choice"}
            Write-Host
            # Check OS Version (WMI)
            Write-Host "Checking OS Version..."
            $Error.Clear()
            $OSVersion = (Get-WmiObject -Class Win32_OperatingSystem -ComputerName "$PCName" -ErrorAction SilentlyContinue).Version
            If ($Error.Count -gt 0) {
                Write-Host
                Write-Host "The specified entry $PCName is either not a Windows computer or an"
                Write-Host "error occured when attempting to connect to WMI."
                Write-Host
                While ('Y','N','Yes','No' -notcontains $Confirm) {$Confirm = Read-Host "Do you want to continue?(Y/N)"}
            }
            If ('N','No' -contains $Confirm) {break} # Break to Exit Prompt
            # Switch method, event ID, strings & context by search choice & OS
            Switch ($PCSearchChoice) {
                1 {
                    $EntryType = 'SuccessAudit'
                    If ($OSVersion -like '5*') {
                        $InstanceId = 528,540
                        $ContextString = '^Successful'
                        $Context = 0,8
                        $UsernameString = 'User Name:'
                        $DomainString = 'Domain:'
                        $Method = '2'
                    }
                    Elseif (($OSVersion -like '4*') -or ($OSVersion -like '3*') -or ($OSVersion -like '2*') -or (($OSVersion -like '1*') -and ($OSVersion -notlike '10*'))) {
                        Write-Host "Not a supported Operating System"
                        $Breakout = "1"
                    }
                    Else {
                        $InstanceId = 4624
                        $ContextString = 'Logon Type:'
                        $Context = 0,10
                        $UsernameString = 'Account Name:'
                        $DomainString = 'Account Domain:'
                        $Method = '2'
                    }
                }
                2 {
                    $EntryType = 'FailureAudit'
                    If ($OSVersion -like '5*') {
                        $InstanceId = 529,530,531,532,533,534,535,536,537,539
                        $ContextString = 'Reason:'
                        $Context = 0,6
                        $UsernameString = 'User Name:'
                        $DomainString = 'Domain:'
                        $ReasonString = 'Reason:'
                        $Method = '2'
                    }
                    Elseif (($OSVersion -like '4*') -or ($OSVersion -like '3*') -or ($OSVersion -like '2*') -or (($OSVersion -like '1*') -and ($OSVersion -notlike '10*'))) {
                        Write-Host "Not a supported Operating System"
                        $Breakout = "1"
                    }
                    Else {
                        $InstanceId = 4625
                        $ContextString = 'Logon Type:'
                        $Context = 0,10
                        $UsernameString = 'Account Name:'
                        $DomainString = 'Account Domain:'
                        $ReasonString = 'Failure Reason:'
                        $Method = '1'
                    }
                }
            }
            If ($Breakout -eq "1") {break} # Break to Exit Prompt
            Write-Host
            Write-Host "Collecting and filtering events - be patient as this may take a long time"
            Write-Host "Please note if a large number of events are found (e.g. 10,000+) the"
            Write-Host "script can appear to hang whilst it retrieves all of them."
            Write-Host
            # Start search & filter
            $SearchInitiated = '1'
            $TimeStart = Get-Date
            $Result = @()
            $EventCounter = 0
            Write-Host "Checking for events on $PCName..."
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
            Write-Host "$TotalCount event(s) found"
            Foreach ($WinEvent in $Events) {
                Clear-Variable -Name Domain,Account,LogonType,FailureReason,EventTime -ErrorAction SilentlyContinue
                $FilterMessage = $WinEvent.Message -split '\r\n' | Select-String $ContextString -Context $Context
                $Account = (($FilterMessage -split '\r\n' | Select-String $UsernameString -Context 0) -replace $UsernameString,'' -replace '\$$','').Trim()
                $Domain = (($FilterMessage -split '\r\n' | Select-String $DomainString -Context 0) -replace $DomainString,'').Trim()
                $LogonTypeCode = (($FilterMessage -split '\r\n' | Select-String "Logon Type:" -Context 0) -replace 'Logon Type:','' -replace '^>','').Trim()
                $LogonType = $LogonTypeTable.$LogonTypeCode
                Switch ($ResultView) {
                    'S' {$EventTime = 'N/A'}
                    'C' {
                        Switch ($Method) {
                            1 {$EventTime = $WinEvent.TimeCreated}
                            2 {$EventTime = $WinEvent.TimeGenerated}
                        }
                    }
                }
                Switch ($PCSearchChoice) {
                    1 {$FailureReason = 'N/A'}
                    2 {$FailureReason = (($FilterMessage -split '\r\n' | Select-String $ReasonString -Context 0) -replace $ReasonString,'' -replace '^>','').Trim()}
                }
                If (($FinalPCList -notcontains $Account) -and ($Domain,$Account,$LogonType -notcontains '') -and ('-','NT AUTHORITY' -notcontains $Domain)) { # <<-------<< Manual filters here <<-------<<
                    $Object = New-Object PsObject
                    $Object | Add-Member -MemberType NoteProperty -Name "Account" -Value "$Domain\$Account"
                    $Object | Add-Member -MemberType NoteProperty -Name "Logon Type" -Value $LogonType
                    $Object | Add-Member -MemberType NoteProperty -Name "Failure Reason" -Value $FailureReason
                    $Object | Add-Member -MemberType NoteProperty -Name "Time Created" -Value $EventTime
                    $Result += $Object
                }
                $EventCounter = $EventCounter+1
                Write-Progress -Activity "Filtering events from $PCName" -Status "% Complete" -PercentComplete ($EventCounter/$Events.Count*100) -ErrorAction SilentlyContinue
            }
            Write-Progress -Activity "Filtering events from $PCName" -Status "Completed" -Completed -ErrorAction SilentlyContinue
            $TimeEnd = Get-Date
        }
        # End of PC search
        # End of search type switch
        'Q' {exit}
    }
    If ($Result.Count -gt 0) {
        $TimeDiff = $TimeEnd-$TimeStart
        $TimeDays = $TimeDiff.Days
        $TimeHours = $TimeDiff.Hours
        $TimeMinutes = $TimeDiff.Minutes
        $TimeSeconds = $TimeDiff.Seconds
        Switch ($ResultView) {
            'C' {
                $FinalResult = $Result | Sort-Object -Property 'Time Created' -Descending
                Switch ($SearchChoice) {
                    1 {
                        Switch ($UserSearchChoice) {
                            1 {$DisplayedProperties = 'IP Address','DNS Entry','Time Created'}
                            2 {$DisplayedProperties = 'IP Address','DNS Entry','Failure Reason','Time Created'}
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
                        $FinalResult = $Result | Select-Object -Property 'IP Address','DNS Entry','Failure Reason','Time Created' -Unique | Sort-Object -Property 'IP Address','DNS Entry','Failure Reason','Time Created'
                        Switch ($UserSearchChoice) {
                            1 {$DisplayedProperties = 'IP Address','DNS Entry'}
                            2 {$DisplayedProperties = 'IP Address','DNS Entry','Failure Reason'}
                        }
                    }
                    2 {
                        $FinalResult = $Result | Select-Object -Property 'Account','Logon Type','Failure Reason','Time Created' -Unique | Sort-Object -Property 'Account','Logon Type','Failure Reason','Time Created'
                        Switch ($PCSearchChoice) {
                            1 {$DisplayedProperties = 'Account','Logon Type'}
                            2 {$DisplayedProperties = 'Account','Logon Type','Failure Reason'}
                        }
                    }
                }
            }
        }
        # Display results
        Write-Host
        Write-Host "------------------------------------------------------------------------"
        Switch ($SearchChoice) {
            1 {Write-Host "$ResultViewText of $TotalCount events for the account $Username."}
            2 {Write-Host "$ResultViewText of $TotalCount events for the computer $PCName."}
        }
        Write-Host "The earliest event retrieved was created at $EarliestEvent."
        Write-Host "------------------------------------------------------------------------"
        $FinalResult | FT -Property $DisplayedProperties -AutoSize
        Write-Host "------------------------------------------------------------------------"
        Write-Host "Total Search Time (D:H:M:S) - $TimeDays`:$TimeHours`:$TimeMinutes`:$TimeSeconds"
        Write-Host "------------------------------------------------------------------------"
        Write-Host
    }
    Elseif (($SearchInitiated -eq '1') -and ($Result.Count -eq 0)) {
        Write-Host
        Write-Host "No events were found for the specified criteria"
        Switch ($SearchChoice) {
            1 {
                If ($OldestEventTable.Count -gt 0) {
                    Write-Host
                    Write-Host "At time of search the oldest event in the Security logs of each"
                    Write-Host "domain controller were created at the following times:"
                    Write-Host
                    $OldestEventTable
                }
            }
            2 {
                If ($OldestEvent.Count -gt 0) {
                    Write-Host
                    Write-Host "At time of search the oldest event in the Security log of the"
                    Write-Host "computer $PCName was created at $OldestEvent"
                }
            }
        }
    }
    If ($Result.Count -gt 0) {
        # Prompt to export file
        While ('Yes','Y','No','N' -notcontains $FileExport) {$FileExport = Read-Host "Do you want to export a file?(Y/N)"}
        If ('Yes','Y' -contains $FileExport) {
            While ('No','N' -notcontains $ExportRetry) {
                Clear-Variable -Name ExportRetry -ErrorAction SilentlyContinue
                Write-Host
                While ('csv','txt' -notcontains $FileFormat) {$FileFormat = Read-Host "Format?(CSV/TXT)"}
                Write-Host
                $FileName = ''
                While ($FileName -eq [string]::empty) {$FileName = Read-Host "Filename"}
                While (Test-Path -Path "$HOME\$FileName.$FileFormat") {
                    Write-Host
                    Write-Host "The file $HOME\$FileName.$FileFormat already exists."
                    Write-Host "What would you like to do?"
                    Write-Host
                    Write-Host "1) Overwrite the file"
                    Write-Host "2) Append data to file (CSV requires same search type)"
                    Write-Host "3) Change filename"
                    Write-Host "4) Quit"
                    Write-Host
                    While ('1','2','3','4' -notcontains $FileChoice) {$FileChoice = Read-Host "Please enter the number for your choice"}
                    If ($FileChoice -eq '3') {
                        Clear-Variable -Name FileName,FileChoice -ErrorAction SilentlyContinue
                        Write-Host
                        $FileName = ''
                        While ($FileName -eq [string]::empty) {$FileName = Read-Host "Filename"}
                    }
                    Elseif ('1','2','4' -contains $FileChoice) {break}
                }
                If ($FileChoice -eq '4') {break} # Break to Exit Prompt
                $Error.Clear()
                Switch ($FileFormat) {
                    'csv' {
                        If ($FileChoice -eq '2') {
                        $FinalResult | Export-Csv -Path "$HOME\$FileName.$FileFormat" -Append -Force -NoTypeInformation}
                        Else {$FinalResult | Export-Csv -Path "$HOME\$FileName.$FileFormat" -Force -NoTypeInformation}
                        Trap {continue}
                    }
                    'txt' {
                        If ($FileChoice -eq '2') {
                        $FinalResult | Out-File -FilePath "$HOME\$FileName.$FileFormat" -Append -Force}
                        Else {$FinalResult | Out-File -FilePath "$HOME\$FileName.$FileFormat" -Force}
                        Trap {continue}
                    }
                }
                If ($Error.Count -gt 0) {
                    Write-Host
                    Write-Host "The following error occured whilst trying to export the file:"
                    Write-Host
                    $Error.Exception
                    Write-Host
                    While ('Yes','Y','No','N' -notcontains $ExportRetry) {$ExportRetry = Read-Host "Do you want to retry?(Y/N)"}
                    If ('Yes','Y' -contains $ExportRetry) {Clear-Variable -Name FileFormat,FileChoice -ErrorAction SilentlyContinue}
                }
                Else {
                    Write-Host
                    Write-Host "File exported to $HOME\$FileName.$FileFormat"
                    $ExportRetry = 'N'
                }
            }
        }
    }
    Foreach ($Item in $Variables) {Clear-Variable -Name $Item -ErrorAction SilentlyContinue}
    [System.GC]::Collect()
    Start-Sleep -Milliseconds 500
    Write-Host
    While ('Yes','Y','No','N' -notcontains $ExitPrompt) {$ExitPrompt = Read-Host "Do you want to perform another search?(Y/N)"}
    If ('No','N' -contains $ExitPrompt) {exit}
}