------------
Introduction
------------

This script has been designed as an interactive command line tool for use in an Active Directory domain environment. It can be used to search 
Windows Event security logs for credential validation and logon events, by username or hostname, to find & summarise typical domain account activity.
It has been designed as a simple tool of convenience and should not be used where intensive forensic auditing/examination is required.

------------------------
Group Policy Information
------------------------

Two Group Policy options will need to be enabled in order for both searches to work, both of which can be found at the following location:
'Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Audit Policy'

Audit account logon events:

Required for the username search, both success & failure attempts need to be audited. This policy should be applied to all domain controllers and will
create events for credential validation attempts of domain accounts only.
Enabling this policy will write the following events to the security log of a domain controller:
- ID 4768: A Kerberos authentication ticket (TGT) was requested"
- ID 4769: A Kerberos service ticket was requested"
- ID 4770: A Kerberos service ticket was renewed"
- ID 4771: Kerberos pre-authentication failed"
- ID 4774: An account was mapped for logon"
- ID 4776: The domain controller attempted to validate the credentials for an account"

Audit logon events:

Required for the computer search, both success & failure attempts need to be audited. This policy should be applied to all domain computers (or just the
computers you want to be able to audit) and will create events for logon attempts of either local or domain accounts. 
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

Username search:

Option 1 - Successful credential validation

Searches all Domain Controllers for events with ID 4768 (generated when a Kerberos TGT is requested) which include the keyword 'Audit Success'.
Extracts the IP Address logged in each event and returns this with the DNS entry of the address if one can be found. Use this search to determine 
where a domain account has recently been used to log in successfully.

***IMPORTANT*** - Certain types of software (such as inventory or monitoring software) that require the use of a domain account can log many of these
credential validation attempts in a short period of time. Searching for accounts used by this type of software may find a greater number of events, 
requiring much longer to retrieve and filter them. (A typical example would be the built-in Domain Admin account)

Option 2 - Failed credential validation

Searches all Domain Controllers for events with ID 4768 (generated when a Kerberos TGT is requested) and ID 4771 (generated when the KDC fails to
issue a Kerberos TGT) which include the keyword 'Audit Failure'. Extracts the IP Address logged in each event and returns this with the DNS entry of
the address if one exists, as well as the reason for the failure. Use this search to determine where a domain account has recently attempted to log
in but failed to do so.

Computer search:

Option 1 - Successful logon

Searches the security log on the destination PC for events with ID 4624 (generated when a logon session is created) on Windows Vista/Server 2008 
or higher. Searches for event ID 528 & 540 on Windows XP/Server 2003. Extracts the username logged in each event and returns this along with Logon Type. 
Use this search to determine which local and domain accounts have recently logged in successfully to the specified Computer.

***IMPORTANT*** - Computers sharing network resources with a high number of users (e.g. File Servers or MS Exchange) can log thousands of these 
events in a couple of hours, potentially needing a lot more time to retrieve & filter them.

Option 2 - Failed logon attempt

Searches the security log on the destination PC for events with ID 4625 (generated when a logon is attempted but fails) on Windows Vista/Server 2008 
or higher. Searches for event ID 529-537 & 539 on Windows XP/Server 2003. Extracts the username logged in each event and returns this along with Logon Type 
& reason for the failure. Use this search to determine which local and domain accounts have recently attempted but failed to login to the specified Computer.

A note about OS Versions:

Significant changes were made to the event IDs and event message format following Windows XP/2003. 
In order to determine the correct method to search the security log on the target PC, WMI is used to find the OS Version. 
If this fails for whatever reason, the search will default to the method used for Windows Vista & later versions.

------------------
Result Information
------------------

Results for all searches can be displayed as one of two types:

Summarised view:

Displays results as a unique summary (i.e. eliminates duplicates) of all events found in the search, sorted in either alphabetical or ascending order. 
Does not retrieve the time events were created. This is the default.

Chronological view:

Displays results as a collection of all events found, sorted in chronological order of their creation. If a high number of events are found it is 
likely this will create more output than space available in the Console (exporting a file is recommended).

---------------------
Issues & Requirements
---------------------

- DC(s) for username search must be Server 2008 or higher
- PC(s) for computer search must be Windows 2000 or higher
- Requires at least Powershell v3 on the computer the script is run from
- Prompts for elevation - Certain situations may not work without admin access (e.g. attempting search against local PC)
- Uses several .NET static methods to retrieve AD info. and perform DNS lookups (faster than AD modules)
- Uses WMI to determine OS Version in computer search as pre-Vista security events were logged very differently. If WMI fails you can continue which defaults to method used for Vista & later
- Manual filters (line 379) in computer search will stop certain events being added to results. Mainly to eliminate machine accounts, service accounts or events with empty results (change if needed)
- DNS lookups are done in real time on username search (when script is run) but IP Address may have been reassigned via DHCP since event was logged i.e. small chance the lookup could be inaccurate
- If the script wont return a result against the local PC using the hostname please try the IP Address (only seen on Win 10)
- There is a temptation to increase the security log size in order to cover a greater time period of events logged. Bear in mind this is a balancing act, as increasing the log size will cause the searches to take longer

-------------
Author's Note
-------------

There are quite a number of factors involved in this script meaning search times can vary dramatically. The vast majority of searches will be unlikely to need 
more than a few minutes to complete, but certain conditions may cause the search parameters to find a lot of events (over 100,000) and in these situations 
the entire search/filtering process could take more than 30 minutes to finish. The only times I personally saw this was computers sharing network resources 
with a large number of users (e.g. File Servers) or where a domain account was used a lot in specific types of software (the built in Domain Admin account 
being used for inventory/monitoring software etc). Other factors can also potentially have an effect (e.g. log sizes, bandwidth, HDD speed, resource availability).
