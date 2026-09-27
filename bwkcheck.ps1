<#
     ###################################################################################
     ##  bwkcheck.ps1  -by Duane Holt.                                         ##
     ##  A utility for checking passwords in a Bitwarden .json Export against the     ##
     ##  Have I Been Pwned APIs, will identify compromised passwords.                 ##
     ##  Uses a partial SHA-1 hash (keeping your passwords off the wire/internet)     ##
     ##                                                                               ##
     ##  First time users, try just inputing the .json export with no options         ##
     ###################################################################################

     Mandatory parameters: 
         -JSONFile  Full File Path to JSON Export from Bitwarden
                    Example:  "C:\..path..\bitwarden_export_XXXX.json"
         OR
         -UseVault    Connect to Bitwarden via the local Bitwarden CLI

     Optional parameters:
         -CSVFilePath       Full File Path to CSV output report
                            Example:  "C:\..path..\PasswordAudit.csv"
         -CSVFileReplace    Will Replace an Existing CSVfile, default behavior is to append
         -HideSafeAccounts  Suppress output accounts with safe passwords 
         -MaskBadPasswords  Mask display of compromised passwords in console/CSV 
         -SuppressWarnings   Bypass the initial password display warning prompt
         -SuppressCSVPrompt  Bypass the interactive CSV path selection prompt
         -HighContrastText  Changes text to high-contrast white on black for accessibility

     Notes:
         You may need to Bypass powershell policy preventing script execution
         PS C:\temp> Set-ExecutionPolicy Bypass -Scope Process   ---CURRENT PROCESS
         PS C:\temp> Set-ExecutionPolicy RemoteSigned -Scope CurrentUser   ---PERMANENT FOR YOUR USER
       
     Example #1) Full Path Execution, output to a CSV:
         PS C:\temp> .\Check-Passwords.ps1 -JSONFile "C:\..fullpath..\passwordexport.json" -CSVFilePath "C:\temp\report.csv" 

     Example #2) Local Vault Execution, hiding safe accounts: 
         PS C:\temp> .\Check-Passwords.ps1 -UseVault -HideSafeAccounts 
#>
#############################
# MAIN INPUT PARAMETERS     #
# AND GLOBAL VARIABLES      #
#############################
# Define input parameters to script
[CmdletBinding()]
param (    

    [Parameter(Mandatory=$false)]
    [string]$JSONFile,

    [Parameter(Mandatory=$false)]
    [switch]$UseVault,

    #Export accounts to a CSV file
    [Parameter(Mandatory=$false)]
    [string]$CSVFilePath,

    #suppress CSV export path interactive prompt
    [Parameter(Mandatory=$false)]
    [switch]$SuppressCSVPrompt,

    #Script will not show or output accounts with safe passwords.
    [Parameter(Mandatory=$false)]
    [switch]$HideSafeAccounts,  

    #suppress output of compromised password text itself
    [Parameter(Mandatory=$false)]
    [switch]$MaskBadPasswords,
    
    #suppress output of compromised password text itself
    [Parameter(Mandatory=$false)]
    [switch]$SuppressWarnings,

    #suppress output of compromised password text itself
    [Parameter(Mandatory=$false)]
    [switch]$CSVFileReplace,

    #change text to white on black
    [Parameter(Mandatory=$false)]
    [switch]$HighContrastText
)
# Define global constants  
$ColorWarningFG = "Yellow"
$ColorWarningBG = "DarkRed"
$ColorMessageFG = "Cyan"
$ColorGoodAcctFG = "Green"
$ColorBadAcctFG = "Red"
$ColorEndReportFG = "White"
$ColorErrorFG = "Red"
$ColorTitleFg = "Cyan"
$ColorSubTitleFg = "Gray"
#############################
# Script's Helper Functions #
#############################

#Helper Function to switch colors for high contrast / color blind accessibility
function Set-HighContrastText
{
    $script:ColorWarningFG = "White"
    $script:ColorWarningBG = "Black"
    $script:ColorMessageFG = "White"
    $script:ColorGoodAcctFG = "Gray"
    $script:ColorBadAcctFG  = "White"
    $script:ColorEndReportFG = "White"
    $script:ColorErrorFG   = "White"
    $script:ColorTitleFg   = "White"
    $script:ColorSubTitleFg  = "Gray"
}

# Helper Function to initial display for startup
function Show-StartupBanner {
    Write-Host ""
    Write-Host "╔═════════════════════════════════════════════════════════════════════╗" -ForegroundColor $ColorTitleFg
    Write-Host "            🛡️  bwcheck: A Bitwarden Password Checker  🔐             " -ForegroundColor $ColorTitleFg
    Write-Host "                               - by Duane Holt (2026)                 " -ForegroundColor $ColorTitleFg
    Write-Host "╠═════════════════════════════════════════════════════════════════════╣" -ForegroundColor $ColorTitleFg
    Write-Host "       Privacy  │ k-Anonymity Active (Safe password comparisons)        " -ForegroundColor $ColorTitleFg
    Write-Host "       Source   │ Have I Been Pwned Public Passwords API               " -ForegroundColor $ColorTitleFg
    Write-Host "╚═════════════════════════════════════════════════════════════════════╝" -ForegroundColor $ColorTitleFg  
    Write-Host ""  
}




# Helper Function to display active configuration options
function Show-ConfigurationSummary {
    Write-Host " ───────────────────────────────────────────────────────────" -ForegroundColor $ColorMessageFG
    Write-Host "                      ACTIVE CONFIGURATION                  " -ForegroundColor $ColorTitleFg
    Write-Host " ───────────────────────────────────────────────────────────" -ForegroundColor $ColorMessageFG
    
    if (-not [string]::IsNullOrWhiteSpace($JSONFile)) {
        Write-Host "  • Source Mode        : JSON File" -ForegroundColor $ColorMessageFG
        Write-Host "  • JSON Input File    : $JSONFile" -ForegroundColor $ColorMessageFG
    } elseif ($UseVault) {
        Write-Host "  • Source Mode        : Bitwarden CLI Vault" -ForegroundColor $ColorMessageFG
    } else {
        Write-Host "  • Source Mode         : " -ForegroundColor $ColorMessageFG -NoNewline
        Write-Host "[None - Prompt User]" -ForegroundColor $ColorWarningFG
    }
    
    Write-Host "  • CSV Export Path     : $(if ($CSVFilePath) { $CSVFilePath } else { '[None - Console Only]' })" -ForegroundColor $ColorMessageFG
   # Write-Host "  •                     : -CSVFilePath" -ForegroundColor $ColorMessageFG
   # Write-Host "  •                     : -HideSafeAccounts" -ForegroundColor $ColorMessageFG
    Write-Host "  • Hide Safe Accounts  : $($HideSafeAccounts.IsPresent)   -HideSafeAccounts" -ForegroundColor $ColorMessageFG
    Write-Host "  • Mask Bad Passwords  : $($MaskBadPasswords.IsPresent)   -MaskBadPasswords" -ForegroundColor $ColorMessageFG
    Write-Host "  • Suppress CSV Prompt : $($SuppressCSVPrompt.IsPresent)   -SuppressCSVPrompt" -ForegroundColor $ColorMessageFG
    Write-Host "  • Suppress Warnings   : $($SuppressWarnings.IsPresent)   -SuppressWarnings" -ForegroundColor $ColorMessageFG
    Write-Host "  • High Contrast Text  : $($HighContrastText.IsPresent)   -HighContrastText" -ForegroundColor $ColorMessageFG
    Write-Host " ───────────────────────────────────────────────────────────" -ForegroundColor $ColorMessageFG
 
}
# Helper Function to warn user if they are displaying passwords - give them a chance to abort
function WarnUserIfDisplayingPasswords {
    if ($SuppressWarnings) {return}
    if (-not $MaskBadPasswords)
    {
            Write-Host "`n 📢 PASSWORD DISPLAY WARNING 📢 " -ForegroundColor $ColorWarningFG  
            Write-Host "Compromised passwords will be displayed in cleartext and written to CSV if enabled." -ForegroundColor $ColorWarningFG 
            Write-Host "In the future, you can use the script switches:" -ForegroundColor $ColorMessageFG 
            Write-Host " - MaskBadPasswords : to mask passwords." -ForegroundColor $ColorMessageFG
            Write-Host " - SuppressWarnings  : to bypass this message." -ForegroundColor $ColorMessageFG
            do {
                Write-Host "Do you want to Proceed?" -ForegroundColor $ColorMessageFG
                $choice = Read-Host "[Y]es or [Enter] to proceed, [C]ancel and exit script"
                switch ($choice.ToUpper()) {
                    'Y' { 
                        Write-Host "Proceeding." -ForegroundColor $ColorMessageFG
                        return 'Proceed' 
                    }                
                    'C' { 
                        Write-Host "Operation cancelled by user." -ForegroundColor $ColorMessageFG
                        exit 
                    }
                    default { 

                        if ([string]::IsNullOrWhiteSpace($choice)) {
                            Write-Host "Proceeding." -ForegroundColor $ColorMessageFG
                            return 'Proceed' 
                        }
                                            
                        Write-Host "Invalid choice. Please enter P or C, then press Enter." -ForegroundColor $ColorErrorFG 
                    }
                }
            } while ($true)
    }
}





# Helper Function to handle file overwrite/append prompts
function Test-And-PromptExportFile {
    param([string]$Path)
    
    if (Test-Path $Path) {
        if ($CSVFileReplace) { return 'Overwrite' }
        Write-Host "`n 🚧 CSV File Already Exists 🚧 " -ForegroundColor $ColorWarningFG  
        Write-Host "The file [$Path] already exists, choose an option." -ForegroundColor $ColorMessageFG   
        do {
            $choice = Read-Host " Do you want to [O]verwrite, [A]ppend, or [C]ancel?"
            switch ($choice.ToUpper()) {
                'O' { 
                    Remove-Item $Path -Force
                    # Write header for new/overwritten file
                    return 'Overwrite' 
                }
                'A' { return 'Append' }
                'C' { 
                    Write-Host "Operation cancelled by user." -ForegroundColor $ColorMessageFG 
                    exit
                     
                }
                default { Write-Host "Invalid choice. Please enter O, A, or C, then press Enter." -ForegroundColor $ColorErrorFG  }
            }
        } while ($true)
    }
    return 'New'
}

#Helper Function to read from Bitwarden CLI across personal and organization vaults
function Read-Vault
{
    Write-Host "Connecting to local Bitwarden vault..." -ForegroundColor $ColorMessageFG
    
    # Ensure CLI is available
    if (-not (Get-Command bw -ErrorAction SilentlyContinue)) {
        throw "Bitwarden CLI ('bw') is not installed or not in your system path."
    }

    # Check lock status / unlock if needed
    $status = bw status | ConvertFrom-Json
    if ($status.status -eq "unlocked") {
        Write-Host "Vault is already unlocked." -ForegroundColor $ColorMessageFG
    }
    elseif ($status.status -eq "locked") {
        $masterPassword = Read-Host "Enter your Bitwarden Master Password" -AsSecureString
        
        # Cross-platform secure string to plaintext conversion
        $plainPassword = [System.Net.NetworkCredential]::new("", $masterPassword).Password
        
        # Unlock and grab the session key
        $env:BW_SESSION = bw unlock $plainPassword --raw
        if (-not $env:BW_SESSION) {
            throw "Failed to unlock Bitwarden vault. Check your master password."
        }
    }
    else {
        throw "Bitwarden CLI is not logged in. Run 'bw login' first."
    }

    # Ensure local cache is synchronized with the server
    Write-Host "Synchronizing local vault cache..." -ForegroundColor $ColorMessageFG
    bw sync --session $env:BW_SESSION | Out-Null

    # Initialize a clean array container
    $allVaultItems = @()

    # Fetch personal items directly into memory
    Write-Host "Fetching live items from personal vault..." -ForegroundColor $ColorMessageFG
    $personalJson = bw list items --session $env:BW_SESSION
    if (-not [string]::IsNullOrWhiteSpace($personalJson)) {
        $personalItems = $personalJson | ConvertFrom-Json
        if ($personalItems) {
            $allVaultItems += $personalItems
        }
    }

    # Automatically discover and fetch items from any organizations (e.g., Team Giraffe)
    Write-Host "Checking for organization vaults..." -ForegroundColor $ColorMessageFG
    $orgJson = bw list organizations --session $env:BW_SESSION
    if (-not [string]::IsNullOrWhiteSpace($orgJson)) {
        $orgs = $orgJson | ConvertFrom-Json
        foreach ($org in $orgs) {
            if ($org.id) {
                Write-Host "Fetching items from organization: $($org.name)..." -ForegroundColor $ColorMessageFG
                $orgItemsJson = bw list items --organizationid $org.id --session $env:BW_SESSION
                if (-not [string]::IsNullOrWhiteSpace($orgItemsJson)) {
                    $orgItems = $orgItemsJson | ConvertFrom-Json
                    if ($orgItems) {
                        $allVaultItems += $orgItems
                    }
                }
            }
        }
    }

    # Wrap the combined items into the expected structure
    $jsonContent = [PSCustomObject]@{
        items = $allVaultItems
    }
    
    return $jsonContent
}

#Helper Function to read from JSON File if selected as source
function Read-JSONFile
{
    param([string]$Path)
    # See if input file exists
    if (-not (Test-Path $Path)) {
        throw "File not found: $Path"
    }

    # Read and parse the Bitwarden JSON structure
    Write-Verbose  "Parsing Bitwarden JSON export."
    try {
        $jsonContent = Get-Content $Path -Raw | ConvertFrom-Json
    }
    catch {
        throw "Failed to parse JSON file. Ensure it is a valid, unencrypted Bitwarden JSON export. Error: $_"    
    }

    return $jsonContent
}



function Get-CsvExportPath {
    param(
        [string]$DefaultFileName = "Bitwarden_Audit_Report.csv"
    )
    
    $defaultCsv = Join-Path $PSScriptRoot $DefaultFileName

    Write-Host "`n 🚚 NO CSV EXPORT FILE PROVIDED 🚚" -ForegroundColor $ColorWarningFG
    Write-Host "To avoid this message in the future use the script switch:   -SuppressCSVPrompt " -ForegroundColor $ColorMessageFG
 
    # Part 1: Initial Text Prompt
    Write-Host "`Continue with no CSV Output:" -ForegroundColor $ColorMessageFG
    Write-Host " [Y]es or [Enter] - Continue without a CSV File [Console Only Output]"
    Write-Host " [N]ew            - Enter a custom file name"
    Write-Host " [D]efault CSV    - Create the default CSV File: $defaultCsv"
    
    
    $initialChoice =$null
    while ($null -eq $initialChoice) {$inputKey = Read-Host "Select option (Y, N, or D)"
        switch ($inputKey.Trim().ToUpper()) {
            'Y' { $initialChoice = 'Skip' }
            'D' { $initialChoice = 'Default' }
            'N' { $initialChoice = 'New' }
            default { 
                if ([string]$inputKey.Trim().Length -eq 0) {$initialChoice = 'Skip'}
                else
                {Write-Host "Invalid selection. Please enter Y, N, or D." -ForegroundColor $ColorErrorFG }
                }
        }
    }
    
    if ($initialChoice -eq 'Skip') {
        Write-Host "CSV export disabled for this run." -ForegroundColor $ColorMessageFG
        return $null
    }
    
    if ($initialChoice -eq 'Default') {
        Write-Host "Using default path: $defaultCsv" -ForegroundColor $ColorMessageFG
        return $defaultCsv
    }
    
    # Part 2: Custom Filename Entry & Validation Loop
    $validCustom =$false
    while (-not $validCustom) {
        Write-Host "`nCurrent directory is: $PSScriptRoot" -ForegroundColor $ColorMessageFG
        Write-Host "`Enter file name for CSV file export (or type 'C' to cancel):" -ForegroundColor $ColorMessageFG 
        $userInput = Read-Host "File name or path"
        
        # Check for cancellation
        if ($userInput.Trim() -eq 'C' -or $userInput.Trim() -eq 'c') {
            Write-Host "CSV file name entry cancelled. Skipping CSV export." -ForegroundColor $ColorWarningFG
            return $null
        }
        
        # Input validation: length check
        if ([string]::IsNullOrWhiteSpace($userInput) -or $userInput.Length -le 1) {
            Write-Host "Error: File name must be greater than 1 character." -ForegroundColor $ColorErrorFG
            continue
        }
        
        # Append .csv extension if no period is present
        if (-not $userInput.Contains(".")) {
            $userInput = "$userInput.csv"
        }
        
        # Path resolution (absolute vs relative check)
        if (-not [System.IO.Path]::IsPathRooted($userInput)) {
            $targetPath = Join-Path $PSScriptRoot $userInput
        } else {
            $targetPath = $userInput
        }
        
        # Verify parent directory validity
        try {
            $parentDir = [System.IO.Path]::GetDirectoryName($targetPath)
            if (-not [string]::IsNullOrEmpty($parentDir) -and -not (Test-Path $parentDir)) {
                New-Item -ItemType Directory -Path $parentDir -Force | Out-Null
            }
        }
        catch {
            Write-Host "Error: The specified file path is invalid. Please try again." -ForegroundColor Red
            continue
        }
        
        # Final Confirmation Prompt
        Write-Host "`nConfirm CSV export path [$targetPath]: "   -ForegroundColor Cyan
        Write-Host " [Y]es or [Enter] to confirm,  [N]o to retry,  or [C]ancel to exit" -ForegroundColor Cyan
                
        $confirmChoice =$null
        while ($null -eq $confirmChoice) {$confirmInput = Read-Host "Confirm selection (Y, N, or D)"
            switch ($confirmInput.Trim().ToUpper()) {
                'Y' { 
                    Write-Host "Exporting to custom CSV: $targetPath" -ForegroundColor $ColorMessageFG
                    return $targetPath 
                }
                'N' { 
                    $confirmChoice = 'Retry'
                    Write-Host "Let's try again..." -ForegroundColor $ColorMessageFG
                }
                'C' { 
                    Write-Host "Cancel and Exit." -ForegroundColor $ColorMessageFG
                    exit 
                }
                default{
                    if ([string]::IsNullOrWhiteSpace($confirmInput)) {
                        Write-Host "Exporting to custom CSV: $targetPath" -ForegroundColor $ColorMessageFG
                        return $targetPath 
                    }
                    Write-Host "Invalid selection. Please enter Y, N, or C." -ForegroundColor Red 
                    
                } 
            }
        }
    }
    
    return $null
}

# Helper Function to prompt for input source if neither JSONFile nor UseVault is provided
function Get-CredentialSource {
    param(
        [ref]$JSONFileRef,
        [ref]$UseVaultRef
    )
    
    while ([string]::IsNullOrWhiteSpace($JSONFileRef.Value) -and -not $UseVaultRef.Value) {
        Write-Host "`n 🔍 NO CREDENTIAL SOURCE PROVIDED 🔍" -ForegroundColor $ColorWarningFG
        Write-Host "To avoid this prompt in the future, use one of the two script arguments:" -ForegroundColor Cyan
        Write-Host "   -UseVault                              (use an installed Bitwarden CLI)  " -ForegroundColor Cyan
        Write-Host "   -JSONFile `"bw_export.json`"       OR    (exported Bitwarden JSON - same directory)" -ForegroundColor Cyan
        Write-Host "   -JSONFile `"<path>bw_export.json`"       (exported Bitwarden JSON - full file path)" -ForegroundColor Cyan
        Write-Host "Choose an Option:" -ForegroundColor Cyan
        Write-Host "  [V] Use Vault - Connect via local Bitwarden CLI"
        Write-Host "  [J] JSON File - Enter path to a Bitwarden JSON export  "
        Write-Host "  [C] Cancel    - Exit script"
        
        $choice = Read-Host "Select source option (V, J, or C)"
        switch ($choice.Trim().ToUpper()) {
            'V' {
                $UseVaultRef.Value = $true
                Write-Host "Selected: Bitwarden CLI Vault." -ForegroundColor $ColorMessageFG
            }
            'J' {
                $pathInput = Read-Host "Enter full path to the Bitwarden JSON export file"
                if (-not [string]::IsNullOrWhiteSpace($pathInput)) {
                    if (-not [System.IO.Path]::IsPathRooted($pathInput)) {$pathInput = Join-Path $PSScriptRoot $pathInput
                    }
                    if (Test-Path $pathInput) {
                        $JSONFileRef.Value = $pathInput
                        Write-Host "Selected JSON File: $pathInput" -ForegroundColor $ColorMessageFG
                    } else {
                        Write-Host "Error: File not found at '$pathInput'." -ForegroundColor $ColorErrorFG
                    }
                }
            }
            'C' {
                Write-Host "Operation cancelled by user." -ForegroundColor $ColorMessageFG
                exit
            }
            default {
                Write-Host "Invalid selection. Please enter V, J, or C." -ForegroundColor $ColorErrorFG
            }
        }
    }
}

#######################
# Script's Main Block #
#######################

if ($HighContrastText) {Set-HighContrastText}
Show-StartupBanner
Show-ConfigurationSummary
# Prompt for source if neither JSONFile nor UseVault was passed as a parameter
$rval = Get-CredentialSource -JSONFileRef ([ref]$JSONFile) -UseVaultRef ([ref]$UseVault)
#Warn Users if we are going to cleartexting passwords
$rval = WarnUserIfDisplayingPasswords


# Output verbose
# Output information passed as parameters

Write-Verbose "*Script Parameters (or default values)*" 
Write-Verbose  "-JSONFile $JSONFile" 
Write-Verbose "-CSVFilePath $CSVFilePath" 
Write-Verbose "-HideSafeAccounts $HideSafeAccounts" 

# Conditionally invoke prompt helper if no CSV file path was provided and prompt isn't suppressed
if (-not $PSBoundParameters.ContainsKey('CSVFilePath') -or [string]::IsNullOrWhiteSpace($CSVFilePath)) {
    if ($SuppressCSVPrompt) {
        Write-Host "CSV export prompt suppressed. No CSV export will be created." -ForegroundColor $ColorMessageFG
        $CSVFilePath =$null
    } else {
        $CSVFilePath = Get-CsvExportPath
    }
}


if ($HideSafeAccounts) {
    Write-Host "Suppressing output of accounts with good/uncompromised passwords. `n -> Process may appear delayed while checking these accounts." -ForegroundColor $ColorMessageFG 
} else {
    Write-Host "Displaying output of accounts with good/uncompromised passwords. Note: Good/uncompromised are always masked." -ForegroundColor $ColorMessageFG 
}

if (-not [string]::IsNullOrWhiteSpace($JSONFile)) {
    $jsonContent = Read-JSONFile -Path $JSONFile
    }
else {
        if ($UseVault) {$jsonContent = Read-Vault}
        else {
        Write-Host "Error. Either -JSONFile  or -UseVault are required to check Bitwarden credentials" 
        throw "Missing Json File or Bitwarden CLI"
        }
    }

# Filter for items that contain login credentials
$loginItems = $jsonContent.items  |  Where-Object {$_.type -eq 1 -and $_.login -ne$null -and $_.login.password -ne$null }

# Warn if no items found in a valid JSON 
if (-not $loginItems) {
    Write-Host "No login credentials found in the JSON  [type=1].`nDone." -ForegroundColor $ColorEndReportFG
    Write-Host "====================================================" -ForegroundColor $ColorEndReportFG
    exit
}


# Output number of items found 
$TotalBWLoginAccounts = $loginItems.Count
Write-Host "Found $TotalBWLoginAccounts accounts in JSON file.  Queuing k-Anonymity hash values for HIBP queries." -ForegroundColor $ColorMessageFG 

#take care of setting up CSV File export now that we have items to process (if we need to export to CSV)
if ($CSVFilePath) { 
    $fileAction = Test-And-PromptExportFile -Path $CSVFilePath    
    
    if ($fileAction -eq 'Overwrite' -and (Test-Path $CSVFilePath)) {
        Remove-Item $CSVFilePath -Force
    }
}

# Setup SHA1 hashing, iterate the found items and setup an execution loop (for each) 
$sha1 = [System.Security.Cryptography.SHA1]::Create()
$passwordsprocessed = 0
$blankpasswords = 0
$safepasswords = 0
$compromisedpasswords = 0

foreach ($item in $loginItems) {
    
    
    #Calculate percentage complete safely (avoid division by zero)
    $percent = if ($TotalBWLoginAccounts -gt 0) { 
    [int](($passwordsprocessed / $TotalBWLoginAccounts) * 100) 
    } else { 
    0 
    }
    
    ## progress bar incompatile with Write-Host in my loop, if we want to implement this next block
    ## we need to move everything into this part that we would write to screen as write-progress,
    ## then dump it all at once.  So far I like the scrolling effect.
    #Write-Progress -Activity "Auditing Bitwarden Vault against HIBP" `
    #               -Status "Processed: $passwordsprocessed of$TotalBWLoginAccounts accounts" `
    #               -PercentComplete $percent `
    #               -CurrentOperation "Checking: ($item.name)"

    #debug/verbose 
    Write-Verbose "NEXT ITEM: $item `nLOOP COUNTER: passwordsprocessed = $passwordsprocessed , blankpasswords =$blankpasswords , safepasswords = $safepasswords , compromisedpasswords =$compromisedpasswords"
    # Grab individual elements from inner JSON
    $pwd =$item.login.password
    $title =$item.name
    $username =$item.login.username

    # Skip this entry if there is no password (continue to next item in for each)
    if ([string]::IsNullOrWhiteSpace($pwd)) {$blankpasswords++ 
        continue }

    # Compute SHA-1 hash locally
    $utf8Bytes = [System.Text.Encoding]::UTF8.GetBytes($pwd)
    $hashBytes = $sha1.ComputeHash($utf8Bytes)
    $hashString = [System.BitConverter]::ToString($hashBytes) -replace '-'
    
    # Split into prefix (5 chars) and suffix
    $prefix =$hashString.Substring(0, 5)
    $suffix =$hashString.Substring(5)

    # Query HIBP API using only the prefix for k-anonymity, see API docs
    $url = "https://api.pwnedpasswords.com/range/$prefix"
    try {
        Write-Verbose "GET: $url"
        # Send WebRequest
        $response = Invoke-RestMethod -Uri $url -Method Get -UseBasicParsing
        
        ## Next Write-Verbose is is massive but you will understand whats happening :) 
        ## Write-Verbose "RESPONSE: $response"
        # Parse the Response
        $found =$false  #this variable gets set to true once we find data about our chunked/paswdhash, meaning its been compromised.
        foreach ($line in ($response -split "`r?`n")) {
            if ([string]::IsNullOrWhiteSpace($line)) { continue }  # Ignore blank lines
            $parts =$line.Split(':')  # Splitting data up based on ":" to find response for compromised password
            if ($parts[0] -eq$suffix) {
                $PWDinHIBPcount = [int]$parts[1]  # The count of the number of times the password is in the HIBP database
                
                $found =$true
                break
            }
        }
                
        # Grab an object to format outputs into one neat little place
        $auditRow = [PSCustomObject]@{
                Status   = if ($found) { "Compromised" } else { "Good" }
                Title    = $Title
                Username = $Username
                Password = if ($found) { if($MaskBadPasswords) {'*' * $pwd.Length} else {"$pwd"} } else { '*' * $pwd.Length }
                NumOfMatches = if ($found) { "$PWDinHIBPcount" } else { "0" }
            }
        
        #Supress output of safe accounts
        if (-not($HideSafeAccounts -and -not$found))
        {
            #Write to CSV if necessary        
            if ($CSVFilePath) {                
                $isAppend = (Test-Path $CSVFilePath) 
                #Passing -Append:$isAppend dynamically ensures that if the file was just wiped or doesn't exist yet, it writes the column headers on line 1, and subsequent rows append cleanly without duplicating headers
                $auditRow | Export-Csv -Path $CSVFilePath -Append:$isAppend -NoTypeInformation -Encoding utf8
            }

            # Output to Console
            $color = if ($found) { $ColorBadAcctFG } else {$ColorGoodAcctFG }
            Write-Host "[$($auditRow.Status)]$($auditRow.Title)  | $($auditRow.Username)  | $($auditRow.Password) ($($auditRow.NumOfMatches))" -ForegroundColor $color
        }

        #increment counts
        if ($found) {$compromisedpasswords++} else {$safepasswords++}$passwordsprocessed++
        ## a testing loop ending early, because my test file is huge... should be commented out for full use
        #if($passwordsprocessed -gt 20) {break}
    }
    # Failed portion of try {} catch {} loop, something went wrong on this item's https webrequest to get data
    catch {
        Write-Error "Error checking item '$title'. Reported Error =  $_" -ErrorAction Continue -Category InvalidResult
    }

    # Rate limit buffer on the API -- prevent IP block from the server side DDoS protections
    Start-Sleep -Milliseconds 100
}

Write-Progress -Activity "Auditing Bitwarden Vault against HIBP" -Completed
    
# Memory Cleanup
$sha1.Dispose()
# Done
Write-Host "Password checking complete. " -ForegroundColor $ColorMessageFG  -NoNewline
$totalsoutput = "Totals:: Accounts:$TotalBWLoginAccounts Processed:$passwordsprocessed BlankPwd:$blankpasswords Safe:$safepasswords  Compromised:$compromisedpasswords"
Write-Host $totalsoutput -ForegroundColor $ColorEndReportFG
$lastline = '=' * ($totalsoutput.Length + 28)
Write-Host "$lastline" -ForegroundColor $ColorEndReportFG