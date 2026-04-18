# PowerShell 7+ required (for -SkipCertificateCheck on Invoke-RestMethod)
# Install the Excel module (one-time, no Excel installation needed)
Install-Module -Name ImportExcel -Scope CurrentUser -Force


### Usage Example

# Basic — prompts for password, exports to current directory
.\Export-NSXFirewallRules.ps1 -NSXManager "192.168.1.10" -SkipCertificateCheck

# Full example with all options
.\Export-NSXFirewallRules.ps1 `
    -NSXManager "nsxmgr.corp.local" `
    -Username admin `
    -Password "YourPassword" `
    -OutputPath "C:\NSX_Exports" `
    -OutputFormat Both `
    -SkipCertificateCheck

# Production (valid cert, Excel only)
.\Export-NSXFirewallRules.ps1 -NSXManager nsxmgr.corp.local -OutputFormat Excel
