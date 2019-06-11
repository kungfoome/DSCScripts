$sqlOU         = 'OU=Servers,DC=contoso,DC=com'
$domainName    = 'contoso.com'
$sqlNodes      = 'SQL17-01', 'SQL17-02'
$gMSQGroupName = 'gMSASQL2017'
$msaAccounts   = @{
    SQLEngine   = 'msaSQLEngine'
    SQLAgent    = 'msaSQLAgent'
    SQLAnalysis = 'msaSQLAnalys'
}

#### Create Managed Service Account Group ####
$gMSAGroup = @{
    Name           = $gMSQGroupName
    SamAccountName = $gMSQGroupName
    GroupCategory  = 'Security'
    GroupScope     = 'Global'
    DisplayName    = $gMSQGroupName
    Path           = $sqlOU
    Description    = 'Members of this group use gMSA'
}

New-ADGroup @gMSAGroup

#### Create Computer Nodes and add them to Managed Service Account Group ####
$sqlNodes | ForEach-Object {
    New-ADComputer -Name $_ -SAMAccountName $_ -Path $sqlOU
    $gMSAGroupMember = @{
        Identity = $gMSAGroup.Name
        Members  = -join($_,"$")
    }
    Add-ADGroupMember @gMSAGroupMember
}

#### Create Managed Service Accounts ####
$gMSASQLEngine = @{
    Name                                       = $msaAccounts.SQLEngine
    DNSHostName                                = '{0}.{1}' -f $msaAccounts.SQLEngine, $domainName
    PrincipalsAllowedToRetrieveManagedPassword = $gMSAGroup.Name
    Path                                       = $sqlOU
}
$gMSASQLAgent = @{
    Name                                       = $msaAccounts.SQLAgent
    DNSHostName                                = '{0}.{1}' -f $msaAccounts.SQLAgent, $domainName
    PrincipalsAllowedToRetrieveManagedPassword = $gMSAGroup.Name
    Path                                       = $sqlOU
}
$gMSASQLAnalysis = @{
    Name                                       = $msaAccounts.SQLAnalysis
    DNSHostName                                = '{0}.{1}' -f $msaAccounts.SQLAnalysis, $domainName
    PrincipalsAllowedToRetrieveManagedPassword = $gMSAGroup.Name
    Path                                       = $sqlOU
}

New-ADServiceAccount @gMSASQLEngine
New-ADServiceAccount @gMSASQLAgent
New-ADServiceAccount @gMSASQLAnalysis
