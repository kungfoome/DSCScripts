Function ManagedServiceAccount {
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $ServiceAccountName
    )

    if(!($ServiceAccountName -match '\$$')){
        throw "'$ServiceAccountName' is not a proper managed service. Check to make sure it ends with a '$' character"
    }

    return New-Object System.Management.Automation.PSCredential($ServiceAccountName, ("nopassword" | ConvertTo-SecureString -AsPlainText -Force))
}

<#
	.SYNOPSIS
		Function to cleanup a MACAddress string

	.DESCRIPTION
		Function to cleanup a MACAddress string

	.PARAMETER MacAddress
		Specifies the MacAddress

	.PARAMETER Separator
		Specifies the separator every two characters

	.PARAMETER Uppercase
        Specifies the output must be Uppercase if true. If False it is set to lowercase. If set to None, it won't change.
        Default is Uppercase

	.OUTPUTS
		System.String
#>
function CleanMacAddress {
	param
	(
        [Parameter(Position=0)]
		[String]$MacAddress,

        [Parameter(Position=1)]
		[ValidateSet(':', '', '.', "-")]
		[String]$Separator = '-',

        [Parameter(Position=2)]
        [ValidateSet($true, $false, 'None')]
		$Uppercase = $true
	)

	BEGIN {
		# Initial Cleanup
		$MacAddress = $MacAddress -replace "-", "" #Replace Dash
		$MacAddress = $MacAddress -replace ":", "" #Replace Colon
		$MacAddress = $MacAddress -replace "/s", "" #Remove whitespace
		$MacAddress = $MacAddress -replace " ", "" #Remove whitespace
		$MacAddress = $MacAddress -replace "\.", "" #Remove dots
		$MacAddress = $MacAddress.trim() #Remove space at the beginning
		$MacAddress = $MacAddress.trimend() #Remove space at the end
	}
	PROCESS {
        $MacAddress = $MacAddress -replace '(..(?!$))', "`$1$Separator"
        if ($Uppercase) {
            $MacAddress = $macaddress.toupper()
        }elseif(!$Uppercase){
            $MacAddress = $macaddress.tolower()
        }

	} END {
        Write-Verbose "Clean MAC address is now: $MacAddress"
		Return $MacAddress
	}
}

#Not really used for anything but here in the config to reduce clutter
$iSCSITargetPrefix =  'iqn.1991-05.com.microsoft:s2.contoso.com'

$config = @{
    AllNodes = @(
        @{
            NodeName = '*'
            PSDscAllowDomainUser = $true
            PSDscAllowPlainTextPassword = $true

            DomainName = 'CONTOSO.COM'
            TimeZone = 'Pacific Standard Time'
            TimeZoneIsSingleInstance = 'Yes'
        }
        @{
            NodeName = 'localhost'
        }
        @{
            NodeName             = 'SQL17-01'
            PrivateIPAddress     = '192.168.21.11'
            PrivateNetAdapterMAC = CleanMacAddress('00:50:56:8b:4f:d4')
            ClusterNetAdapterMAC = CleanMacAddress('00:50:56:8b:29:ef')
            Role                 = @('SQL2017', 'WindowsClusterFirstNode', 'SQL2017ClusterFirstNode', 'Core')
        }
        @{
            NodeName             = 'SQL17-02'
            PrivateIPAddress     = '192.168.21.12'
            PrivateNetAdapterMAC = CleanMacAddress('00:50:56:8b:b4:4d')
            ClusterNetAdapterMAC = CleanMacAddress('00:50:56:8b:c9:ec')
            Role                 = @('SQL2017', 'WindowsClusterAdditionalNode', 'SQL2017ClusterAdditionalNode', 'Core')
        }
    )

    SQL2017ActiveDirectory = @{
        OrganizationalUnitName   = 'SQL'
        OrganizationalUnitPath   = 'OU=Servers,DC=contoso,DC=com'
        OrganizationalUnitDesc   = 'All AD Objects related to the SQL 2017 Cluster are kept in this OU'

        gMSASecurityGroup        = 'gMSASQL2017'
        gMSASecurityGroupDesc    = 'Members of this group give permissions to use gMSA service accounts for the SQL 2017 Cluster'

        DBASecurityGroup         = 'SQL-Admins'
        DBASecurityGroupOU       = 'OU=SQL,OU=Groups,DC=contoso,DC=com'
        DBASecurityGroupMembers  = 'dbadminuser1', 'dbaadminuser2' #Add DBA admins to the sql-admins group
        DBASecurityGroupDesc     = 'DBA Administrators for the SQL 2017 Cluster'
    }

    SQL2017BaselineOS = @{
        PrivateNetAdapter = @{
            Name            = 'Private'
            AddressFamily   = 'IPv4'
            Dhcp            = 'Disabled'
        }

        ClusterNetAdapter = @{
            Name            = 'Cluster'
            AddressFamily   = 'IPv4'
            Dhcp            = 'Enabled'
        }

        iSCSITargetPortal = '172.16.0.100'

        SQLQuorumDrive = @{
            DiskId             = 1
            iSCSITarget        = "$iSCSITargetPrefix-tgt0" #Set proper iscsi target here
            DriveLetter        = "Q"
            AllocationUnitSize = 4KB
            Label              = "Cluster Quorum"
        }

        SQLDataDrive = @{
            DiskId             = 2
            iSCSITarget        = "$iSCSITargetPrefix-tgt1" #Set proper iscsi target here
            DriveLetter        = "M"
            AllocationUnitSize = 64KB
            Label              = "SQL Data"
        }

        SQLBackupDrive = @{
            DiskId             = 3
            iSCSITarget        = "$iSCSITargetPrefix-tgt2" #Set proper iscsi target here
            DriveLetter        = "X"
            AllocationUnitSize = 64KB
            Label              = "SQL Backup"
        }
    }

    SQL2017WindowsCluster = @{
        ClusterName      = 'SQL-CLUSTER'
        ClusterIPAddress = '172.16.0.101/24'

        ClusterNetworkPublic       = '172.16.0.0'
        ClusterNetworkPublicMask   = '255.255.255.0'
        ClusterNetworkPublicName   = 'Public'
        ClusterNetworkPublicRole   = '3' #ClusterAndClient
        ClusterNetworkPublicMetric = '10'

        ClusterNetworkHeartBeat       = '192.168.21.0'
        ClusterNetworkHeartBeatMask   = '255.255.255.0'
        ClusterNetworkHeartBeatName   = 'Heartbeat'
        ClusterNetworkHeartBeatRole   = '1' #Cluster
        ClusterNetworkHeartBeatMetric = '200'
    }

    SQL2017Cluster = @{
        InstanceName        = 'MSSQLSERVER'
        Features            = 'SQLENGINE,AS'
        SQLCollation        = 'Latin1_General_CI_AS'
        SQLFilesSourcePath  = '\\fileserver\AppPackage\SQL' #Set to shared drive on network

        SQLClusterClientAccessName = 'SQL-MSSQL'
        SQLClusterIPAddress        = '172.16.0.102'
        SQLClusterGroupName        = 'SQL Server (MSSQLSERVER)'

        InstallSharedDir    = 'C:\Program Files\Microsoft SQL Server'
        InstallSharedWOWDir = 'C:\Program Files (x86)\Microsoft SQL Server'
        InstanceDir         = 'C:\Program Files\Microsoft SQL Server'

        svcAccountAgent     = ManagedServiceAccount('NEA\msaSQLAgent$')
        svcAccountAnalysis  = ManagedServiceAccount('NEA\msaSQLAnalys$')
        svcAccountEngine    = ManagedServiceAccount('NEA\msaSQLEngine$')
        SQLSysAdminAccounts = 'SQL2017-Admins'
        ASSysAdminAccounts  = 'SQL2017-Admins'

        InstallSQLDataDir   = 'M:\MSSQL\Data'
        SQLUserDBDir        = 'M:\MSSQL\Data'
        SQLUserDBLogDir     = 'M:\MSSQL\Log'
        SQLTempDBDir        = 'M:\MSSQL\Temp'
        SQLTempDBLogDir     = 'M:\MSSQL\Temp'
        SQLBackupDir        = 'X:\MSSQL\Backup'
        ASConfigDir         = 'M:\AS\Config'
        ASDataDir           = 'M:\AS\Data'
        ASLogDir            = 'M:\AS\Log'
        ASTempDir           = 'M:\AS\Temp'
        ASBackupDir         = 'X:\AS\Backup'
    }
}

Configuration SQL2017Configuration {
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [System.Management.Automation.PSCredential]
        $DomainAdminCredential,
        [ValidateNotNullorEmpty()]
        $DomainNodeName = $env:computername
    )

    Import-DscResource -ModuleName 'PSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'
    Import-DscResource -ModuleName 'xActiveDirectory'
    Import-DscResource -ModuleName 'ComputerManagementDsc'
    Import-DscResource -ModuleName 'NetworkingDsc'
    Import-DscResource -ModuleName 'iSCSIDSc'
    Import-DscResource -ModuleName 'StorageDsc'
    Import-DscResource -ModuleName 'xFailOverCluster'
    Import-DscResource -ModuleName 'SqlServerDSC'

    $SQL2017ActiveDirectory = $ConfigurationData.SQL2017ActiveDirectory
    $SQL2017BaselineOS      = $ConfigurationData.SQL2017BaselineOS
    $SQL2017WindowsCluster  = $ConfigurationData.SQL2017WindowsCluster
    $SQL2017Cluster         = $ConfigurationData.SQL2017Cluster

    #Baseline Settings for All Nodes
    Node $AllNodes.NodeName {
        ##### Rename Computer and join domain #####
        Computer 'JoinDomain' {
            Name       = $DomainNodeName
            DomainName = $Node.DomainName
            Credential = $DomainAdminCredential # Credential to join to domain
        }

        ##### Set Timezone #####
        TimeZone 'TimeZoneArab' {
            IsSingleInstance = $Node.TimeZoneIsSingleInstance
            TimeZone         = $Node.TimeZone
        }
    }

    #Baseline Settings for Server Core
    Node $AllNodes.Where{ $_.Role -eq 'Core' }.NodeName {
        ##### Set startup shell to powershell instead of cmd on core #####
        xRegistry 'SetStartupPowershell' {
            Ensure    = "Present"  # You can also set Ensure to "Absent"
            Key       = "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\winlogon"
            ValueName = "Shell"
            ValueData = 'PowerShell.exe -noExit -Command "$psversiontable"'
            Force     = $true
        }
    }

    #Baseline Settings for SQL2017 (Drives, Network, OS Related)
    Node $AllNodes.Where{ $_.Role -eq 'SQL2017' }.NodeName {
        #### Configure Active Directory Objects ####
        WindowsFeature 'RSATADPowershell' {
            Ensure    = 'Present'
            Name      = 'RSAT-AD-PowerShell'
            DependsOn = "[Computer]JoinDomain"
        }

        xADOrganizationalUnit 'CreateOUForSQL2017Objects' {
            Ensure      = 'Present'
            Name        = $SQL2017ActiveDirectory.OrganizationalUnitName
            Path        = $SQL2017ActiveDirectory.OrganizationalUnitPath
            Description = $SQL2017ActiveDirectory.OrganizationalUnitDesc
            Credential  = $DomainAdminCredential
            DependsOn   = '[WindowsFeature]RSATADPowershell'
        }

        xADComputer 'EnsureNodesExist' {
            Ensure                        = 'Present'
            ComputerName                  = $Node.NodeName
            DisplayName                   = $Node.NodeName
            Path                          = -join("OU=",$SQL2017ActiveDirectory.OrganizationalUnitName,",", $SQL2017ActiveDirectory.OrganizationalUnitPath)
            DomainAdministratorCredential = $DomainAdminCredential
            DependsOn                     = '[Computer]JoinDomain', '[xADOrganizationalUnit]CreateOUForSQL2017Objects'
        }

        xADGroup 'CreategMSASecurityGroup' {
            Ensure           = 'Present'
            GroupName        = $SQL2017ActiveDirectory.gMSASecurityGroup
            DisplayName      = $SQL2017ActiveDirectory.gMSASecurityGroup
            MembersToInclude = -join($Node.NodeName,"$")
            Path             = -join("OU=",$SQL2017ActiveDirectory.OrganizationalUnitName,",", $SQL2017ActiveDirectory.OrganizationalUnitPath)
            Description      = $SQL2017ActiveDirectory.gMSASecurityGroupDesc
            Credential       = $DomainAdminCredential
            DependsOn        = '[xADComputer]EnsureNodesExist', '[xADOrganizationalUnit]CreateOUForSQL2017Objects'
        }

        xADGroup 'CreateDBASecurityGroup' {
            Ensure      = 'Present'
            GroupName   = $SQL2017ActiveDirectory.DBASecurityGroup
            DisplayName = $SQL2017ActiveDirectory.DBASecurityGroup
            Members     = $SQL2017ActiveDirectory.DBASecurityGroupMembers
            Path        = -join("OU=",$SQL2017ActiveDirectory.OrganizationalUnitName,",", $SQL2017ActiveDirectory.OrganizationalUnitPath)
            Description = $SQL2017ActiveDirectory.DBASecurityGroupDesc
            Credential  = $DomainAdminCredential
            DependsOn   = '[xADComputer]EnsureNodesExist', '[xADOrganizationalUnit]CreateOUForSQL2017Objects'
        }

        #region Configure Private Network Adapter
        NetAdapterName 'RenameNetAdapterPrivate' {
            NewName    = $SQL2017BaselineOS.PrivateNetAdapter.Name
            MacAddress = $Node.PrivateNetAdapterMAC
        }

        NetIPInterface 'DisableDhcpPrivate' {
            InterfaceAlias = $SQL2017BaselineOS.PrivateNetAdapter.Name
            AddressFamily  = $SQL2017BaselineOS.PrivateNetAdapter.AddressFamily
            Dhcp           = $SQL2017BaselineOS.PrivateNetAdapter.Dhcp
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrivate'
        }

        IPAddress 'SetIPv4Address' {
            InterfaceAlias = $SQL2017BaselineOS.PrivateNetAdapter.Name
            IPAddress      = $Node.PrivateIPAddress
            AddressFamily  = $SQL2017BaselineOS.PrivateNetAdapter.AddressFamily
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrivate'
        }

        NetAdapterBinding 'DisableIPv6Private' {
            InterfaceAlias = $SQL2017BaselineOS.PrivateNetAdapter.Name
            ComponentId    = 'ms_tcpip6'
            State          = 'Disabled'
            DependsOn      = '[NetAdapterName]RenameNetAdapterPrivate'
        }
        #endregion Configure Private Network Adapter

        ##### Configure Public Cluster Network Adapter #####
        NetAdapterName 'RenameNetAdapterCluster' {
            NewName    = $SQL2017BaselineOS.ClusterNetAdapter.Name
            MacAddress = $Node.ClusterNetAdapterMAC
        }

        NetIPInterface 'EnableDhcpClientCluster' {
            InterfaceAlias = $SQL2017BaselineOS.ClusterNetAdapter.Name
            AddressFamily  = $SQL2017BaselineOS.ClusterNetAdapter.AddressFamily
            Dhcp           = $SQL2017BaselineOS.ClusterNetAdapter.Dhcp
            DependsOn      = '[NetAdapterName]RenameNetAdapterCluster'
        }

        NetAdapterBinding 'DisableIPv6Cluster' {
            InterfaceAlias = $SQL2017BaselineOS.ClusterNetAdapter.Name
            ComponentId    = 'ms_tcpip6'
            State          = 'Disabled'
            DependsOn      = '[NetAdapterName]RenameNetAdapterCluster'
        }

        ##### Configure iSCSI Drives #####
        Service 'iSCSIServiceFirstAttempt' {
            Name        = 'MSiSCSI'
            StartupType = 'Automatic'
            State       = 'Running'
        }

        xService 'iSCSIService' {
            Name        = 'MSiSCSI'
            StartupType = 'Automatic'
            State       = 'Running'
        }

        iSCSIInitiator 'iSCSIInitiateSQLQuorumDrive' {
            Ensure                 = 'Present'
            NodeAddress            = $SQL2017BaselineOS.SQLQuorumDrive.iSCSITarget
            TargetPortalAddress    = $SQL2017BaselineOS.iSCSITargetPortal
            IsPersistent           = $true
            DependsOn              = "[xService]iSCSIService", "[Computer]JoinDomain"
        }

        iSCSIInitiator 'iSCSIInitiateSQLDataDrive' {
            Ensure                 = 'Present'
            NodeAddress            = $SQL2017BaselineOS.SQLDataDrive.iSCSITarget
            TargetPortalAddress    = $SQL2017BaselineOS.iSCSITargetPortal
            IsPersistent           = $true
            DependsOn              = "[xService]iSCSIService"
        }

        iSCSIInitiator 'iSCSIInitiateSQLBackupDrive' {
            Ensure                 = 'Present'
            NodeAddress            = $SQL2017BaselineOS.SQLBackupDrive.iSCSITarget
            TargetPortalAddress    = $SQL2017BaselineOS.iSCSITargetPortal
            IsPersistent           = $true
            DependsOn              = "[xService]iSCSIService"
        }

        Firewall 'AddFirewallRuleSQLServer' {
            Ensure                = 'Present'
            Name                  = 'SQL Server'
            DisplayName           = 'SQL Server'
            Group                 = 'SQL Cluster'
            Enabled               = 'True'
            Profile               = 'Domain', 'Private'
            Direction             = 'Inbound'
            LocalPort             = '1433'
            Protocol              = 'TCP'
            Description           = 'SQL Server Engine'
        }

        Firewall 'AddFirewallRuleSQLAdminConn' {
            Ensure                = 'Present'
            Name                  = 'SQL Admin Connection'
            DisplayName           = 'SQL Admin Connection'
            Group                 = 'SQL Cluster'
            Enabled               = 'True'
            Profile               = 'Domain', 'Private'
            Direction             = 'Inbound'
            LocalPort             = '1434'
            Protocol              = 'TCP'
            Description           = 'SQL Admin Connection'
        }

        Firewall 'AddFirewallRuleSQLDatabaseManagement' {
            Ensure                = 'Present'
            Name                  = 'SQL Database Management'
            DisplayName           = 'SQL Database Management'
            Group                 = 'SQL Cluster'
            Enabled               = 'True'
            Profile               = 'Domain', 'Private'
            Direction             = 'Inbound'
            LocalPort             = '1434'
            Protocol              = 'UDP'
            Description           = 'SQL Database Management'
        }

        Firewall 'AddFirewallRuleSQLServiceBroker' {
            Ensure                = 'Present'
            Name                  = 'SQL Service Broker'
            DisplayName           = 'SQL Service Broker'
            Group                 = 'SQL Cluster'
            Enabled               = 'True'
            Profile               = 'Domain', 'Private'
            Direction             = 'Inbound'
            LocalPort             = '4022'
            Protocol              = 'TCP'
            Description           = 'SQL Service Broker'
        }

        Firewall 'AddFirewallRuleSQLDebuggerRPC' {
            Ensure                = 'Present'
            Name                  = 'SQL Debugger/RPC'
            DisplayName           = 'SQL Debugger/RPC'
            Group                 = 'SQL Cluster'
            Enabled               = 'True'
            Profile               = 'Domain', 'Private'
            Direction             = 'Inbound'
            LocalPort             = '135'
            Protocol              = 'TCP'
            Description           = 'SQL Debugger/RPC'
        }

        Firewall 'AddFirewallRuleSQLAnalysisServices' {
            Ensure                = 'Present'
            Name                  = 'SQL Analysis Services'
            DisplayName           = 'SQL Analysis Services'
            Group                 = 'SQL Cluster'
            Enabled               = 'True'
            Profile               = 'Domain', 'Private'
            Direction             = 'Inbound'
            LocalPort             = '2383'
            Protocol              = 'TCP'
            Description           = 'SQL Analysis Services'
        }

        Firewall 'AddFirewallRuleSQLBrowser' {
            Ensure                = 'Present'
            Name                  = 'SQL Browser'
            DisplayName           = 'SQL Browser'
            Group                 = 'SQL Cluster'
            Enabled               = 'True'
            Profile               = 'Domain', 'Private'
            Direction             = 'Inbound'
            LocalPort             = '2382'
            Protocol              = 'TCP'
            Description           = 'SQL Browser'
        }

        FirewallProfile 'ConfigureFirewallDomainProfile' {
            Name = 'Domain'
            Enabled = 'True'
            DefaultInboundAction = 'Block'
            DefaultOutboundAction = 'Allow'
            AllowInboundRules = 'True'
            NotifyOnListen = 'True'
            AllowUnicastResponseToMulticast = 'True'
        }

        FirewallProfile 'ConfigureFirewallPrivateProfile' {
            Name = 'Private'
            Enabled = 'True'
            DefaultInboundAction = 'Block'
            DefaultOutboundAction = 'Allow'
            AllowInboundRules = 'True'
            NotifyOnListen = 'True'
            AllowUnicastResponseToMulticast = 'True'
        }

    }

    #Baseline Settings for SQL2017 Windows Cluster (First Node)
    Node $AllNodes.Where{ $_.Role -eq 'WindowsClusterFirstNode' }.NodeName {
        WindowsFeature 'AddFailoverFeature' {
            Ensure    = 'Present'
            Name      = 'Failover-clustering'
            DependsOn = "[Computer]JoinDomain"
        }

        WindowsFeature 'AddRemoteServerAdministrationToolsClusteringPowerShellFeature' {
            Ensure    = 'Present'
            Name      = 'RSAT-Clustering-PowerShell'
            DependsOn = '[WindowsFeature]AddFailoverFeature'
        }

        WindowsFeature 'AddRemoteServerAdministrationToolsClusteringCmdInterfaceFeature' {
            Ensure    = 'Present'
            Name      = 'RSAT-Clustering-CmdInterface'
            DependsOn = '[WindowsFeature]AddRemoteServerAdministrationToolsClusteringPowerShellFeature'
        }

        xCluster 'CreateCluster' {
            Name                          = $SQL2017WindowsCluster.ClusterName
            StaticIPAddress               = $SQL2017WindowsCluster.ClusterIPAddress
            DomainAdministratorCredential = $DomainAdminCredential
            DependsOn                     = '[WindowsFeature]AddRemoteServerAdministrationToolsClusteringCmdInterfaceFeature', '[NetAdapterName]RenameNetAdapterPrivate', '[NetAdapterName]RenameNetAdapterCluster'
        }

        xADObjectPermissionEntry 'FullControlClusterObject' {
            Ensure                             = 'Present'
            IdentityReference                  = -join($SQL2017WindowsCluster.ClusterName,'$')
            Path                               = -join("OU=",$SQL2017ActiveDirectory.OrganizationalUnitName,",", $SQL2017ActiveDirectory.OrganizationalUnitPath)
            ActiveDirectoryRights              = 'GenericAll'
            AccessControlType                  = 'Allow'
            ObjectType                         = '00000000-0000-0000-0000-000000000000'
            ActiveDirectorySecurityInheritance = 'None'
            InheritedObjectType                = '00000000-0000-0000-0000-000000000000'
            PsDscRunAsCredential               = $DomainAdminCredential
            DependsOn                          = '[xCluster]CreateCluster'
        }

        xClusterNetwork 'ChangeNetwork-172' {
            Address     = $SQL2017WindowsCluster.ClusterNetworkPublic
            AddressMask = $SQL2017WindowsCluster.ClusterNetworkPublicMask
            Name        = $SQL2017WindowsCluster.ClusterNetworkPublicName
            Role        = $SQL2017WindowsCluster.ClusterNetworkPublicRole
            Metric      = $SQL2017WindowsCluster.ClusterNetworkPublicMetric
            DependsOn   = '[xCluster]CreateCluster'
        }

        xClusterNetwork 'ChangeNetwork-192' {
            Address     = $SQL2017WindowsCluster.ClusterNetworkHeartBeat
            AddressMask = $SQL2017WindowsCluster.ClusterNetworkHeartBeatMask
            Name        = $SQL2017WindowsCluster.ClusterNetworkHeartBeatName
            Role        = $SQL2017WindowsCluster.ClusterNetworkHeartBeatRole
            Metric      = $SQL2017WindowsCluster.ClusterNetworkHeartBeatMetric
            DependsOn   = '[xCluster]CreateCluster'
        }


        Disk 'VolumeSQLQuorumDrive' {
            DiskId             = $SQL2017BaselineOS.SQLQuorumDrive.DiskId
            DriveLetter        = $SQL2017BaselineOS.SQLQuorumDrive.DriveLetter
            AllocationUnitSize = $SQL2017BaselineOS.SQLQuorumDrive.AllocationUnitSize
            FSLabel            = $SQL2017BaselineOS.SQLQuorumDrive.Label
            DependsOn          = '[iSCSIInitiator]iSCSIInitiateSQLQuorumDrive'
        }

        Disk 'VolumeSQLDataDrive' {
            DiskId             = $SQL2017BaselineOS.SQLDataDrive.DiskId
            DriveLetter        = $SQL2017BaselineOS.SQLDataDrive.DriveLetter
            AllocationUnitSize = $SQL2017BaselineOS.SQLDataDrive.AllocationUnitSize
            FSLabel            = $SQL2017BaselineOS.SQLDataDrive.Label
            DependsOn          = '[iSCSIInitiator]iSCSIInitiateSQLDataDrive'
        }

        Disk 'VolumeSQLBackupDrive' {
            DiskId             = $SQL2017BaselineOS.SQLBackupDrive.DiskId
            DriveLetter        = $SQL2017BaselineOS.SQLBackupDrive.DriveLetter
            AllocationUnitSize = $SQL2017BaselineOS.SQLBackupDrive.AllocationUnitSize
            FSLabel            = $SQL2017BaselineOS.SQLBackupDrive.Label
            DependsOn          = '[iSCSIInitiator]iSCSIInitiateSQLBackupDrive'
        }

        WaitForVolume 'WaitForSQLQuorumDrive' {
            DriveLetter      = $SQL2017BaselineOS.SQLQuorumDrive.DriveLetter
            RetryIntervalSec = 5
            RetryCount       = 10
            DependsOn        = '[Disk]VolumeSQLQuorumDrive'
        }

        xClusterDisk 'AddClusterDiskQuorum' {
            Number    = 1
            Ensure    = 'Present'
            Label     = 'WindowsCluster-Quorum'
            DependsOn = '[xCluster]CreateCluster', '[WaitForVolume]WaitForSQLQuorumDrive'
        }

        xClusterQuorum 'SetQuorumToNodeAndDiskMajority' {
            IsSingleInstance = 'Yes'
            Type             = 'NodeAndDiskMajority'
            Resource         = 'WindowsCluster-Quorum'
            DependsOn        = '[xClusterDisk]AddClusterDiskQuorum'
        }

        WaitForVolume 'WaitForSQLDataDrive' {
            DriveLetter      = $SQL2017BaselineOS.SQLDataDrive.DriveLetter
            RetryIntervalSec = 5
            RetryCount       = 10
            DependsOn        = '[Disk]VolumeSQLDataDrive'
        }

        xClusterDisk 'AddClusterDiskSQLDataDrive' {
            Number    = 2
            Ensure    = 'Present'
            Label     = 'SQL2017-Data'
            DependsOn = '[xCluster]CreateCluster', '[WaitForVolume]WaitForSQLDataDrive'
        }

        WaitForVolume 'WaitForSQLBackupDrive' {
            DriveLetter      = $SQL2017BaselineOS.SQLBackupDrive.DriveLetter
            RetryIntervalSec = 5
            RetryCount       = 10
            DependsOn        = '[Disk]VolumeSQLBackupDrive'
        }

        xClusterDisk 'AddClusterDisk-SQL2017-Backup' {
            Number    = 3
            Ensure    = 'Present'
            Label     = 'SQL2017-Backup'
            DependsOn = '[xCluster]CreateCluster', '[WaitForVolume]WaitForSQLBackupDrive'
        }

    }

    #Baseline Settings for SQL2017 Windows Cluster (Additional Node)
    Node $AllNodes.Where{ $_.Role -eq 'WindowsClusterAdditionalNode' }.NodeName {
        WindowsFeature 'AddFailoverFeature' {
            Ensure    = 'Present'
            Name      = 'Failover-clustering'
            DependsOn = "[Computer]JoinDomain"
        }

        WindowsFeature 'AddRemoteServerAdministrationToolsClusteringPowerShellFeature' {
            Ensure    = 'Present'
            Name      = 'RSAT-Clustering-PowerShell'
            DependsOn = '[WindowsFeature]AddFailoverFeature'
        }

        WindowsFeature 'AddRemoteServerAdministrationToolsClusteringCmdInterfaceFeature' {
            Ensure    = 'Present'
            Name      = 'RSAT-Clustering-CmdInterface'
            DependsOn = '[WindowsFeature]AddRemoteServerAdministrationToolsClusteringPowerShellFeature'
        }
        xWaitForCluster 'WaitForCluster' {
            Name             = $SQL2017WindowsCluster.ClusterName
            RetryIntervalSec = 10
            RetryCount       = 60
            DependsOn        = '[WindowsFeature]AddRemoteServerAdministrationToolsClusteringCmdInterfaceFeature'
        }

        xCluster 'JoinSecondNodeToCluster' {
            Name                          = $SQL2017WindowsCluster.ClusterName
            StaticIPAddress               = $SQL2017WindowsCluster.ClusterIPAddress
            DomainAdministratorCredential = $DomainAdminCredential
            DependsOn                     = '[xWaitForCluster]WaitForCluster', '[NetAdapterName]RenameNetAdapterPrivate', '[NetAdapterName]RenameNetAdapterCluster'
        }
    }

    #SQL Setup for SQL2017 Cluster (First Node)
    Node $AllNodes.Where{ $_.Role -eq 'SQL2017ClusterFirstNode' }.NodeName {

        WindowsFeature 'NetFramework45' {
            Ensure = 'Present'
            Name   = 'NET-Framework-45-Core'
        }

        SqlSetup 'InstallSQL2017FirstNode' {
            Action                     = 'InstallFailoverCluster'
            ForceReboot                = $false
            UpdateEnabled              = 'False'
            SourcePath                 = $SQL2017Cluster.SQLFilesSourcePath
            SourceCredential           = $DomainAdminCredential

            InstanceName               = $SQL2017Cluster.InstanceName
            Features                   = $SQL2017Cluster.Features

            InstallSharedDir           = $SQL2017Cluster.InstallSharedDir
            InstallSharedWOWDir        = $SQL2017Cluster.InstallSharedWOWDir
            InstanceDir                = $SQL2017Cluster.InstanceDir

            SQLCollation               = $SQL2017Cluster.SQLCollation
            SQLSvcAccount              = $SQL2017Cluster.svcAccountEngine
            AgtSvcAccount              = $SQL2017Cluster.svcAccountAgent
            SQLSysAdminAccounts        = $SQL2017Cluster.SQLSysAdminAccounts
            ASSvcAccount               = $SQL2017Cluster.svcAccountAnalysis
            ASSysAdminAccounts         = $SQL2017Cluster.ASSysAdminAccounts

            # Drive D: must be a shared disk.
            InstallSQLDataDir          = $SQL2017Cluster.InstallSQLDataDir
            SQLUserDBDir               = $SQL2017Cluster.SQLUserDBDir
            SQLUserDBLogDir            = $SQL2017Cluster.SQLUserDBLogDir
            SQLTempDBDir               = $SQL2017Cluster.SQLTempDBDir
            SQLTempDBLogDir            = $SQL2017Cluster.SQLTempDBLogDir
            SQLBackupDir               = $SQL2017Cluster.SQLBackupDir
            ASConfigDir                = $SQL2017Cluster.ASConfigDir
            ASDataDir                  = $SQL2017Cluster.ASDataDir
            ASLogDir                   = $SQL2017Cluster.ASLogDir
            ASBackupDir                = $SQL2017Cluster.ASBackupDir
            ASTempDir                  = $SQL2017Cluster.ASTempDir

            FailoverClusterNetworkName = $SQL2017Cluster.SQLClusterClientAccessName
            FailoverClusterIPAddress   = $SQL2017Cluster.SQLClusterIPAddress
            FailoverClusterGroupName   = $SQL2017Cluster.SQLClusterGroupName

            PsDscRunAsCredential       = $DomainAdminCredential
            DependsOn                  = '[WindowsFeature]NetFramework45', '[Computer]JoinDomain', '[xADObjectPermissionEntry]FullControlClusterObject'
        }
    }

    #SQL Setup for SQL2017 Cluster (Additional Node)
    Node $AllNodes.Where{ $_.Role -eq 'SQL2017ClusterAdditionalNode' }.NodeName {
        WindowsFeature 'NetFramework45' {
            Ensure = 'Present'
            Name   = 'NET-Framework-45-Core'
        }

        SqlSetup 'InstallSQL2017AdditionalNode' {
            Action                     = 'AddNode'
            ForceReboot                = $false
            UpdateEnabled              = 'False'
            SourcePath                 = $SQL2017Cluster.SQLFilesSourcePath
            SourceCredential           = $DomainAdminCredential

            InstanceName               = $SQL2017Cluster.InstanceName
            Features                   = $SQL2017Cluster.Features

            SQLSvcAccount              = $SQL2017Cluster.svcAccountEngine
            AgtSvcAccount              = $SQL2017Cluster.svcAccountAgent
            ASSvcAccount               = $SQL2017Cluster.svcAccountAnalysis

            FailoverClusterNetworkName = $SQL2017Cluster.SQLClusterClientAccessName

            PsDscRunAsCredential       = $DomainAdminCredential
            DependsOn                  = '[WindowsFeature]NetFramework45', '[Computer]JoinDomain', '[xCluster]JoinSecondNodeToCluster'
        }
    }
}


