cls
#################################################################################
#
#       Ivanti Patch REST API Example                       
#		
# 		Purpose: Baseline Patching during mdt deployments
# 		Source: https://help.ivanti.com/iv/help/en_US/isec/API/Topics/Start-to-Finish-Example-Using-PS.htm
#       
#  		Edwin ten Haaf T4Change 
#
#	   
#   	Version: 0.1 changed to adapt to customer needs
# 		Version: 0.2 Force Windows Update to automatic (prevent errorcode 1058)
#       Version: 0.3 Switch to Ip adress instead of machinename to scan (Non domain joined, automated deployments)
#
#       Setup
#       Get ST root cerificate (insert at line 66) - embedded and changed from user to machine (prompt bypass)
#		Secure Deploymentshare (remove read access everyone and use AD groups)
#       Define Console & machine Accounts (line 46-50)
# 		Change $apiServer to your Ivantipatch(console) server (line 54)		
# 		Change variables for templates to use (starts at line 565)
#		Change Password $secpasswd(line 599)
#################################################################################

#Windows Update to automatic (prevent errorcode 1058)
Set-Service -Name wuauserv -StartupType Automatic

# Reboot the machine to scan immediately after deployment
$reboot = $true
 
# Deploy ALL missing patches
$deployPatches = $true

# Delete the sample data from the application
$deleteSampleData = $true

# IP Address, NETBios Name or FQDN
$machineToScan =  (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias Ethernet0 ).IPv4Address
 
# What CVE do you want to add to the patch group and deploy to the machine to scan?
#
# The null patches is always scanned for. This will be in addition to
#
# Example @("CVE1", "CVE2")
$cveList = @()
 
# What is the credential user name that is an administrator of the console machine?  This script defaults it to the current user.
#$consoleAuthenthicationAndSessionUserName = "$env:USERDOMAIN\$env:USERNAME"
$consoleAuthenthicationAndSessionUserName = "<domain\username>"
# Localadmin account on endpoint 
$MachineAdministrator = "$env:computername\<username>"

# What is the Console's IP Address, NETBios Name or FQDN?  The script defaults to the current computer name.
#$apiServer = if ([String]::IsNullOrEmpty($env:userdnsdomain)) {"$env:computername"} else {"$env:computername.$env:userdnsdomain"}
$apiServer = "<Patch server fqdn>"

$apiLocalPort = 3121

#Deploy issuing Certificate
#
# 
<#
.SYNOPSIS
 Imports the issuing certificate into the local machines certificate store.
#>
$derEncodedBytes = '<certificate>'

$decodedBytes = [System.Convert]::FromBase64String($derEncodedBytes)
$isPS2 = $PSVersionTable.PSVersion.Major -eq 2
if($isPS2)
{
    [void][Reflection.Assembly]::LoadWithPartialName("System.Security") 
}
else
{
    Add-Type -AssemblyName "System.Security" > $null
}

try
{
    Push-Location 'Cert:\LocalMachine\Root'
    $certificateMissing = (Get-ChildItem | Where-Object { $_.Thumbprint -eq $iSeCIssuingCertificate.Thumbprint } ) -eq $null
    if($certificateMissing)
    {
        $iSeCIssuingCertificate = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$decodedBytes)
        
        $store = Get-Item 'Cert:\LocalMachine\Root'
        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($iSeCIssuingCertificate)
    }
}
finally
{
    Pop-Location

    if($store -ne $null)
    {
        $store.Close()
    }

    if(-not $isPS2)
    {
        if($iSeCIssuingCertificate -ne $null)
        {
            $iSeCIssuingCertificate.Dispose()
            $iSeCIssuingCertificate = $null
        }

        if($store -ne $null)
        {
            $store.Dispose()
            $store = $null
        }
    }
}


 
$Uris =
@{
	AssetScanTemplates = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/asset/scantemplates"
	Credentials = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/credentials"
	CertificateConsole = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/configuration/certificate"	
	DistributionServers = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/distributionservers"
	Hypervisors = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/virtual/hypervisors"
	IPRanges = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/ipranges"
	MachineGroups = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/machinegroups"
	MetadataVendors = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/metadata/vendors"
	NullPatch = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/patches?bulletinIds=MSST-001"
	Operations = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/operations"
	Patches = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/patches"
	PatchDeployments = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/patch/deployments"
	PatchDeployTemplates = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/patch/deploytemplates"
	PatchDownloads = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/patch/downloads"
	PatchDownloadsScansPatch = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/patch/downloads/scans"
	PatchGroups = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/patch/groups"
	PatchMetaData = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/patch/patchmetadata"
	PatchScans = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/patch/scans"
	PatchScanMachines = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/patch/scans/{0}/machines"
	PatchScanMachinesPatches = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/patch/scans/{0}/machines/{1}/patches"
	PatchScanTemplates = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/patch/scanTemplates"
	SessionCredentials = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/sessioncredentials"
	VCenters = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/virtual/vcenters"
	VirtualInfrastructure = "https://$apiServer`:$apiLocalPort/st/console/api/v1.0/virtual"
}
Add-Type -AssemblyName System.Security
#Encrypt using RSA
function Encrypt-RSAConsoleCert
{
	param
	(
		[Parameter(Mandatory=$True, Position = 0)]
		[Byte[]]$ToEncrypt,
		[Parameter(Mandatory=$True, Position = 1)]
		[PSCredential]$authenticationAndSessionCredential
	)
	try
	{
		$certResponse = Invoke-RestMethod $Uris.CertificateConsole -Method Get -Credential $authenticationAndSessionCredential
		[Byte[]] $rawBytes = ([Convert]::FromBase64String($certResponse.derEncoded))
		$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList @(,$rawBytes)
		$rsaPublicKey = $cert.PublicKey.Key;
 
		$encryptedKey = $rsaPublicKey.Encrypt($ToEncrypt, $True);
		return $encryptedKey
	}
		finally
	{
		$cert.Dispose();
	}
}
 
function Create-CredentialRequest
{
	param
	(
		[Parameter(Mandatory=$True, Position=0)]
		[String]$FriendlyName,
 
		[Parameter(Mandatory=$True, Position=1)]
		[String]$UserName,
 
		[Parameter(Mandatory=$True, Position=2)]
		[ValidateNotNull()]
		[SecureString]$Password,

		[Parameter(Mandatory=$True, Position = 3)]
		[PSCredential]$AuthenticationAndSessionCredential
	)
 
	$body = @{ "userName" = $UserName; "name" = $FriendlyName; }
	$bstr = [IntPtr]::Zero;
	try
	{
		## Create an AES 128 Session key.
		$algorithm = [System.Security.Cryptography.Xml.EncryptedXml]::XmlEncAES128Url
		$aes = [System.Security.Cryptography.SymmetricAlgorithm]::Create($algorithm);
		$keyBytes = $aes.Key;
 
		# Encrypt the session key with the console cert
		$encryptedKey = Encrypt-RSAConsoleCert -ToEncrypt $keyBytes -authenticationAndSessionCredential $AuthenticationAndSessionCredential
		$session = @{ "algorithmIdentifier" = $algorithm; "encryptedKey" = [Convert]::ToBase64String($encryptedKey); "iv" = [Convert]::ToBase64String($aes.IV); }
 
		# Encrypt the password with the Session key.
		$cryptoTransform = $aes.CreateEncryptor();
 
		# Copy the BSTR contents to a byte array, excluding the trailing string terminator.
		$size = [System.Text.Encoding]::Unicode.GetMaxByteCount($Password.Length - 1);
 
		$bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password)
		$clearTextPasswordArray = New-Object Byte[] $size
		[System.Runtime.InteropServices.Marshal]::Copy($bstr, $clearTextPasswordArray, 0, $size)
		$cipherText = $cryptoTransform.TransformFinalBlock($clearTextPasswordArray, 0 , $size)
 
		$passwordJson = @{ "cipherText" = $cipherText; "protectionMode" = "SessionKey"; "sessionKey" = $session }
	}
	finally
	{
		# Ensure All sensitive byte arrays are cleared and all crypto keys/handles are disposed.
		if ($clearTextPasswordArray -ne $null)
		{
			[Array]::Clear($clearTextPasswordArray, 0, $size)
		}
		if ($keyBytes -ne $null)
		{
			[Array]::Clear($keyBytes, 0, $keyBytes.Length);
		}
		if ($bstr -ne [IntPtr]::Zero)
		{
			[System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
		}
		if ($cryptoTransform -ne $null)
		{
			$cryptoTransform.Dispose();
		}
		if ($aes -ne $null)
		{
			$aes.Dispose();
		}
	}
	$body.Add("password", $passwordJson)
	return $Body
}
function Get-PaginatedResults
{
	param
	(
		[String]$uri,
		[PSCredential]$authenticationAndSessionCredential
	)
 
	$entireList = [System.Collections.ArrayList]@()
	$nextUri = $uri
	do
	{
		$result = Invoke-RestMethod $nextUri -Method Get -ErrorAction Stop -Credential $authenticationAndSessionCredential 
		$result.value | Foreach-Object { $entireList.Add($_) }
 
		$nextUri = $result.links.next.href
	} until ($nextUri -eq $null)
 
	return $entireList
}

function Remove-RestResourceSafe
{
	param
	(
		[String]$Uri,
		[PSCredential] $authenticationAndSessionCredential
	)
	try
	{
		Invoke-RestMethod $uri -Method Delete -Credential $authenticationAndSessionCredential > $null
	}
	catch
	{
	}
}

function Wait-Operation {
	param(
		[String] $OperationLocation,
		[Int32] $TimeoutMinutes,
		[PSCredential]$authenticationAndSessionCredential
	)
 
	$startTime = [DateTime]::Now
	$operationResult = Invoke-RestMethod -Uri $OperationLocation -Method Get -Credential $authenticationAndSessionCredential 
	while ($operationResult.Status -eq 'Running')
	{
		if ([DateTime]::Now -gt $startTime.AddMinutes($TimeoutMinutes))
		{
			throw "Timed out waiting for operation to complete"
		}
 
		Start-Sleep 5
		$operationResult = Invoke-RestMethod -Uri $OperationLocation -Method Get -Credential $authenticationAndSessionCredential
	}
 
	return $operationResult
}

function Add-Credential
{
	Param
	(
		[String]$credentialName,
		[PSCredential]$credential,
		[PSCredential]$authenticationAndSessionCredential
	)
#	$body = @{ name = $credentialName; password = @{cipherText = $cipherText; protectionMode = "SessionKey"; sessionKey = "AES" }; username = $credential.UserName } | ConvertTo-Json -Depth 99
#	$response = Invoke-RestMethod -Uri $Uris.Credentials -Method Post -Body $body -ContentType "application/json" -Credential $authenticationAndSessionCredential 
 
	$body = Create-CredentialRequest -FriendlyName $credentialName -UserName $credential.UserName -Password $credential.Password -AuthenticationAndSessionCredential $authenticationAndSessionCredential | ConvertTo-Json -Depth 99
	$response = Invoke-RestMethod -Uri $Uris.Credentials -Method Post -Body $body -ContentType "application/json" -Credential $authenticationAndSessionCredential
	return $response
}

function Add-MachineGroup
{
	Param
	(
		[String]$groupName,
		[String]$machineName,
		[String]$machineAdminCredentialId,
		[PSCredential]$authenticationAndSessionCredential
	)
		$body =
			@{
				name = $groupName;
				discoveryFilters =  @(
				@{
					AdminCredentialId = $machineAdminCredentialId;
					category = "MachineName";
					name = $machineName
				})
			} |  ConvertTo-Json -Depth 99
	$response = Invoke-RestMethod -Uri $Uris.MachineGroups -Method Post -Body $body -ContentType "application/json" -Credential $authenticationAndSessionCredential

	return $response
}

function Add-CveToPatchGroup
{
	Param
	(
		[String]$id,
		[String]$cve,
		[PSCredential]$authenticationAndSessionCredential
	)
 
	$body = @{ Cve = $cve; } | ConvertTo-Json -Depth 99
	Invoke-RestMethod -Uri "$($Uris.PatchGroups)/$($id)/patches/cve" -Method Post -Body $body -ContentType "application/json" -Credential $authenticationAndSessionCredential > $null
}

function Add-NullPatchToPatchGroup
{
	Param
	(
		[String]$id,
		[PSCredential]$authenticationAndSessionCredential
	)
 
	$nullPatchResult = Invoke-RestMethod -Uri $Uris.NullPatch -Method Get -Credential $authenticationAndSessionCredential
	foreach($value in $nullPatchResult.value)
	{
		foreach ($vulnerability in $value.vulnerabilities)
		{
			$body = ConvertTo-Json -Depth 99 -InputObject  @(, $vulnerability.id)
			Invoke-RestMethod -Uri "$($Uris.PatchGroups)/$($id)/patches" -Method POST -Body $body -ContentType "application/json" -Credential $authenticationAndSessionCredential > $null
		}
	}
}

function Add-PatchGroup
{
	Param
	(
		[String]$groupName,
		[PSCredential]$authenticationAndSessionCredential
	)
	$body = @{ name = $groupName; } | ConvertTo-Json -Depth 99
	$response = Invoke-RestMethod -Uri $Uris.PatchGroups -Method Post -Body $body -ContentType "application/json" -Credential $authenticationAndSessionCredential
	return $response
}

function Add-PatchScanTemplate
{
	Param
	(
		[String]$templateName,
		[String]$patchGroupId,
		[PSCredential]$authenticationAndSessionCredential
	)
	$body = @{ name = $templateName; PatchFilter = @{ patchGroupFilterType = 'Scan'; patchGroupIds = @($patchGroupId) }} | ConvertTo-Json -Depth 99
	$response = Invoke-RestMethod -Uri $Uris.PatchScanTemplates -Method Post -Body $body -ContentType "application/json" -Credential $authenticationAndSessionCredential
	return $response
}

function Add-PatchDeployTemplate
{
	Param
	(
		[String]$templateName,
		[PSCredential]$authenticationAndSessionCredential
	)
 
	#never reboot
	if ($reboot)
	{
		# You want to reboot the machine immediately
		$body =@{
			name = $templateName;
			PostDeploymentReboot = @{
				options = @{
					powerState = 'Restart';
					countdownMinutes = 2;
					extendMinutes = 1;
					forceActionAfterMinutes = 1;
					loggedOnUserAction = 'ForceActionAfterMinutes';
					systemDialogSeconds = 10;
					userOptions = 'AllowExtension';
				}
			when = 'ImmediateIfRequired'
			}
		} | ConvertTo-Json -Depth 99;
	}
	else
	{
		$body =@{
			name = $templateName;
			PostDeploymentReboot = @{
			when = 'NoReboot'
			}
		} | ConvertTo-Json -Depth 99;
	}
 
	$response = Invoke-RestMethod -Uri $Uris.PatchDeployTemplates -Method Post -Body $body -ContentType "application/json" -Credential $authenticationAndSessionCredential 
	return $response
}

# Adds a session credential
function Add-SessionCredential
{
	Param
	(
		[PSCredential]$authenticationAndSessionCredential
	)

	# Using common code to create a secure credential request object.
	# For session credentials, only need to use the password property is used.
	$credentialRequest = Create-CredentialRequest -FriendlyName "unused" -UserName "unused" -Password $authenticationAndSessionCredential.Password -AuthenticationAndSessionCredential $authenticationAndSessionCredential
	$body = $credentialRequest.Password | ConvertTo-Json -Depth 99
	$response = Invoke-RestMethod -Uri $Uris.SessionCredentials -Method Post -Body $body -ContentType "application/json" -Credential $authenticationAndSessionCredential
	return $response
}

# Removes a session credential
function Remove-SessionCredential
{
	Param
	(
		[PSCredential]$authenticationAndSessionCredential
	)

	try
	{
		Invoke-RestMethod -Uri $Uris.SessionCredentials -Method Delete -ContentType "application/json" -Credential $authenticationAndSessionCredential
	}
	catch
	{
		# status code 404 indicates that the session cred did not exist.  This is common when running the script for the first time.
		if ($_.Exception.Response.StatusCode.value__ -ne 404)
		{
			throw
		}
	}
}

function Invoke-PatchAndDeploy
{
	Param
	(
		[String]$ScanTemplateName,
		[String]$MachineGroupName,
		[String]$DeployTemplateName,
		[String]$ScanName,
		[PSCredential]$authenticationAndSessionCredential
	)
 
	# Find scan template
	$allScanTemplates = Get-PaginatedResults $Uris.PatchScanTemplates $authenticationAndSessionCredential
	$foundScanTemplate = $allScanTemplates | Where-Object { $_.Name -eq $ScanTemplateName }
	if ($null -eq $foundScanTemplate)
	{
		Write-Error ("could not find patch scan template with name " + $ScanTemplateName)
	}
 
	# find machine group
	$allMachineGroups = Get-PaginatedResults $Uris.MachineGroups $authenticationAndSessionCredential
	$foundMachineGroup = $allMachineGroups | Where-Object { $_.Name -eq $MachineGroupName }
	if ($null -eq $foundMachineGroup)
	{
		Write-Error ("could not find machine group with name " + $MachineGroupName)
	}
 
	# Find deploy template
	$allDeployTemplates = Get-PaginatedResults $Uris.PatchDeployTemplates $authenticationAndSessionCredential
	$foundDeployTemplate = $allDeployTemplates | Where-Object { $_.Name -eq $DeployTemplateName }
	if ($null -eq $foundDeployTemplate)
	{
		Write-Error ("could not find patch deploy template with name " + $DeployTemplateName)
	}
 
	# perform the scan
	$body = @{ MachineGroupIds = @( $foundMachineGroup.id ); Name = $ScanName; TemplateId = $foundScanTemplate.id } | ConvertTo-Json -Depth 99
	Write-Host "Starting scan, using Deploymenttemplate:"  $DeployTemplateName "and ScanTemplate:" $ScanTemplateName "on device" $env:computername "with ip" $machineToScan
	$scanOperation = Invoke-WebRequest -Uri $Uris.PatchScans -Method Post -Body $body -Credential $authenticationAndSessionCredential -ContentType 'application/json' 
 
	# wait for scan to complete
	$completedScan = Wait-Operation $scanOperation.headers['Operation-Location'] 5 $authenticationAndSessionCredential
 
	# get the scan id for future use
	$scan = Invoke-RestMethod -Uri $completedScan.resourceLocation -Credential $authenticationAndSessionCredential -Method GET
	Write-Host ( "Scan complete " + $scan.id)
 
	# get the scan id for future use
	$machines = Invoke-RestMethod -Uri $scan.links.machines.href -Credential $authenticationAndSessionCredential -Method GET
 
	foreach ($machineScanned in $machines)
	{
		foreach ($value in $machineScanned.value)
		{
			if (($value.installedPatchCount -gt 0) -or ($value.missingPatchCount -gt 0))
			{
				$patches = Invoke-RestMethod -Uri $value.links.patches.href -Credential $authenticationAndSessionCredential -Method GET
				foreach ($patch in $patches.value)
				{
					if ($deployPatches -eq $false -or $patch.scanState -ne "MissingPatch")
					{
						Write-Host ( $patch.bulletinId + " / " + $patch.kb + " (" + $patch.scanState + ") - NOT being deployed." )
					}
					else
					{
						Write-Host ( $patch.bulletinId + " / " + $patch.kb + " (" + $patch.scanState + ") - DEPLOYING." )
					}
				}
			}
			else
			{
				Write-Host ( "No patches were found")
			}
		}
	}
	# perform the deployment
	if ($deployPatches)
	{
		Write-Host "Starting deployment"
		$body = @{ ScanId=$scan.id; TemplateId = $foundDeployTemplate.id } | ConvertTo-Json -Depth 99
		$deploy = Invoke-WebRequest -Uri $Uris.PatchDeployments -Method Post -Body $body -Credential $authenticationAndSessionCredential -ContentType 'application/json'
 
		# wait until deployment has a deployment resource location
		$operationUri = $deploy.Headers['Operation-Location']
		$operation = Invoke-RestMethod -Uri $operationUri -Credential $authenticationAndSessionCredential -Method GET
 
		while((($null -eq $operation.resourceLocation) -or ($operation.operation -eq "PatchDownload")) -and -not ($operation.status -eq "Succeeded"))
		{
			if (($operation.operation -eq "PatchDownload") -and ($null -ne $operation.percentComplete))
			{
				Write-Host ("Downloading patches..." + $operation.percentComplete + "%")
			}
			Start-Sleep -Seconds 1
			$operation = Invoke-RestMethod -Uri $operationUri -Credential $authenticationAndSessionCredential -Method GET
		}
 
		# It's possible we didn't have anything to patch in which case we're already succeeded.
		# If so, don't both getting machine statuses as it will never return anything good.
		if (-not $operation.status -eq "Succeeded")
		{
			# start getting deployment detailed status updates
			$statusUri = $deploy.Headers['Location'] + '/machines'
			$machineStatuses = Invoke-RestMethod $statusUri -Credential $authenticationAndSessionCredential -Method GET
 
			# now start getting and displaying the statuses
			while(($machineStatuses.value[0].overallState -ne "Complete") -and ($machineStatuses.value[0].overallState -ne "Failed"))
			{
				Write-Host ("Overall Status = " + $machineStatuses.value[0].overallState)
				Write-Host ("Status Description = " + $machineStatuses.value[0].statusDescription)
 
				$updateDelaySeconds = 30
 
				# only check for new updates every $updateDelaySeconds
				Start-Sleep  -Seconds $updateDelaySeconds
				$machineStatuses = Invoke-RestMethod $statusUri -Credential $authenticationAndSessionCredential -Method GET
			}
		}
		Write-Host "Deployment scheduled"
	}
	else
	{
		Write-Host "You specified NOT to Deploy the patches."
	}
}
 
function Invoke-ScanAndDeploy
{
	Param
	(
		[parameter(Mandatory = $true)]
		[String]$machineToScan = $(throw "Must supply a machine to scan."),
		[parameter(Mandatory = $false)]
		[String[]]$cveToScanFor,		
		[parameter(Mandatory = $true)]
		[PSCredential]$machineAdminCredential = $(throw "Must supply machine administrator credentials."),
		[parameter(Mandatory = $true)]
		[PSCredential]$authenticationAndSessionCredential = $(throw "Must supply authentication and session credentials.")
	)
 
	$toDelete = [System.Collections.ArrayList]@()
	try
	{
		# For testing purposes, remove the session credentials before re-creating.
		Remove-SessionCredential $authenticationAndSessionCredential
		Add-SessionCredential $authenticationAndSessionCredential

		$uid = [Guid]::NewGuid()
		$machineAdminCredentialName = "Machine Admin Credential -" + $uid
		$machineAdminCredentiaRef = Add-Credential $machineAdminCredentialName $machineAdminCredential $authenticationAndSessionCredential
		$toDelete.Add($machineAdminCredentiaRef.links.self.href) > $null

		$machineGrouplName = "MDT Patching Machinegroup -" + $uid
		$response = Add-MachineGroup $machineGrouplName $machineToScan $machineAdminCredentiaRef.id $authenticationAndSessionCredential
		$toDelete.Add($response.links.self.href) > $null
		
		#change to prefered Patch Group Name (not in use) 
		$patchGroupName = "Windows 10 critical"
		
		$cveToScanFor | ForEach-Object { Add-CveToPatchGroup $patchGroupRef.id $_ $authenticationAndSessionCredential }
		$toDelete.Add($patchGroupRef.links.self.href) > $null
		
		#change to prefered scan template name
		#$scanTemplateName = "Critical Patch Scan Template"
        $scanTemplateName = "All Patches"
		
		#change to prefered Deployment Template
		$deployTemplateName = "MDT Deployment"
		
		Invoke-PatchAndDeploy -ScanTemplateName $scanTemplateName -MachineGroupName $machineGrouplName -DeployTemplateName $deployTemplateName -ScanName $uid  -AuthenticationAndSessionCredential $authenticationAndSessionCredential
	}
	finally
	{
		if ($deleteSampleData)
		{
			# cleanup collateral
			$toDelete.Reverse();
			$toDelete | ForEach-Object { Remove-RestResourceSafe $_ $authenticationAndSessionCredential }
		}
		else
		{
			Write-Host "You did NOT want to delete the sample data."
		}
	}
}
#####################################
#   Start Script
#####################################
try
{
	

	#Write  "Please enter the credential that will be used to authenticate to the console Rest API"
	#$AuthenticationAndSessionCredential = Get-Credential $consoleAuthenthicationAndSessionUserName
    
    $secpasswd = ConvertTo-SecureString "<password>>" -AsPlainText -Force
	$AuthenticationAndSessionCredential = New-Object System.Management.Automation.PSCredential ($consoleAuthenthicationAndSessionUserName, $secpasswd)

    # request local admin on machine to scan
    #Write  "Please enter the credential that is an administrator of the machine being scanned"
    $secpasswd2 = ConvertTo-SecureString "<passowrd>>" -AsPlainText -Force
    $MachineAdministratorCredential = New-Object System.Management.Automation.PsCredential($MachineAdministrator,$secpasswd2)
        
    #Uncomment when same account is used for console access and endpoint permissions(local admin) & Comment $MachineAdministratorCredential lines above
	#$MachineAdministratorCredential = $AuthenticationAndSessionCredential

	Invoke-ScanAndDeploy $machineToScan $cveList $MachineAdministratorCredential $AuthenticationAndSessionCredential
    
    # Wait some time to get patch tasks in local scheduleder and downloaded to device (C:\Windows\ProPatches)
    #Start-Sleep 300

}
catch [Exception]
{
	$private:e = $_.Exception
	do
	{
		Write-Host "Error: " $private:e
		$private:e = $private:e.InnerException
	}
	while ($private:e -ne $null)
}