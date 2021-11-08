param (
    [string]$ObjectSamAccountName = $( Read-Host "Object samaccountname"),
    [string]$ObjectDomain = $( Read-Host "Object FQDN domain name")
)

Class NestMembersOf {
	[String]$samAccountName
	[String]$samDomAcct
	[String]$Domain
	[String]$Dn
	[System.DirectoryServices.DirectoryEntry]$Memberof
	[String]$Nest
}

Function Find-ObjectBySAN(){
	Param ($strSamaccountname,
		   $strDomain
	)
	#"LDAP://" + $strDomain +"/DC=" + $strDomain.replace(".",",DC=") |out-host
	$oSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $oSearcher.SearchRoot = "LDAP://" + $strDomain +"/DC=" + $strDomain.replace(".",",DC=")
    $oSearcher.PageSize = 10
    $oSearcher.Filter = "(samaccountName=" + $strSamaccountname + ")"
    $oSearcher.SearchScope = "Subtree"
    try{
        $oObject=$oSearcher.FindOne().getdirectoryEntry()
		return $oObject
        }
    catch{
		return $null
    }
	
}
function get-OobjectDomainFQDN(){
	Param($oObject)
	$pattern = '(?i)DC=\w{1,}?\b'
	$strTmp = ([RegEx]::Matches(($oObject.distinguishedName), $pattern) | ForEach-Object { $_.Value.replace("DC=","") }) -join '.'
	return $strTmp
}


function Object-memberOf-In-domain(){
	Param ($oObject,
		  $strDomainFQDN,
		  $iNiv=1,		  
		  $strChaine=''
	)
	$strObjetDomainFQDN = get-OobjectDomainFQDN $oObject
	$strObjetsamAccountNAme = $oObject.samAccountName
	#Write-host $strObjetsamAccountNAme $strChaine $strDomainFQDN
	$strChaine = "<-" + $strObjetDomainFQDN + "\" + $strObjetsamAccountNAme  + $strChaine 
	#Write-host $strChaine 
	$aNetMem = @{}
	Write-host (("`t"*$iNiv) + $strObjetDomainFQDN +"\"+ $strObjetsamAccountNAme + "***"+ $strDomainFQDN)
	$oSearcher = New-Object System.DirectoryServices.DirectorySearcher
	$oSearcher.SearchRoot = "LDAP://" +$strDomainFQDN +"/DC=" + $strDomainFQDN.replace(".",",DC=") 
    $oSearcher.PageSize = 1000
    $oSearcher.SearchScope = "Subtree"
	if ($strObjetDomainFQDN.toupper() -eq $strDomainFQDN.toupper()){
		$oSearcher.Filter = "(member=" + $oObject.distinguishedName + ")"
        try {
			$oResults=$oSearcher.findall()
		}
		catch {
			return $null
		}
        foreach ( $oResult in $oResults){
			$aTmp = new-Object NestMembersOf 
			$aTmp.samAccountName = $oResult.getdirectoryEntry().samAccountName
			$aTmp.Domain = (get-OobjectDomainFQDN $oResult.getdirectoryEntry())
			$aTmp.samDomAcct = $aTmp.Domain+ "\" + $aTmp.samAccountName
			$aTmp.Dn = $oResult.getdirectoryEntry().distinguishedName
			$aTmp.Memberof = $oResult.getdirectoryEntry()
			$aTmp.Nest =  $strChaine
			$null=$aNetMem.add($aTmp.Dn,$aTmp)
		}
    }
	else {
	    $strObjectSID = (New-Object System.Security.Principal.SecurityIdentifier(($oObject.objectSid).value,0)).tostring()
		#write-host ("(member=" +"CN=" +$strObjectSID + ",CN=ForeignSecurityPrincipals,DC=" + $strDomainFQDN.replace(".",",DC=") + ")")
        $oSearcher.Filter = "(member=" +"CN=" +$strObjectSID + ",CN=ForeignSecurityPrincipals,DC=" + $strDomainFQDN.replace(".",",DC=") + ")"
		try {
			$oResults=$oSearcher.findall()
		}
		catch {
			return $null
		}
	    foreach ( $oResult in $oResults){
			$aTmp= new-Object NestMembersOf 
			$aTmp.samAccountName = $oResult.getdirectoryEntry().samAccountName
			$aTmp.Domain = (get-OobjectDomainFQDN $oResult.getdirectoryEntry())
			$aTmp.samDomAcct = $aTmp.Domain+ "\" + $aTmp.samAccountName
			$aTmp.Dn = $oResult.getdirectoryEntry().distinguishedName
			$aTmp.Memberof = $oResult.getdirectoryEntry()
			$aTmp.Nest =  $strChaine
			$null=$aNetMem.add($aTmp.Dn,$aTmp)
		}
	}
    $aNetMemTmp= $aNetMem.Clone()
	foreach ( $L in $aNetMemTmp.keys){
		$tMemberOfsTmp = Object-memberOf-In-domain ($aNetMemTmp[$L].Memberof) ($aNetMemTmp[$L].Domain) ($iNiv+1) $strChaine
		if($tMemberOfsTmp) {
			foreach( $k in $tMemberOfsTmp.keys ){
				$aTmp= $tMemberOfsTmp[$k]
#				if ($aTmp){
					if ($aNetMem.contains($k)){
						$aNetMem[$k].Nest = ($aNetMem[$k].Nest) + ";" + ($aTmp.nest)
					}
					else{
						$null=$aNetMem.add($k,$aTmp)
					}
#				}
			}
		}
	}
	return $aNetMem
}
<###############################################################################################
/#
/# List all trusting domains
/#
/###############################################################################################>
function GetTrustingDomains(){
    Param($strDomainFQDN=[System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name)
    $colTmp=@{}
    $colTmp.add($strDomainFQDN,"this")
    $objDomainContext= New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('domain',$strDomainFQDN) 
    try{
		$ObjDomain =  [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($objDomainContext)
    }
    catch{
        write-host ("Can't join domain: " + $strDomainFQDN + "`n`t <" + $_.tostring() + ">")
    }
    # Enumerate domains within the same forest
    $colForestDomains = $ObjDomain.forest.Domains
    foreach ($objDom in  $colForestDomains){
        if (!($colTmp.Contains($objDom.name))){$colTmp.add($objDom.name,"intraforst")}
    }
    
    # Enumerate domains with external trust 
    try {
		$aTmp=$objDomain.GetAllTrustRelationships()
	}
    catch{
        write-host  ("Can't enumerate domains with external trust: " + $strDomainFQDN + "`n`t <" + $_.tostring() + ">")
    }		
    foreach ($objTrust in $aTmp){
        if (($objTrust.trustType.tostring().toupper() -eq "EXTERNAL") -and ($objTrust.TrustDirection.tostring().toupper() -ne "OUTBOUND")){
            if (!($colTmp.Contains($objTrust.TargetName))){$colTmp.add($objTrust.TargetName,"external")}
        }
    }
    

    # Enumerate domains having forests trust with our domain's forest
    try {
		$aTmp=$ObjDomain.forest.GetAllTrustRelationships()
	}
	catch{
        write-host  ("Can't enumerate forest s trusting the domain forest: " + $strDomainFQDN + "`n`t <" + $_.tostring() + ">")
    }
    foreach ($objTrust in $aTmp){
		if ($objTrust.TrustDirection.tostring().toupper() -ne "OUTBOUND"){
			foreach ($objDom in $objTrust.TrustedDomainInformation){
				if (!($colTmp.Contains($objDom.DnsName))){$colTmp.add($objDom.DnsName,"interforest")}
			}
		}
	}
    return $colTmp
}

<########################################################################################
/#
/# MAIN
/#
/########################################################################################>


$Allgroups=@{}
$oObject=Find-ObjectBySAN $ObjectSamAccountName $ObjectDomain 
$aObjetDomainGroups=Object-memberOf-In-domain $oObject $ObjectDomain
$Allgroups += $aObjetDomainGroups 
$aTrustingDomains = GetTrustingDomains $ObjectDomain
foreach ($strDomainFQDN in $aTrustingDomains.keys){
	$strDomainFQDN 
	$aTrustingDomains[$strDomainFQDN]
	$err1=$false
	$objDomainContext= New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('domain',$strDomainFQDN)
	try{
		$ObjDomain =  [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($objDomainContext)
	}
	catch{
		write-host ("Can't join domain: " + $strDomainFQDN + "`n`t <" + $_.tostring() + ">")
		#$err1=$true
		continue
	}

	if (($aTrustingDomains[$strDomainFQDN] -eq "this" ) -or $err1 ){continue}
	$aObjetOtherDomainGroups = Object-memberOf-In-domain $oObject $strDomainFQDN 
	$Allgroups += $aObjetOtherDomainGroups
	foreach( $L in $aObjetDomainGroups.keys){
		$tMemberOfsTmp = Object-memberOf-In-domain $aObjetDomainGroups[$L].MemberOf $strDomainFQDN 1 ($aObjetDomainGroups[$L].Nest)
		foreach( $k in $tMemberOfsTmp.keys ){
			$aTmp= $tMemberOfsTmp[$k]
			if ($Allgroups.contains($k)){
				$Allgroups[$k].Nest = ($Allgroups[$k].Nest) + ";" + ($aTmp.nest)
			}
			else{
				$null=$Allgroups.add($k,$aTmp)
			}
		}
	}	
}


"Object	Group	Nesting	Occurrence"
foreach($oNest in $Allgroups.values){
	$i=1
	$aNest = ($oNest.Nest).split(";")
	foreach ($strNest in $aNest){
		"{0}	{1}	{2}	{3}" -f ($ObjectDomain+"\"+$ObjectSamAccountName)  ,$oNest.samDomAcct, $strNest, $i
		$i++
	}
	#$oNest.memberOf
}


