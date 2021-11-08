# ad-groups
Simple Powershell script to list all user groups including groups in trussing domains and forests
## Usage
` .\get-AllUserGroups.ps1 <object(user,group,computer,...) samaccountname> <user fqdn domain name>`
## Output
Four colomns  separated by TAB are sent to the stadard output, it can redirected to a file and opened by Excel 
"<Object>	<Group>	<how the user is nested in the group>	<how many times the object is directly or indirectly member of the group> "
