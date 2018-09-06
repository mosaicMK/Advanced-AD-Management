# Advanced-AD-Management
Adds more functionality to the Microsoft Active Directory module 

The Module provides cmdlets that convert the properties of ad objects to PowerShell Objects, this allows processes like getting
what groups a user is part of to be simplified to a single command. 

## Commands 
- Get-DomainUser
- Unlock-DomainUser
- Reset-DomainUserPassword
- Get-DomainUserGroupMembership
- Get-DomainGroupMembers
- Get-DomainGroup
- Get-DomainComputer

## Examples:
To get all groups a user is part of 
```
Get-DomainUser SSmith | Get-DomainUserGroupMembership
```
Get more information on each group a user it part of 
```
Get-DomainUser SSMith | Get-DomainUserGroupMembership | Get-DomainGroup
```
## Changes
### V 1.0.1.1
- Fixed an issue that stopped Get-DomainUserGroupMemers from accepting a pipeline
- Added the Get-DomainComputer cmdlet
- Added more aliases to each cmdlet to allow other cmdlets to work better with them
