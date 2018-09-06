Function Get-DomainUser{
    <#
    .SYNOPSIS
    Get information about a user account

    .PARAMETER User
    The user account to gather information for
    Accepts wildcards

    .EXAMPLE
    Get-DomainUser -User jsmith*
    Finds all users that start with jsmith

    .NOTES
    Created By: Kris Gross
    Contact: Contact@mosaicMK.com
    Version 1.0.0.0

    .LINK
    https://www.mosaciMK.com
    #>
    [CmdletBinding()]
     Param(
            [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName)]
            [Alias("Name","SamAccountName","AccountName","UserAccount")]
            $SamAccountName
        )
        process{
            $DMUser = Get-ADUser -filter {SamAccountName -like $SamAccountName} -Properties *
            Foreach ($item in $DMUser)
            {
                $DomainUser = New-Object -TypeName psobject
                $DomainUser | Add-Member -MemberType NoteProperty -Name DisplayName -Value $Item.DisplayName
                $DomainUser | Add-Member -MemberType NoteProperty -Name SamAccountName -Value $Item.SamAccountName
                $DomainUser | Add-Member -MemberType NoteProperty -Name CanonicalName -Value $Item.CanonicalName
                $DomainUser | Add-Member -MemberType NoteProperty -Name EmailAddress -Value $Item.EmailAddress
                $DomainUser | Add-Member -MemberType NoteProperty -Name Initials -Value $Item.Initials
                $DomainUser | Add-Member -MemberType NoteProperty -Name DateCreated -Value $Item.whenCreated
                $DomainUser | Add-Member -MemberType NoteProperty -Name LastLogonDate -Value $item.LastLogonDate
                $DomainUser | Add-Member -MemberType NoteProperty -Name PasswordExpired -Value $item.PasswordExpired
                $DomainUser | Add-Member -MemberType NoteProperty -Name PasswordLastSet -Value $Item.PasswordLastSet
                $DomainUser | Add-Member -MemberType NoteProperty -Name PasswordNeverExpires -Value $Item.PasswordNeverExpires
                $DomainUser | Add-Member -MemberType NoteProperty -Name PasswordNotRequired -Value $Item.PasswordNotRequired
                $DomainUser | Add-Member -MemberType NoteProperty -Name LockedOut -Value $Item.LockedOut
                $DomainUser | Add-Member -MemberType NoteProperty -Name badPwdCount -Value $Item.badPwdCount
                $DomainUser | Add-Member -MemberType NoteProperty -Name LastChanged -Value $item.WhenChanged
                $DomainUser | Add-Member -MemberType NoteProperty -Name DistinguishedName $item.DistinguishedName
                $DomainUser | Add-Member -MemberType NoteProperty -Name Description -Value $item.Description
                $DomainUser | Add-Member -MemberType NoteProperty -Name AccountExpirationDate -Value $item.AccountExpirationDate
                $DomainUser | Add-Member -MemberType NoteProperty -Name UserPrincipalName -$item.UserPrincipalName
                $DomainUser
            }
        }
}

Function Unlock-DomainUser{
    <#
    .SYNOPSIS
    unlocks a user account

    .PARAMETER Samaccountname
    the samaccount of the user

    .NOTES
    Created By: Kris Gross
    Contact: Contact@mosaicMK.com
    Version 1.0.0.0

    .LINK
    https://www.mosaciMK.com
    #>
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName)]
        [Alias("Name","SamAccountName","AccountName","UserAccount")]
        $SamAccountName
    )
    Process{
        Unlock-ADAccount $SamAccountName
    }
}

Function Reset-DomainUserPassword{
    <#
    .SYNOPSIS
    Resets the the password for a user account

    .PARAMETER Samaccountname
    the samaccount of the user

    .PARAMETER Password
    the password you want to set for the user

    .PARAMETER DontChangePasswordAtLogin
    use this switch if the user is to not change there password on the next login

    .NOTES
    Created By: Kris Gross
    Contact: Contact@mosaicMK.com
    Version 1.0.0.0

    .LINK
    https://www.mosaciMK.com
    #>

    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName)]
        [Alias("Name","SamAccountName","AccountName","UserAccount")]
        $SamAccountName,
        [string]$Password,
        [switch]$DontChangePasswordAtLogin
    )

    Process{
        If ($Password) {
            $Value = $Password | ConvertTo-SecureString -AsPlainText -Force
            Set-ADAccountPassword -Identity $SamAccountName -Reset -NewPassword $Value
        }
        IF (!($Password)){Set-ADAccountPassword -Identity $SamAccountName -Reset}
        IF ($DontChangePasswordAtLogin) {Set-ADUser -Identity $SamAccountName -ChangePasswordAtLogon $false} IF (!($DontChangePasswordAtLogin)){Set-ADUser -Identity $SamAccountName -ChangePasswordAtLogon $True}
        $Value = $null
        $Password = $null
    }
}

function Get-DomainUserGroupMembership {
    <#
    .SYNOPSIS
    Gets the groups the user is a member of

    .PARAMETER Samaccountname
    the samaccount of the user

    .NOTES
    Created By: Kris Gross
    Contact: Contact@mosaicMK.com
    Version 1.0.0.0

    .LINK
    https://www.mosaciMK.com
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName)]
        [Alias("Name","SamAccountName")]
        $AccountName
    )

    Process{
        $Groups = (Get-Aduser $AccountName -Properties *).MemberOf
        $AllObjects = @()
        foreach ($item in $Groups) {
            $GroupName = Get-ADGroup "$item" -Properties *
            $DGroup = $GroupName.cn | Out-String
            $DGroup = $DGroup.Trim()
            $AllObjects += [pscustomobject]@{
                GroupName = $DGroup
            }
        }
        $AllObjects
    }
}

Function Get-DomainGroupMembers{
    <#
    .SYNOPSIS
    Gets gets the members of a domain group

    .PARAMETER GroupName
    Name of the group to the members of

    .NOTES
    Created By: Kris Gross
    Contact: Contact@mosaicMK.com
    Version 1.0.0.0

    .LINK
    https://www.mosaciMK.com
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName)]
        [Alias("Name","DomainGroupName","DomainGroup")]
        $GroupName
    )
    process{
        $GroupN = Get-ADGroupMember $GroupName
        $AllObjects = @()
        foreach ($item in $groupN)
        {
            $AllObjects += [pscustomobject]@{
                Name = $Item.name.Trim()
                SamAccountName = $item.SamAccountName.trim()
            }
        }
        $AllObjects
    }
}

function Get-DomainGroup {
    <#
    .SYNOPSIS
    Gets inforamtion about a group

    .PARAMETER Samaccountname
    Name of the group you want to gether information for

    .NOTES
    Created By: Kris Gross
    Contact: Contact@mosaicMK.com
    Version 1.0.0.0

    .LINK
    https://www.mosaciMK.com
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName)]
        [Alias("Name","DomainGroupName","DomainGroup")]
        $GroupName
    )
    Process{
        $Group = Get-ADGroup -Filter {CN -like $GroupName} -Properties *
        Foreach ($Item in $Group){
            $DGroup = New-Object -TypeName psobject
            $DGroup | Add-Member -MemberType NoteProperty -Name GroupName -Value $Item.CN
            $DGroup | Add-Member -MemberType NoteProperty -Name CononicalName -Value $Item.CanonicalName
            $DGroup | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $Item.DistinguishedName
            $DGroup | Add-Member -MemberType NoteProperty -Name DateCreated -Value $Item.whenCreated
            $DGroup | Add-Member -MemberType NoteProperty -Name DateModified -Value $Item.WhenChanged
            $DGroup | Add-Member -MemberType NoteProperty -Name Type -Value $Item.GroupCategory
            $DGroup | Add-Member -MemberType NoteProperty -Name Scope -Value $Item.GroupScope
            $DGroup
        }
    }
}


Function Get-DomainComputer{
    <#
    .SYNOPSIS
    Gets a domain computer

    .PARAMETER ComputerName
    Name of the computer to get

    .NOTES
    Created By: Kris Gross
    Contact: Contact@mosaicMK.com
    Version 1.0.0.0

    .LINK
    https://www.mosaciMK.com
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$True, ValueFromPipelineByPropertyName)]
        [Alias("Name","DeviceName","Computer","Device")]
        $ComputerName
    )
    Process{
        $Device = Get-ADComputer -filter {name -like $ComputerName} -Properties *
        Foreach ($item in $Device){
            $DDevice = New-Object -TypeName psobject
            $DDevice | Add-Member -MemberType NoteProperty -Name Name -Value $item.Name
            $DDevice | Add-Member -MemberType NoteProperty -Name Description -Value $item.Description
            $DDevice | Add-Member -MemberType NoteProperty -Name CanonicalName -Value $item.CanonicalName
            $DDevice | Add-Member -MemberType NoteProperty -Name DistinguishedName -Value $item.DistinguishedName
            $DDevice | Add-Member -MemberType NoteProperty -Name DateCreated -Value $item.Created
            $BitLockerObjects = (Get-ADObject -Filter {objectclass -eq 'msFVE-RecoveryInformation'} -SearchBase $item.DistinguishedName -Properties 'msFVE-RecoveryPassword').'msFVE-RecoveryPassword'
            $DDevice | Add-Member -MemberType NoteProperty -Name BitLockerRecoveryPassword -Value $BitLockerObjects
            $DDevice
        }
    }
}
