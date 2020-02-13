
# Gets all expired accounts in the Users OU and sets the expiration date
Search-ADAccount -SearchBase "OU=Users,DC=karl,DC=lab" -AccountExpired -UsersOnly -ResultPageSize 2000 -resultSetSize $null |
Set-ADAccountExpiration -DateTime 3/5/2018

# Retrieves all user accounts that have an expiration date later than 2-10-2018 and sets the expiration date to 2/3/2019
Get-ADUser -Filter {AccountExpirationDate -lt "2-10-2018"} -SearchBase "OU=Users,DC=karl,DC=lab" |
Set-ADAccountExpiration -DateTime 2/3/2019


# Get all users that expire in the next 30 days
$Today = Get-Date
$MonthFromToday = (Get-Date).AddDays(30)
Get-ADUser -Filter {(AccountExpirationDate -gt $Today) -and (AccountExpirationDate -lt $MonthFromToday)} -SearchBase "OU=Users,DC=karl,DC=lab"


# between dates  (lt is Less Than ; gt is Greater Than)
Get-ADUser -Filter {(AccountExpirationDate -gt "2-10-2018") -and (AccountExpirationDate -lt "3-10-2018")} -SearchBase "OU=Users,DC=karl,DC=lab"


# Get all users that expire in the next 30 days and select just the Name
$Today = Get-Date
$MonthFromToday = (Get-Date).AddDays(30)
Get-ADUser -Filter {(AccountExpirationDate -gt $Today) -and (AccountExpirationDate -lt $MonthFromToday)} -SearchBase "OU=Users,DC=karl,DC=lab" |
Select-Object Name

# Get the number of users that expire in the next 30 days
$Today = Get-Date
$MonthFromToday = (Get-Date).AddDays(30)
Get-ADUser -Filter {(AccountExpirationDate -gt $Today) -and (AccountExpirationDate -lt $MonthFromToday)} -SearchBase "OU=Users,DC=karl,DC=lab" |
Measure-Object


# Get the number of users that expire in the next 30 days and export to CSV
$Today = Get-Date
$MonthFromToday = (Get-Date).AddDays(30)

$StartDate = Get-Date -Format yyyy-MM-dd
$EndDate = (Get-Date).AddDays(30) | Get-Date -Format yyyy-MM-dd

Get-ADUser -Filter {(AccountExpirationDate -gt $Today) -and (AccountExpirationDate -lt $MonthFromToday)} -SearchBase "OU=Users,DC=karl,DC=lab" -Properties AccountExpirationDate | 
Export-Csv -Path "C:\temp\ADAccountExpirations_$StartDate_$EndDate.csv" -NoTypeInformation


