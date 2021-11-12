# Input bindings are passed in via param block.
param($Timer)

#Import-module .\TimerTrigger\modules\Write-OMSLogfile.ps1
###################################################################################
#  API Log to OMS Log Analytics Workspace
###################################################################################
#Credit: https://github.com/tsrob50/LogAnalyticsAPIFunction

#Additional Functions come from AzTable to assist with Table Row Maintenance

function Get-AuthToken{
    [cmdletbinding()]
        Param(
            [Parameter(Mandatory = $true, Position = 0)]
            [string]$ClientID,
            [parameter(Mandatory = $true, Position = 1)]
            [string]$ClientSecret,
            [Parameter(Mandatory = $true, Position = 2)]
            [string]$tenantdomain,
            [Parameter(Mandatory = $true, Position = 3)]
            [string]$TenantGUID
        )
    # Create app of type Web app / API in Azure AD, generate a Client Secret, and update the client id and client secret here
    $loginURL = "https://login.microsoftonline.com/"
    # Get the tenant GUID from Properties | Directory ID under the Azure Active Directory section
    $resource = "https://manage.office.com"
    # auth
    $body = @{grant_type="client_credentials";resource=$resource;client_id=$ClientID;client_secret=$ClientSecret}
    $oauth = Invoke-RestMethod -Method Post -Uri $loginURL/$tenantdomain/oauth2/token?api-version=1.0 -Body $body
    $headerParams = @{'Authorization'="$($oauth.token_type) $($oauth.access_token)"}
    return $headerParams 
}

function Get-AzTableRow
{
    <#
    .AUTHOR
        Paulo Marques (MSFT)
    .DESCRIPTION
        Sample functions to add/retrieve/update entities on Azure Storage Tables from PowerShell (This is the same as AzureRmStorageTable module but with a new module name). It requires latest PowerShell Az module installed. Instructions at https://docs.microsoft.com/en-us/powershell/azure/install-az-ps?view=azps-1.6.0. For documentation, please visit https://paulomarquesc.github.io/working-with-azure-storage-tables-from-powershell/
    .SYNOPSIS
        Used to return entities from a table with several options, this replaces all other Get-AzTable<XYZ> cmdlets.
    .DESCRIPTION
        Used to return entities from a table with several options, this replaces all other Get-AzTable<XYZ> cmdlets.
    .PARAMETER Table
        Table object of type Microsoft.Azure.Cosmos.Table.CloudTable to retrieve entities (common to all parameter sets)
    .PARAMETER PartitionKey
        Identifies the table partition (byPartitionKey and byPartRowKeys parameter sets)
    .PARAMETER RowKey
        Identifies the row key in the partition (byPartRowKeys parameter set)
    .PARAMETER SelectColumn
        Names of the properties to return for each entity
    .PARAMETER ColumnName
        Column name to compare the value to (byColummnString and byColummnGuid parameter sets)
    .PARAMETER Value
        Value that will be looked for in the defined column (byColummnString parameter set)
    .PARAMETER GuidValue
        Value that will be looked for in the defined column as Guid (byColummnGuid parameter set)
    .PARAMETER Operator
        Supported comparison Operator. Valid values are "Equal","GreaterThan","GreaterThanOrEqual","LessThan" ,"LessThanOrEqual" ,"NotEqual" (byColummnString and byColummnGuid parameter sets)
    .PARAMETER CustomFilter
        Custom Filter string (byCustomFilter parameter set)
    .PARAMETER Top
        Return only the first n rows from the query (all parameter sets)
    .EXAMPLE
        # Getting all rows
        Get-AzTableRow -Table $Table
    .EXAMPLE
        # Getting specific properties for all rows
        $columns = ('osVersion', 'computerName')
        Get-AzTableRow -Table $Table -SelectColumn $columns
    .EXAMPLE
        # Getting rows by partition key
        Get-AzTableRow -Table $table -partitionKey NewYorkSite
    .EXAMPLE
        # Getting rows by partition and row key
        Get-AzTableRow -Table $table -partitionKey NewYorkSite -rowKey "afc04476-bda0-47ea-a9e9-7c739c633815"
    .EXAMPLE
        # Getting rows by Columnm Name using Guid columns in table
        Get-AzTableRow -Table $Table -ColumnName "id" -guidvalue "5fda3053-4444-4d23-b8c2-b26e946338b6" -operator Equal
    .EXAMPLE
        # Getting rows by Columnm Name using string columns in table
        Get-AzTableRow -Table $Table -ColumnName "osVersion" -value "Windows NT 4" -operator Equal
    .EXAMPLE
        # Getting rows using Custom Filter
        Get-AzTableRow -Table $Table -CustomFilter "(osVersion eq 'Windows NT 4') and (computerName eq 'COMP07')"
    .EXAMPLE
        # Querying with a maximum number of rows returned
        Get-AzTableRow -Table $Table -partitionKey NewYorkSite -Top 10
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true,ParameterSetName="GetAll")]
        [Parameter(ParameterSetName="byPartitionKey")]
        [Parameter(ParameterSetName="byPartRowKeys")]
        [Parameter(ParameterSetName="byColummnString")]
        [Parameter(ParameterSetName="byColummnGuid")]
        [Parameter(ParameterSetName="byCustomFilter")]
        $Table,

        [Parameter(ParameterSetName="GetAll")]
        [Parameter(ParameterSetName="byPartitionKey")]
        [Parameter(ParameterSetName="byPartRowKeys")]
        [Parameter(ParameterSetName="byColummnString")]
        [Parameter(ParameterSetName="byColummnGuid")]
        [Parameter(ParameterSetName="byCustomFilter")]
        [System.Collections.Generic.List[string]]$SelectColumn,

        [Parameter(Mandatory=$true,ParameterSetName="byPartitionKey")]
        [Parameter(ParameterSetName="byPartRowKeys")]
        [AllowEmptyString()]
        [string]$PartitionKey,

        [Parameter(Mandatory=$true,ParameterSetName="byPartRowKeys")]
        [AllowEmptyString()]
        [string]$RowKey,

        [Parameter(Mandatory=$true, ParameterSetName="byColummnString")]
        [Parameter(ParameterSetName="byColummnGuid")]
        [string]$ColumnName,

        [Parameter(Mandatory=$true, ParameterSetName="byColummnString")]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(ParameterSetName="byColummnGuid",Mandatory=$true)]
        [guid]$GuidValue,

        [Parameter(Mandatory=$true, ParameterSetName="byColummnString")]
        [Parameter(ParameterSetName="byColummnGuid")]
        [validateSet("Equal","GreaterThan","GreaterThanOrEqual","LessThan" ,"LessThanOrEqual" ,"NotEqual")]
        [string]$Operator,
        
        [Parameter(Mandatory=$true, ParameterSetName="byCustomFilter")]
        [string]$CustomFilter,

        [Parameter(Mandatory=$false)]
        [Nullable[Int32]]$Top = $null
    )

    $TableQuery = New-Object -TypeName "Microsoft.Azure.Cosmos.Table.TableQuery"

    # Building filters if any
    if ($PSCmdlet.ParameterSetName -eq "byPartitionKey")
    {
        [string]$Filter = `
            [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterCondition("PartitionKey",`
            [Microsoft.Azure.Cosmos.Table.QueryComparisons]::Equal,$PartitionKey)
    }
    elseif ($PSCmdlet.ParameterSetName -eq "byPartRowKeys")
    {
        [string]$FilterA = `
            [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterCondition("PartitionKey",`
            [Microsoft.Azure.Cosmos.Table.QueryComparisons]::Equal,$PartitionKey)

        [string]$FilterB = `
            [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterCondition("RowKey",`
            [Microsoft.Azure.Cosmos.Table.QueryComparisons]::Equal,$RowKey)

        [string]$Filter = [Microsoft.Azure.Cosmos.Table.TableQuery]::CombineFilters($FilterA,"and",$FilterB)
    }
    elseif ($PSCmdlet.ParameterSetName -eq "byColummnString")
    {
        [string]$Filter = `
            [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterCondition($ColumnName,[Microsoft.Azure.Cosmos.Table.QueryComparisons]::$Operator,$Value)
    }
    elseif ($PSCmdlet.ParameterSetName -eq "byColummnGuid")
    {
        [string]$Filter = `
            [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterConditionForGuid($ColumnName,[Microsoft.Azure.Cosmos.Table.QueryComparisons]::$Operator,$GuidValue)
    }
    elseif ($PSCmdlet.ParameterSetName -eq "byCustomFilter")
    {
        [string]$Filter = $CustomFilter
    }
    else
    {
        [string]$filter = $null    
    }
    
    # Adding filter if not null
    if (-not [string]::IsNullOrEmpty($Filter))
    {
        $TableQuery.FilterString = $Filter
    }

    # Selecting columns if specified
    if ($null -ne $SelectColumn){
        $TableQuery.SelectColumns = $SelectColumn
    }

    # Set number of rows to return.
    if ($null -ne $Top)
    {
        $TableQuery.TakeCount = $Top
    }

    # Getting results
    if (($TableQuery.FilterString -ne $null) -or ($PSCmdlet.ParameterSetName -eq "GetAll"))
    {
        $Result = ExecuteQueryAsync -Table $Table -TableQuery $TableQuery

        # if (-not [string]::IsNullOrEmpty($Result.Result.Results))
        # {
        # return (GetPSObjectFromEntity($Result.Result.Results))
        # }

        if (-not [string]::IsNullOrEmpty($Result))
        {
            return (GetPSObjectFromEntity($Result))
        }
    }
}

function Add-AzTableRow
{
    <#
    .SYNOPSIS
        Adds a row/entity to a specified table
    .DESCRIPTION
        Adds a row/entity to a specified table
    .PARAMETER Table
        Table object of type Microsoft.Azure.Cosmos.Table.CloudTable where the entity will be added
    .PARAMETER PartitionKey
        Identifies the table partition
    .PARAMETER RowKey
        Identifies a row within a partition
    .PARAMETER Property
        Hashtable with the columns that will be part of the entity. e.g. @{"firstName"="Paulo";"lastName"="Marques"}
    .PARAMETER UpdateExisting
        Signalizes that command should update existing row, if such found by PartitionKey and RowKey. If not found, new row is added.
    .EXAMPLE
        # Adding a row
        Add-AzTableRow -Table $Table -PartitionKey $PartitionKey -RowKey ([guid]::NewGuid().tostring()) -property @{"firstName"="Paulo";"lastName"="Costa";"role"="presenter"}
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $Table,
        
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [String]$PartitionKey,

        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [String]$RowKey,

        [Parameter(Mandatory=$false)]
        [hashtable]$property,
        [Switch]$UpdateExisting
    )
    
    # Creates the table entity with mandatory PartitionKey and RowKey arguments
    $entity = New-Object -TypeName "Microsoft.Azure.Cosmos.Table.DynamicTableEntity" -ArgumentList $PartitionKey, $RowKey
    
    # Adding the additional columns to the table entity
    foreach ($prop in $property.Keys)
    {
        if ($prop -ne "TableTimestamp")
        {
            $entity.Properties.Add($prop, $property.Item($prop))
        }
    }

    if ($UpdateExisting)
    {
        return ($Table.Execute([Microsoft.Azure.Cosmos.Table.TableOperation]::InsertOrReplace($entity)))
    }
    else
    {
        return ($Table.Execute([Microsoft.Azure.Cosmos.Table.TableOperation]::Insert($entity)))
    }
}

function Remove-AzTableRow
{
    <#
    .SYNOPSIS
        Remove-AzTableRow - Removes a specified table row
    .DESCRIPTION
        Remove-AzTableRow - Removes a specified table row. It accepts multiple deletions through the Pipeline when passing entities returned from the Get-AzTableRow
        available cmdlets. It also can delete a row/entity using Partition and Row Key properties directly.
    .PARAMETER Table
        Table object of type Microsoft.Azure.Cosmos.Table.CloudTable where the entity exists
    .PARAMETER Entity (ParameterSetName=byEntityPSObjectObject)
        The entity/row with new values to perform the deletion.
    .PARAMETER PartitionKey (ParameterSetName=byPartitionandRowKeys)
        Partition key where the entity belongs to.
    .PARAMETER RowKey (ParameterSetName=byPartitionandRowKeys)
        Row key that uniquely identifies the entity within the partition.
    .EXAMPLE
        # Deleting an entry by entity PS Object
        [string]$Filter1 = [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterCondition("firstName",[Microsoft.Azure.Cosmos.Table.QueryComparisons]::Equal,"Paulo")
        [string]$Filter2 = [Microsoft.Azure.Cosmos.Table.TableQuery]::GenerateFilterCondition("lastName",[Microsoft.Azure.Cosmos.Table.QueryComparisons]::Equal,"Marques")
        [string]$finalFilter = [Microsoft.Azure.Cosmos.Table.TableQuery]::CombineFilters($Filter1,"and",$Filter2)
        $personToDelete = Get-AzTableRowByCustomFilter -Table $Table -CustomFilter $finalFilter
        $personToDelete | Remove-AzTableRow -Table $Table
    .EXAMPLE
        # Deleting an entry by using PartitionKey and row key directly
        Remove-AzTableRow -Table $Table -PartitionKey "TableEntityDemoFullList" -RowKey "399b58af-4f26-48b4-9b40-e28a8b03e867"
    .EXAMPLE
        # Deleting everything
        Get-AzTableRowAll -Table $Table | Remove-AzTableRow -Table $Table
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        $Table,

        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ParameterSetName="byEntityPSObjectObject")]
        $entity,

        [Parameter(Mandatory=$true,ParameterSetName="byPartitionandRowKeys")]
        [AllowEmptyString()]
        [string]$PartitionKey,

        [Parameter(Mandatory=$true,ParameterSetName="byPartitionandRowKeys")]
        [AllowEmptyString()]
        [string]$RowKey
    )

    begin
    {
        $updatedEntityList = @()
        $updatedEntityList += $entity

        if ($updatedEntityList.Count -gt 1)
        {
            throw "Delete operation cannot happen on an array of entities, altough you can pipe multiple items."
        }
        
        $Results = @()
    }
    
    process
    {
        if ($PSCmdlet.ParameterSetName -eq "byEntityPSObjectObject")
        {
            $PartitionKey = $entity.PartitionKey
            $RowKey = $entity.RowKey
        }

        $TableQuery = New-Object -TypeName "Microsoft.Azure.Cosmos.Table.TableQuery"
        [string]$Filter =  "(PartitionKey eq '$($PartitionKey)') and (RowKey eq '$($RowKey)')"
        $TableQuery.FilterString = $Filter
        $itemToDelete = ExecuteQueryAsync -Table $Table -TableQuery $TableQuery

        if ($itemToDelete -ne $null)
        {
            # Converting DynamicTableEntity to TableEntity for deletion
            $entityToDelete = New-Object -TypeName "Microsoft.Azure.Cosmos.Table.TableEntity"
            $entityToDelete.ETag = $itemToDelete.Etag
            $entityToDelete.PartitionKey = $itemToDelete.PartitionKey
            $entityToDelete.RowKey = $itemToDelete.RowKey

            $Results += $Table.Execute([Microsoft.Azure.Cosmos.Table.TableOperation]::Delete($entityToDelete))
        }
    }
    
    end
    {
        return ,$Results
    }
}

function GetPSObjectFromEntity($entityList)
{
    # Internal function
    # Converts entities output from the ExecuteQuery method of table into an array of PowerShell Objects

    $returnObjects = @()

    if (-not [string]::IsNullOrEmpty($entityList))
    {
        foreach ($entity in $entityList)
        {
            $entityNewObj = New-Object -TypeName psobject
            $entity.Properties.Keys | ForEach-Object {Add-Member -InputObject $entityNewObj -Name $_ -Value $entity.Properties[$_].PropertyAsObject -MemberType NoteProperty}

            # Adding table entity other attributes
            Add-Member -InputObject $entityNewObj -Name "PartitionKey" -Value $entity.PartitionKey -MemberType NoteProperty
            Add-Member -InputObject $entityNewObj -Name "RowKey" -Value $entity.RowKey -MemberType NoteProperty
            Add-Member -InputObject $entityNewObj -Name "TableTimestamp" -Value $entity.Timestamp -MemberType NoteProperty
            Add-Member -InputObject $entityNewObj -Name "Etag" -Value $entity.Etag -MemberType NoteProperty

            $returnObjects += $entityNewObj
        }
    }

    return $returnObjects

}

function ExecuteQueryAsync
{
    param
    (
        [Parameter(Mandatory=$true)]
        $Table,
        [Parameter(Mandatory=$true)]
        $TableQuery
    )
    # Internal function
    # Executes query in async mode

    if ($TableQuery -ne $null)
    {
        $token = $null
        $AllRows = @()
        do
        {
            $Results = $Table.ExecuteQuerySegmentedAsync($TableQuery, $token)
            $token = $Results.Result.ContinuationToken
            $AllRows += $Results.Result.Results
            # TakeCount controls the number of results returned per page, not
            # for the entire query. See e.g. the note in
            # https://docs.microsoft.com/azure/cosmos-db/table-storage-design-guide#retrieve-large-numbers-of-entities-from-a-query
            if (($null -ne $token) -and ($null -ne $TableQuery.TakeCount))
            {
                # If the take count is larger than the number of rows in this
                # segment, there are more rows to return.
                if ($TableQuery.TakeCount -gt $Results.Result.Results.Count)
                {
                    $TableQuery.TakeCount -= $Results.Result.Results.Count
                }
                else
                {
                    # No more rows are available in the current page.
                    break
                }
            }
        } while ($token)
    
        return $AllRows
    }
}

function Write-OMSLogfile {
    <#
    .SYNOPSIS
    Inputs a hashtable, date and workspace type and writes it to a Log Analytics Workspace.
    .DESCRIPTION
    Given a  value pair hash table, this function will write the data to an OMS Log Analytics workspace.
    Certain variables, such as Customer ID and Shared Key are specific to the OMS workspace data is being written to.
    This function will not write to multiple OMS workspaces.  Build-signature and post-analytics function from Microsoft documentation
    at https://docs.microsoft.com/en-us/azure/log-analytics/log-analytics-data-collector-api
    .PARAMETER DateTime
    date and time for the log.  DateTime value
    .PARAMETER Type
    Name of the logfile or Log Analytics "Type".  Log Analytics will append _CL at the end of custom logs  String Value
    .PARAMETER LogData
    A series of key, value pairs that will be written to the log.  Log file are unstructured but the key should be consistent
    withing each source.
    .INPUTS
    The parameters of data and time, type and logdata.  Logdata is converted to JSON to submit to Log Analytics.
    .OUTPUTS
    The Function will return the HTTP status code from the Post method.  Status code 200 indicates the request was received.
    .NOTES
    Version:        2.0
    Author:         Travis Roberts
    Creation Date:  7/9/2018
    Purpose/Change: Crating a stand alone function.
    .EXAMPLE
    This Example will log data to the "LoggingTest" Log Analytics table
    $type = 'LoggingTest'
    $dateTime = Get-Date
    $data = @{
        ErrorText   = 'This is a test message'
        ErrorNumber = 1985
    }
    $returnCode = Write-OMSLogfile $dateTime $type $data -Verbose
    write-output $returnCode
    #>
        [cmdletbinding()]
        Param(
            [Parameter(Mandatory = $true, Position = 0)]
            [datetime]$dateTime,
            [parameter(Mandatory = $true, Position = 1)]
            [string]$type,
            [Parameter(Mandatory = $true, Position = 2)]
            [psobject]$logdata,
            [Parameter(Mandatory = $true, Position = 3)]
            [string]$CustomerID,
            [Parameter(Mandatory = $true, Position = 4)]
            [string]$SharedKey
        )
        Write-Verbose -Message "DateTime: $dateTime"
        Write-Verbose -Message ('DateTimeKind:' + $dateTime.kind)
        Write-Verbose -Message "Type: $type"
        write-Verbose -Message "LogData: $logdata"

        #region Workspace ID and Key
        # Workspace ID for the workspace
        #$CustomerID = 'ENTER WORKSPACE ID HERE'

        # Shared key needs to be set for environment
        # Below uses an encrypted variable from Azure Automation
        # Uncomment the next two lines if using Azure Automation Variable and comment the last
        # $automationVarName = 'Enter Variable Name Here'
        # $sharedKey = Get-AutomationVariable -name $automationVarName
        # Key Vault is another secure option for storing the value
        # Less secure option is to put the key in the code
        #$SharedKey = 'ENTER WORKSPACE KEY HERE'

        #endregion

        # Supporting Functions
        # Function to create the auth signature
        function Build-signature ($CustomerID, $SharedKey, $Date, $ContentLength, $method, $ContentType, $resource) {
            $xheaders = 'x-ms-date:' + $Date
            $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
            $bytesToHash = [text.Encoding]::UTF8.GetBytes($stringToHash)
            $keyBytes = [Convert]::FromBase64String($SharedKey)
            $sha256 = New-Object System.Security.Cryptography.HMACSHA256
            $sha256.key = $keyBytes
            $calculateHash = $sha256.ComputeHash($bytesToHash)
            $encodeHash = [convert]::ToBase64String($calculateHash)
            $authorization = 'SharedKey {0}:{1}' -f $CustomerID,$encodeHash
            return $authorization
        }
        # Function to create and post the request
        Function Post-LogAnalyticsData ($CustomerID, $SharedKey, $Body, $Type) {
            $method = "POST"
            $ContentType = 'application/json'
            $resource = '/api/logs'
            $rfc1123date = ($dateTime).ToString('r')
            $ContentLength = $Body.Length
            $signature = Build-signature `
                -customerId $CustomerID `
                -sharedKey $SharedKey `
                -date $rfc1123date `
                -contentLength $ContentLength `
                -method $method `
                -contentType $ContentType `
                -resource $resource
            $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
            $headers = @{
                "Authorization" = $signature;
                "Log-Type" = $type;
                "x-ms-date" = $rfc1123date
                "time-generated-field" = $dateTime
            }
            $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $ContentType -Headers $headers -Body $body -UseBasicParsing
            Write-Verbose -message ('Post Function Return Code ' + $response.statuscode)
            return $response.statuscode
        }

        # Add DateTime to hashtable
        #$logdata.add("DateTime", $dateTime)
        $logdata | Add-Member -MemberType NoteProperty -Name "DateTime" -Value $dateTime

        #Build the JSON file
        $logMessage = ConvertTo-Json $logdata -Depth 20
        Write-Verbose -Message $logMessage

        #Submit the data
        $returnCode = Post-LogAnalyticsData -CustomerID $CustomerID -SharedKey $SharedKey -Body ([System.Text.Encoding]::UTF8.GetBytes($logMessage)) -Type $type
        Write-Verbose -Message "Post Statement Return Code $returnCode"
        return $returnCode
}

function Get-O365Data{
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$utcStartTime,
        [parameter(Mandatory = $true, Position = 1)]
        [string]$utcEndTime,
        [Parameter(Mandatory = $true, Position = 2)]
        [psobject]$headerParams,
        [parameter(Mandatory = $true, Position = 3)]
        [string]$tenantGuid,
        [Parameter(Mandatory=$true, Position = 4)]
        $Table
    )
    #List Available Content
    $contentTypes = $env:contentTypes.split(",")
    $numDuplicates = 0
    $numLogged = 0
    #Loop for each content Type like Audit.General
    foreach($contentType in $contentTypes){
        $listAvailableContentUri = "https://manage.office.com/api/v1.0/$tenantGUID/activity/feed/subscriptions/content?contentType=$contentType&PublisherIdentifier=$env:publisher&startTime=$utcStartTime&endTime=$utcEndTime"
        do {
            #List Available Content
            $contentResult = Invoke-RestMethod -Method GET -Headers $headerParams -Uri $listAvailableContentUri
            $contentResult.Count
            #Loop for each Content
            foreach($obj in $contentResult){
                #Retrieve Content
                $data = Invoke-RestMethod -Method GET -Headers $headerParams -Uri ($obj.contentUri)
                $data.Count
                #Loop through each Record in the Content
                foreach($event in $data){
                    #Filtering for Recrord types
                    #Get all Record Types
                    $eventCreationFormat = $Event.CreationTime | Get-Date -format yyyy-MM-ddTHH:mm
                    if($env:recordTypes -eq "0"){
                        #We dont need Cloud App Security Alerts due to MCAS connector
                        if(($event.Source) -ne "Cloud App Security"){
                            #Write each event to Log A
                            $TableData = Get-AzTableRow -Table $Table -PartitionKey $Event.RecordType -RowKey $Event.Id
                            if ($TableData) {
                                $numDuplicates++
                                #Write-Output "Skipping - $DateNow $($Event.Id) -= $($Event.RecordType) $($Event.Operation)"
                                }else{
                                $numLogged++
                                $DateNow = Get-Date ([datetime]::UtcNow) -format yyyy-MM-ddTHH:mm
                                #Write-Output "$DateNow $($Event.Id)  $($Event.CreationTime) $($Event.RecordType) $($Event.Operation)"
                                # Add results to Table for Log Tracking and publish to Log Analytics
                                Add-AzTableRow -Table $Table -PartitionKey $Event.RecordType -RowKey $Event.Id -Property @{'TimeCreated' = $eventCreationFormat; 'TimeIngested'= $DateNow} | Out-Null
                                $writeResult = Write-OMSLogfile (Get-Date) $env:customLogName $event $env:workspaceId $env:workspaceKey
                            }
                        }
                    }
                    else{
                        #Get only certain record types
                        $types = ($env:recordTypes).split(",")
                        $eventCreationFormat = $Event.CreationTime | Get-Date -format yyyy-MM-ddTHH:mm
                        if(($event.RecordType) -in $types){
                            #We dont need Cloud App Security Alerts due to MCAS connector
                            if(($event.Source) -ne "Cloud App Security"){
                                #Write each event to Log A
                                $TableData = Get-AzTableRow -Table $Table -PartitionKey $types[0] -RowKey $Event.Id
                                if ($TableData) {
                                    $numDuplicates++
                                    #Write-Output "Skipping - $DateNow $($Event.Id)  $($Event.CreationTime) $($Event.RecordType) $($Event.Operation)"
                                }else{
                                    $numLogged++
                                    $DateNow = Get-Date ([datetime]::UtcNow) -format yyyy-MM-ddTHH:mm
                                    #Write-Output "$DateNow $($Event.Id)  $($Event.CreationTime) $($Event.RecordType) $($Event.Operation)"
                                    # Add results to Table for Log Tracking and publish to Log Analytics
                                    Add-AzTableRow -Table $Table -PartitionKey $types[0] -RowKey $Event.Id -Property @{'TimeCreated' = $eventCreationFormat; 'TimeIngested'= $DateNow} | Out-Null
                                    $writeResult = Write-OMSLogfile (Get-Date) $env:customLogName $event $env:workspaceId $env:workspaceKey
                                }
                            }
                        }
                        
                    }
                }
            }
            
            #Handles Pagination
            $nextPageResult = Invoke-WebRequest -Method GET -Headers $headerParams -Uri $listAvailableContentUri
            If(($nextPageResult.Headers.NextPageUrl) -ne $null){
                $nextPage = $true
                $listAvailableContentUri = $nextPageResult.Headers.NextPageUrl
            }
            Else{$nextPage = $false}
        } until ($nextPage -eq $false)
    }
    Write-Output "$numLogged Log entries imported to Log Analytics"
    Write-Output "$numDuplicates Log entries skipped because they were previously imported"
    
}

#Configure span of log query for API calls
$lookbackTime = New-TimeSpan -Minutes $env:lookbackTimeInMins
$utcEndTime = Get-Date ([datetime]::UtcNow) -format yyyy-MM-ddTHH:mm
$utcStartTime = (Get-Date ([datetime]::UtcNow)) - $lookbackTime
$utcStartTime = $utcStartTime | Get-Date -format yyyy-MM-ddTHH:mm

#Configure Storage Context
$storAccountKeys = Get-AzStorageAccountKey -ResourceGroupName $env:storageAccountRG -Name $env:storageAccount
$storContext = New-AzStorageContext -StorageAccountName $env:storageAccount -StorageAccountKey $storAccountKeys[0].Value
$storAccountTable = (Get-AzStorageTable -Name $env:storageAccountTableName -context $storContext).CloudTable

# The 'IsPastDue' porperty is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

Write-Output "Searching for logs from: $utcStartTime to $utcEndTime"

$headerParams = Get-AuthToken $env:clientID $env:clientSecret $env:domain $env:tenantGuid
Get-O365Data $utcStartTime $utcEndTime $headerParams $env:tenantGuid $storAccountTable

# Remove logs older than Lookback Time from Table
$logsOld = Get-AzTableRow -Table $storAccountTable -CustomFilter "(TimeCreated lt '$utcStartTime')"
$logsOld | Remove-AzTableRow -Table $storAccountTable | Out-Null

Write-Output "$($logsOld.count) expired historical log entries removed from reference table"
