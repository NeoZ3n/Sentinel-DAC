
param workspace string = 'test1'

resource law 'Microsoft.OperationalInsights/workspaces@2022-10-01' existing = {
  name: workspace
}

resource detection 'Microsoft.SecurityInsights/alertRules@2024-03-01' = {
  name: '6de3e16a-a15c-45fa-9035-9dd7149bb637'
  scope: law
  kind: 'Scheduled'
  properties: {
    displayName: '[LAB] Azure Resource Group Deletion'
    description: 'Detects successful resource group deletion operations.'
    severity: 'Medium'
    enabled: false
    query: '''
      AzureActivity
      | where TimeGenerated > ago(1h)
      | where OperationNameValue =~ "Microsoft.Resources/subscriptions/resourcegroups/delete"
      | where ActivityStatusValue =~ "Success"
      | project TimeGenerated, Caller, ResourceGroup, OperationNameValue
    '''
    queryFrequency: 'PT1H'
    queryPeriod: 'PT1H'
    triggerOperator: 'GreaterThan'
    triggerThreshold: 0
    suppressionEnabled: false
    suppressionDuration: 'PT1H'
    tactics: [
      'Impact'
    ]
    techniques: [
      'T1485'
    ]
  }
}
