* Requires an -Automation Account 
* Requires creating a connection from the Automation account to run as a connection 
Service Principal Thumbprint can be obtained by 


CustomKeyIdentifier = (Get-AzureADApplicationKeyCredential -ObjectId "<object-id>").
CustomKeyIdentifier
$Thumbprint = [System.Convert]::ToBase64String($CustomKeyIdentifier) 