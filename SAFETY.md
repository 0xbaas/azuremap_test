\# AzureMap Safety Rules



AzureMap must remain safe and read-only by default.



Allowed:

\- ARM / ARG / Microsoft Graph configuration reads

\- RBAC assignment and role definition reads

\- capability detection

\- detecting whether a role could call sensitive actions

\- safe evidence collection



Not allowed:

\- no write/update/delete actions

\- no exploitation

\- no secret dumping

\- no listKeys execution

\- no listCredentials execution

\- no listSecrets execution

\- no app settings dumping

\- no connection string dumping

\- no Function key dumping

\- no APIM secret dumping

\- no Automation credential secret reads

\- no Connect-AzAccount inside runtime



Allowed exception:

\- Set-AzContext is allowed only for local subscription context switching.



Data-plane:

\- Data-plane checks must be opt-in.

\- Use -IncludeDataPlane for data-plane checks.

\- Default run should remain control-plane focused.

