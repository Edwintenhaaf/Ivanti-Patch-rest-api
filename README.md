# Ivanti-Patch-rest-api
Use Ivanti Patch (security controls) to run updates during deployment



      Ivanti Patch REST API Example                       
		
 		Purpose: Baseline Patching during mdt deployments
 		Source: https://help.ivanti.com/iv/help/en_US/isec/API/Topics/Start-to-Finish-Example-Using-PS.htm
      
 		Edwin ten Haaf T4Change 

	   
   	Version: 0.1 changed to adapt to customer needs
 	Version: 0.2 Force Windows Update to automatic (prevent errorcode 1058)
        Version: 0.3 Switch to Ip adress instead of machinename to scan (Non domain joined, automated deployments)

       Setup
       Get ST root cerificate (insert at line 66) - embedded and changed from user to machine (prompt bypass)
	   Secure Deploymentshare (remove read access everyone and use AD groups)
       Define Console & machine Accounts (line 46-50)
 	   Change $apiServer to your Ivantipatch(console) server (line 54)		
	   Change variables for templates to use (starts at line 565)
	   Change Password $secpasswd(line 599)

