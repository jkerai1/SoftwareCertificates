# Intune Stuff!  

# Browser Extensions 
Browser extension whitelisting is MUCH better than blacklisting. However if this is something you are struggling to achieve, this list may give you a good starting point  

I've included in my blocklist:  

VPNS, crypto, ungoverened AI (including grammarly), Piracy and screen wake tools   


With regards to blocking process names, this is a weak policy and can be bypassed as it runs in user context and only applicable to file explorer however can add an extra layer if WDAC is not an option.



This Setting can be nice to layer but reality is it can be bypassed easily. The corresponding Reg key lives in User land also.    

"This policy setting only prevents users from running programs that are started by the File Explorer process. It doesn't prevent users from running programs, such as Task Manager, which are started by the system process or by other processes. Also, if users have access to the command prompt (Cmd.exe), this policy setting doesn't prevent them from starting programs in the command window even though they would be prevented from doing so using File Explorer."  


# List of disallowed applications (User)

This Setting can be nice to layer but reality is it can be bypassed easily. The corresponding Reg key lives in User land also.    

"This policy setting only prevents users from running programs that are started by the File Explorer process. It doesn't prevent users from running programs, such as Task Manager, which are started by the system process or by other processes. Also, if users have access to the command prompt (Cmd.exe), this policy setting doesn't prevent them from starting programs in the command window even though they would be prevented from doing so using File Explorer."  

https://learn.microsoft.com/en-gb/windows/client-management/mdm/policy-csp-admx-shellcommandpromptregedittools?WT.mc_id=Portal-fx#disallowapps


![image](https://github.com/user-attachments/assets/13c0059d-af09-430a-818a-8862d3664895)

```


```
