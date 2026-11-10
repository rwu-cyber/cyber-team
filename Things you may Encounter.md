**1. Wazuh Services won't restart (Indexer and Manager)**
   a) Restart in this order: Indexer, Manager, Dashboard
**2. Wazuh Degraded Status**
   a) The platform is still running and partially functional, but one or more components, nodes, or replica shards are failing or operating below normal capacity
**3. Wazuh Services not Restarting**
   a) Update Wazuh Services: sudo apt update && sudo apt upgrade
   b) If you see "setSecurityManager...", don't try to troubleshoot; YOU CAN'T FIX IT! Try to update the software
   c) systemctl restart wazuh-indexer, systemctl restart wazuh-manager, systemctl restart wazuh-dashboard
**4. Can't Access Wazuh (Username and Password won't work on Dashboard)
   a) Use: sudo bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p <YourNewPassword>
**5. Restart the dashboard while Wazuh is updating**
   a) Stop all Wazuh Services 
   b) 
**6. 
