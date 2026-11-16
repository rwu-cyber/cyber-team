**1. Wazuh Services won't restart (Indexer and Manager)**
   1. Restart in this order: Indexer, Manager, Dashboard

**2. Wazuh Degraded Status**
   1. The platform is still running and partially functional, but one or more components, nodes, or replica shards are failing or operating below normal capacity

**3. Wazuh Services Not Restarting**
   1. Update Wazuh Services: sudo apt update && sudo apt upgrade
   2. If you see "setSecurityManager...", don't try to troubleshoot; YOU CAN'T FIX IT! Try to update the software
   3. systemctl restart wazuh-indexer, systemctl restart wazuh-manager, systemctl restart wazuh-dashboard

**4. Can't access Wazuh (Username and Password won't work on the dashboard)
   1. Use: sudo bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/wazuh-passwords-tool.sh -u admin -p <YourNewPassword>

**5. Restart the dashboard while Wazuh is updating**
   1. Stop all Wazuh Services
