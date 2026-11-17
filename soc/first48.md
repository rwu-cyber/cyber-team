1. Run an Extensive NMap Scan
    1. **Make sure you are on the VPN**  
    2. **Take note of the OS of the different machines**
    3. **nmap -sC -sV [target]**
   
2. Locate Wazuh or an equivalent
   1. **sudo cat /etc/os-release**
   
3. Make sure the web server/dashboard is up
   1. **Check out Things you may Encounter.md if you run into issues**
   
4. Make a new user account
   1. **Reset the password**
   2. **Can't be done through the GUI; must be done through the terminal**
   3. **sudo bash wazuh-passwords-tool.sh -u admin -p <YOUR PASSWORD HERE>**
          1. **https://documentation.wazuh.com/current/user-manual/user-administration/password-management.html**
   
5. Add Windows and Linux Machines as nodes
   1. **COME BACK TO THIS**

6. Monitoring User Accounts - Linux
   **1. View User Creation Alerts in the Wazuh Dashboard**
   Follow these steps to find the exact timestamp and details of a newly created Linux account:
   -  Open the dashboard. Log in to your Wazuh web interface and navigate to Modules > Threat Hunting (or Security Events depending on your Wazuh version).**
    - Select the Events tab. Click on Events at the top of the module to view raw, searchable alert logs.
    - Filter by Rule ID. In the search bar at the top, enter rule.id: 5902 and press Enter. You can also filter by MITRE ATT&CK technique using rule.mitre.id:         T1136.
    - Adjust the time range. Use the time picker in the top-right corner to select the timeframe you want to inspect.
   - Inspect the alert details. Expand any matching event to view the @timestamp (exact creation time), agent.name (the Linux host), and full_log (which shows the     newly created username, UID, GID, and home directory).
    **2. Detect Manual Account Creation**
    Attackers sometimes bypass standard commands by manually editing system files. To catch this behavior, use Wazuh's File Integrity Monitoring (FIM) module:
     - Monitor account files. Confirm that /etc/passwd, /etc/shadow, /etc/group, and /etc/gshadow are included under <directories> in the <syscheck> section of        /var/ossec/etc/ossec.conf.
   - Check FIM events. Navigate to Modules > File Integrity Monitoring in the dashboard and filter by syscheck.path: /etc/passwd to see the exact timestamp             whenever the file is modified.

8. Monitoring User Accounts - Windows
   **1. View Wazuh's centralized configuration or SCA (Security Configuration Assessment) module to ensure windows endpoints have "Audit User           Account Management" and "Audit Logon policies" active.**
   **2. Filter pre-built Windows security rules in Wazuh by ID.**
      - Navigate to Threat Hunting -> Events and filter by ID:
      - account creation (60109)
      - account manipulation (60110–60121, 60154–60160)
      - logon activity (60106, 60122, 60115)
    **3. Open the MITRE ATT&CK module in Wazuh to automatically group and monitor alerts mapped to:**
       - Create Account (T1136)
       - Account Manipulation (T1098)
       - Valid Accounts (T1078)
    **4. Add composite rules on the Wazuh Manager using <if_sid> and <if_matched_sid> to escalate severity when a newly created user (60109) is          immediately added to an admin group (60160)**
    **5. (Optional) Automate response using custom scripting.**

9. 
