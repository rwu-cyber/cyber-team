**Broad Filter Query DSL Script**
Below is a verbose and functional version of a Query DSL script meant to filter key indicators in the 
threathunting dashboard pertaining to windows.

{
  "query": {
    "bool": {
      "should": [
        {
          "terms": {
            "rule.id": [
              "60109",
              "60110",
              "60111",
              "60113",
              "60114",
              "60115",
              "60121",
              "60154",
              "60155",
              "60156",
              "60157",
              "60158",
              "60159",
              "60160",
              "61603",
              "61605",
              "92031",
              "92032",
              "92052",
              "100201",
              "100202",
              "100203"
            ]
          }
        },
        {
          "bool": {
            "must": [
              {
                "terms": {
                  "rule.id": [
                    "60106",
                    "60122"
                  ]
                }
              },
              {
                "terms": {
                  "data.win.eventdata.logonType": [
                    "3",
                    "10"
                  ]
                }
              }
            ]
          }
        },
        {
          "wildcard": {
            "data.win.system.channel": "*OpenSSH*"
          }
        }
      ],
      "must_not": [
        {
          "wildcard": {
            "data.win.eventdata.targetUserName": "*$"
          }
        },
        {
          "terms": {
            "data.win.eventdata.targetUserName": [
              "ANONYMOUS LOGON",
              "SYSTEM"
            ]
          }
        }
      ],
      "minimum_should_match": 1
    }
  }
}


**ID Glossary:**

**Built-in Windows Account & Logon Rules**
• 60106 // Successful logon (Event 4624).
• 60109 // Account created (Event 4720).
• 60110 // Account enabled (Event 4722).
• 60111 // Account changed (Event 4738).
• 60113 // Account disabled (Event 4725).
• 60114 // Password changed (Event 4723).
• 60115 // Account locked out (Event 4740).
• 60121 // Password reset (Event 4724).
• 60122 // Failed logon (Event 4625).
• 60154 // Added to global group (Event 4728).
• 60155 // Removed from global group (Event 4729).
• 60156 // Added to local group (Event 4732).
• 60157 // Removed from local group (Event 4733).
• 60158 // Added to universal group (Event 4756).
• 60159 // Removed from universal group (Event 4757).
• 60160 // Added to privileged group (Events 4728/4732).

**Built-in Sysmon & Execution Rules**
• 61603 // Process created (Sysmon Event 1).
• 61605 // Network connection (Sysmon Event 3).
• 92031 // Suspicious PowerShell execution.
• 92032 // Encoded PowerShell command.
• 92052 // Shell spawned by web server.

**Custom Rules (local_rules.xml)**
• 100000 to 120000 // Custom rule ID range.
• 100105 // New account added to privileged group.
• 100201 // Ad-hoc web server spin-up.
• 100202 // Inbound traffic on high-level port.
• 100203 // Reverse shell signature detected.
