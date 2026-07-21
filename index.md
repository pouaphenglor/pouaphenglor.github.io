---
layout: default
---
[LinkedIn](https://www.linkedin.com/in/pouapheng-lor/)

[GitHub Profile](https://www.github.com/pouaphenglor/)

# About Me

I'm a Denver-based Cybersecurity professional. My background combines a grounding in networking and systems with years of experience leading teams and managing operational workflows. I am
comfortable troubleshooting complex issues under pressure, and I pride myself on documenting and explaining technicaldetails clearly. I'm ready to bring sharp work ethic and my training to a fast-paced team.

## Labs

### Network Configuration + Troubleshooting
###### April 2023
*   Used Wireshark to capture traffic and track down packet loss, identifying a faulty router as the cause
*   Diagnosed network and DNS issues using common troubleshooting tools
*   Isolated issues by ruling out endpoint and DNS related problems during troubleshooting
*   Reviewed router firewalls and configuration settings and verified network stability after changes were made
*   Retested connectivity and traffic flow to confirm the issue was fully resolved

### Threat intelligence Analysis & Honeypot Deployment
###### July 2026
*   Deployed Cowrie honeypot on a public facing cloud VPS, configuring it on port 22 to capture SSH and telnet brute-force attacks
*   Colelcted live adversary data, eaxtracting attacker source IPs, attempted credentials and malicous payloads
*   Built a central dashboard to parse and visualize attack logs and documented project with screenshot proof of real attacks on [GitHub](https://www.github.com/pouaphenglor/)

### Malware Analysis Detection
###### July 2026
*   Detonated Malware Sample in a controlled isolated virtual machine
*   Conducted reverse engineering analysis using Ghidra to identify malware execution logic
*   Engineered custom Sigma and YARA rules based on extracted behaviors
  
#### Developed Sigma Rule:

<pre><code class="language-yaml">
title: Command Shell Spawning Encoded PowerShell Download Cradle
id: 9b2d3e14-fa4b-4654-a311-dfbc0474ce8f
status: production
description: Detects command prompt processes invoking hidden or encoded instances of PowerShell, commonly observed in malicious payload delivery chains like Qakbot or Emotet.
references:
    - https://www.malware-traffic-analysis.net
author: PouaPheng Lor
date: 2026/07/06
logsource:
    category: process_creation
    product: windows
detection:
    selection_parent:
        ParentImage|endswith: '\cmd.exe'
    selection_child:
        Image|endswith: '\powershell.exe'
    selection_args:
        CommandLine|contains:
            - '-enc'
            - '-encoded'
            - ' -w hidden'
            - 'windowstyle hidden'
            - 'bypass'
    condition: selection_parent and selection_child and selection_args
falsepositives:
    - Legacy corporate endpoint management scripts (must be baselined out via parent path exceptions)
level: high
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1204.002
</code></pre>
