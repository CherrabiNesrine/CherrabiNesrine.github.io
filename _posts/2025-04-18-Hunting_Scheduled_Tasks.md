---
layout: post
title:  "Hunting Scheduled Tasks"
tags: [Scheduled Tasks, Detection, Threat Hunting, simulation ,hunting]
---


## 1. Introduction

Scheduled tasks are a normal part of system operations — they help with updates, backups, and maintenance jobs.  
But attackers love them too. They often use scheduled tasks to make their tools run repeatedly, stay hidden, or survive reboots.

In this blog, we’ll simulate how attackers abuse scheduled tasks, build a hunting hypothesis, and walk through detection using both logs and endpoint tools.

---

## 2. Simulation

Before hunting, we simulate realistic attacker behavior using three tools:

### 2.1 Atomic Red Team

[Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) is a great framework for safely simulating attacker techniques.

- I used **T1053.005** — an atomic test that creates a scheduled task running `calc.exe`.
- **Steps:**
  - List existing scheduled tasks
  - Choose an atomic test under `T1053.005`
  - Copy and execute the commands
    
    ```cmd 
    schtasks /create /tn "T1053_005_OnLogon" /sc onlogon /tr "cmd.exe /c calc.exe"
    ```
    
     ![atomics](/assets/img/atomics.png)
    
- This harmless task leaves behind the artifacts we want to hunt for.

  ![atomics](/assets/img/at.png)

### 2.2 Sharpersist

[Sharpersist](https://github.com/mandiant/Sharpersist) simulates persistence techniques through scheduled tasks.

![Sharp](/assets/img/sharp.png)

- I created a scheduled task not for detection testing, but to **observe the traces and artifacts** it leaves.
- It helps in understanding the typical footprint of attacker-created tasks.

```powershell
SharPersist -t schtask -c "C:\Windows|System32\cmd.exe" -a "/c calc.exe" -n "SharPersist" -m add
  ```
![Sharpex](/assets/img/1.png)

---

## 3. Hunting Hypothesis


> **Has a scheduled task been created or modified suspiciously on my network?**



That’s the main question we are  trying to answer. While scheduled tasks are common, attackers often use them to stay persistent or automate malicious actions. By asking this, we can start looking for tasks that stand out

---

## 4. Hunting Method

Now that we’ve simulated attacker behavior, it’s time to hunt for it.

We’ll use a combination of **log-based hunting** and **endpoint-based hunting**.  
This two-layered approach gives both:

- **Infrastructure visibility** (via event logs)
- **Endpoint visibility** (via direct system queries)

### 4.1 Log-Based Hunting

First, find suspicious task executions triggered by task runner processes.

**Example KQL query:**

```sql
process.parent.name : "taskeng.exe" 
OR process.parent.name : "taskhostw.exe" 
OR process.parent.command_line : "*svchost.exe -k netsvcs -p -s Schedule*"
```

Next, we want to look for task files stored in the Windows Task folder (System32\Tasks). This is where scheduled tasks are usually defined.
Search for these files with this query:

```sql
file.path : *\\Windows\\System32\\Tasks\\*
```

![taskxml](/assets/img/4.png)


Also, look for **Scheduled Task Creation** events — specifically, **Event ID 4698**:

> **Event 4698** = "A scheduled task was created."
> ✅ **Make sure this logging is enabled!**

```sql
from logs-system.security-default-*
| where  @timestamp > now() - 7 day
| where host.os.family == "windows" and event.code == "4698" and event.action == "scheduled-task-created"
 /* parsing unstructured data from winlog message to extract a scheduled task Exec command */
| grok message "(?<Command><Command>.+</Command>)" | eval Command = replace(Command, "(<Command>|</Command>)", "")
| where Command is not null
 /* normalise task name by removing usersid and uuid string patterns */
| eval TaskName = replace(winlog.event_data.TaskName, """((-S-1-5-.*)|\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\})""", "")
 /* normalise task name by removing random patterns in a file path */
| eval Task_Command = replace(Command, """(ns[a-z][A-Z0-9]{3,4}\.tmp|DX[A-Z0-9]{3,4}\.tmp|7z[A-Z0-9]{3,5}\.tmp|[0-9\.\-\_]{3,})""", "")
 /* normalize user home profile path */
| eval Task_Command = replace(Task_Command, """[cC]:\\[uU][sS][eE][rR][sS]\\[a-zA-Z0-9\.\-\_\$~]+\\""", "C:\\\\users\\\\user\\\\")
| where Task_Command like "?*" and not starts_with(Task_Command, "C:\\Program Files") and not starts_with(Task_Command, "\"C:\\Program Files")
| stats tasks_count = count(*), hosts_count = count_distinct(host.id) by Task_Command, TaskName
| where hosts_count == 1
```
![esql](/assets/img/3.png)


### 4.2 Endpoint-Based Hunting

Once suspicious tasks are detected in logs, we move to direct endpoint investigation.

**Useful PowerShell commands:**

- **List all scheduled tasks:**

  ```powershell
  Get-ScheduledTask -TaskPath "\"
  ```
- **This gives us a closer look at each task , and sometimes, that's where hidden persistence shows up** 

  ```powershell
   schtasks /query /TN "Sharpersist" /V /FO LIST
  ```
  
![powershell](/assets/img/5.png)

By connecting data from logs, and direct endpoint checks, it becomes possible to build a clear picture of any suspicious scheduled task activity happening in the environment.


## 5. Next Steps

After we finish our manual hunting, it’s a smart move to automate detection and make our defenses even stronger.

- We can check [SigmaHQ](https://github.com/SigmaHQ/sigma) for existing detection rules related to Scheduled Task abuse.
- We should also explore the Elastic Security GitHub their [Elastic Detections](https://github.com/elastic/detection-rules) might have something ready for us.
  
And if needed, we can build our own custom alerts in the SIEM based on the hunting queries we’ve developed.

By putting automation in place, we make sure that even the stealthiest Scheduled Task abuses are caught early  without depending only on manual investigations.

## 6. Conclusion 

In this blog, we simulated various attacker techniques involving scheduled tasks and explored practical hunting strategies to detect them.

Ultimately, it's not about catching every scheduled task—it's about recognizing what’s normal so you can quickly identify anomalies.

The better you understand your environment, the harder it is for attackers to conceal their actions.

see you in the Next blog ! 





