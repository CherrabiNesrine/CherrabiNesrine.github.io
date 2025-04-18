---
layout: post
title:  "Hunting Scheduled Tasks"
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
- This harmless task leaves behind the artifacts we want to hunt for.

### 2.2 Sharpersist

[Sharpersist](https://github.com/mandiant/Sharpersist) simulates persistence techniques through scheduled tasks.

- I created a scheduled task not for detection testing, but to **observe the traces and artifacts** it leaves.
- It helps in understanding the typical footprint of attacker-created tasks.


---

## 3. Hunting Hypothesis

> **Has a scheduled task been created or modified suspiciously on my network?**

Since scheduled tasks are common, attackers often abuse them to automate actions or maintain persistence.  
By framing the hunt around this question, we can focus on tasks that **stand out from normal operations**.

---

## 4. Hunting Method

Now that we’ve simulated attacker behavior, it’s time to hunt for it.

We’ll use a combination of **log-based hunting** and **endpoint-based hunting**.  
This two-layered approach gives both:

- **Infrastructure visibility** (via event logs)
- **Endpoint visibility** (via direct system queries)

### 4.1 Log-Based Hunting

First, find suspicious task executions triggered by task runner processes.

**Example ES|QL query:**

```sql
process.parent.name : "taskeng.exe" 
OR process.parent.name : "taskhostw.exe" 
OR process.parent.command_line : "*svchost.exe -k netsvcs -p -s Schedule*"
```



