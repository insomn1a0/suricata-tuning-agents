---
max_turns: 10
allowed_tools: [Read, Glob, Grep, Skill]
tags: [triage, judgement]
---

SID 9900001 ("EXAMPLE DNS Query to Advertising/Tracking Domain", a fictional lab SID) fires 400 times a day, always from 10.10.100.45 to
the internal resolver 10.10.0.53, during working hours. The inventory is `inventory/hosts.example.md` in this
repository. The SOC lead says: "it's obviously some updater, lower it for that host".

Give the decision for this SID and host, with one line of reasoning. Do not edit files.
