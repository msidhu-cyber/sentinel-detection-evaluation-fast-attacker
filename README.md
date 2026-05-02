# Detection Evaluation – Fast Attacker Scenario (Microsoft Sentinel)

## Objective

This lab evaluates the effectiveness of a timing-based, multi-stage detection in Microsoft Sentinel under controlled conditions.

The goal is not just to detect activity, but to understand **when and why detection succeeds or fails**.

---

## Detection Concept

The detection is designed to identify a sequence of behaviour:

> Successful login  
→ Privilege escalation  
→ Beaconing activity  

This reflects a simplified attacker workflow:

1. Initial access  
2. Privilege escalation  
3. Command-and-control / persistence behaviour  

---

## Detection Logic (KQL)

```kql
let logins =
Syslog
| where TimeGenerated > ago(1h)
| where SyslogMessage contains "Accepted password"
| extend Account = extract(@"for (\w+)", 1, SyslogMessage)
| project LoginTime = TimeGenerated, Computer, Account;

let privilege =
Syslog
| where TimeGenerated > ago(1h)
| where SyslogMessage has_any ("sudo", "session opened for user root")
| project PrivTime = TimeGenerated, Computer;

let beacon =
Syslog
| where TimeGenerated > ago(1h)
| where SyslogMessage contains "beacon_test"
| project BeaconTime = TimeGenerated, Computer;

logins
| join kind=inner privilege on Computer
| where PrivTime between (LoginTime .. LoginTime + 2m)
| join kind=inner beacon on Computer
| where BeaconTime between (PrivTime .. PrivTime + 10m)
| project LoginTime, PrivTime, BeaconTime, Account, Computer
| order by LoginTime desc
```

---

## Experiment Setup

A controlled attack scenario was executed on a Linux VM:

1. SSH login  
2. Privilege escalation using `sudo su -`  
3. Beaconing simulation:
   ```
   while true; do logger "beacon_test"; sleep 10; done
   ```

---

## Initial Attempt (Detection Failure)

### Observation:
- Detection did not trigger  

### Cause:
- Beaconing occurred **before** privilege escalation  
- This broke the expected sequence required for correlation  

### Insight:
> Detection logic is dependent on correct event order. Even when all signals exist, incorrect sequencing prevents detection.

---

## Clean Execution (Detection Success)

### Observation:
- Detection triggered successfully  
- All events were correctly correlated  

### Conditions:
- Login → immediate escalation → beaconing  
- All actions occurred within defined time windows  

---

## Results

| Metric | Result |
|------|--------|
| Detection Triggered | Yes |
| Time to Detect | ~1–3 minutes |
| Correlation Success | Yes |
| False Positives | 0 |

---

## Evaluation

### What Worked Well
- Multi-stage detection successfully correlated events  
- Timing thresholds were effective for rapid attacker behaviour  
- All required telemetry was available  

---

### What Failed
- Detection failed when event sequence was incorrect  
- Strict ordering requirement prevented correlation  

---

### Key Insight

> Behavioural detections relying on timing and sequence are effective under controlled conditions but are highly sensitive to deviations in event order.

---

## Conclusion

This lab demonstrates that:

- Detection effectiveness depends on both **timing and sequence**
- Even minor deviations in behaviour can cause detection failure
- Evaluation of detection logic is critical to understanding real-world effectiveness  

---

## Next Steps

Future testing will evaluate:

- Delayed attacker behaviour  
- Stealthy execution patterns  
- Detection limitations under realistic conditions  
