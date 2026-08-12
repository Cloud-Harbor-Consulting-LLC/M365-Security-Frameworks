# Sentinel and Security Copilot Integration

How to implement the Security Reporting Decision Rubric's audience-scoped reports in Microsoft Sentinel workbooks, and how to use Microsoft Security Copilot to auto-draft the executive narrative sections.

## Prerequisites

- Microsoft Sentinel workspace with the Microsoft Defender XDR data connector enabled (forwards `SecurityIncident` and `SecurityAlert` tables).
- For Security Copilot prompt patterns: a Microsoft Security Copilot capacity unit purchased and assigned.
- For workbook deployment: Contributor role on the Sentinel workspace resource group.

The Defender XDR data connector forwards incident and alert data in near-real-time. Sentinel's `SecurityIncident` table is the primary source for all audience reports. `SecurityAlert` is used for false-positive tuning queries (SOC lead).

---

## Part 1 — Sentinel workbook pattern

Each audience report maps to a Sentinel workbook. The workbook queries `SecurityIncident` and `SecurityAlert`, applies the severity floor and time range for that audience, and renders the output as a formatted view.

### Workbook ARM template skeleton

Deploy one workbook per audience. Replace all `REPLACE_WITH_*` placeholders before deploying.

```json
{
  "type": "Microsoft.Insights/workbooks",
  "apiVersion": "2022-04-01",
  "name": "REPLACE_WITH_WORKBOOK_GUID",
  "location": "REPLACE_WITH_AZURE_REGION",
  "kind": "shared",
  "properties": {
    "displayName": "REPLACE_WITH_WORKBOOK_NAME",
    "serializedData": "REPLACE_WITH_SERIALIZED_WORKBOOK_JSON",
    "sourceId": "/subscriptions/REPLACE_WITH_SUBSCRIPTION_ID/resourceGroups/REPLACE_WITH_RESOURCE_GROUP/providers/Microsoft.OperationalInsights/workspaces/REPLACE_WITH_WORKSPACE_NAME",
    "category": "sentinel"
  }
}
```

The `serializedData` field holds the workbook definition JSON, which references the KQL queries in Part 2 as tile datasources. Build the workbook in the Azure portal using the Sentinel Workbooks editor, then export the serialized JSON for version control.

### Workbook tile pattern

Each tile in the workbook has this structure:

```json
{
  "type": 3,
  "content": {
    "version": "KqlItem/1.0",
    "query": "REPLACE_WITH_KQL_FROM_PART_2",
    "size": 0,
    "timeContext": {
      "durationMs": REPLACE_WITH_DURATION_MS
    },
    "queryType": 0,
    "resourceType": "microsoft.operationalinsights/workspaces"
  }
}
```

Time context values: 604800000 = 7 days, 2592000000 = 30 days, 7776000000 = 90 days.

---

## Part 2 — KQL query library

### SOC lead — weekly (severity floor: Medium and above)

**MTTD and MTTR trend — 7 days**

```kql
SecurityIncident
| where TimeGenerated > ago(7d)
| where Severity in ("High", "Medium")
| where Status == "Closed"
| extend
    MTTD_min = datetime_diff('minute', FirstModifiedTime, CreatedTime),
    MTTR_hr = datetime_diff('hour', ClosedTime, CreatedTime)
| summarize
    MedianMTTD_min = percentile(MTTD_min, 50),
    P90MTTD_min = percentile(MTTD_min, 90),
    MedianMTTR_hr = percentile(MTTR_hr, 50),
    IncidentCount = count()
```

**Top 5 false-positive detection rules**

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where AlertSeverity in ("High", "Medium")
| summarize
    TotalAlerts = count(),
    ConfirmedTP = countif(ConfidenceLevel == "High")
    by AlertName
| extend FalsePositiveRate = round((1.0 - (toreal(ConfirmedTP) / toreal(TotalAlerts))) * 100, 1)
| where TotalAlerts > 5
| sort by FalsePositiveRate desc
| take 5
| project AlertName, TotalAlerts, ConfirmedTP, FalsePositiveRate
```

**Exception backlog (open exceptions by age)**

```kql
SecurityIncident
| where Status == "Active"
| where Classification == "TruePositive"
| where TimeGenerated < ago(1d)
| extend AgeInDays = datetime_diff('day', now(), CreatedTime)
| project IncidentName, CreatedTime, AgeInDays, Owner = tostring(parse_json(Owner).userPrincipalName)
| sort by AgeInDays desc
```

---

### CISO — monthly (severity floor: High; Medium as trend only)

**MTTD and MTTR — 90-day weekly trend**

```kql
SecurityIncident
| where TimeGenerated > ago(90d)
| where Severity in ("High", "Medium")
| where Status == "Closed"
| extend
    WeekBin = startofweek(CreatedTime),
    MTTD_min = datetime_diff('minute', FirstModifiedTime, CreatedTime),
    MTTR_hr = datetime_diff('hour', ClosedTime, CreatedTime)
| summarize
    MedianMTTD_min = percentile(MTTD_min, 50),
    MedianMTTR_hr = percentile(MTTR_hr, 50),
    HighCount = countif(Severity == "High"),
    MediumCount = countif(Severity == "Medium")
    by WeekBin
| sort by WeekBin asc
```

**Top 3 material incidents — current month**

```kql
SecurityIncident
| where TimeGenerated > ago(30d)
| where Severity == "High"
| where Status == "Closed"
| where Classification == "TruePositive"
| project
    IncidentName,
    CreatedTime,
    ClosedTime,
    Description,
    Owner = tostring(parse_json(Owner).userPrincipalName)
| sort by CreatedTime desc
| take 3
```

---

### Executive committee and board — quarterly (severity floor: High material incidents only)

**Dwell time trend — rolling 5 quarters**

```kql
SecurityIncident
| where TimeGenerated > ago(450d)
| where Severity == "High"
| where Status == "Closed"
| where Classification == "TruePositive"
| extend
    QuarterBin = strcat(format_datetime(CreatedTime, "yyyy"), "-Q", tostring((monthofyear(CreatedTime) - 1) / 3 + 1)),
    DwellTime_days = datetime_diff('day', ClosedTime, CreatedTime)
| summarize
    MedianDwell_days = percentile(DwellTime_days, 50),
    MaxDwell_days = max(DwellTime_days),
    MaterialIncidentCount = count()
    by QuarterBin
| sort by QuarterBin asc
```

KQL's `format_datetime()` has no quarter format specifier, so the quarter label is built with `strcat()` and integer division on `monthofyear()`. The resulting `yyyy-Qn` string sorts correctly both within and across years.

**Top 3 material incidents — current quarter**

```kql
SecurityIncident
| where TimeGenerated > ago(90d)
| where Severity == "High"
| where Status == "Closed"
| where Classification == "TruePositive"
| project
    IncidentName,
    CreatedTime,
    ClosedTime,
    Description
| sort by CreatedTime desc
| take 3
```

---

## Part 3 — Security Copilot prompt patterns

These prompts are designed for use in Microsoft Security Copilot standalone or in the Defender XDR embedded Copilot experience. Paste the prompt, review the output, and edit before inserting into the report. Do not publish Copilot output without human review.

### SOC lead weekly — MTTD/MTTR narrative

```
Summarize the detection and response performance for the past 7 days in 2 sentences. 
Use this data: median MTTD [X] minutes, 90th percentile MTTD [X] minutes, median MTTR [X] hours, 
[X%] of incidents have a Copilot investigation summary. 
If any metric is higher than last week, name the most likely cause based on incident types this week. 
Audience: SOC lead. No jargon.
```

### CISO monthly — top 3 incidents narrative

```
Summarize the top 3 High severity confirmed security incidents from the past 30 days in this format:
Incident name. What happened in 1 sentence. Business impact in 1 sentence. Current status in 1 sentence.
Do not use technical identifiers (CVE numbers, process names, IP addresses) unless the CISO explicitly needs them.
Audience: CISO. Plain language.
```

### Executive committee — investment narrative

```
Write a 2-sentence summary connecting our security investment this quarter to measurable risk reduction.
Use this data: [investment amount and initiative], [specific risk metric that improved, with before and after values].
The reader is an executive committee member who approves budget. No technical jargon.
Audience: Executive committee.
```

### Board — quarterly posture narrative

```
Write a 1-sentence summary of our overall security posture for the past quarter.
Use this data: overall Zero Trust maturity stage [X], [direction of change], [1 material incident or "no material incidents"].
The reader is a board member. Plain language. Do not mention product names.
Audience: Board.
```

---

## Usage notes

- All KQL queries target a 7-day, 30-day, or 90-day lookback by default. Adjust the `ago()` parameter to match the reporting period.
- The `ConfidenceLevel` field in `SecurityAlert` is populated by Defender XDR's ML models. In high-noise environments, supplement with analyst classification labels from the incident queue.
- Security Copilot prompts are starting points. Verify every factual claim in the output against the Defender XDR incident queue before publishing to an executive audience.
- Workbook deployment requires the Sentinel Contributor role at minimum. Do not share workbook ARM templates with workspace resource IDs committed to version control — use the `REPLACE_WITH_*` placeholders and substitute at deploy time.
