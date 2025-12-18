# APISec Report Enhancement Tasks

## Overview
This file tracks the implementation status of feedback items for the PDF vulnerability report generator.
Latest feedback: Some reports show no "Vulnerable Parameter" highlighting (e.g., IDOR/cookie findings with no injection payloads).

---

## Completed
- [x] Vulnerability Summary Table - added table listing all vulns by severity
- [x] Auth Status per Finding - shows authentication role/method used
- [x] Enhanced Remediation Details - OWASP descriptions and category-based impact
- [x] Application Name - auto-fetched from API instead of manual input
- [x] Separate Vulnerabilities from Informational - distinct sections with separate counts
- [x] Host URL in Executive Summary - extracted from ApplicationDetails and displayed in report header
- [x] APISec Vulnerability ID in Summary Table - added Detection ID column showing first 8 chars
- [x] Better Visual Separation for Request/Response Logs - colored headers (green/indigo), left borders, and status code badges
- [x] Dedicated "Endpoints Scanned" Table - shows method (colored badge), endpoint, vuln count, info count, auth status (from endpoint config)
- [x] Highlighted Vulnerable Parameter - extracts and highlights injected payloads from HTTP logs; also highlights exposed identifier fields (UUID/numeric IDs) for IDOR/BOLA-style findings when no injection payload is present
- [x] Table of Contents - clickable links to all major sections
- [x] Enhanced Remediation Section - solution/exploitation/references per finding (category/test mappings)
- [x] Vulnerability Status Column - status column in summary table sourced from detection status (displays API-provided status values)

---

## In Progress
- [ ] **None currently**

---

## TODO (Prioritized)

### Low Priority - Complex/Uncertain Requirements

1. **Reopened Status Detection**
   - Compare current findings with historical data to detect reopened vulns
   - Complexity: Very High
   - Data source: Would need to query multiple historical scans
   - Note: Parking this - may not implement

2. **Vulnerability Count Clarification**
   - Decide: count info as "vulnerabilities" or separate?
   - Currently: Separate sections with separate counts
   - Status: Already implemented - may need UI/wording tweaks

---

## Implementation Notes

### Data Sources
- `ScanResults` - vulnerabilities, issues, metadata
- `DetectionsResponse` - detectionId, status, vulnerability details
- `ApplicationDetails` - appName, hostUrl, instances
- `DetectionLogs` - HTTP request/response, auth info
- `EndpointConfigResponse` - endpoint auth requirements (requiresAuthorization per endpoint)

### Files to Modify
- `lib/pdf/generator.ts` - PDF rendering logic
- `lib/pdf/models.ts` - Data structures
- `lib/apisec-client.ts` - API data fetching
- `lib/types.ts` - TypeScript interfaces

---

## How to Use This File
1. Pick an item from TODO
2. Move it to "In Progress"
3. Implement the change
4. Get user review
5. Move to "Completed" or iterate based on feedback
