# APIsec API Guide for Report Generation

## API Base URL

**IMPORTANT**: APIsec uses a SINGLE API endpoint for all tenants:

```
https://api.apisecapps.com
```

The tenant (bmo, cloud, infineon, etc.) is determined by the **Bearer token**, NOT the URL. The token contains a `custom:tenantId` claim that tells the API which tenant's data to return.

**WRONG**: `https://bmo.apisecapps.com/v1/...` (this is the UI, not API)
**CORRECT**: `https://api.apisecapps.com/v1/...` (always use this)

---

## API Endpoints Needed

### 1. List Scans
```
GET /v1/applications/{appId}/instances/{instanceId}/scans
Authorization: Bearer {token}
```

Response:
```json
{
  "scans": [
    {
      "scanId": "019a507c-819d-73ce-8851-2d3dc6376e22",
      "status": "Complete",
      "startTime": "2025-10-28T12:10:25.563Z",
      "lastUpdateTime": "2025-10-28T12:11:59.831Z"
    }
  ]
}
```

### 2. Get Scan Results (vulnerabilities + informational detections)
```
GET /v1/applications/{appId}/instances/{instanceId}/scans/{scanId}
Authorization: Bearer {token}
```

Response:
```json
{
  "scanId": "019a507c-819d-73ce-8851-2d3dc6376e22",
  "status": "Complete",
  "startTime": "2025-10-28T12:10:25.563Z",
  "lastUpdateTime": "2025-10-28T12:11:59.831Z",
  "scanAuth": "oauth2",
  "vulnerabilities": [
    {
      "endpointId": "R0VUOi9hcGkvdXNlcnM=",
      "method": "get",
      "resource": "/api/users",
      "scanFindings": [
        {
          "executionId": "abc123-def456",
          "detectionDate": "2025-10-28",
          "testDetails": {
            "categoryId": "injection",
            "categoryName": "injection",
            "categoryTestId": "sqlInjection",
            "categoryTestName": "sqlInjection",
            "owaspTags": ["API1:2023"]
          },
          "testStatus": {
            "value": "FAILED",
            "description": "Test description..."
          },
          "testResult": {
            "cvssScore": 9.8,
            "cvssQualifier": "Critical",
            "detectionDescription": "SQL injection vulnerability found..."
          }
        }
      ]
    }
  ],
  "issues": [
    {
      "endpointId": "UE9TVDovY2VydGlmaWNhdGVz",
      "method": "post",
      "resource": "/certificates",
      "scanFindings": [
        {
          "executionId": "3f4dc942-a19f-4526-94d5-c95151a61b8b",
          "detectionDate": "",
          "testDetails": {
            "categoryId": "headers",
            "categoryName": "headers",
            "categoryTestId": "cors",
            "categoryTestName": "cors",
            "owaspTags": ["API8:2023"]
          },
          "testStatus": {
            "value": "PASSED",
            "description": "CORS policy check..."
          },
          "testResult": {
            "cvssScore": 2.0,
            "cvssQualifier": "Low",
            "detectionDescription": "Informational finding about CORS..."
          }
        }
      ]
    }
  ],
  "metadata": {
    "endpointsUnderTest": 10,
    "endpointsScanned": 10,
    "totalTests": 495,
    "testsPassed": 414,
    "testsFailed": 3,
    "testsSkipped": 78,
    "numVulnerabilities": 3,
    "numIssues": 54
  }
}
```

**Key distinction:**
- `vulnerabilities[]` = FAILED tests (actual security vulnerabilities)
- `issues[]` = PASSED tests with informational findings (not vulnerabilities, but worth noting)

### 3. Get Detections (alternative to scan results)
```
GET /v1/applications/{appId}/instances/{instanceId}/detections
Authorization: Bearer {token}
```

This returns detection data in a different format, grouped by test category. Each vulnerability has a `detectionId` that can be used to fetch logs.

Response:
```json
{
  "detections": [
    {
      "category": { "id": "injection", "name": "injection" },
      "test": {
        "id": "sqlInjection",
        "name": "sqlInjection",
        "owaspTag": ["API1:2023"]
      },
      "totalDetections": 1,
      "data": {
        "numVulnerableEndpoints": 1,
        "numActiveVulnerabilities": 1,
        "numInfoDetections": 0,
        "numResolved": 0,
        "vulnerabilities": [
          {
            "detectionId": "7a8b9c0d-1e2f-3g4h-5i6j-7k8l9m0n1o2p",
            "endpointId": "R0VUOi9hcGkvdXNlcnM=",
            "method": "get",
            "resource": "/api/users",
            "testResult": {
              "cvssScore": 9.8,
              "cvssQualifier": "Critical",
              "detectionDescription": "SQL injection..."
            },
            "detectionDate": "2025-10-28",
            "status": "ACTIVE"
          }
        ]
      }
    }
  ],
  "metadata": {
    "totalHighSeverityVulnerabilities": 1,
    "totalActiveVulnerabilities": 3,
    "totalVulnerabilitiesResolved": 0,
    "totalTests": 495,
    "totalHoursSaved": 120
  }
}
```

### 4. Get Detection Logs (HTTP request/response data)
```
GET /v1/applications/{appId}/instances/{instanceId}/detections/{detectionId}
Authorization: Bearer {token}
```

**CRITICAL**: This endpoint requires a `detectionId` from the `/detections` endpoint, NOT an `executionId` from `/scans/{scanId}`.

Response:
```json
{
  "category": { "id": "injection", "name": "injection" },
  "test": { "id": "sqlInjection", "name": "sqlInjection" },
  "logs": {
    "evidence": "corr-id-12345",
    "testChain": [
      {
        "category": "dry_run",
        "roleName": "admin",
        "authName": "oauth2",
        "request": {
          "correlationId": "corr-id-12344",
          "method": "GET",
          "url": "https://api.example.com/api/users",
          "headers": {
            "Authorization": "Bearer xxx",
            "Content-Type": "application/json"
          },
          "body": null
        },
        "response": {
          "statusCode": 200,
          "responseTime": 145.5,
          "headers": {
            "Content-Type": "application/json"
          },
          "content": "{\"users\": [...]}",
          "contentLength": 1234
        }
      },
      {
        "category": "attack",
        "roleName": "admin",
        "authName": "oauth2",
        "request": {
          "correlationId": "corr-id-12345",
          "method": "GET",
          "url": "https://api.example.com/api/users?id=' OR '1'='1",
          "headers": {
            "Authorization": "Bearer xxx",
            "Content-Type": "application/json"
          },
          "body": null
        },
        "response": {
          "statusCode": 200,
          "responseTime": 89.2,
          "headers": {
            "Content-Type": "application/json"
          },
          "content": "{\"users\": [all users returned due to SQL injection]}",
          "contentLength": 5678
        }
      }
    ]
  }
}
```

The `logs.evidence` field contains the `correlationId` of the request/response that triggered the detection (usually the "attack" category entry).

---

## How to Get Logs into PDF

### Step-by-step process:

1. **Get scan results** to show what vulnerabilities/issues exist:
   ```
   GET /v1/applications/{appId}/instances/{instanceId}/scans/{scanId}
   ```

2. **Get detections** to get the `detectionId` values:
   ```
   GET /v1/applications/{appId}/instances/{instanceId}/detections
   ```

3. **For each vulnerability**, find its `detectionId` and fetch logs:
   ```
   GET /v1/applications/{appId}/instances/{instanceId}/detections/{detectionId}
   ```

4. **Match logs to findings** using endpoint + test category

### Important Limitation

**HTTP logs are ONLY available for vulnerabilities (FAILED tests), NOT for informational detections (PASSED tests/issues).**

- `vulnerabilities[]` from scan results → Have `detectionId` in detections API → CAN fetch logs
- `issues[]` from scan results → Only have `executionId` → CANNOT fetch logs (API returns 500)

---

## TypeScript Types

```typescript
// Scan Results
interface ScanResults {
  scanId: string;
  status: string;
  startTime: string;
  lastUpdateTime: string;
  scanAuth: string;
  vulnerabilities: EndpointFindings[];
  issues: EndpointFindings[];
  metadata: ScanMetadata;
}

interface EndpointFindings {
  endpointId: string;
  method: string;
  resource: string;
  scanFindings: ScanFinding[];
}

interface ScanFinding {
  executionId: string;  // NOT usable for logs API!
  detectionDate: string;
  testDetails: TestDetails;
  testStatus: TestStatus;
  testResult: TestResult | null;
}

interface TestDetails {
  categoryId: string;
  categoryName: string;
  categoryTestId: string;
  categoryTestName: string;
  owaspTags: string[];
}

interface TestStatus {
  value: "PASSED" | "FAILED" | "SKIPPED";
  description: string;
}

interface TestResult {
  cvssScore: number;
  cvssQualifier: "Critical" | "High" | "Medium" | "Low" | "Info";
  detectionDescription: string;
}

// Detections (for getting detectionIds)
interface DetectionsResponse {
  detections: Detection[];
  metadata: DetectionMetadata;
}

interface Detection {
  category: { id: string; name: string };
  test: { id: string; name: string; owaspTag: string[] };
  totalDetections: number;
  data: {
    numVulnerableEndpoints: number;
    numActiveVulnerabilities: number;
    numInfoDetections: number;
    numResolved: number;
    vulnerabilities: VulnerabilityDetail[];
  };
}

interface VulnerabilityDetail {
  detectionId: string;  // USE THIS for logs API!
  endpointId: string;
  method: string;
  resource: string;
  testResult: TestResult;
  detectionDate: string;
  status: string;
}

// Detection Logs
interface DetectionWithLogs {
  category: { id: string; name: string };
  test: { id: string; name: string };
  logs: {
    evidence: string;  // correlationId of the failing request
    testChain: TestChainEntry[];
  };
}

interface TestChainEntry {
  category: string;  // "dry_run", "attack", etc.
  roleName?: string;
  authName?: string;
  request: HttpRequest;
  response: HttpResponse;
}

interface HttpRequest {
  correlationId: string;
  method: string;
  url: string;
  headers: Record<string, string>;
  body?: string;
}

interface HttpResponse {
  statusCode: number;
  responseTime: number;
  headers: Record<string, string>;
  content?: string;
  contentLength?: number;
}
```

---

## Recommended Fetch Flow

```typescript
async function fetchReportData(
  token: string,
  appId: string,
  instanceId: string,
  scanId: string,
  includeLogs: boolean = true
): Promise<ReportData> {
  // 1. Get scan results (vulnerabilities + issues)
  const scanResults = await fetch(
    `/api/apisec/v1/applications/${appId}/instances/${instanceId}/scans/${scanId}`,
    { headers: { Authorization: token } }
  ).then(r => r.json());

  // 2. If we want logs, get detections to find detectionIds
  let detectionLogs: Map<string, TestChainEntry[]> = new Map();

  if (includeLogs && scanResults.vulnerabilities.length > 0) {
    // Get detections list
    const detectionsResponse = await fetch(
      `/api/apisec/v1/applications/${appId}/instances/${instanceId}/detections`,
      { headers: { Authorization: token } }
    ).then(r => r.json());

    // Extract all detectionIds
    const detectionIds: string[] = [];
    for (const detection of detectionsResponse.detections) {
      for (const vuln of detection.data.vulnerabilities) {
        detectionIds.push(vuln.detectionId);
      }
    }

    // Fetch logs for each detection
    for (const detectionId of detectionIds) {
      try {
        const logsResponse = await fetch(
          `/api/apisec/v1/applications/${appId}/instances/${instanceId}/detections/${detectionId}`,
          { headers: { Authorization: token } }
        ).then(r => r.json());

        if (logsResponse.logs?.testChain) {
          detectionLogs.set(detectionId, logsResponse.logs.testChain);
        }
      } catch (e) {
        console.warn(`Failed to fetch logs for ${detectionId}`);
      }
    }
  }

  return {
    scanResults,
    detectionLogs
  };
}
```

---

## Matching Logs to Scan Findings

Since scan results use `executionId` but logs require `detectionId`, you need to match by endpoint + test:

```typescript
function findLogsForFinding(
  finding: ScanFinding,
  endpoint: EndpointFindings,
  detections: Detection[],
  detectionLogs: Map<string, TestChainEntry[]>
): TestChainEntry[] | null {
  // Find matching detection by category + test + endpoint
  for (const detection of detections) {
    if (detection.category.id !== finding.testDetails.categoryId) continue;
    if (detection.test.id !== finding.testDetails.categoryTestId) continue;

    // Find matching vulnerability by endpoint
    for (const vuln of detection.data.vulnerabilities) {
      if (vuln.resource === endpoint.resource && vuln.method === endpoint.method) {
        return detectionLogs.get(vuln.detectionId) || null;
      }
    }
  }
  return null;
}
```

---

## Summary

1. **API Base URL**: Always `https://api.apisecapps.com` (tenant is in token)
2. **Scan results** give you vulnerabilities + issues
3. **Detections** give you `detectionId` values needed for logs
4. **Logs** are only available for vulnerabilities, not informational issues
5. **Match** scan findings to detections using category + test + endpoint
