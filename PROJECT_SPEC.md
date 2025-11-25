# APIsec Report Generator - Project Specification

## Overview
A Next.js frontend application that generates PDF vulnerability reports from APIsec scan data. Users input their APIsec credentials and scan details, and the app fetches data and generates a downloadable PDF report.

## Tech Stack
- **Framework**: Next.js 16+ (App Router)
- **UI**: Tailwind CSS v4 + shadcn/ui
- **PDF Generation**: @react-pdf/renderer
- **State**: React useState/useReducer (no external state management needed)
- **Hosting**: Vercel

## Features

### 1. Input Form
User provides:
- **Auth Token**: Bearer token from browser (paste from APIsec Network tab)
- **Tenant**: Dropdown or text input (e.g., `cloud`, `bmo`, `infineon`)
- **App ID**: UUID of the application
- **Instance ID**: UUID of the instance
- **Scan ID**: UUID of the scan (optional - if not provided, list available scans)

### 2. API Integration
Base URL: `https://api.apisecapps.com`

**Endpoints to call:**

```typescript
// 1. List scans (if no scan ID provided)
GET /v1/applications/{appId}/instances/{instanceId}/scans
Headers: { Authorization: "Bearer {token}" }

// 2. Get scan results with vulnerabilities and issues
GET /v1/applications/{appId}/instances/{instanceId}/scans/{scanId}
Headers: { Authorization: "Bearer {token}" }
Response: {
  scanId: string,
  status: string,
  vulnerabilities: EndpointFindings[],  // Failed tests
  issues: EndpointFindings[],           // Informational detections
  metadata: ScanMetadata
}

// 3. Get detection logs (for vulnerabilities only)
GET /v1/applications/{appId}/instances/{instanceId}/detections/{detectionId}
Headers: { Authorization: "Bearer {token}" }
Response: {
  logs: {
    testChain: [{
      category: string,
      request: { method, url, headers, body },
      response: { statusCode, headers, content }
    }]
  }
}
```

### 3. Data Types

```typescript
interface ScanResults {
  scanId: string;
  status: string;
  startTime: string;
  lastUpdateTime: string;
  scanAuth: string;
  vulnerabilities: EndpointFindings[];
  issues: EndpointFindings[];
  metadata: {
    endpointsUnderTest: number;
    endpointsScanned: number;
    totalTests: number;
    testsPassed: number;
    testsFailed: number;
    testsSkipped: number;
    numVulnerabilities: number;
    numIssues: number;
  };
}

interface EndpointFindings {
  endpointId: string;
  method: string;
  resource: string;
  scanFindings: ScanFinding[];
}

interface ScanFinding {
  executionId: string;
  detectionDate: string;
  testDetails: {
    categoryId: string;
    categoryName: string;
    categoryTestId: string;
    categoryTestName: string;
    owaspTags: string[];
  };
  testStatus: {
    value: "PASSED" | "FAILED" | "SKIPPED";
    description: string;
  };
  testResult: {
    cvssScore: number;
    cvssQualifier: "Critical" | "High" | "Medium" | "Low" | "Info";
    detectionDescription: string;
  } | null;
}

interface DetectionLogs {
  logs: {
    testChain: TestChainEntry[];
    evidence: string;  // Correlation ID of the failing request
  };
}

interface TestChainEntry {
  category: string;
  roleName?: string;
  authName?: string;
  request: {
    correlationId: string;
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  response: {
    statusCode: number;
    responseTime: number;
    headers: Record<string, string>;
    content?: string;
    contentLength?: number;
  };
}
```

### 4. PDF Report Structure

```
┌─────────────────────────────────────────┐
│           VULNERABILITY REPORT          │
│                                         │
│  Application: {appName}                 │
│  Instance: {instanceName}               │
│  Scan Date: {date}                      │
│  Status: {status}                       │
├─────────────────────────────────────────┤
│  EXECUTIVE SUMMARY                      │
│  ┌─────┬─────┬─────┬─────┬─────┐       │
│  │Crit │High │Med  │Low  │Info │       │
│  │  0  │  2  │  5  │  3  │ 54  │       │
│  └─────┴─────┴─────┴─────┴─────┘       │
├─────────────────────────────────────────┤
│  FINDINGS                               │
│                                         │
│  [HIGH] SQL Injection                   │
│  Endpoint: POST /api/users              │
│  OWASP: API1:2023                       │
│  CVSS: 7.5                              │
│  Description: ...                       │
│                                         │
│  HTTP Request:                          │
│  ┌─────────────────────────────────┐   │
│  │ POST /api/users HTTP/1.1        │   │
│  │ Host: api.example.com           │   │
│  │ Content-Type: application/json  │   │
│  │                                 │   │
│  │ {"username": "' OR '1'='1"}     │   │
│  └─────────────────────────────────┘   │
│                                         │
│  HTTP Response:                         │
│  ┌─────────────────────────────────┐   │
│  │ HTTP/1.1 200 OK                 │   │
│  │ Content-Type: application/json  │   │
│  │                                 │   │
│  │ {"users": [...]}                │   │
│  └─────────────────────────────────┘   │
│                                         │
│  ─────────────────────────────────────  │
│                                         │
│  [INFO] Missing Rate Limit Header       │
│  Endpoint: GET /api/products            │
│  ...                                    │
└─────────────────────────────────────────┘
```

### 5. UI Flow

```
┌─────────────────────────────────────────────────────────┐
│  APIsec Report Generator                                │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  Auth Token:                                            │
│  ┌─────────────────────────────────────────────────┐   │
│  │ Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp...      │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Tenant:  [cloud    ▼]                                 │
│                                                         │
│  App ID:                                                │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 019a5078-facf-7627-b23b-0137d701186d            │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Instance ID:                                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 019a5079-10b7-7aae-ae6b-23b29998cd78            │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  Scan ID (optional):                                    │
│  ┌─────────────────────────────────────────────────┐   │
│  │                                                 │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
│  [ ] Include HTTP Logs (slower, vulnerabilities only)  │
│  [ ] Include Informational Findings                    │
│                                                         │
│  ┌─────────────────────┐                               │
│  │   Generate Report   │                               │
│  └─────────────────────┘                               │
│                                                         │
│  ┌─────────────────────────────────────────────────┐   │
│  │  Progress: Fetching scan results...             │   │
│  │  ████████████░░░░░░░░░░░░░░░░░░░░  35%         │   │
│  └─────────────────────────────────────────────────┘   │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### 6. CORS Consideration

**Problem**: APIsec API likely doesn't have CORS headers for browser requests.

**Solutions** (pick one):

1. **Next.js API Route as Proxy** (Recommended)
   ```typescript
   // app/api/apisec/[...path]/route.ts
   export async function GET(request: Request) {
     const token = request.headers.get('Authorization');
     const path = // extract path
     const response = await fetch(`https://api.apisecapps.com${path}`, {
       headers: { Authorization: token }
     });
     return Response.json(await response.json());
   }
   ```

2. **Browser Extension** (for development)
   - Use "CORS Unblock" extension during dev

3. **Vercel Edge Config** (if APIsec allows specific origins)

## File Structure

```
apisec-report-generator/
├── app/
│   ├── layout.tsx
│   ├── page.tsx                 # Main form UI
│   ├── api/
│   │   └── apisec/
│   │       └── [...path]/
│   │           └── route.ts     # Proxy to APIsec API
│   └── globals.css
├── components/
│   ├── ui/                      # shadcn components
│   ├── report-form.tsx          # Input form
│   ├── scan-selector.tsx        # Scan dropdown
│   ├── progress-indicator.tsx   # Loading state
│   └── pdf/
│       ├── report-document.tsx  # @react-pdf/renderer document
│       ├── cover-page.tsx
│       ├── summary-section.tsx
│       ├── finding-card.tsx
│       └── http-log-block.tsx
├── lib/
│   ├── apisec-client.ts         # API fetch functions
│   ├── types.ts                 # TypeScript interfaces
│   └── utils.ts                 # Helpers
├── package.json
├── tailwind.config.js
└── tsconfig.json
```

## Implementation Order

1. **Setup**: Create Next.js app with Tailwind + shadcn
2. **Types**: Define all TypeScript interfaces
3. **API Proxy**: Create Next.js API route to proxy APIsec calls
4. **API Client**: Create fetch functions for each endpoint
5. **Form UI**: Build the input form with validation
6. **PDF Components**: Create @react-pdf/renderer components
7. **Integration**: Wire everything together
8. **Polish**: Loading states, error handling, styling

## Dependencies

```json
{
  "dependencies": {
    "next": "^14.0.0",
    "react": "^18.2.0",
    "react-dom": "^18.2.0",
    "@react-pdf/renderer": "^3.1.0",
    "tailwindcss": "^3.3.0",
    "class-variance-authority": "^0.7.0",
    "clsx": "^2.0.0",
    "lucide-react": "^0.294.0"
  }
}
```

## Key Implementation Notes

### PDF Generation with @react-pdf/renderer

```tsx
// components/pdf/report-document.tsx
import { Document, Page, Text, View, StyleSheet } from '@react-pdf/renderer';

const styles = StyleSheet.create({
  page: { padding: 30 },
  title: { fontSize: 24, marginBottom: 20 },
  section: { marginBottom: 15 },
  finding: {
    marginBottom: 10,
    padding: 10,
    backgroundColor: '#f5f5f5'
  },
  codeBlock: {
    fontFamily: 'Courier',
    fontSize: 8,
    backgroundColor: '#1e1e1e',
    color: '#d4d4d4',
    padding: 10,
  }
});

export function ReportDocument({ data }: { data: ReportData }) {
  return (
    <Document>
      <Page size="A4" style={styles.page}>
        <Text style={styles.title}>Vulnerability Report</Text>
        {/* ... */}
      </Page>
    </Document>
  );
}
```

### Triggering PDF Download

```tsx
import { pdf } from '@react-pdf/renderer';
import { saveAs } from 'file-saver';

async function generatePDF(data: ReportData) {
  const blob = await pdf(<ReportDocument data={data} />).toBlob();
  saveAs(blob, `vulnerability-report-${data.scanId}.pdf`);
}
```

### API Client

```typescript
// lib/apisec-client.ts
const API_BASE = '/api/apisec';  // Proxy route

export async function getScanResults(
  token: string,
  appId: string,
  instanceId: string,
  scanId: string
): Promise<ScanResults> {
  const res = await fetch(
    `${API_BASE}/v1/applications/${appId}/instances/${instanceId}/scans/${scanId}`,
    { headers: { Authorization: token } }
  );
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

export async function getDetectionLogs(
  token: string,
  appId: string,
  instanceId: string,
  detectionId: string
): Promise<DetectionLogs> {
  const res = await fetch(
    `${API_BASE}/v1/applications/${appId}/instances/${instanceId}/detections/${detectionId}`,
    { headers: { Authorization: token } }
  );
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
```

## Error Handling

- **401 Unauthorized**: Token expired, prompt user to refresh
- **404 Not Found**: Invalid IDs, show user-friendly message
- **500 Server Error**: APIsec issue, suggest retry
- **CORS Error**: Proxy not working, check API route

## Future Enhancements

- [ ] Save report configurations locally
- [ ] Batch report generation for multiple scans
- [ ] Custom branding/logo upload
- [ ] Export to other formats (HTML, Markdown)
- [ ] Compare two scans (diff report)
