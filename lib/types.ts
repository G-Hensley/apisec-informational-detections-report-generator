/**
 * APIsec API Types
 *
 * Why: Defines the shape of data returned by the APIsec API.
 * These are "Client" types - representing external API responses.
 */

export interface ScanResults {
  scanId: string;
  status: string;
  startTime: string;
  lastUpdateTime: string;
  scanAuth: string;
  vulnerabilities: EndpointFindings[];
  issues: EndpointFindings[];
  metadata: ScanMetadata;
}

export interface ScanMetadata {
  endpointsUnderTest: number;
  endpointsScanned: number;
  totalTests: number;
  testsPassed: number;
  testsFailed: number;
  testsSkipped: number;
  numVulnerabilities: number;
  numIssues: number;
}

export interface EndpointFindings {
  endpointId: string;
  method: string;
  resource: string;
  scanFindings: ScanFinding[];
}

export interface ScanFinding {
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

export interface DetectionLogs {
  logs: {
    testChain: TestChainEntry[];
    evidence: string;
  };
}

export interface TestChainEntry {
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

export interface ScanListItem {
  scanId: string;
  status: string;
  startTime: string;
  lastUpdateTime: string;
}

/**
 * Application details from the /v1/applications/{appId} endpoint.
 */
export interface ApplicationDetails {
  applicationId: string;
  applicationName: string;
  applicationType: string;
  origin: string;
  instances: Array<{
    instanceId: string;
    hostUrl: string;
    instanceName: string | null;
  }>;
}

/**
 * Detections API Response Types
 *
 * Why: The detections endpoint provides detectionIds needed to fetch HTTP logs.
 * executionId from scan results CANNOT be used for logs - only detectionId works.
 */
export interface DetectionsResponse {
  detections: Detection[];
  metadata: DetectionMetadata;
}

export interface Detection {
  category: { id: string; name: string };
  test: { id: string; name: string; owaspTag: string[] };
  totalDetections: number;
  data: {
    numVulnerableEndpoints: number;
    numActiveVulnerabilities: number;
    numInfoDetections: number;
    numResolved: number;
    vulnerabilities: DetectionVulnerability[];
  };
}

export interface DetectionVulnerability {
  detectionId: string; // USE THIS for logs API!
  endpointId: string;
  method: string;
  resource: string;
  testResult: {
    cvssScore: number;
    cvssQualifier: string;
    detectionDescription: string;
  };
  detectionDate: string;
  status: string;
}

export interface DetectionMetadata {
  totalHighSeverityVulnerabilities: number;
  totalActiveVulnerabilities: number;
  totalVulnerabilitiesResolved: number;
  totalTests: number;
  totalHoursSaved: number;
}

/**
 * Endpoint Configuration Response Types
 *
 * Why: The /endpoints API provides auth requirements per endpoint,
 * allowing us to show whether endpoints require authentication.
 */
export interface EndpointConfigResponse {
  metadata: {
    numEndpoints: number;
    numEndpointsRequireAuth: number;
    numSensitiveEndpoints: number;
  };
  endpointGroups: EndpointConfigGroup[];
}

export interface EndpointConfigGroup {
  groupId: string;
  name: string;
  sensitivityQualifier: string;
  endpoints: EndpointConfig[];
}

export interface EndpointConfig {
  id: string;
  path: string;
  method: string;
  sensitivityQualifier: string;
  requiresAuthorization: boolean;
  metadata: {
    numParams: number;
    numSensitive: number;
    sensitiveParams: string[];
    nonSensitiveParams: string[];
  };
  testabilityStatus: {
    testability: string;
    authUsed: string[];
    reasonIfNot: string | null;
    dateTime: string | null;
    request: unknown | null;
    response: unknown | null;
  };
}

/**
 * Form Input Types
 *
 * Why: Defines the shape of user input from the report form.
 */
export interface ReportConfig {
  token: string;
  tenant: string;
  appId: string;
  instanceId: string;
  scanId: string;
  includeHttpLogs: boolean;
  includeInformational: boolean;
}
