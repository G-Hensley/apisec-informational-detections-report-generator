/**
 * APIsec API client for fetching vulnerability scan data.
 *
 * Why: Encapsulates all API communication with proper error handling
 * and type safety. Follows the Client pattern from type boundary architecture.
 *
 * IMPORTANT: APIsec uses a SINGLE API endpoint for all tenants.
 * The tenant is determined by the Bearer token, NOT the URL.
 */

import {
  ScanResults,
  DetectionLogs,
  ScanListItem,
  DetectionsResponse,
  EndpointFindings,
  ApplicationDetails,
  EndpointConfigResponse,
} from "./types";

const API_BASE = "/api/apisec";

export class ApiSecError extends Error {
  constructor(
    message: string,
    public status: number,
    public details?: string
  ) {
    super(message);
    this.name = "ApiSecError";
  }
}

async function fetchApi<T>(
  path: string,
  token: string
): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: {
      Authorization: token,
      "Content-Type": "application/json",
    },
  });

  if (!res.ok) {
    const errorText = await res.text();
    let errorData: { error?: string; details?: string } = {};
    try {
      errorData = JSON.parse(errorText);
    } catch {
      errorData = { details: errorText };
    }
    console.error(`[API] Error ${res.status}:`, errorData);
    throw new ApiSecError(
      errorData.error || `API error: ${res.status}`,
      res.status,
      errorData.details
    );
  }

  return res.json();
}

/**
 * Get application details including name.
 */
export async function getApplicationDetails(
  token: string,
  appId: string
): Promise<ApplicationDetails> {
  return fetchApi<ApplicationDetails>(
    `/v1/applications/${appId}`,
    token
  );
}

/**
 * List available scans for an application instance.
 */
export async function listScans(
  token: string,
  appId: string,
  instanceId: string
): Promise<ScanListItem[]> {
  return fetchApi<ScanListItem[]>(
    `/v1/applications/${appId}/instances/${instanceId}/scans`,
    token
  );
}

/**
 * Get scan results including vulnerabilities and issues.
 */
export async function getScanResults(
  token: string,
  appId: string,
  instanceId: string,
  scanId: string
): Promise<ScanResults> {
  return fetchApi<ScanResults>(
    `/v1/applications/${appId}/instances/${instanceId}/scans/${scanId}`,
    token
  );
}

/**
 * Get detections list to obtain detectionIds for fetching logs.
 *
 * IMPORTANT: This is required because scan results only have executionId,
 * but the logs API requires detectionId which is only available here.
 */
export async function getDetections(
  token: string,
  appId: string,
  instanceId: string
): Promise<DetectionsResponse> {
  return fetchApi<DetectionsResponse>(
    `/v1/applications/${appId}/instances/${instanceId}/detections`,
    token
  );
}

/**
 * Get endpoint configuration for an instance.
 *
 * Why: Provides authentication requirements per endpoint,
 * allowing reports to show whether endpoints require auth.
 */
export async function getEndpointConfig(
  token: string,
  appId: string,
  instanceId: string
): Promise<EndpointConfigResponse> {
  return fetchApi<EndpointConfigResponse>(
    `/v1/applications/${appId}/instances/${instanceId}/endpoints?include=metadata&slim=true`,
    token
  );
}

/**
 * Get detection logs for a specific vulnerability using detectionId.
 *
 * IMPORTANT: This requires a detectionId from getDetections(),
 * NOT an executionId from getScanResults(). Using executionId will fail!
 */
export async function getDetectionLogs(
  token: string,
  appId: string,
  instanceId: string,
  detectionId: string
): Promise<DetectionLogs> {
  const endpoint = `/v1/applications/${appId}/instances/${instanceId}/detections/${detectionId}`;

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rawResponse = await fetchApi<any>(endpoint, token);

  // The response should have logs.testChain
  if (rawResponse.logs?.testChain) {
    return rawResponse as DetectionLogs;
  }

  // Fallback: wrap if testChain is at root level
  if (rawResponse.testChain) {
    return { logs: rawResponse };
  }

  return rawResponse as DetectionLogs;
}

/**
 * Result from fetchReportData containing scan results and optional logs.
 */
export interface FetchReportDataResult {
  scanResults: ScanResults;
  detectionLogsMap: Map<string, DetectionLogs>;
  /** Maps detectionId to matching scan finding key (endpoint:method:category:test) */
  detectionToFindingMap: Map<string, string>;
  /** Maps finding key (resource:method:categoryId:testId) to detection status */
  detectionStatusByKey: Map<string, string>;
  /** Finding keys that should be excluded (resolved/false positive status) */
  excludedFindingKeys: Set<string>;
  /** Application name fetched from the API */
  appName?: string;
  /** Host URL for the scanned instance */
  hostUrl?: string;
  /** Maps endpoint path to whether it requires authentication (from instance config) */
  endpointAuthMap: Map<string, boolean>;
}

/**
 * Create a key for matching scan findings to detections for exclusion filtering.
 * Uses method:resource:categoryId:testId for reliable matching between APIs.
 */
function createExclusionKey(
  method: string,
  resource: string,
  categoryId: string,
  testId: string
): string {
  // Normalize: lowercase method, trim resource, normalize path separators
  return `${method.toUpperCase()}:${resource.trim()}:${categoryId}:${testId}`;
}

/**
 * Create a key for matching logs (uses resource path for log lookup).
 */
function createLogKey(
  resource: string,
  method: string,
  categoryId: string,
  testId: string
): string {
  return `${resource}:${method.toLowerCase()}:${categoryId}:${testId}`;
}

/**
 * Resolution statuses that should be excluded from reports.
 * These represent findings that have been addressed or determined to not be real issues.
 * All statuses are stored normalized (lowercase, spaces instead of underscores).
 */
const EXCLUDED_STATUSES = ["false positive", "resolved"];

/**
 * Normalize a status string for comparison.
 * Converts to lowercase and replaces underscores with spaces.
 */
function normalizeStatus(status: string): string {
  return status.toLowerCase().replace(/_/g, " ");
}

/**
 * Check if a detection should be included in the report based on its resolution status.
 */
function isActiveDetection(status: string): boolean {
  return !EXCLUDED_STATUSES.includes(normalizeStatus(status));
}

/**
 * Build ScanResults from detections data when scanId is not available.
 * This allows generating vulnerability-only reports without a scan ID.
 */
function buildScanResultsFromDetections(
  detectionsResponse: DetectionsResponse,
  instanceId: string
): ScanResults {
  // Group vulnerabilities by endpoint
  const endpointMap = new Map<string, EndpointFindings>();

  for (const detection of detectionsResponse.detections) {
    for (const vuln of detection.data.vulnerabilities) {
      // Skip resolved or false positive detections
      if (!isActiveDetection(vuln.status)) {
        continue;
      }

      const endpointKey = `${vuln.method}:${vuln.resource}`;

      if (!endpointMap.has(endpointKey)) {
        endpointMap.set(endpointKey, {
          endpointId: vuln.endpointId,
          method: vuln.method,
          resource: vuln.resource,
          scanFindings: [],
        });
      }

      const endpoint = endpointMap.get(endpointKey)!;
      endpoint.scanFindings.push({
        executionId: vuln.detectionId, // Use detectionId as executionId
        detectionDate: vuln.detectionDate,
        testDetails: {
          categoryId: detection.category.id,
          categoryName: detection.category.name,
          categoryTestId: detection.test.id,
          categoryTestName: detection.test.name,
          owaspTags: detection.test.owaspTag || [],
        },
        testStatus: {
          value: "FAILED",
          description: vuln.testResult.detectionDescription,
        },
        testResult: {
          cvssScore: vuln.testResult.cvssScore,
          cvssQualifier: vuln.testResult.cvssQualifier as "Critical" | "High" | "Medium" | "Low" | "Info",
          detectionDescription: vuln.testResult.detectionDescription,
        },
      });
    }
  }

  const vulnerabilities = Array.from(endpointMap.values());
  const totalVulns = vulnerabilities.reduce((sum, e) => sum + e.scanFindings.length, 0);

  // Handle case where metadata might be null
  const totalTests = detectionsResponse.metadata?.totalTests ?? totalVulns;

  return {
    scanId: `detections-${instanceId}`, // Synthetic scan ID
    status: "COMPLETED",
    startTime: new Date().toISOString(),
    lastUpdateTime: new Date().toISOString(),
    scanAuth: "",
    vulnerabilities,
    issues: [], // No issues available without scan results
    metadata: {
      endpointsUnderTest: vulnerabilities.length,
      endpointsScanned: vulnerabilities.length,
      totalTests,
      testsPassed: totalTests - totalVulns,
      testsFailed: totalVulns,
      testsSkipped: 0,
      numVulnerabilities: totalVulns,
      numIssues: 0,
    },
  };
}

/**
 * Fetch all data needed for report generation.
 *
 * Why: Separates data fetching from PDF generation, allowing the
 * PDFReportGenerator to focus solely on data transformation and rendering.
 *
 * Flow (with scanId):
 * 1. Get scan results (vulnerabilities + issues)
 * 2. Get detections list to obtain detectionIds
 * 3. Fetch logs for each detectionId
 * 4. Build a map to match logs to scan findings
 *
 * Flow (without scanId - vulnerabilities only):
 * 1. Get detections list (contains vulnerability data)
 * 2. Build synthetic scan results from detections
 * 3. Optionally fetch logs for each detection
 */
export async function fetchReportData(
  token: string,
  _tenant: string, // Kept for API compatibility but not used (tenant is in token)
  appId: string,
  instanceId: string,
  scanId: string, // Can be empty - only needed for informational findings
  includeHttpLogs: boolean,
  onProgress?: (message: string, percent: number) => void
): Promise<FetchReportDataResult> {
  const detectionLogsMap = new Map<string, DetectionLogs>();
  const detectionToFindingMap = new Map<string, string>();
  const detectionStatusByKey = new Map<string, string>();
  const excludedFindingKeys = new Set<string>();
  const endpointAuthMap = new Map<string, boolean>();
  let scanResults: ScanResults;
  let appName: string | undefined;
  let hostUrl: string | undefined;

  // Fetch application details to get the app name and host URL
  onProgress?.("Fetching application details...", 3);
  try {
    const appDetails = await getApplicationDetails(token, appId);
    appName = appDetails.applicationName;
    // Find the matching instance to get the host URL
    const matchingInstance = appDetails.instances.find(i => i.instanceId === instanceId);
    hostUrl = matchingInstance?.hostUrl;
  } catch (error) {
    console.warn("Failed to fetch application details:", error);
  }

  // Fetch endpoint configuration to get auth requirements per endpoint
  onProgress?.("Fetching endpoint configuration...", 6);
  try {
    const endpointConfig = await getEndpointConfig(token, appId, instanceId);
    // Build map of endpoint path -> requires auth
    for (const group of endpointConfig.endpointGroups) {
      for (const endpoint of group.endpoints) {
        // Key: METHOD:path (normalized to uppercase method)
        const key = `${endpoint.method.toUpperCase()}:${endpoint.path}`;
        endpointAuthMap.set(key, endpoint.requiresAuthorization);
      }
    }
  } catch (error) {
    console.warn("Failed to fetch endpoint configuration:", error);
  }

  // Check if we have a scan ID
  const hasScanId = scanId && scanId.trim() !== "";

  if (hasScanId) {
    // Original flow: Get scan results (includes issues/informational)
    onProgress?.("Fetching scan results...", 10);
    scanResults = await getScanResults(token, appId, instanceId, scanId);

    // Also fetch detections to determine which findings are resolved/false positive
    onProgress?.("Fetching detection status...", 20);
    try {
      const detectionsResponse = await getDetections(token, appId, instanceId);

      for (const detection of detectionsResponse.detections) {
        for (const vuln of detection.data.vulnerabilities) {
          const exclusionKey = createExclusionKey(
            vuln.method,
            vuln.resource,
            detection.category.id,
            detection.test.id
          );

          // Track status for display
          const logKey = createLogKey(
            vuln.resource,
            vuln.method,
            detection.category.id,
            detection.test.id
          );
          detectionStatusByKey.set(logKey, vuln.status);

          if (!isActiveDetection(vuln.status)) {
            excludedFindingKeys.add(exclusionKey);
          }
        }
      }
    } catch (error) {
      console.warn("Failed to fetch detection status for filtering:", error);
    }
  } else {
    // No scan ID: Build from detections only (vulnerabilities only, no issues)
    // Filtering is already done in buildScanResultsFromDetections
    onProgress?.("Fetching detections...", 10);
    const detectionsResponse = await getDetections(token, appId, instanceId);
    scanResults = buildScanResultsFromDetections(detectionsResponse, instanceId);

    // Track status for display
    for (const detection of detectionsResponse.detections) {
      for (const vuln of detection.data.vulnerabilities) {
        const logKey = createLogKey(
          vuln.resource,
          vuln.method,
          detection.category.id,
          detection.test.id
        );
        detectionStatusByKey.set(logKey, vuln.status);
      }
    }
  }

  // Fetch HTTP logs if requested
  if (includeHttpLogs && scanResults.vulnerabilities.length > 0) {
    onProgress?.("Fetching detections list...", 30);

    try {
      const detectionsResponse = await getDetections(token, appId, instanceId);

      // Extract all detectionIds and build mapping (excluding resolved/false positive)
      const detectionIds: Array<{ detectionId: string; findingKey: string }> = [];

      for (const detection of detectionsResponse.detections) {
        for (const vuln of detection.data.vulnerabilities) {
          // Skip resolved or false positive detections
          if (!isActiveDetection(vuln.status)) {
            continue;
          }

          // Use createLogKey for log matching (uses resource path)
          const logKey = createLogKey(
            vuln.resource,
            vuln.method,
            detection.category.id,
            detection.test.id
          );
          detectionIds.push({ detectionId: vuln.detectionId, findingKey: logKey });
          detectionToFindingMap.set(vuln.detectionId, logKey);
          detectionStatusByKey.set(logKey, vuln.status);
        }
      }

      // Fetch logs for each detection
      onProgress?.("Fetching HTTP logs...", 40);

      const total = detectionIds.length;
      for (let i = 0; i < total; i++) {
        const { detectionId } = detectionIds[i];
        try {
          const logs = await getDetectionLogs(token, appId, instanceId, detectionId);
          detectionLogsMap.set(detectionId, logs);
        } catch {
          // Silently skip failed log fetches
        }

        const progress = 40 + Math.round((i / total) * 50);
        onProgress?.(`Fetching HTTP logs (${i + 1}/${total})...`, progress);
      }
    } catch (error) {
      console.error("Failed to fetch detections:", error);
    }
  }

  onProgress?.("Data fetch complete", 95);

  return {
    scanResults,
    detectionLogsMap,
    detectionToFindingMap,
    detectionStatusByKey,
    excludedFindingKeys,
    appName,
    hostUrl,
    endpointAuthMap,
  };
}

/**
 * Find logs for a scan finding by matching endpoint + category + test.
 */
export function findLogsForFinding(
  resource: string,
  method: string,
  categoryId: string,
  testId: string,
  detectionToFindingMap: Map<string, string>,
  detectionLogsMap: Map<string, DetectionLogs>
): DetectionLogs | undefined {
  const logKey = createLogKey(resource, method, categoryId, testId);

  // Find the detectionId that matches this finding
  for (const [detectionId, key] of detectionToFindingMap.entries()) {
    if (key === logKey) {
      return detectionLogsMap.get(detectionId);
    }
  }

  return undefined;
}
