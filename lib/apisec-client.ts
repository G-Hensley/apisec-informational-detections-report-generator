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
  console.log(`[DEBUG] Fetching detection logs from: ${endpoint}`);

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rawResponse = await fetchApi<any>(endpoint, token);

  console.log(`[DEBUG] Raw API response for ${detectionId}:`, JSON.stringify(rawResponse).substring(0, 500));

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
}

/**
 * Create a key for matching scan findings to detections.
 */
function createFindingKey(
  resource: string,
  method: string,
  categoryId: string,
  testId: string
): string {
  return `${resource}:${method.toLowerCase()}:${categoryId}:${testId}`;
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
  let scanResults: ScanResults;

  // Check if we have a scan ID
  const hasScanId = scanId && scanId.trim() !== "";

  if (hasScanId) {
    // Original flow: Get scan results (includes issues/informational)
    onProgress?.("Fetching scan results...", 10);
    scanResults = await getScanResults(token, appId, instanceId, scanId);
    console.log(`[DEBUG] Scan has ${scanResults.vulnerabilities.length} endpoint groups with vulnerabilities`);
    console.log(`[DEBUG] Scan has ${scanResults.issues.length} endpoint groups with issues`);
  } else {
    // No scan ID: Build from detections only (vulnerabilities only, no issues)
    onProgress?.("Fetching detections...", 10);
    const detectionsResponse = await getDetections(token, appId, instanceId);
    console.log(`[DEBUG] Got ${detectionsResponse.detections.length} detection categories`);

    scanResults = buildScanResultsFromDetections(detectionsResponse, instanceId);
    console.log(`[DEBUG] Built scan results with ${scanResults.vulnerabilities.length} endpoint groups`);
  }

  // Fetch HTTP logs if requested
  if (includeHttpLogs && scanResults.vulnerabilities.length > 0) {
    onProgress?.("Fetching detections list...", 30);

    try {
      const detectionsResponse = await getDetections(token, appId, instanceId);
      console.log(`[DEBUG] Got ${detectionsResponse.detections.length} detection categories`);

      // Extract all detectionIds and build mapping
      const detectionIds: Array<{ detectionId: string; findingKey: string }> = [];

      for (const detection of detectionsResponse.detections) {
        for (const vuln of detection.data.vulnerabilities) {
          const findingKey = createFindingKey(
            vuln.resource,
            vuln.method,
            detection.category.id,
            detection.test.id
          );
          detectionIds.push({ detectionId: vuln.detectionId, findingKey });
          detectionToFindingMap.set(vuln.detectionId, findingKey);

          console.log(`[DEBUG] Found detectionId ${vuln.detectionId} for ${findingKey}`);
        }
      }

      console.log(`[DEBUG] Found ${detectionIds.length} total detectionIds`);

      // Fetch logs for each detection
      onProgress?.("Fetching HTTP logs...", 40);

      const total = detectionIds.length;
      for (let i = 0; i < total; i++) {
        const { detectionId, findingKey } = detectionIds[i];
        try {
          const logs = await getDetectionLogs(token, appId, instanceId, detectionId);
          detectionLogsMap.set(detectionId, logs);
          console.log(`[DEBUG] Got logs for ${detectionId} (${findingKey})`);
        } catch (error) {
          console.warn(`Failed to fetch logs for ${detectionId}:`, error);
        }

        const progress = 40 + Math.round((i / total) * 50);
        onProgress?.(`Fetching HTTP logs (${i + 1}/${total})...`, progress);
      }

      console.log(`[DEBUG] Total logs fetched: ${detectionLogsMap.size}`);
    } catch (error) {
      console.error("Failed to fetch detections:", error);
    }
  }

  onProgress?.("Data fetch complete", 95);

  return {
    scanResults,
    detectionLogsMap,
    detectionToFindingMap,
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
  const findingKey = createFindingKey(resource, method, categoryId, testId);

  // Find the detectionId that matches this finding
  for (const [detectionId, key] of detectionToFindingMap.entries()) {
    if (key === findingKey) {
      return detectionLogsMap.get(detectionId);
    }
  }

  return undefined;
}
