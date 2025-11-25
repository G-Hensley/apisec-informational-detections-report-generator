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
 * Fetch all data needed for report generation.
 *
 * Why: Separates data fetching from PDF generation, allowing the
 * PDFReportGenerator to focus solely on data transformation and rendering.
 *
 * Flow:
 * 1. Get scan results (vulnerabilities + issues)
 * 2. Get detections list to obtain detectionIds
 * 3. Fetch logs for each detectionId
 * 4. Build a map to match logs to scan findings
 */
export async function fetchReportData(
  token: string,
  _tenant: string, // Kept for API compatibility but not used (tenant is in token)
  appId: string,
  instanceId: string,
  scanId: string,
  includeHttpLogs: boolean,
  onProgress?: (message: string, percent: number) => void
): Promise<FetchReportDataResult> {
  onProgress?.("Fetching scan results...", 10);

  // Step 1: Get scan results
  const scanResults = await getScanResults(token, appId, instanceId, scanId);
  const detectionLogsMap = new Map<string, DetectionLogs>();
  const detectionToFindingMap = new Map<string, string>();

  console.log(`[DEBUG] Scan has ${scanResults.vulnerabilities.length} endpoint groups with vulnerabilities`);

  // Step 2: If we want logs and have vulnerabilities, get detections
  if (includeHttpLogs && scanResults.vulnerabilities.length > 0) {
    onProgress?.("Fetching detections list...", 30);

    try {
      const detectionsResponse = await getDetections(token, appId, instanceId);
      console.log(`[DEBUG] Got ${detectionsResponse.detections.length} detection categories`);

      // Step 3: Extract all detectionIds and build mapping
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

      // Step 4: Fetch logs for each detection
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
