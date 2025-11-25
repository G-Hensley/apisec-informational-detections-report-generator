/**
 * Pydantic-style models for PDF report generation.
 *
 * Why: Provides type-safe data structures for transforming API query results
 * into structured report data. Uses the Client→Consumer boundary pattern to ensure
 * data validation and type safety throughout the PDF generation pipeline.
 */

/**
 * Summary statistics for vulnerability counts by severity.
 *
 * Why: Provides high-level metrics for executive summary section.
 */
export interface VulnerabilitySummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

/**
 * Individual failing log entry for a vulnerability.
 *
 * Why: Represents a single HTTP request/response that triggered the vulnerability.
 */
export interface FailingLog {
  method: string;
  endpoint: string;
  statusCode: number;
  requestContent: string;
  responseContent: string;
}

/**
 * Detailed vulnerability information for a specific endpoint.
 *
 * Why: Represents a single vulnerability finding with all context needed
 * for remediation including test details, severity, and failing examples.
 */
export interface VulnerabilityDetail {
  testName: string;
  category: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  cvssScore: number;
  description: string;
  endpoint: string;
  method: string;
  detectionDate: Date;
  owaspTags: string[];
  failingLogs: FailingLog[];
}

/**
 * Group of vulnerabilities for a specific endpoint.
 *
 * Why: Organizes vulnerabilities by endpoint for easier developer remediation.
 * Developers typically fix issues on a per-endpoint basis.
 */
export interface EndpointGroup {
  endpoint: string;
  vulnerabilityCount: number;
  vulnerabilities: VulnerabilityDetail[];
}

/**
 * Complete data structure for PDF report generation.
 *
 * Why: Top-level container for all report data with validated types.
 * Follows the Consumer pattern from the type boundary architecture.
 */
export interface PDFReportData {
  scanId: string;
  status: string;
  hostUrl?: string;
  generatedAt: Date;
  summary: VulnerabilitySummary;
  endpointGroups: EndpointGroup[];
  metadata: {
    endpointsScanned: number;
    endpointsUnderTest: number;
    totalTests: number;
    testsPassed: number;
    testsFailed: number;
  };
}

// CVSS Score severity thresholds
export const CVSS_CRITICAL_THRESHOLD = 9.0;
export const CVSS_HIGH_THRESHOLD = 7.0;
export const CVSS_MEDIUM_THRESHOLD = 4.0;
export const CVSS_LOW_THRESHOLD = 0.1;

/**
 * Determine severity label from CVSS score.
 */
export function getSeverityFromCvss(cvssScore: number): VulnerabilityDetail["severity"] {
  if (cvssScore >= CVSS_CRITICAL_THRESHOLD) return "Critical";
  if (cvssScore >= CVSS_HIGH_THRESHOLD) return "High";
  if (cvssScore >= CVSS_MEDIUM_THRESHOLD) return "Medium";
  if (cvssScore >= CVSS_LOW_THRESHOLD) return "Low";
  return "Info";
}

/**
 * Get CSS color class for severity level.
 */
export function getSeverityColor(severity: string): string {
  const colors: Record<string, string> = {
    critical: "#dc2626",
    high: "#ea580c",
    medium: "#ca8a04",
    low: "#2563eb",
    info: "#6b7280",
  };
  return colors[severity.toLowerCase()] || colors.info;
}
