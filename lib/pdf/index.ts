/**
 * PDF Report Generation Module
 *
 * Why: Centralizes PDF generation exports for clean imports.
 */

export { PDFReportGenerator, PDFGeneratorError } from "./generator";
export type {
  PDFReportData,
  VulnerabilitySummary,
  VulnerabilityDetail,
  EndpointGroup,
  FailingLog,
} from "./models";
export {
  getSeverityFromCvss,
  getSeverityColor,
  CVSS_CRITICAL_THRESHOLD,
  CVSS_HIGH_THRESHOLD,
  CVSS_MEDIUM_THRESHOLD,
  CVSS_LOW_THRESHOLD,
} from "./models";
