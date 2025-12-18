/**
 * PDF generation entry point for client-side usage.
 *
 * Why: Provides a simple function interface for the report form component
 * while delegating to the PDFReportGenerator class internally.
 */

import { saveAs } from "file-saver";
import { PDFReportGenerator } from "./pdf";
import { ScanResults, DetectionLogs } from "./types";

export interface GeneratePDFOptions {
  scanResults: ScanResults;
  detectionLogsMap: Map<string, DetectionLogs>;
  detectionToFindingMap: Map<string, string>;
  detectionStatusByKey: Map<string, string>;
  excludedFindingKeys: Set<string>;
  includeInformational: boolean;
  appName?: string;
  hostUrl?: string;
  /** Maps endpoint key (METHOD:path) to whether it requires authentication */
  endpointAuthMap: Map<string, boolean>;
  onProgress?: (message: string, percent: number) => void;
}

/**
 * Generate and download a PDF vulnerability report.
 */
export async function generatePDF(options: GeneratePDFOptions): Promise<void> {
  const generator = new PDFReportGenerator({
    onProgress: options.onProgress,
  });

  const blob = await generator.generate(
    options.scanResults,
    options.detectionLogsMap,
    options.detectionToFindingMap,
    options.detectionStatusByKey,
    options.excludedFindingKeys,
    options.includeInformational,
    options.appName,
    options.hostUrl,
    options.endpointAuthMap
  );

  const timestamp = new Date().toISOString().slice(0, 10);
  const scanIdShort = options.scanResults.scanId.slice(0, 8);
  const filename = `vulnerability-report-${scanIdShort}-${timestamp}.pdf`;

  saveAs(blob, filename);
}
