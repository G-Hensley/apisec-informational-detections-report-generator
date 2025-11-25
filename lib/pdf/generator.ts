/**
 * PDF report generator for vulnerability reports.
 *
 * Why: Generates professional PDF vulnerability reports from API data using
 * jsPDF for direct PDF generation. Avoids html2canvas CSS parsing issues.
 */

import { jsPDF } from "jspdf";
import {
  PDFReportData,
  VulnerabilitySummary,
  VulnerabilityDetail,
  EndpointGroup,
  FailingLog,
  getSeverityFromCvss,
  getSeverityColor,
} from "./models";
import {
  ScanResults,
  DetectionLogs,
  TestChainEntry,
} from "@/lib/types";

export class PDFGeneratorError extends Error {
  constructor(
    message: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = "PDFGeneratorError";
  }
}

interface GeneratorCallbacks {
  onProgress?: (message: string, percent: number) => void;
  onLog?: (level: "info" | "warn" | "error", message: string, data?: Record<string, unknown>) => void;
}

// PDF Layout constants (in mm)
const PAGE_WIDTH = 210;
const PAGE_HEIGHT = 297;
const MARGIN = 15;
const CONTENT_WIDTH = PAGE_WIDTH - 2 * MARGIN;
const LINE_HEIGHT = 5;
const FONT_SIZE_TITLE = 24;
const FONT_SIZE_SECTION = 14;
const FONT_SIZE_NORMAL = 10;
const FONT_SIZE_SMALL = 8;

// Colors (RGB)
const COLORS = {
  black: [26, 26, 26] as [number, number, number],
  gray: [102, 102, 102] as [number, number, number],
  lightGray: [153, 153, 153] as [number, number, number],
  white: [255, 255, 255] as [number, number, number],
  critical: [220, 38, 38] as [number, number, number],
  high: [234, 88, 12] as [number, number, number],
  medium: [202, 138, 4] as [number, number, number],
  low: [37, 99, 235] as [number, number, number],
  info: [107, 114, 128] as [number, number, number],
  background: [245, 245, 245] as [number, number, number],
  codeBg: [30, 30, 30] as [number, number, number],
  codeText: [212, 212, 212] as [number, number, number],
};

/**
 * Generates PDF vulnerability reports from APIsec scan data.
 */
export class PDFReportGenerator {
  private callbacks: GeneratorCallbacks;
  private doc!: jsPDF;
  private y: number = MARGIN;

  constructor(callbacks: GeneratorCallbacks = {}) {
    this.callbacks = callbacks;
  }

  private log(level: "info" | "warn" | "error", message: string, data?: Record<string, unknown>) {
    this.callbacks.onLog?.(level, message, data);
    if (level === "error") {
      console.error(`[PDFGenerator] ${message}`, data);
    }
  }

  private progress(message: string, percent: number) {
    this.callbacks.onProgress?.(message, percent);
  }

  /**
   * Generate PDF vulnerability report from scan results.
   */
  async generate(
    scanResults: ScanResults,
    detectionLogsMap: Map<string, DetectionLogs>,
    detectionToFindingMap: Map<string, string>,
    includeInformational: boolean
  ): Promise<Blob> {
    this.log("info", "pdf_generation_started", {
      scanId: scanResults.scanId,
      includeInformational,
    });

    try {
      // Step 1: Transform data to report structure
      this.progress("Transforming data...", 10);
      const reportData = this.transformData(scanResults, detectionLogsMap, detectionToFindingMap, includeInformational);

      this.log("info", "data_transformation_completed", {
        endpointCount: reportData.endpointGroups.length,
        totalVulnerabilities: reportData.summary.total,
      });

      // Step 2: Generate PDF
      this.progress("Generating PDF...", 50);
      const blob = this.buildPdf(reportData);

      this.log("info", "pdf_generation_completed", {
        vulnerabilityCount: reportData.summary.total,
        endpointCount: reportData.endpointGroups.length,
      });

      this.progress("Complete!", 100);
      return blob;

    } catch (error) {
      this.log("error", "pdf_generation_failed", {
        error: error instanceof Error ? error.message : String(error),
        errorType: error instanceof Error ? error.constructor.name : typeof error,
      });

      throw new PDFGeneratorError(
        `Failed to generate PDF report: ${error instanceof Error ? error.message : error}`,
        { scanId: scanResults.scanId }
      );
    }
  }

  /**
   * Build the PDF document using jsPDF.
   */
  private buildPdf(data: PDFReportData): Blob {
    this.doc = new jsPDF({
      orientation: "portrait",
      unit: "mm",
      format: "a4",
    });

    this.y = MARGIN;

    // Cover page
    this.renderHeader(data);
    this.renderSummary(data.summary);
    this.renderStatistics(data);

    // Findings
    this.renderFindings(data);

    // Footer on each page
    const totalPages = this.doc.getNumberOfPages();
    for (let i = 1; i <= totalPages; i++) {
      this.doc.setPage(i);
      this.renderFooter(i, totalPages);
    }

    return this.doc.output("blob");
  }

  private renderHeader(data: PDFReportData) {
    // Title
    this.doc.setFontSize(FONT_SIZE_TITLE);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.black);
    this.doc.text("VULNERABILITY REPORT", MARGIN, this.y);
    this.y += 10;

    // Subtitle
    this.doc.setFontSize(12);
    this.doc.setFont("helvetica", "normal");
    this.doc.setTextColor(...COLORS.gray);
    this.doc.text("APIsec Security Assessment", MARGIN, this.y);
    this.y += 8;

    // Divider
    this.doc.setDrawColor(...COLORS.black);
    this.doc.setLineWidth(0.5);
    this.doc.line(MARGIN, this.y, PAGE_WIDTH - MARGIN, this.y);
    this.y += 10;

    // Metadata
    this.doc.setFontSize(FONT_SIZE_NORMAL);
    const metadata = [
      ["Scan ID:", data.scanId],
      ["Status:", data.status],
      ["Generated:", this.formatDate(data.generatedAt)],
    ];

    for (const [label, value] of metadata) {
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text(label, MARGIN, this.y);
      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.black);
      this.doc.text(value, MARGIN + 35, this.y);
      this.y += LINE_HEIGHT;
    }

    this.y += 10;
  }

  private renderSummary(summary: VulnerabilitySummary) {
    this.renderSectionTitle("Executive Summary");

    const boxWidth = (CONTENT_WIDTH - 4 * 5) / 5; // 5 boxes with 5mm gaps
    const boxHeight = 20;
    const boxes = [
      { label: "CRITICAL", value: summary.critical, color: COLORS.critical },
      { label: "HIGH", value: summary.high, color: COLORS.high },
      { label: "MEDIUM", value: summary.medium, color: COLORS.medium },
      { label: "LOW", value: summary.low, color: COLORS.low },
      { label: "INFO", value: summary.info, color: COLORS.info },
    ];

    let x = MARGIN;
    for (const box of boxes) {
      // Box background
      this.doc.setFillColor(...box.color);
      this.doc.roundedRect(x, this.y, boxWidth, boxHeight, 2, 2, "F");

      // Label
      this.doc.setFontSize(7);
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.white);
      this.doc.text(box.label, x + boxWidth / 2, this.y + 6, { align: "center" });

      // Value
      this.doc.setFontSize(16);
      this.doc.text(String(box.value), x + boxWidth / 2, this.y + 15, { align: "center" });

      x += boxWidth + 5;
    }

    this.y += boxHeight + 10;
  }

  private renderStatistics(data: PDFReportData) {
    this.renderSectionTitle("Scan Statistics");

    const stats = [
      [`Endpoints Scanned: ${data.metadata.endpointsScanned} / ${data.metadata.endpointsUnderTest}`],
      [`Total Tests: ${data.metadata.totalTests}`],
      [`Tests Passed: ${data.metadata.testsPassed}`],
      [`Tests Failed: ${data.metadata.testsFailed}`],
      [`Total Findings: ${data.summary.total}`],
      [`Endpoints Affected: ${data.endpointGroups.length}`],
    ];

    this.doc.setFontSize(FONT_SIZE_NORMAL);
    this.doc.setFont("helvetica", "normal");
    this.doc.setTextColor(...COLORS.black);

    const colWidth = CONTENT_WIDTH / 3;
    let col = 0;
    let startY = this.y;

    for (const [stat] of stats) {
      const x = MARGIN + col * colWidth;
      this.doc.text(stat, x, this.y);

      col++;
      if (col >= 3) {
        col = 0;
        this.y += LINE_HEIGHT + 2;
      }
    }

    if (col !== 0) {
      this.y += LINE_HEIGHT + 2;
    }

    this.y += 5;
  }

  private renderFindings(data: PDFReportData) {
    this.renderSectionTitle("Findings");

    if (data.endpointGroups.length === 0) {
      this.doc.setFontSize(FONT_SIZE_NORMAL);
      this.doc.setFont("helvetica", "italic");
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text("No findings detected in this scan.", MARGIN, this.y);
      return;
    }

    for (const group of data.endpointGroups) {
      this.renderEndpointGroup(group);
    }
  }

  private renderEndpointGroup(group: EndpointGroup) {
    // Check if we need a new page
    if (this.y > PAGE_HEIGHT - 60) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    // Endpoint header
    this.doc.setFillColor(...COLORS.black);
    this.doc.roundedRect(MARGIN, this.y, CONTENT_WIDTH, 8, 1, 1, "F");

    this.doc.setFontSize(FONT_SIZE_SMALL);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.white);
    const headerText = `${group.endpoint} (${group.vulnerabilityCount} finding${group.vulnerabilityCount !== 1 ? "s" : ""})`;
    this.doc.text(this.truncateText(headerText, CONTENT_WIDTH - 10), MARGIN + 4, this.y + 5.5);
    this.y += 12;

    // Vulnerabilities
    for (const vuln of group.vulnerabilities) {
      this.renderFinding(vuln);
    }

    this.y += 5;
  }

  private renderFinding(vuln: VulnerabilityDetail) {
    const severityColor = this.getSeverityColorRgb(vuln.severity);
    const cardHeight = this.estimateCardHeight(vuln);

    // Check if we need a new page
    if (this.y + cardHeight > PAGE_HEIGHT - MARGIN) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    const startY = this.y;

    // Card background with severity border
    this.doc.setFillColor(...COLORS.background);
    this.doc.setDrawColor(...severityColor);
    this.doc.setLineWidth(1);
    this.doc.roundedRect(MARGIN, this.y, CONTENT_WIDTH, cardHeight, 2, 2, "FD");

    // Reset to draw content
    this.y += 5;

    // Title and severity badge
    this.doc.setFontSize(11);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.black);
    const titleText = this.truncateText(vuln.testName, CONTENT_WIDTH - 40);
    this.doc.text(titleText, MARGIN + 4, this.y);

    // Severity badge
    const badgeWidth = 20;
    const badgeX = PAGE_WIDTH - MARGIN - badgeWidth - 4;
    this.doc.setFillColor(...severityColor);
    this.doc.roundedRect(badgeX, this.y - 4, badgeWidth, 6, 1, 1, "F");
    this.doc.setFontSize(7);
    this.doc.setTextColor(...COLORS.white);
    this.doc.text(vuln.severity.toUpperCase(), badgeX + badgeWidth / 2, this.y, { align: "center" });

    this.y += 6;

    // Details
    this.doc.setFontSize(FONT_SIZE_SMALL);
    this.doc.setFont("helvetica", "normal");

    const details = [
      `Endpoint: ${vuln.method} ${vuln.endpoint}`,
      `Category: ${vuln.category}`,
    ];

    if (vuln.cvssScore > 0) {
      details.push(`CVSS Score: ${vuln.cvssScore.toFixed(1)}`);
    }

    for (const detail of details) {
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text(this.truncateText(detail, CONTENT_WIDTH - 10), MARGIN + 4, this.y);
      this.y += 4;
    }

    // OWASP Tags
    if (vuln.owaspTags.length > 0) {
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text(`OWASP: ${vuln.owaspTags.join(", ")}`, MARGIN + 4, this.y);
      this.y += 4;
    }

    // Description
    if (vuln.description) {
      this.y += 2;
      this.doc.setTextColor(...COLORS.black);
      const descLines = this.doc.splitTextToSize(vuln.description, CONTENT_WIDTH - 10);
      const maxLines = 4;
      const linesToShow = descLines.slice(0, maxLines);
      for (const line of linesToShow) {
        this.doc.text(line, MARGIN + 4, this.y);
        this.y += 4;
      }
      if (descLines.length > maxLines) {
        this.doc.setTextColor(...COLORS.gray);
        this.doc.text("... [see full report]", MARGIN + 4, this.y);
        this.y += 4;
      }
    }

    // Move y to end of card (without HTTP logs - those are rendered separately)
    this.y = startY + cardHeight + 3;

    // HTTP Logs (rendered outside the card for better space management)
    if (vuln.failingLogs.length > 0) {
      this.renderHttpLogs(vuln.failingLogs[0]);
    }
  }

  private renderHttpLogs(log: FailingLog) {
    const codeBlockPadding = 3;
    const lineHeight = 3;
    const maxLinesPerBlock = 15;

    // Check if we need a new page
    if (this.y > PAGE_HEIGHT - 80) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    // Request block
    this.doc.setFontSize(8);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.black);
    this.doc.text("HTTP Request:", MARGIN, this.y);
    this.y += 5;

    const requestLines = this.doc.splitTextToSize(log.requestContent, CONTENT_WIDTH - 10);
    const requestLinesToShow = requestLines.slice(0, maxLinesPerBlock);
    const requestBlockHeight = requestLinesToShow.length * lineHeight + codeBlockPadding * 2;

    // Request code block background
    this.doc.setFillColor(...COLORS.codeBg);
    this.doc.roundedRect(MARGIN, this.y, CONTENT_WIDTH, requestBlockHeight, 2, 2, "F");

    // Request content
    this.doc.setFontSize(6);
    this.doc.setFont("courier", "normal");
    this.doc.setTextColor(...COLORS.codeText);
    let textY = this.y + codeBlockPadding + 2;
    for (const line of requestLinesToShow) {
      this.doc.text(line, MARGIN + codeBlockPadding, textY);
      textY += lineHeight;
    }
    if (requestLines.length > maxLinesPerBlock) {
      this.doc.text("... [truncated]", MARGIN + codeBlockPadding, textY);
    }

    this.y += requestBlockHeight + 5;

    // Check if we need a new page for response
    if (this.y > PAGE_HEIGHT - 60) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    // Response block
    this.doc.setFontSize(8);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.black);
    this.doc.text(`HTTP Response (${log.statusCode}):`, MARGIN, this.y);
    this.y += 5;

    const responseLines = this.doc.splitTextToSize(log.responseContent, CONTENT_WIDTH - 10);
    const responseLinesToShow = responseLines.slice(0, maxLinesPerBlock);
    const responseBlockHeight = responseLinesToShow.length * lineHeight + codeBlockPadding * 2;

    // Response code block background
    this.doc.setFillColor(...COLORS.codeBg);
    this.doc.roundedRect(MARGIN, this.y, CONTENT_WIDTH, responseBlockHeight, 2, 2, "F");

    // Response content
    this.doc.setFontSize(6);
    this.doc.setFont("courier", "normal");
    this.doc.setTextColor(...COLORS.codeText);
    textY = this.y + codeBlockPadding + 2;
    for (const line of responseLinesToShow) {
      this.doc.text(line, MARGIN + codeBlockPadding, textY);
      textY += lineHeight;
    }
    if (responseLines.length > maxLinesPerBlock) {
      this.doc.text("... [truncated]", MARGIN + codeBlockPadding, textY);
    }

    this.y += responseBlockHeight + 8;
  }

  private estimateCardHeight(vuln: VulnerabilityDetail): number {
    let height = 25; // Base height for title, badge, and basic details

    height += 4 * 3; // 3 detail lines

    if (vuln.owaspTags.length > 0) height += 4;

    if (vuln.description) {
      const lines = Math.min(4, Math.ceil(vuln.description.length / 80));
      height += lines * 4 + 4;
    }

    // HTTP logs are rendered separately now, not in the card
    return Math.max(height, 30);
  }

  private renderSectionTitle(title: string) {
    if (this.y > PAGE_HEIGHT - 40) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    this.doc.setFontSize(FONT_SIZE_SECTION);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.black);
    this.doc.text(title, MARGIN, this.y);
    this.y += 3;

    // Underline
    this.doc.setDrawColor(...COLORS.lightGray);
    this.doc.setLineWidth(0.3);
    this.doc.line(MARGIN, this.y, PAGE_WIDTH - MARGIN, this.y);
    this.y += 8;
  }

  private renderFooter(pageNum: number, totalPages: number) {
    const footerY = PAGE_HEIGHT - 10;

    this.doc.setFontSize(8);
    this.doc.setFont("helvetica", "normal");
    this.doc.setTextColor(...COLORS.lightGray);

    this.doc.text("Generated by APIsec Report Generator", PAGE_WIDTH / 2, footerY, { align: "center" });
    this.doc.text(`Page ${pageNum} of ${totalPages}`, PAGE_WIDTH - MARGIN, footerY, { align: "right" });
  }

  private getSeverityColorRgb(severity: string): [number, number, number] {
    const colors: Record<string, [number, number, number]> = {
      critical: COLORS.critical,
      high: COLORS.high,
      medium: COLORS.medium,
      low: COLORS.low,
      info: COLORS.info,
    };
    return colors[severity.toLowerCase()] || COLORS.info;
  }

  private truncateText(text: string, maxWidth: number): string {
    const avgCharWidth = 2; // Approximate mm per character at font size 10
    const maxChars = Math.floor(maxWidth / avgCharWidth);
    if (text.length <= maxChars) return text;
    return text.substring(0, maxChars - 3) + "...";
  }

  private formatDate(date: Date): string {
    return date.toLocaleString("en-US", {
      year: "numeric",
      month: "long",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  }

  // ============ Data Transformation Methods ============

  /**
   * Create a key for matching scan findings to detections.
   */
  private createFindingKey(
    resource: string,
    method: string,
    categoryId: string,
    testId: string
  ): string {
    return `${resource}:${method.toLowerCase()}:${categoryId}:${testId}`;
  }

  /**
   * Find logs for a scan finding by matching endpoint + category + test.
   */
  private findLogsForFinding(
    resource: string,
    method: string,
    categoryId: string,
    testId: string,
    detectionToFindingMap: Map<string, string>,
    detectionLogsMap: Map<string, DetectionLogs>
  ): DetectionLogs | undefined {
    const findingKey = this.createFindingKey(resource, method, categoryId, testId);
    console.log(`[DEBUG] Looking for logs with key: ${findingKey}`);

    // Find the detectionId that matches this finding
    for (const [detectionId, key] of detectionToFindingMap.entries()) {
      if (key === findingKey) {
        console.log(`[DEBUG] Found matching detectionId: ${detectionId}`);
        return detectionLogsMap.get(detectionId);
      }
    }

    console.log(`[DEBUG] No matching logs found for ${findingKey}`);
    return undefined;
  }

  private transformData(
    scanResults: ScanResults,
    detectionLogsMap: Map<string, DetectionLogs>,
    detectionToFindingMap: Map<string, string>,
    includeInformational: boolean
  ): PDFReportData {
    const endpointMap = new Map<string, VulnerabilityDetail[]>();
    const severityCounts: VulnerabilitySummary = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    // Process vulnerabilities (failed tests)
    for (const endpoint of scanResults.vulnerabilities) {
      for (const finding of endpoint.scanFindings) {
        if (finding.testStatus.value !== "FAILED") continue;

        // Find logs by matching endpoint + category + test (not executionId)
        const logs = this.findLogsForFinding(
          endpoint.resource,
          endpoint.method,
          finding.testDetails.categoryId,
          finding.testDetails.categoryTestId,
          detectionToFindingMap,
          detectionLogsMap
        );

        const vuln = this.transformFinding(
          endpoint.resource,
          endpoint.method,
          finding,
          logs
        );

        this.addToEndpointMap(endpointMap, vuln);
        this.incrementSeverityCount(severityCounts, vuln.severity);
      }
    }

    // Process issues (informational) if requested - no logs available for these
    if (includeInformational) {
      for (const endpoint of scanResults.issues) {
        for (const finding of endpoint.scanFindings) {
          const vuln = this.transformFinding(
            endpoint.resource,
            endpoint.method,
            finding,
            undefined // Logs are ONLY available for vulnerabilities, not issues
          );

          this.addToEndpointMap(endpointMap, vuln);
          this.incrementSeverityCount(severityCounts, vuln.severity);
        }
      }
    }

    const endpointGroups: EndpointGroup[] = Array.from(endpointMap.entries())
      .map(([endpoint, vulnerabilities]) => ({
        endpoint,
        vulnerabilityCount: vulnerabilities.length,
        vulnerabilities: this.sortVulnerabilitiesBySeverity(vulnerabilities),
      }))
      .sort((a, b) => b.vulnerabilityCount - a.vulnerabilityCount);

    return {
      scanId: scanResults.scanId,
      status: scanResults.status,
      generatedAt: new Date(),
      summary: severityCounts,
      endpointGroups,
      metadata: {
        endpointsScanned: scanResults.metadata.endpointsScanned,
        endpointsUnderTest: scanResults.metadata.endpointsUnderTest,
        totalTests: scanResults.metadata.totalTests,
        testsPassed: scanResults.metadata.testsPassed,
        testsFailed: scanResults.metadata.testsFailed,
      },
    };
  }

  private transformFinding(
    resource: string,
    method: string,
    finding: ScanResults["vulnerabilities"][0]["scanFindings"][0],
    logs?: DetectionLogs
  ): VulnerabilityDetail {
    const cvssScore = finding.testResult?.cvssScore ?? 0;
    const severity = finding.testResult?.cvssQualifier ?? getSeverityFromCvss(cvssScore);

    const failingLogs: FailingLog[] = [];

    // Debug: Log what we receive
    console.log(`[DEBUG] transformFinding for ${finding.executionId}:`, {
      hasLogs: !!logs,
      logsKeys: logs ? Object.keys(logs) : [],
      hasLogsLogs: !!logs?.logs,
      logsLogsKeys: logs?.logs ? Object.keys(logs.logs) : [],
      hasTestChain: !!logs?.logs?.testChain,
      testChainLength: logs?.logs?.testChain?.length,
    });

    if (logs?.logs?.testChain) {
      const evidenceCorrelationId = logs.logs.evidence;
      console.log(`[DEBUG] Evidence correlationId: ${evidenceCorrelationId}`);

      for (const entry of logs.logs.testChain) {
        console.log(`[DEBUG] Entry correlationId: ${entry.request.correlationId}`);
        if (entry.request.correlationId === evidenceCorrelationId) {
          failingLogs.push(this.transformLogEntry(entry, resource));
        }
      }

      if (failingLogs.length === 0 && logs.logs.testChain.length > 0) {
        console.log(`[DEBUG] No matching correlation, using last entry`);
        const lastEntry = logs.logs.testChain[logs.logs.testChain.length - 1];
        failingLogs.push(this.transformLogEntry(lastEntry, resource));
      }
    }

    console.log(`[DEBUG] failingLogs count: ${failingLogs.length}`);

    return {
      testName: finding.testDetails.categoryTestName,
      category: finding.testDetails.categoryName,
      severity: severity as VulnerabilityDetail["severity"],
      cvssScore,
      description: finding.testResult?.detectionDescription ?? "",
      endpoint: resource,
      method,
      detectionDate: new Date(finding.detectionDate),
      owaspTags: finding.testDetails.owaspTags,
      failingLogs,
    };
  }

  private transformLogEntry(entry: TestChainEntry, endpoint: string): FailingLog {
    const requestLines = [
      `${entry.request.method} ${entry.request.url}`,
      ...Object.entries(entry.request.headers || {}).map(([k, v]) => `${k}: ${v}`),
    ];
    if (entry.request.body) {
      requestLines.push("", entry.request.body);
    }

    const responseLines = [
      `HTTP ${entry.response.statusCode}`,
      ...Object.entries(entry.response.headers || {}).map(([k, v]) => `${k}: ${v}`),
    ];
    if (entry.response.content) {
      responseLines.push("", this.truncateContent(entry.response.content, 500));
    }

    return {
      method: entry.request.method,
      endpoint,
      statusCode: entry.response.statusCode,
      requestContent: requestLines.join("\n"),
      responseContent: responseLines.join("\n"),
    };
  }

  private truncateContent(content: string, maxLength: number): string {
    if (content.length <= maxLength) return content;
    return content.substring(0, maxLength) + "\n... [truncated]";
  }

  private addToEndpointMap(map: Map<string, VulnerabilityDetail[]>, vuln: VulnerabilityDetail) {
    const existing = map.get(vuln.endpoint) || [];
    existing.push(vuln);
    map.set(vuln.endpoint, existing);
  }

  private incrementSeverityCount(counts: VulnerabilitySummary, severity: string) {
    counts.total++;
    const key = severity.toLowerCase() as keyof Omit<VulnerabilitySummary, "total">;
    if (key in counts) {
      counts[key]++;
    }
  }

  private sortVulnerabilitiesBySeverity(vulns: VulnerabilityDetail[]): VulnerabilityDetail[] {
    const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    return [...vulns].sort((a, b) => order[a.severity] - order[b.severity]);
  }
}
