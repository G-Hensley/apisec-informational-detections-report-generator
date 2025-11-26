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

    // Calculate vulnerabilities vs informational
    const vulnCount = summary.critical + summary.high + summary.medium + summary.low;
    const infoCount = summary.info;

    // Summary text
    this.doc.setFontSize(FONT_SIZE_NORMAL);
    this.doc.setFont("helvetica", "normal");
    this.doc.setTextColor(...COLORS.black);
    this.doc.text(
      `This scan identified ${vulnCount} vulnerabilit${vulnCount !== 1 ? "ies" : "y"} and ${infoCount} informational finding${infoCount !== 1 ? "s" : ""}.`,
      MARGIN,
      this.y
    );
    this.y += 10;

    // Severity boxes - only show vulnerability severities (not info) in the main summary
    const boxWidth = (CONTENT_WIDTH - 3 * 5) / 4; // 4 boxes with 5mm gaps
    const boxHeight = 22;
    const vulnBoxes = [
      { label: "CRITICAL", value: summary.critical, color: COLORS.critical },
      { label: "HIGH", value: summary.high, color: COLORS.high },
      { label: "MEDIUM", value: summary.medium, color: COLORS.medium },
      { label: "LOW", value: summary.low, color: COLORS.low },
    ];

    let x = MARGIN;
    for (const box of vulnBoxes) {
      // Box background
      this.doc.setFillColor(...box.color);
      this.doc.roundedRect(x, this.y, boxWidth, boxHeight, 2, 2, "F");

      // Label
      this.doc.setFontSize(8);
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.white);
      this.doc.text(box.label, x + boxWidth / 2, this.y + 7, { align: "center" });

      // Value
      this.doc.setFontSize(18);
      this.doc.text(String(box.value), x + boxWidth / 2, this.y + 17, { align: "center" });

      x += boxWidth + 5;
    }

    this.y += boxHeight + 5;

    // Info box (separate, smaller)
    if (infoCount > 0) {
      const infoBoxWidth = 45;
      this.doc.setFillColor(...COLORS.info);
      this.doc.roundedRect(MARGIN, this.y, infoBoxWidth, 14, 2, 2, "F");

      this.doc.setFontSize(8);
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.white);
      this.doc.text(`INFORMATIONAL: ${infoCount}`, MARGIN + infoBoxWidth / 2, this.y + 9, { align: "center" });

      this.y += 18;
    } else {
      this.y += 5;
    }
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
    const hasVulnerabilities = data.vulnerabilityGroups.length > 0;
    const hasInformational = data.informationalGroups.length > 0;

    // Render vulnerabilities section first
    if (hasVulnerabilities) {
      this.renderSectionTitle("Vulnerabilities");

      // Count total vulns
      const totalVulns = data.vulnerabilityGroups.reduce((sum, g) => sum + g.vulnerabilityCount, 0);
      this.doc.setFontSize(FONT_SIZE_SMALL);
      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text(`${totalVulns} vulnerability finding${totalVulns !== 1 ? "s" : ""} detected`, MARGIN, this.y);
      this.y += 8;

      for (const group of data.vulnerabilityGroups) {
        this.renderEndpointGroup(group, false);
      }
    }

    // Render informational section after vulnerabilities
    if (hasInformational) {
      // Add page break before informational if we had vulnerabilities
      if (hasVulnerabilities) {
        this.doc.addPage();
        this.y = MARGIN;
      }

      this.renderSectionTitle("Informational Findings");

      // Count total info findings
      const totalInfo = data.informationalGroups.reduce((sum, g) => sum + g.vulnerabilityCount, 0);
      this.doc.setFontSize(FONT_SIZE_SMALL);
      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text(`${totalInfo} informational finding${totalInfo !== 1 ? "s" : ""} detected`, MARGIN, this.y);
      this.y += 8;

      for (const group of data.informationalGroups) {
        this.renderEndpointGroup(group, true);
      }
    }

    // No findings at all
    if (!hasVulnerabilities && !hasInformational) {
      this.renderSectionTitle("Findings");
      this.doc.setFontSize(FONT_SIZE_NORMAL);
      this.doc.setFont("helvetica", "italic");
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text("No findings detected in this scan.", MARGIN, this.y);
    }
  }

  private renderEndpointGroup(group: EndpointGroup, isInformational: boolean = false) {
    // Check if we need a new page
    if (this.y > PAGE_HEIGHT - 60) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    // Endpoint header - use different color for informational
    const headerColor = isInformational ? COLORS.info : COLORS.black;
    this.doc.setFillColor(...headerColor);
    this.doc.roundedRect(MARGIN, this.y, CONTENT_WIDTH, 8, 1, 1, "F");

    this.doc.setFontSize(FONT_SIZE_SMALL);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.white);
    const findingType = isInformational ? "info finding" : "finding";
    const headerText = `${group.endpoint} (${group.vulnerabilityCount} ${findingType}${group.vulnerabilityCount !== 1 ? "s" : ""})`;
    this.doc.text(this.truncateText(headerText, CONTENT_WIDTH - 10), MARGIN + 4, this.y + 5.5);
    this.y += 12;

    // Vulnerabilities/Findings
    for (const vuln of group.vulnerabilities) {
      this.renderFinding(vuln, isInformational);
    }

    this.y += 5;
  }

  private renderFinding(vuln: VulnerabilityDetail, isInformational: boolean = false) {
    const severityColor = this.getSeverityColorRgb(vuln.severity);
    const contentX = MARGIN + 8;
    const labelWidth = 22;

    // Check if we need a new page before starting
    if (this.y > PAGE_HEIGHT - 60) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    const startY = this.y;

    // Draw colored severity bar on left (will extend as content grows)
    const drawSeverityBar = (endY: number) => {
      this.doc.setFillColor(...severityColor);
      this.doc.rect(MARGIN, startY, 3, endY - startY, "F");
    };

    // Leave space for severity bar
    this.y += 6;

    // Title with severity badge inline
    this.doc.setFontSize(11);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.black);
    const titleText = vuln.testName;

    // Build severity badge text
    const severityText = vuln.cvssScore > 0
      ? `${vuln.severity.toUpperCase()} (CVSS: ${vuln.cvssScore.toFixed(1)})`
      : vuln.severity.toUpperCase();

    // Render title (allow wrapping for long titles)
    const titleLines = this.doc.splitTextToSize(titleText, CONTENT_WIDTH - 70);
    for (let i = 0; i < titleLines.length; i++) {
      this.doc.text(titleLines[i], contentX, this.y);
      if (i === 0) {
        // Render severity badge on first line
        const titleWidth = this.doc.getTextWidth(titleLines[i]);
        const badgeX = contentX + titleWidth + 4;
        const badgeWidth = this.doc.getTextWidth(severityText) + 6;

        this.doc.setFillColor(...severityColor);
        this.doc.roundedRect(badgeX, this.y - 4, badgeWidth, 6, 1, 1, "F");
        this.doc.setFontSize(7);
        this.doc.setFont("helvetica", "bold");
        this.doc.setTextColor(...COLORS.white);
        this.doc.text(severityText, badgeX + 3, this.y - 0.5);

        // Reset font for next title line if any
        this.doc.setFontSize(11);
        this.doc.setFont("helvetica", "bold");
        this.doc.setTextColor(...COLORS.black);
      }
      this.y += 5;
    }

    this.y += 3;

    // Labeled fields - matching reference format
    this.doc.setFontSize(FONT_SIZE_SMALL);

    // Category
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.gray);
    this.doc.text("Category:", contentX, this.y);
    this.doc.setFont("helvetica", "normal");
    this.doc.setTextColor(...COLORS.black);
    this.doc.text(vuln.category, contentX + labelWidth, this.y);
    this.y += 5;

    // Method
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.gray);
    this.doc.text("Method:", contentX, this.y);
    this.doc.setFont("helvetica", "normal");
    this.doc.setTextColor(...COLORS.black);
    this.doc.text(`${vuln.method} ${vuln.endpoint}`, contentX + labelWidth, this.y);
    this.y += 5;

    // Detected date
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.gray);
    this.doc.text("Detected:", contentX, this.y);
    this.doc.setFont("helvetica", "normal");
    this.doc.setTextColor(...COLORS.black);
    this.doc.text(this.formatDate(vuln.detectionDate), contentX + labelWidth, this.y);
    this.y += 5;

    // OWASP Tags (if present)
    if (vuln.owaspTags.length > 0) {
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text("OWASP:", contentX, this.y);
      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.black);
      this.doc.text(vuln.owaspTags.join(", "), contentX + labelWidth, this.y);
      this.y += 5;
    }

    // Description - render all lines without truncation
    if (vuln.description) {
      this.y += 2;
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text("Description:", contentX, this.y);
      this.y += 5;

      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.black);
      const descLines = this.doc.splitTextToSize(vuln.description, CONTENT_WIDTH - 15);
      for (const line of descLines) {
        // Check if we need a new page mid-description
        if (this.y > PAGE_HEIGHT - MARGIN - 10) {
          // Draw severity bar up to current position before page break
          drawSeverityBar(this.y + 3);
          this.doc.addPage();
          this.y = MARGIN;
          // No severity bar on continuation page
        }
        this.doc.text(line, contentX, this.y);
        this.y += 4;
      }
    }

    // Draw the severity bar for this finding
    drawSeverityBar(this.y + 3);

    this.y += 6;

    // HTTP Logs (rendered outside the card for better space management)
    // Only render for non-informational (vulnerabilities) that have logs
    if (!isInformational && vuln.failingLogs.length > 0) {
      this.renderHttpLogs(vuln.failingLogs[0]);
    }
  }

  private renderHttpLogs(log: FailingLog) {
    const codeBlockPadding = 3;
    const lineHeight = 3;

    // Check if we need a new page
    if (this.y > PAGE_HEIGHT - 80) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    // "Failing Test Logs" header
    this.doc.setFontSize(10);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.black);
    this.doc.text("Failing Test Logs", MARGIN, this.y);
    this.y += 2;

    // Underline
    this.doc.setDrawColor(...COLORS.lightGray);
    this.doc.setLineWidth(0.2);
    this.doc.line(MARGIN, this.y, MARGIN + 35, this.y);
    this.y += 6;

    // Request block
    this.doc.setFontSize(10);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.gray);
    this.doc.text("Request:", MARGIN, this.y);
    this.y += 5;

    const requestLines = this.doc.splitTextToSize(log.requestContent, CONTENT_WIDTH - 10);
    this.renderCodeBlock(requestLines, lineHeight, codeBlockPadding);

    this.y += 5;

    // Check if we need a new page for response
    if (this.y > PAGE_HEIGHT - 40) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    // Response block
    this.doc.setFontSize(10);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.gray);
    this.doc.text(`Response (${log.statusCode}):`, MARGIN, this.y);
    this.y += 5;

    const responseLines = this.doc.splitTextToSize(log.responseContent, CONTENT_WIDTH - 10);
    this.renderCodeBlock(responseLines, lineHeight, codeBlockPadding);

    this.y += 10;
  }

  /**
   * Render a code block that can span multiple pages if needed.
   */
  private renderCodeBlock(
    lines: string[],
    lineHeight: number,
    padding: number
  ) {
    let remainingLines = [...lines];

    while (remainingLines.length > 0) {
      // Calculate how many lines fit on this page
      const availableHeight = PAGE_HEIGHT - this.y - MARGIN - 5;
      const maxLinesThisPage = Math.floor((availableHeight - padding * 2) / lineHeight);

      if (maxLinesThisPage <= 0) {
        this.doc.addPage();
        this.y = MARGIN;
        continue;
      }

      const linesToRender = remainingLines.slice(0, maxLinesThisPage);
      remainingLines = remainingLines.slice(maxLinesThisPage);

      const blockHeight = linesToRender.length * lineHeight + padding * 2;

      // Code block background
      this.doc.setFillColor(...COLORS.codeBg);
      this.doc.roundedRect(MARGIN, this.y, CONTENT_WIDTH, blockHeight, 2, 2, "F");

      // Code content
      this.doc.setFontSize(8);
      this.doc.setFont("courier", "normal");
      this.doc.setTextColor(...COLORS.codeText);
      let textY = this.y + padding + 2;
      for (const line of linesToRender) {
        this.doc.text(line, MARGIN + padding, textY);
        textY += lineHeight;
      }

      this.y += blockHeight;

      // If more lines remain, add a new page
      if (remainingLines.length > 0) {
        this.doc.addPage();
        this.y = MARGIN;

        // Add continuation indicator
        this.doc.setFontSize(7);
        this.doc.setFont("helvetica", "italic");
        this.doc.setTextColor(...COLORS.gray);
        this.doc.text("(continued)", MARGIN, this.y);
        this.y += 5;
      }
    }
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
    // Separate maps for vulnerabilities vs informational
    const vulnEndpointMap = new Map<string, VulnerabilityDetail[]>();
    const infoEndpointMap = new Map<string, VulnerabilityDetail[]>();

    const severityCounts: VulnerabilitySummary = {
      total: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    // Process vulnerabilities (failed tests with CVSS > 0)
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

        // Vulnerabilities have CVSS > 0 and severity is not Info
        if (vuln.severity !== "Info" && vuln.cvssScore > 0) {
          this.addToEndpointMap(vulnEndpointMap, vuln);
        } else {
          // Info-level findings from vulnerabilities go to informational
          this.addToEndpointMap(infoEndpointMap, vuln);
        }
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

          this.addToEndpointMap(infoEndpointMap, vuln);
          this.incrementSeverityCount(severityCounts, vuln.severity);
        }
      }
    }

    // Build vulnerability groups (sorted by severity, then count)
    const vulnerabilityGroups: EndpointGroup[] = Array.from(vulnEndpointMap.entries())
      .map(([endpoint, vulnerabilities]) => ({
        endpoint,
        vulnerabilityCount: vulnerabilities.length,
        vulnerabilities: this.sortVulnerabilitiesBySeverity(vulnerabilities),
      }))
      .sort((a, b) => {
        // Sort by highest severity first, then by count
        const aMaxSeverity = this.getMaxSeverityOrder(a.vulnerabilities);
        const bMaxSeverity = this.getMaxSeverityOrder(b.vulnerabilities);
        if (aMaxSeverity !== bMaxSeverity) return aMaxSeverity - bMaxSeverity;
        return b.vulnerabilityCount - a.vulnerabilityCount;
      });

    // Build informational groups
    const informationalGroups: EndpointGroup[] = Array.from(infoEndpointMap.entries())
      .map(([endpoint, vulnerabilities]) => ({
        endpoint,
        vulnerabilityCount: vulnerabilities.length,
        vulnerabilities: this.sortVulnerabilitiesBySeverity(vulnerabilities),
      }))
      .sort((a, b) => b.vulnerabilityCount - a.vulnerabilityCount);

    // Combined groups for backward compatibility
    const endpointGroups = [...vulnerabilityGroups, ...informationalGroups];

    return {
      scanId: scanResults.scanId,
      status: scanResults.status,
      generatedAt: new Date(),
      summary: severityCounts,
      vulnerabilityGroups,
      informationalGroups,
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

  private getMaxSeverityOrder(vulns: VulnerabilityDetail[]): number {
    const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
    if (vulns.length === 0) return 5;
    return Math.min(...vulns.map(v => order[v.severity]));
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
      responseLines.push("", entry.response.content);
    }

    return {
      method: entry.request.method,
      endpoint,
      statusCode: entry.response.statusCode,
      requestContent: requestLines.join("\n"),
      responseContent: responseLines.join("\n"),
    };
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
