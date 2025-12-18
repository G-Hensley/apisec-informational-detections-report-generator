# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

A Next.js application that generates PDF vulnerability reports from APIsec API scan data. Users input their APIsec credentials and scan details, and the app fetches data and generates a downloadable PDF report.

## Development Commands

```bash
npm run dev      # Start development server at localhost:3000
npm run build    # Build for production
npm run lint     # Run ESLint
```

## Architecture

### Data Flow
1. User enters APIsec credentials (Bearer token, app ID, instance ID, optional scan ID) in the form
2. Form calls `fetchReportData()` in `lib/apisec-client.ts`
3. API client proxies requests through `/api/apisec/[...path]/route.ts` to bypass CORS
4. PDF generation uses `PDFReportGenerator` class which uses jsPDF directly
5. Generated PDF is downloaded via file-saver

### Key API Concepts

**Tenant Handling**: APIsec uses a SINGLE API endpoint (`api.apisecapps.com`). The tenant is determined by the Bearer token, NOT the URL.

**ID Mapping**: Scan results contain `executionId` but fetching HTTP logs requires `detectionId` from the detections endpoint. The `detectionToFindingMap` maps between them using composite keys.

**Finding Types**:
- `vulnerabilities`: FAILED tests with CVSS scores (real security issues)
- `issues`: Informational detections (lower priority findings)

**Exclusion Filtering**: Findings with status "resolved" or "false positive" are excluded from reports via `excludedFindingKeys`.

### Code Organization

- `lib/apisec-client.ts` - API communication, data fetching, error handling
- `lib/pdf/generator.ts` - jsPDF-based PDF rendering (~900 lines)
- `lib/pdf/models.ts` - TypeScript interfaces for PDF data structures
- `lib/types.ts` - APIsec API response types
- `components/report-form.tsx` - Main form UI with URL parsing, progress tracking
- `app/api/apisec/[...path]/route.ts` - Next.js API proxy to APIsec

### PDF Generation

Uses jsPDF directly (not html2canvas) for reliable rendering. Key sections:
- Cover page with scan metadata
- Executive summary with severity counts
- Vulnerability details grouped by endpoint
- HTTP request/response logs (optional)
- Informational findings section (optional)

CVSS severity thresholds: Critical ≥9.0, High ≥7.0, Medium ≥4.0, Low ≥0.1, Info <0.1

## Tech Stack

- Next.js 16 (App Router)
- React 19
- Tailwind CSS v4 with shadcn/ui components
- jsPDF for PDF generation
- file-saver for downloads
