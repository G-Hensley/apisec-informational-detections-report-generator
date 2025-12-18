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
  EndpointSummary,
  FailingLog,
  InjectedPayload,
  getSeverityFromCvss,
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
  criticalDark: [153, 27, 27] as [number, number, number],
  high: [234, 88, 12] as [number, number, number],
  medium: [202, 138, 4] as [number, number, number],
  low: [37, 99, 235] as [number, number, number],
  info: [107, 114, 128] as [number, number, number],
  background: [245, 245, 245] as [number, number, number],
  codeBg: [30, 30, 30] as [number, number, number],
  codeText: [212, 212, 212] as [number, number, number],
  // HTTP log header colors
  requestHeader: [22, 163, 74] as [number, number, number],   // Green for outgoing request
  responseHeader: [79, 70, 229] as [number, number, number],  // Indigo for incoming response
};

// OWASP Top 10 2021 mappings for enhanced remediation details
const OWASP_DESCRIPTIONS: Record<string, string> = {
  "A01:2021": "Broken Access Control - Restrictions on authenticated users are not properly enforced",
  "A02:2021": "Cryptographic Failures - Failures related to cryptography leading to sensitive data exposure",
  "A03:2021": "Injection - User-supplied data is not validated, allowing malicious code execution",
  "A04:2021": "Insecure Design - Missing or ineffective security controls in the design",
  "A05:2021": "Security Misconfiguration - Insecure default configurations or incomplete setup",
  "A06:2021": "Vulnerable Components - Using components with known vulnerabilities",
  "A07:2021": "Authentication Failures - Weaknesses in authentication and session management",
  "A08:2021": "Software and Data Integrity Failures - Assumptions about software updates or data integrity",
  "A09:2021": "Security Logging Failures - Insufficient logging and monitoring",
  "A10:2021": "Server-Side Request Forgery - Web application fetches remote resources without validation",
};

// Category-based impact descriptions for common vulnerability types
const CATEGORY_IMPACTS: Record<string, string> = {
  // SQL Injection variants
  "sql injection": "Could allow unauthorized database access, data theft, or modification of sensitive records",
  "sql": "Could allow unauthorized database access, data theft, or modification of sensitive records",
  // XSS variants
  "xss": "May enable script injection that could steal user sessions or perform actions on behalf of users",
  "cross-site scripting": "May enable script injection that could steal user sessions or perform actions on behalf of users",
  // CORS
  "cors": "May enable cross-origin attacks against authenticated users, potentially exposing sensitive data",
  // Authentication
  "authentication": "Could allow unauthorized access to protected resources and user accounts",
  "auth": "Could allow unauthorized access to protected resources and user accounts",
  "broken authentication": "Could allow unauthorized access to protected resources and user accounts",
  // Authorization / RBAC
  "authorization": "May allow users to access resources or perform actions beyond their permissions",
  "rbac": "May allow users to access resources or perform actions beyond their permissions",
  "access control": "May allow users to access resources or perform actions beyond their permissions",
  "broken access control": "May allow users to access resources or perform actions beyond their permissions",
  "bola": "May allow users to access other users' data by manipulating object identifiers",
  "idor": "May allow users to access other users' data by manipulating object identifiers",
  // SSRF
  "ssrf": "Could allow internal network reconnaissance or access to internal services from external requests",
  "server-side request forgery": "Could allow internal network reconnaissance or access to internal services from external requests",
  // Path Traversal
  "path traversal": "May expose sensitive files outside the intended web root directory",
  "directory traversal": "May expose sensitive files outside the intended web root directory",
  // Sensitive Data
  "sensitive data": "Could leak confidential information including credentials, PII, or business data",
  "information disclosure": "Could leak confidential information including credentials, PII, or business data",
  "data exposure": "Could leak confidential information including credentials, PII, or business data",
  // Rate Limiting
  "rate limit": "May allow brute force attacks, denial of service, or resource exhaustion",
  "dos": "May allow denial of service attacks affecting application availability",
  // Input Validation
  "input validation": "Could allow malformed data to bypass security controls or cause unexpected behavior",
  "injection": "Could allow malicious input to be executed as commands or queries",
};

type RemediationReference = { label: string; url: string };
type RemediationDetails = {
  solutionSteps: string[];
  exploitation: string[];
  references: RemediationReference[];
};

const COMMON_REFERENCES = {
  owaspApiTop10: { label: "OWASP API Security Top 10", url: "https://owasp.org/www-project-api-security/" },
  owaspAsvs: { label: "OWASP ASVS", url: "https://owasp.org/www-project-application-security-verification-standard/" },
  owaspCheatSheets: { label: "OWASP Cheat Sheet Series", url: "https://cheatsheetseries.owasp.org/" },
  mdnCookies: { label: "MDN: Set-Cookie", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie" },
  mdnCors: { label: "MDN: CORS", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS" },
  mdnHsts: { label: "MDN: Strict-Transport-Security (HSTS)", url: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security" },
  owaspSecureHeaders: { label: "OWASP Secure Headers Project", url: "https://owasp.org/www-project-secure-headers/" },
  ietfRateLimit: { label: "IETF: RateLimit Header Fields for HTTP", url: "https://www.ietf.org/archive/id/draft-ietf-httpapi-ratelimit-headers-02.html" },
};

const REMEDIATION_LIBRARY: Array<{
  match: (category: string, testName: string, owaspTags: string[]) => boolean;
  details: RemediationDetails;
}> = [
  {
    match: (category, testName) => {
      const s = `${category} ${testName}`.toLowerCase();
      return s.includes("infoleak") || s.includes("info leak") || s.includes("information disclosure") || s.includes("network");
    },
    details: {
      solutionSteps: [
        "Remove internal IPs/hostnames and infrastructure details from response headers and bodies.",
        "Disable debug/verbose headers (e.g., Server, X-Powered-By) at the gateway/reverse proxy.",
        "Standardize error responses and avoid leaking stack traces or environment details.",
        "Add automated tests that assert headers do not contain private IP ranges or internal DNS names.",
      ],
      exploitation: [
        "An attacker uses leaked internal addressing to plan SSRF targets or lateral movement after a foothold.",
        "Verbose headers can reveal software versions that enable targeted exploitation.",
      ],
      references: [
        COMMON_REFERENCES.owaspSecureHeaders,
        COMMON_REFERENCES.owaspApiTop10,
      ],
    },
  },
  {
    match: (category, testName) => {
      const s = `${category} ${testName}`.toLowerCase();
      return s.includes("hsts") || s.includes("strict-transport-security");
    },
    details: {
      solutionSteps: [
        "Enable HSTS (Strict-Transport-Security) on HTTPS responses with an appropriate max-age.",
        "Consider includeSubDomains and preload only after validating subdomain HTTPS readiness.",
        "Ensure HTTP redirects to HTTPS and remove mixed-content dependencies.",
      ],
      exploitation: [
        "Without HSTS, users are more vulnerable to HTTPS downgrade and man-in-the-middle attacks on first connection.",
      ],
      references: [
        COMMON_REFERENCES.mdnHsts,
        COMMON_REFERENCES.owaspSecureHeaders,
      ],
    },
  },
  {
    match: (category, testName) => {
      const s = `${category} ${testName}`.toLowerCase();
      return s.includes("ratelimit") || s.includes("rate limit header");
    },
    details: {
      solutionSteps: [
        "Implement rate limiting (per user/API key/IP as appropriate) with sensible burst and steady-state limits.",
        "Return 429 Too Many Requests on throttling and include Retry-After when useful.",
        "Expose RateLimit-* headers (Limit/Remaining/Reset) so clients can self-throttle and avoid accidental abuse.",
        "Apply stricter limits to sensitive or expensive endpoints and monitor for abuse patterns.",
      ],
      exploitation: [
        "Without rate limiting, attackers can brute force credentials, enumerate resources, or cause resource exhaustion (DoS).",
      ],
      references: [
        COMMON_REFERENCES.ietfRateLimit,
        COMMON_REFERENCES.owaspApiTop10,
      ],
    },
  },
  {
    match: (category, testName) => {
      const s = `${category} ${testName}`.toLowerCase();
      return s.includes("headers") || s.includes("security headers");
    },
    details: {
      solutionSteps: [
        "Harden security headers at the edge (gateway/reverse proxy) for consistent coverage.",
        "Ensure HSTS, X-Content-Type-Options, and a safe Referrer-Policy are set where applicable.",
        "Remove or minimize fingerprinting headers (Server, X-Powered-By) and avoid leaking internal routing info.",
      ],
      exploitation: [
        "Missing or weak headers can enable downgrade, content sniffing, or increase attack surface through information disclosure.",
      ],
      references: [
        COMMON_REFERENCES.owaspSecureHeaders,
        COMMON_REFERENCES.owaspApiTop10,
      ],
    },
  },
  {
    match: (category, testName) => {
      const s = `${category} ${testName}`.toLowerCase();
      return s.includes("idor") || s.includes("bola") || s.includes("broken access control") || s.includes("incremental");
    },
    details: {
      solutionSteps: [
        "Enforce object-level authorization on every request (never rely on client-side checks).",
        "Validate the requested object belongs to the authenticated user/tenant before returning data.",
        "Use unguessable identifiers (UUIDs) only as defense-in-depth (still require authorization).",
        "Add tests for cross-user access and alert on repeated authorization failures.",
      ],
      exploitation: [
        "An attacker changes an object identifier (path/body/query) to access another user's records.",
        "Predictable/incremental IDs make enumeration and scraping significantly easier.",
      ],
      references: [
        COMMON_REFERENCES.owaspApiTop10,
        { label: "OWASP Cheat Sheet: Authorization", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" },
      ],
    },
  },
  {
    match: (category, testName) => `${category} ${testName}`.toLowerCase().includes("sql"),
    details: {
      solutionSteps: [
        "Use parameterized queries/prepared statements; never concatenate untrusted input into SQL.",
        "Validate and normalize inputs; use allow-lists for identifiers when needed.",
        "Run DB users as least-privileged; rotate credentials regularly.",
        "Avoid leaking SQL errors in responses; add safe centralized error handling.",
      ],
      exploitation: [
        "An attacker injects SQL via inputs to read/modify data or bypass authorization checks.",
      ],
      references: [
        { label: "OWASP Cheat Sheet: SQL Injection Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html" },
        COMMON_REFERENCES.owaspCheatSheets,
      ],
    },
  },
  {
    match: (category, testName) => {
      const s = `${category} ${testName}`.toLowerCase();
      return s.includes("xss") || s.includes("cross-site scripting");
    },
    details: {
      solutionSteps: [
        "Contextually encode output (HTML/JS/URL) and avoid unsafe DOM sinks.",
        "Use a strong Content Security Policy (CSP) to reduce blast radius.",
        "Validate/normalize inputs and sanitize rich content if you must accept it.",
      ],
      exploitation: [
        "An attacker injects script into content rendered by the client to steal tokens or act as the victim.",
      ],
      references: [
        { label: "OWASP Cheat Sheet: XSS Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html" },
        COMMON_REFERENCES.owaspCheatSheets,
      ],
    },
  },
  {
    match: (category, testName) => `${category} ${testName}`.toLowerCase().includes("cors"),
    details: {
      solutionSteps: [
        "Do not use wildcard origins with credentials; explicitly allow trusted origins only.",
        "Avoid reflecting Origin without validation; enforce an allow-list and exact matches.",
        "Limit allowed methods/headers and avoid exposing sensitive headers unnecessarily.",
      ],
      exploitation: [
        "A malicious site abuses permissive CORS to read API responses in a victim's browser session.",
      ],
      references: [
        COMMON_REFERENCES.mdnCors,
        COMMON_REFERENCES.owaspApiTop10,
      ],
    },
  },
  {
    match: (category, testName) => {
      const s = `${category} ${testName}`.toLowerCase();
      // Cookie issues should be based on cookie/cookie-header detection,
      // not just the OWASP API8 tag (which covers broad misconfiguration).
      return s.includes("cookie") || s.includes("set-cookie");
    },
    details: {
      solutionSteps: [
        "Set cookies with Secure, HttpOnly, and SameSite attributes appropriately.",
        "Avoid cookies for API credentials where possible; prefer token-based auth.",
        "Shorten session lifetime and rotate tokens/identifiers regularly.",
      ],
      exploitation: [
        "Missing cookie attributes can enable session theft via XSS, downgrade, or cross-site request scenarios.",
      ],
      references: [
        COMMON_REFERENCES.mdnCookies,
        COMMON_REFERENCES.owaspApiTop10,
      ],
    },
  },
  {
    match: (category, testName) => `${category} ${testName}`.toLowerCase().includes("ssrf"),
    details: {
      solutionSteps: [
        "Block internal address ranges and metadata IPs; enforce allow-lists for outbound targets.",
        "Disable URL schemes you don't need (file://, gopher://) and validate redirects.",
        "Run outbound fetches in a restricted network sandbox and log all destinations.",
      ],
      exploitation: [
        "An attacker forces the server to fetch internal resources (cloud metadata, internal services) and leak data.",
      ],
      references: [
        { label: "OWASP Cheat Sheet: SSRF Prevention", url: "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html" },
        COMMON_REFERENCES.owaspCheatSheets,
      ],
    },
  },
  {
    match: (category, testName) => {
      const s = `${category} ${testName}`.toLowerCase();
      return s.includes("path traversal") || s.includes("directory traversal");
    },
    details: {
      solutionSteps: [
        "Never map user input directly to filesystem paths; use allow-lists for filenames/IDs.",
        "Normalize and reject traversal sequences; enforce a fixed base directory.",
        "Run the service with least filesystem privileges.",
      ],
      exploitation: [
        "An attacker uses ../ sequences or encodings to read arbitrary files or access restricted paths.",
      ],
      references: [
        { label: "OWASP Cheat Sheet: Path Traversal", url: "https://cheatsheetseries.owasp.org/cheatsheets/Path_Traversal_Cheat_Sheet.html" },
        COMMON_REFERENCES.owaspCheatSheets,
      ],
    },
  },
  {
    match: (category, testName) => {
      const s = `${category} ${testName}`.toLowerCase();
      return s.includes("rate") || s.includes("dos");
    },
    details: {
      solutionSteps: [
        "Add per-user/IP rate limits and burst controls; return 429 with Retry-After.",
        "Protect expensive endpoints with caching and pagination limits.",
        "Add bot protections/WAF rules for public endpoints.",
      ],
      exploitation: [
        "An attacker brute-forces credentials or causes resource exhaustion via high request volume.",
      ],
      references: [
        COMMON_REFERENCES.owaspApiTop10,
        COMMON_REFERENCES.owaspAsvs,
      ],
    },
  },
];

function getEnhancedRemediationDetails(
  category: string,
  testName: string,
  owaspTags: string[]
): RemediationDetails | undefined {
  for (const entry of REMEDIATION_LIBRARY) {
    if (entry.match(category, testName, owaspTags)) return entry.details;
  }
  return undefined;
}

// Common injection payload patterns for detection
const INJECTION_PATTERNS: Array<{ pattern: RegExp; type: string }> = [
  // SQL Injection patterns
  { pattern: /['"](\s*(OR|AND)\s*['"]?[0-9]?['"]?\s*[=<>]|--|;|UNION|SELECT|INSERT|UPDATE|DELETE|DROP|EXEC)/i, type: "SQL Injection" },
  { pattern: /(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+/i, type: "SQL Injection" },
  { pattern: /'\s*OR\s*'.*'\s*=\s*'/i, type: "SQL Injection" },
  { pattern: /\bSLEEP\s*\(/i, type: "SQL Injection" },
  { pattern: /\bWAITFOR\s+DELAY/i, type: "SQL Injection" },
  { pattern: /\bBENCHMARK\s*\(/i, type: "SQL Injection" },
  // XSS patterns
  { pattern: /<script[^>]*>/i, type: "XSS" },
  { pattern: /javascript:/i, type: "XSS" },
  { pattern: /on(error|load|click|mouse|focus|blur)\s*=/i, type: "XSS" },
  { pattern: /<img[^>]+onerror/i, type: "XSS" },
  { pattern: /<svg[^>]+onload/i, type: "XSS" },
  { pattern: /\balert\s*\(/i, type: "XSS" },
  // Path traversal patterns
  { pattern: /\.\.[\/\\]/g, type: "Path Traversal" },
  { pattern: /\.\.%2[fF]/g, type: "Path Traversal" },
  { pattern: /etc\/passwd/i, type: "Path Traversal" },
  { pattern: /windows\\system32/i, type: "Path Traversal" },
  // SSRF patterns
  { pattern: /127\.0\.0\.1|localhost|0\.0\.0\.0/i, type: "SSRF" },
  { pattern: /169\.254\.169\.254/i, type: "SSRF (Cloud Metadata)" },
  { pattern: /\[::1\]/i, type: "SSRF" },
  { pattern: /file:\/\//i, type: "SSRF" },
  { pattern: /gopher:\/\//i, type: "SSRF" },
  // Command injection patterns
  { pattern: /[;&|`$]|\$\(/i, type: "Command Injection" },
  { pattern: /\|\s*\w+/i, type: "Command Injection" },
  // LDAP injection patterns
  { pattern: /[()\\*]/g, type: "LDAP Injection" },
  // XML/XXE patterns
  { pattern: /<!ENTITY/i, type: "XXE" },
  { pattern: /SYSTEM\s+["']/i, type: "XXE" },
  // NoSQL injection patterns
  { pattern: /\$gt|\$lt|\$ne|\$regex|\$where/i, type: "NoSQL Injection" },
  // Template injection patterns
  { pattern: /\{\{.*\}\}/i, type: "Template Injection" },
  { pattern: /\$\{.*\}/i, type: "Template Injection" },
];

/**
 * Check if a value contains injection patterns.
 * Returns the type of injection detected or null if none found.
 */
function detectInjectionPattern(value: string): string | null {
  if (!value || typeof value !== "string") return null;

  for (const { pattern, type } of INJECTION_PATTERNS) {
    // Some patterns use the global flag, making RegExp.test stateful.
    // Reset to ensure consistent results across calls.
    pattern.lastIndex = 0;
    if (pattern.test(value)) {
      return type;
    }
  }
  return null;
}

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const NUMERIC_ID_REGEX = /^\d+$/;

function isIdorLikeFinding(categoryName: string, testName: string): boolean {
  const combined = `${categoryName} ${testName}`.toLowerCase();
  return (
    combined.includes("idor") ||
    combined.includes("bola") ||
    combined.includes("broken access control") ||
    combined.includes("incremental")
  );
}

function normalizeFlattenedKey(flatKey: string): string {
  const withoutIndexes = flatKey.replace(/\[\d+\]/g, "");
  const lastSegment = withoutIndexes.split(".").filter(Boolean).pop();
  return (lastSegment || withoutIndexes).toLowerCase();
}

function looksLikeIdentifierValue(value: string): boolean {
  const trimmed = value.trim();
  if (!trimmed) return false;
  if (UUID_REGEX.test(trimmed)) return true;
  if (NUMERIC_ID_REGEX.test(trimmed)) return true;
  return false;
}

function extractIdentifierFieldsFromJson(
  jsonText: string | undefined,
  location: "body" | "response"
): InjectedPayload[] {
  if (!jsonText) return [];

  const params = new Map<string, string>();
  try {
    const parsed = JSON.parse(jsonText);
    flattenObject(parsed, "", params);
  } catch {
    return [];
  }

  const results: InjectedPayload[] = [];
  for (const [key, value] of params.entries()) {
    const normalizedKey = normalizeFlattenedKey(key);
    const looksLikeIdKey = normalizedKey === "id" || normalizedKey.endsWith("id") || normalizedKey === "uuid";
    if (!looksLikeIdKey) continue;
    if (!looksLikeIdentifierValue(value)) continue;

    results.push({
      parameterName: key,
      payloadValue: value,
      location,
    });
  }

  return results;
}

/**
 * Extract query parameters from a URL string.
 */
function extractQueryParams(url: string): Map<string, string> {
  const params = new Map<string, string>();
  try {
    // Handle relative URLs by adding a base
    const fullUrl = url.startsWith("http") ? url : `https://example.com${url}`;
    const urlObj = new URL(fullUrl);
    urlObj.searchParams.forEach((value, key) => {
      params.set(key, decodeURIComponent(value));
    });
  } catch {
    // Try manual extraction if URL parsing fails
    const queryMatch = url.match(/\?(.+?)(?:#|$)/);
    if (queryMatch) {
      const pairs = queryMatch[1].split("&");
      for (const pair of pairs) {
        const [key, ...valueParts] = pair.split("=");
        if (key) {
          try {
            params.set(key, decodeURIComponent(valueParts.join("=")));
          } catch {
            params.set(key, valueParts.join("="));
          }
        }
      }
    }
  }
  return params;
}

/**
 * Extract path parameters (segments that look like injected values).
 */
function extractPathParams(url: string): Map<string, string> {
  const params = new Map<string, string>();
  try {
    // Remove query string
    const pathOnly = url.split("?")[0];
    const segments = pathOnly.split("/").filter(s => s.length > 0);

    for (let i = 0; i < segments.length; i++) {
      const segment = decodeURIComponent(segments[i]);
      // Check if this segment looks like it might be a parameter value (not a static path)
      // Heuristics: contains special characters, is very long, or matches injection patterns
      if (segment.length > 50 || detectInjectionPattern(segment)) {
        params.set(`path[${i}]`, segment);
      }
    }
  } catch {
    // Ignore parsing errors
  }
  return params;
}

/**
 * Extract parameters from a JSON body.
 */
function extractBodyParams(body: string | undefined): Map<string, string> {
  const params = new Map<string, string>();
  if (!body) return params;

  try {
    const parsed = JSON.parse(body);
    flattenObject(parsed, "", params);
  } catch {
    // Not JSON, try form-urlencoded
    if (body.includes("=")) {
      const pairs = body.split("&");
      for (const pair of pairs) {
        const [key, ...valueParts] = pair.split("=");
        if (key) {
          try {
            params.set(key, decodeURIComponent(valueParts.join("=")));
          } catch {
            params.set(key, valueParts.join("="));
          }
        }
      }
    }
  }
  return params;
}

/**
 * Recursively flatten a JSON object into key-value pairs.
 */
function flattenObject(obj: unknown, prefix: string, result: Map<string, string>): void {
  if (obj === null || obj === undefined) return;

  if (typeof obj === "string" || typeof obj === "number" || typeof obj === "boolean") {
    result.set(prefix || "value", String(obj));
    return;
  }

  if (Array.isArray(obj)) {
    obj.forEach((item, index) => {
      flattenObject(item, prefix ? `${prefix}[${index}]` : `[${index}]`, result);
    });
    return;
  }

  if (typeof obj === "object") {
    for (const [key, value] of Object.entries(obj)) {
      flattenObject(value, prefix ? `${prefix}.${key}` : key, result);
    }
  }
}

/**
 * Extract injected payloads from a request.
 * Analyzes URL query params, path segments, and body to find suspicious values.
 */
function extractInjectedPayloads(
  url: string,
  body: string | undefined,
  headers: Record<string, string>
): InjectedPayload[] {
  const payloads: InjectedPayload[] = [];

  // Check query parameters
  const queryParams = extractQueryParams(url);
  for (const [name, value] of queryParams) {
    if (detectInjectionPattern(value)) {
      payloads.push({
        parameterName: name,
        payloadValue: value,
        location: "query",
      });
    }
  }

  // Check path segments
  const pathParams = extractPathParams(url);
  for (const [name, value] of pathParams) {
    if (detectInjectionPattern(value)) {
      payloads.push({
        parameterName: name,
        payloadValue: value,
        location: "path",
      });
    }
  }

  // Check body parameters
  const bodyParams = extractBodyParams(body);
  for (const [name, value] of bodyParams) {
    if (detectInjectionPattern(value)) {
      payloads.push({
        parameterName: name,
        payloadValue: value,
        location: "body",
      });
    }
  }

  // Check headers (some attacks use headers)
  for (const [name, value] of Object.entries(headers)) {
    // Skip common headers that are unlikely to be injection targets
    const skipHeaders = ["authorization", "content-type", "accept", "user-agent", "host", "content-length"];
    if (skipHeaders.includes(name.toLowerCase())) continue;

    if (detectInjectionPattern(value)) {
      payloads.push({
        parameterName: name,
        payloadValue: value,
        location: "header",
      });
    }
  }

  return payloads;
}

function extractHighlightedParameters(context: {
  categoryName: string;
  testName: string;
  requestUrl: string;
  requestBody: string | undefined;
  requestHeaders: Record<string, string>;
  responseBody: string | undefined;
}): InjectedPayload[] {
  const injected = extractInjectedPayloads(
    context.requestUrl,
    context.requestBody,
    context.requestHeaders
  );
  if (injected.length > 0) return injected;

  // Many findings (e.g., IDOR/BOLA) are not classic "injection payload" attacks.
  // Fall back to highlighting exposed identifiers (UUIDs / numeric IDs) from bodies.
  if (!isIdorLikeFinding(context.categoryName, context.testName)) return [];

  const fromRequest = extractIdentifierFieldsFromJson(context.requestBody, "body");
  const fromResponse = extractIdentifierFieldsFromJson(context.responseBody, "response");

  const combined = [...fromRequest, ...fromResponse];
  const unique = combined.filter((p, idx, self) =>
    idx === self.findIndex(x =>
      x.parameterName === p.parameterName &&
      x.payloadValue === p.payloadValue &&
      x.location === p.location
    )
  );

  return unique.slice(0, 5);
}

/**
 * Get impact description for a category by checking partial matches.
 */
function getCategoryImpact(category: string): string | undefined {
  const lowerCategory = category.toLowerCase();
  for (const [key, impact] of Object.entries(CATEGORY_IMPACTS)) {
    if (lowerCategory.includes(key)) {
      return impact;
    }
  }
  return undefined;
}

/**
 * Get OWASP description for a tag.
 */
function getOwaspDescription(tag: string): string | undefined {
  // Extract the OWASP code (e.g., "A03:2021" from "A03:2021 Injection")
  const match = tag.match(/A\d{2}:\d{4}/);
  if (match) {
    return OWASP_DESCRIPTIONS[match[0]];
  }
  return undefined;
}

/**
 * Generates PDF vulnerability reports from APIsec scan data.
 */
export class PDFReportGenerator {
  private callbacks: GeneratorCallbacks;
  private doc!: jsPDF;
  private y: number = MARGIN;
  private sectionAnchorMap = new Map<string, { page: number; y: number }>();

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
    detectionStatusByKey: Map<string, string>,
    excludedFindingKeys: Set<string>,
    includeInformational: boolean,
    appName?: string,
    hostUrl?: string,
    endpointAuthMap?: Map<string, boolean>
  ): Promise<Blob> {
    this.log("info", "pdf_generation_started", {
      scanId: scanResults.scanId,
      includeInformational,
      excludedCount: excludedFindingKeys.size,
    });

    try {
      // Step 1: Transform data to report structure
      this.progress("Transforming data...", 10);
      const reportData = this.transformData(
        scanResults,
        detectionLogsMap,
        detectionToFindingMap,
        detectionStatusByKey,
        excludedFindingKeys,
        includeInformational,
        appName,
        hostUrl,
        endpointAuthMap
      );

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
    this.sectionAnchorMap.clear();

    // Cover page (title/metadata + TOC)
    this.renderHeader(data);
    const tocStartY = this.y;

    // Main report content starts on page 2 (keeps cover + TOC compact).
    this.doc.addPage();
    this.doc.setPage(2);
    this.y = MARGIN;

    this.renderSummary(data.summary);
    this.renderStatistics(data);
    this.renderVulnerabilitySummaryTable(data);
    this.renderEndpointsScannedTable(data);
    this.renderFindings(data);

    // Populate the TOC on the cover page once we know section anchors.
    this.renderTableOfContentsOnCover(tocStartY);

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
    const metadata: [string, string][] = [
      ["Scan ID:", data.scanId],
      ["Status:", data.status],
      ["Generated:", this.formatDate(data.generatedAt)],
    ];

    // Add application name if provided
    if (data.appName) {
      metadata.unshift(["Application:", data.appName]);
    }

    // Add host URL if provided (after application name)
    if (data.hostUrl) {
      // Insert after Application (index 1) or at start if no app name
      const insertIndex = data.appName ? 1 : 0;
      metadata.splice(insertIndex, 0, ["Host URL:", data.hostUrl]);
    }

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

    // Severity boxes - all 5 levels in one row
    const boxWidth = (CONTENT_WIDTH - 4 * 5) / 5; // 5 boxes with 5mm gaps
    const boxHeight = 22;
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
      this.doc.setFontSize(8);
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.white);
      this.doc.text(box.label, x + boxWidth / 2, this.y + 7, { align: "center" });

      // Value
      this.doc.setFontSize(18);
      this.doc.text(String(box.value), x + boxWidth / 2, this.y + 17, { align: "center" });

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

  /**
   * Render a summary table of all vulnerabilities (not informational) grouped by severity.
   */
  private renderVulnerabilitySummaryTable(data: PDFReportData) {
    // Only render if there are vulnerabilities
    if (data.vulnerabilityGroups.length === 0) return;

    // Flatten all vulnerabilities and sort by severity
    const allVulns = data.vulnerabilityGroups
      .flatMap(g => g.vulnerabilities)
      .filter(v => v.severity !== "Info") // Exclude informational
      .sort((a, b) => {
        const order = { Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4 };
        return order[a.severity] - order[b.severity];
      });

    if (allVulns.length === 0) return;

    this.renderSectionTitle("Vulnerability Summary");

    // Table configuration
    const colWidths = {
      severity: 20,
      status: 20,
      detectionId: 28,
      testName: 48,
      endpoint: 50,
      cvss: 12,
    };
    const rowHeight = 6;
    const headerHeight = 7;

    // Check if we need a new page
    if (this.y > PAGE_HEIGHT - 60) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    // Header row
    this.doc.setFillColor(...COLORS.black);
    this.doc.rect(MARGIN, this.y, CONTENT_WIDTH, headerHeight, "F");

    this.doc.setFontSize(FONT_SIZE_SMALL);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.white);

    let headerX = MARGIN + 2;
    this.doc.text("Severity", headerX, this.y + 5);
    headerX += colWidths.severity;
    this.doc.text("Status", headerX, this.y + 5);
    headerX += colWidths.status;
    this.doc.text("Detection ID", headerX, this.y + 5);
    headerX += colWidths.detectionId;
    this.doc.text("Test Name", headerX, this.y + 5);
    headerX += colWidths.testName;
    this.doc.text("Endpoint", headerX, this.y + 5);
    headerX += colWidths.endpoint;
    this.doc.text("CVSS", headerX, this.y + 5);

    this.y += headerHeight;

    // Data rows
    this.doc.setFont("helvetica", "normal");
    let rowIndex = 0;

    for (const vuln of allVulns) {
      // Check for page break
      if (this.y > PAGE_HEIGHT - MARGIN - 10) {
        this.doc.addPage();
        this.y = MARGIN;

        // Re-render header on new page
        this.doc.setFillColor(...COLORS.black);
        this.doc.rect(MARGIN, this.y, CONTENT_WIDTH, headerHeight, "F");
        this.doc.setFontSize(FONT_SIZE_SMALL);
        this.doc.setFont("helvetica", "bold");
        this.doc.setTextColor(...COLORS.white);

        headerX = MARGIN + 2;
        this.doc.text("Severity", headerX, this.y + 5);
        headerX += colWidths.severity;
        this.doc.text("Status", headerX, this.y + 5);
        headerX += colWidths.status;
        this.doc.text("Detection ID", headerX, this.y + 5);
        headerX += colWidths.detectionId;
        this.doc.text("Test Name", headerX, this.y + 5);
        headerX += colWidths.testName;
        this.doc.text("Endpoint", headerX, this.y + 5);
        headerX += colWidths.endpoint;
        this.doc.text("CVSS", headerX, this.y + 5);

        this.y += headerHeight;
        this.doc.setFont("helvetica", "normal");
      }

      // Alternating row background
      if (rowIndex % 2 === 0) {
        this.doc.setFillColor(...COLORS.background);
        this.doc.rect(MARGIN, this.y, CONTENT_WIDTH, rowHeight, "F");
      }

      // Severity badge
      const severityColor = this.getSeverityColorRgb(vuln.severity);
      this.doc.setFillColor(...severityColor);
      this.doc.roundedRect(MARGIN + 2, this.y + 1, 16, 4, 1, 1, "F");
      this.doc.setFontSize(6);
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.white);
      this.doc.text(vuln.severity.toUpperCase(), MARGIN + 10, this.y + 3.8, { align: "center" });

      // Reset font for other columns
      this.doc.setFontSize(FONT_SIZE_SMALL);
      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.black);

      // Detection ID (show first 8 chars)
      let colX = MARGIN + 2 + colWidths.severity;

      // Status
      const statusText = vuln.status || "N/A";
      this.doc.text(this.truncateTextToWidth(statusText, colWidths.status - 4), colX, this.y + 4.5);

      // Detection ID
      colX += colWidths.status;
      const shortId = vuln.detectionId ? vuln.detectionId.slice(0, 8) : "N/A";
      this.doc.text(shortId, colX, this.y + 4.5);

      // Test name (truncated if needed)
      colX += colWidths.detectionId;
      const humanTestName = this.humanizeTestName(vuln.testName, vuln.category);
      const testNameTruncated = this.truncateTextToWidth(humanTestName, colWidths.testName - 4);
      this.doc.text(testNameTruncated, colX, this.y + 4.5);

      // Endpoint (truncated if needed)
      colX += colWidths.testName;
      const endpointTruncated = this.truncateTextToWidth(`${vuln.method} ${vuln.endpoint}`, colWidths.endpoint - 4);
      this.doc.text(endpointTruncated, colX, this.y + 4.5);

      // CVSS score
      colX += colWidths.endpoint;
      this.doc.text(vuln.cvssScore.toFixed(1), colX, this.y + 4.5);

      this.y += rowHeight;
      rowIndex++;
    }

    this.y += 8;
  }

  /**
   * Render a table of all endpoints scanned.
   */
  private renderEndpointsScannedTable(data: PDFReportData) {
    // Only render if there are endpoints
    if (data.endpointSummaries.length === 0) return;

    this.renderSectionTitle("Endpoints Scanned");

    // Table configuration
    const colWidths = {
      method: 18,
      endpoint: 100,
      vulns: 18,
      info: 18,
      auth: 16,
    };
    const rowHeight = 6;
    const headerHeight = 7;

    // Check if we need a new page
    if (this.y > PAGE_HEIGHT - 60) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    // Helper to render header row
    const renderHeader = () => {
      this.doc.setFillColor(...COLORS.black);
      this.doc.rect(MARGIN, this.y, CONTENT_WIDTH, headerHeight, "F");

      this.doc.setFontSize(FONT_SIZE_SMALL);
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.white);

      let headerX = MARGIN + 2;
      this.doc.text("Method", headerX, this.y + 5);
      headerX += colWidths.method;
      this.doc.text("Endpoint", headerX, this.y + 5);
      headerX += colWidths.endpoint;
      this.doc.text("Vulns", headerX, this.y + 5);
      headerX += colWidths.vulns;
      this.doc.text("Info", headerX, this.y + 5);
      headerX += colWidths.info;
      this.doc.text("Auth", headerX, this.y + 5);

      this.y += headerHeight;
    };

    // Render initial header
    renderHeader();

    // Data rows
    this.doc.setFont("helvetica", "normal");
    let rowIndex = 0;

    for (const ep of data.endpointSummaries) {
      // Check for page break
      if (this.y > PAGE_HEIGHT - MARGIN - 10) {
        this.doc.addPage();
        this.y = MARGIN;
        renderHeader();
        this.doc.setFont("helvetica", "normal");
      }

      // Alternating row background
      if (rowIndex % 2 === 0) {
        this.doc.setFillColor(...COLORS.background);
        this.doc.rect(MARGIN, this.y, CONTENT_WIDTH, rowHeight, "F");
      }

      // Reset font for columns
      this.doc.setFontSize(FONT_SIZE_SMALL);
      this.doc.setTextColor(...COLORS.black);

      // Method badge
      const methodColor = this.getMethodColor(ep.method);
      this.doc.setFillColor(...methodColor);
      this.doc.roundedRect(MARGIN + 2, this.y + 1, 14, 4, 1, 1, "F");
      this.doc.setFontSize(5);
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.white);
      this.doc.text(ep.method, MARGIN + 9, this.y + 3.8, { align: "center" });

      // Reset for other columns
      this.doc.setFontSize(FONT_SIZE_SMALL);
      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.black);

      // Endpoint (truncated if needed)
      let colX = MARGIN + 2 + colWidths.method;
      const endpointTruncated = this.truncateTextToWidth(ep.endpoint, colWidths.endpoint - 4);
      this.doc.text(endpointTruncated, colX, this.y + 4.5);

      // Vulns count (highlight if > 0)
      colX += colWidths.endpoint;
      if (ep.vulnCount > 0) {
        this.doc.setTextColor(...COLORS.critical);
        this.doc.setFont("helvetica", "bold");
      }
      this.doc.text(ep.vulnCount.toString(), colX + 6, this.y + 4.5, { align: "center" });
      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.black);

      // Info count
      colX += colWidths.vulns;
      this.doc.text(ep.infoCount.toString(), colX + 6, this.y + 4.5, { align: "center" });

      // Auth status
      colX += colWidths.info;
      const authColor = ep.authStatus === "Yes" ? COLORS.requestHeader : COLORS.lightGray;
      this.doc.setTextColor(...authColor);
      this.doc.text(ep.authStatus, colX + 4, this.y + 4.5);
      this.doc.setTextColor(...COLORS.black);

      this.y += rowHeight;
      rowIndex++;
    }

    this.y += 8;
  }

  /**
   * Get color for HTTP method badge.
   */
  private getMethodColor(method: string): [number, number, number] {
    const colors: Record<string, [number, number, number]> = {
      GET: [22, 163, 74],      // Green
      POST: [37, 99, 235],     // Blue
      PUT: [202, 138, 4],      // Yellow/Amber
      PATCH: [147, 51, 234],   // Purple
      DELETE: [220, 38, 38],   // Red
      HEAD: [107, 114, 128],   // Gray
      OPTIONS: [107, 114, 128], // Gray
    };
    return colors[method.toUpperCase()] || [107, 114, 128];
  }

  /**
   * Truncate text to fit within a specified width in mm.
   */
  private truncateTextToWidth(text: string, maxWidth: number): string {
    let truncated = text;
    while (this.doc.getTextWidth(truncated) > maxWidth && truncated.length > 3) {
      truncated = truncated.slice(0, -4) + "...";
    }
    return truncated;
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
    const labelWidth = 28; // Increased to fit "Last Detected:"

    // Check if we need a new page before starting
    if (this.y > PAGE_HEIGHT - 60) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    // Track bar position - use object so closure can see updates
    const barState = { startY: this.y };

    // Draw colored severity bar on left (will extend as content grows)
    const drawSeverityBar = (endY: number) => {
      this.doc.setFillColor(...severityColor);
      this.doc.rect(MARGIN, barState.startY, 3, endY - barState.startY, "F");
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

    // Last detected date
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.gray);
    this.doc.text("Last Detected:", contentX, this.y);
    this.doc.setFont("helvetica", "normal");
    this.doc.setTextColor(...COLORS.black);
    this.doc.text(this.formatDate(vuln.detectionDate), contentX + labelWidth, this.y);
    this.y += 5;

    // Injected Payload (if detected) - highlight with colored background
    if (vuln.injectedPayloads && vuln.injectedPayloads.length > 0) {
      this.y += 3;

      // Section header
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.critical);
      this.doc.text("Vulnerable Parameter:", contentX, this.y);
      this.y += 5;

      for (const payload of vuln.injectedPayloads) {
        // Check for page break
        if (this.y > PAGE_HEIGHT - MARGIN - 30) {
          drawSeverityBar(this.y + 3);
          this.doc.addPage();
          this.y = MARGIN;
          barState.startY = this.y;
        }

        // Parameter info box with warning background
        const boxStartY = this.y;
        const boxPadding = 3;

        // Draw parameter name and location
        this.doc.setFontSize(FONT_SIZE_SMALL);
        this.doc.setFont("helvetica", "bold");
        this.doc.setTextColor(...COLORS.black);
        const locationText = payload.location.charAt(0).toUpperCase() + payload.location.slice(1);
        this.doc.text(`${payload.parameterName} (${locationText})`, contentX + boxPadding, this.y + 3);
        this.y += 5;

        // Draw payload value (truncate if very long)
        this.doc.setFont("courier", "bold");
        this.doc.setFontSize(8);
        this.doc.setTextColor(...COLORS.black);

        // Truncate payload for display (keep first 150 chars)
        const displayPayload = payload.payloadValue.length > 150
          ? payload.payloadValue.substring(0, 150) + "..."
          : payload.payloadValue;

        const payloadLines = this.doc.splitTextToSize(displayPayload, CONTENT_WIDTH - 20);
        for (const line of payloadLines) {
          this.doc.text(line, contentX + boxPadding, this.y + 3);
          this.y += 3;
        }
        this.y += 2;

        // Draw background box (after measuring text height)
        const boxHeight = this.y - boxStartY + boxPadding;
        this.doc.setFillColor(254, 242, 242); // Light red background
        this.doc.setDrawColor(...COLORS.critical);
        this.doc.setLineWidth(0.3);
        this.doc.roundedRect(contentX, boxStartY - 1, CONTENT_WIDTH - 10, boxHeight, 1, 1, "FD");

        // Re-draw text on top of background
        this.y = boxStartY;
        this.doc.setFontSize(FONT_SIZE_SMALL);
        this.doc.setFont("helvetica", "bold");
        this.doc.setTextColor(...COLORS.black);
        this.doc.text(`${payload.parameterName} (${locationText})`, contentX + boxPadding, this.y + 3);
        this.y += 5;

        this.doc.setFont("courier", "bold");
        this.doc.setFontSize(8);
        this.doc.setTextColor(...COLORS.black);
        for (const line of payloadLines) {
          this.doc.text(line, contentX + boxPadding, this.y + 3);
          this.y += 3;
        }
        // Add a little extra spacing so the next section (e.g., Auth/OWASP)
        // doesn't visually collide with the callout box.
        this.y += boxPadding + 6;
      }

      // Reset font after payload section
      this.doc.setFontSize(FONT_SIZE_SMALL);
      this.y += 2;
    }

    // Auth status (if available)
    if (vuln.authRole || vuln.authMethod) {
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text("Auth:", contentX, this.y);
      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.black);
      const authParts: string[] = [];
      if (vuln.authMethod) authParts.push(vuln.authMethod);
      if (vuln.authRole) authParts.push(`(${vuln.authRole} role)`);
      this.doc.text(authParts.join(" ") || "N/A", contentX + labelWidth, this.y);
      this.y += 5;
    }

    // OWASP Tags with enhanced descriptions
    if (vuln.owaspTags.length > 0) {
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text("OWASP:", contentX, this.y);
      this.y += 5;

      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.black);
      for (const tag of vuln.owaspTags) {
        const owaspDesc = getOwaspDescription(tag);
        const tagText = owaspDesc ? `${tag} - ${owaspDesc}` : tag;
        const tagLines = this.doc.splitTextToSize(tagText, CONTENT_WIDTH - 15);
        for (const line of tagLines) {
          this.doc.text(line, contentX, this.y);
          this.y += 4;
        }
      }
      this.y += 2;
    }

    // Impact section based on category
    const categoryImpact = getCategoryImpact(vuln.category);
    if (categoryImpact) {
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text("Impact:", contentX, this.y);
      this.y += 5;

      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.black);
      const impactLines = this.doc.splitTextToSize(categoryImpact, CONTENT_WIDTH - 15);
      for (const line of impactLines) {
        this.doc.text(line, contentX, this.y);
        this.y += 4;
      }
      this.y += 2;
    }

    // Enhanced remediation content (no new data required)
    const remediation = getEnhancedRemediationDetails(vuln.category, vuln.testName, vuln.owaspTags);
    if (remediation) {
      const ensureRoom = (minRemaining: number) => {
        if (this.y > PAGE_HEIGHT - MARGIN - minRemaining) {
          drawSeverityBar(this.y + 3);
          this.doc.addPage();
          this.y = MARGIN;
          barState.startY = this.y;
        }
      };

      const renderWrapped = (text: string, indent: number = 0) => {
        const lines = this.doc.splitTextToSize(text, CONTENT_WIDTH - 15 - indent);
        for (const line of lines) {
          ensureRoom(10);
          this.doc.text(line, contentX + indent, this.y);
          this.y += 4;
        }
      };

      this.y += 2;
      ensureRoom(35);
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.gray);
      this.doc.text("Remediation:", contentX, this.y);
      this.y += 5;

      // Solution
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.black);
      this.doc.text("Solution", contentX, this.y);
      this.y += 4;
      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.black);
      for (let i = 0; i < Math.min(remediation.solutionSteps.length, 5); i++) {
        renderWrapped(`${i + 1}. ${remediation.solutionSteps[i]}`);
      }
      this.y += 2;

      // Exploitation
      ensureRoom(20);
      this.doc.setFont("helvetica", "bold");
      this.doc.setTextColor(...COLORS.black);
      this.doc.text("Exploitation", contentX, this.y);
      this.y += 4;
      this.doc.setFont("helvetica", "normal");
      this.doc.setTextColor(...COLORS.black);
      for (let i = 0; i < Math.min(remediation.exploitation.length, 3); i++) {
        renderWrapped(`• ${remediation.exploitation[i]}`);
      }
      this.y += 2;

      // References
      if (remediation.references.length > 0) {
        ensureRoom(18);
        this.doc.setFont("helvetica", "bold");
        this.doc.setTextColor(...COLORS.black);
        this.doc.text("References", contentX, this.y);
        this.y += 4;

        for (let i = 0; i < Math.min(remediation.references.length, 4); i++) {
          const ref = remediation.references[i];
          ensureRoom(10);

          this.doc.setFont("helvetica", "normal");
          this.doc.setTextColor(...COLORS.black);
          const label = `• ${ref.label}: `;
          this.doc.text(label, contentX, this.y);
          const labelWidth = this.doc.getTextWidth(label);

          this.doc.setTextColor(...COLORS.low);
          this.doc.textWithLink(ref.url, contentX + labelWidth, this.y, { url: ref.url });
          this.y += 4;
        }

        this.doc.setTextColor(...COLORS.black);
        this.y += 2;
      }
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
          // Reset bar start for new page
          barState.startY = this.y;
        }
        this.doc.text(line, contentX, this.y);
        this.y += 4;
      }
    }

    // Draw the severity bar for this finding
    drawSeverityBar(this.y + 3);

    this.y += 10;

    // HTTP Logs (rendered outside the card for better space management)
    // Only render for non-informational (vulnerabilities) that have logs
    if (!isInformational && vuln.failingLogs.length > 0) {
      this.renderHttpLogs(vuln.failingLogs[0]);
    }
  }

  private renderHttpLogs(log: FailingLog) {
    const codeBlockPadding = 3;
    const lineHeight = 3;
    const headerHeight = 7;

    // Check if we need a new page
    if (this.y > PAGE_HEIGHT - 80) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    // "Failing Test Logs" section header
    this.doc.setFontSize(10);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.black);
    this.doc.text("Failing Test Logs", MARGIN, this.y);
    this.y += 5;

    // Underline
    this.doc.setDrawColor(...COLORS.lightGray);
    this.doc.setLineWidth(0.2);
    this.doc.line(MARGIN, this.y, MARGIN + 35, this.y);
    this.y += 8;

    // === REQUEST BLOCK ===
    // Request header bar with green background
    this.doc.setFillColor(...COLORS.requestHeader);
    this.doc.roundedRect(MARGIN, this.y, CONTENT_WIDTH, headerHeight, 1, 1, "F");

    // Request label
    this.doc.setFontSize(9);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.white);
    this.doc.text("REQUEST", MARGIN + 4, this.y + 5);

    // Request method and endpoint on the right
    const methodEndpoint = `${log.method} ${log.endpoint}`;
    const methodEndpointTruncated = this.truncateTextToWidth(methodEndpoint, CONTENT_WIDTH - 40);
    this.doc.setFont("helvetica", "normal");
    this.doc.text(methodEndpointTruncated, MARGIN + 30, this.y + 5);

    this.y += headerHeight + 1;

    // Request code block (connects to header visually)
    // IMPORTANT: Set the font BEFORE splitTextToSize - courier is wider than helvetica
    const borderWidth = 3;
    const codeContentWidth = CONTENT_WIDTH - borderWidth - codeBlockPadding * 2 - 2; // -2 for safety margin
    this.doc.setFontSize(8);
    this.doc.setFont("courier", "normal");
    const requestLines = this.doc.splitTextToSize(log.requestContent, codeContentWidth);
    this.renderCodeBlockWithBorder(requestLines, lineHeight, codeBlockPadding, COLORS.requestHeader);

    this.y += 10;

    // Check if we need a new page for response
    if (this.y > PAGE_HEIGHT - 50) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    // === RESPONSE BLOCK ===
    // Response header bar with indigo background
    this.doc.setFillColor(...COLORS.responseHeader);
    this.doc.roundedRect(MARGIN, this.y, CONTENT_WIDTH, headerHeight, 1, 1, "F");

    // Response label with status code
    this.doc.setFontSize(9);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.white);
    this.doc.text("RESPONSE", MARGIN + 4, this.y + 5);

    // Status code badge
    const statusColor = this.getStatusCodeColor(log.statusCode);
    const statusText = `${log.statusCode}`;
    this.doc.setFillColor(...statusColor);
    this.doc.roundedRect(MARGIN + 35, this.y + 1.5, 14, 4, 1, 1, "F");
    this.doc.setFontSize(7);
    this.doc.setTextColor(...COLORS.white);
    this.doc.text(statusText, MARGIN + 42, this.y + 4.5, { align: "center" });

    this.y += headerHeight + 1;

    // Response code block (connects to header visually)
    // IMPORTANT: Set the font BEFORE splitTextToSize - courier is wider than helvetica
    this.doc.setFontSize(8);
    this.doc.setFont("courier", "normal");
    const responseLines = this.doc.splitTextToSize(log.responseContent, codeContentWidth);
    this.renderCodeBlockWithBorder(responseLines, lineHeight, codeBlockPadding, COLORS.responseHeader);

    this.y += 12;
  }

  /**
   * Get color for HTTP status code badge.
   */
  private getStatusCodeColor(statusCode: number): [number, number, number] {
    if (statusCode >= 200 && statusCode < 300) return [22, 163, 74];   // Green - Success
    if (statusCode >= 300 && statusCode < 400) return [202, 138, 4];   // Yellow - Redirect
    if (statusCode >= 400 && statusCode < 500) return [234, 88, 12];   // Orange - Client Error
    if (statusCode >= 500) return [220, 38, 38];                        // Red - Server Error
    return COLORS.gray;                                                  // Gray - Unknown
  }

  /**
   * Render a code block with a colored left border for visual distinction.
   */
  private renderCodeBlockWithBorder(
    lines: string[],
    lineHeight: number,
    padding: number,
    borderColor: [number, number, number]
  ) {
    let remainingLines = [...lines];
    const borderWidth = 3;

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

      // Colored left border
      this.doc.setFillColor(...borderColor);
      this.doc.rect(MARGIN, this.y, borderWidth, blockHeight, "F");

      // Code block background (offset by border width)
      this.doc.setFillColor(...COLORS.codeBg);
      this.doc.rect(MARGIN + borderWidth, this.y, CONTENT_WIDTH - borderWidth, blockHeight, "F");

      // Code content
      this.doc.setFontSize(8);
      this.doc.setFont("courier", "normal");
      this.doc.setTextColor(...COLORS.codeText);
      let textY = this.y + padding + 2;
      for (const line of linesToRender) {
        this.doc.text(line, MARGIN + borderWidth + padding, textY);
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
        this.y += 6;
      }
    }
  }

  private renderSectionTitle(title: string) {
    if (this.y > PAGE_HEIGHT - 40) {
      this.doc.addPage();
      this.y = MARGIN;
    }

    // Record the first occurrence of each major section for TOC links.
    if (!this.sectionAnchorMap.has(title)) {
      this.sectionAnchorMap.set(title, { page: this.getCurrentPageNumber(), y: this.y });
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

  private getCurrentPageNumber(): number {
    // jsPDF's internal API exposes current page info via a plugin method.
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const internal: any = (this.doc as any).internal;
    return internal.getCurrentPageInfo().pageNumber as number;
  }

  private renderTableOfContentsOnCover(tocStartY: number) {
    // Determine which sections exist in the current report and their page numbers.
    const tocItems: Array<{ title: string; page: number; y: number }> = [];
    const orderedTitles = [
      "Executive Summary",
      "Scan Statistics",
      "Vulnerability Summary",
      "Endpoints Scanned",
      "Vulnerabilities",
      "Informational Findings",
    ];

    for (const title of orderedTitles) {
      const anchor = this.sectionAnchorMap.get(title);
      if (anchor) tocItems.push({ title, page: anchor.page, y: anchor.y });
    }

    this.doc.setPage(1);
    let y = tocStartY + 5;
    if (y > PAGE_HEIGHT - MARGIN - 30) {
      // Not enough room on cover (rare). Start TOC on a new page.
      this.doc.addPage();
      this.doc.setPage(2);
      y = MARGIN;
    }
    this.doc.setFontSize(FONT_SIZE_SECTION);
    this.doc.setFont("helvetica", "bold");
    this.doc.setTextColor(...COLORS.black);
    this.doc.text("Table of Contents", MARGIN, y);
    y += 3;

    this.doc.setDrawColor(...COLORS.lightGray);
    this.doc.setLineWidth(0.3);
    this.doc.line(MARGIN, y, PAGE_WIDTH - MARGIN, y);
    y += 10;

    this.doc.setFontSize(FONT_SIZE_NORMAL);
    this.doc.setFont("helvetica", "normal");
    this.doc.setTextColor(...COLORS.black);

    // Render clickable entries (title is the link target).
    for (const item of tocItems) {
      if (y > PAGE_HEIGHT - MARGIN - 15) {
        // If TOC grows, spill to next page.
        this.doc.addPage();
        y = MARGIN;
      }

      const titleX = MARGIN;
      const pageText = String(item.page);
      const pageX = PAGE_WIDTH - MARGIN;

      // Title (clickable)
      this.doc.setTextColor(...COLORS.low);
      this.doc.textWithLink(item.title, titleX, y, {
        pageNumber: item.page,
        // Use XYZ so jsPDF converts Y correctly; FitH expects PDF-space coords.
        magFactor: "XYZ",
        left: 0,
        top: item.y,
        zoom: 0,
      });

      // Dotted leader
      this.doc.setTextColor(...COLORS.lightGray);
      const titleWidth = this.doc.getTextWidth(item.title);
      const pageWidth = this.doc.getTextWidth(pageText);
      const dotsStartX = titleX + titleWidth + 3;
      const dotsEndX = pageX - pageWidth - 3;
      if (dotsEndX > dotsStartX) {
        // Draw a light dotted line to suggest "leader dots".
        this.doc.setLineWidth(0.2);
        this.doc.setDrawColor(...COLORS.lightGray);
        // jsPDF doesn't have dashed dots, so use a dashed line as a close equivalent.
        this.doc.setLineDashPattern([1, 1.2], 0);
        this.doc.line(dotsStartX, y - 1, dotsEndX, y - 1);
        this.doc.setLineDashPattern([], 0);
      }

      // Page number (also clickable)
      this.doc.setTextColor(...COLORS.gray);
      this.doc.textWithLink(pageText, pageX, y, {
        pageNumber: item.page,
        magFactor: "XYZ",
        left: 0,
        top: item.y,
        zoom: 0,
        align: "right",
      });

      y += 7;
    }

    // Restore state for safety (subsequent rendering already happened).
    this.doc.setTextColor(...COLORS.black);
    this.doc.setLineDashPattern([], 0);
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
    // Check if date is valid
    if (!date || isNaN(date.getTime())) {
      return "N/A";
    }
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
   * Create a key for exclusion matching (uses method:resource for consistency with detections).
   */
  private createExclusionKey(
    method: string,
    resource: string,
    categoryId: string,
    testId: string
  ): string {
    // Normalize: uppercase method, trim resource - must match apisec-client.ts
    return `${method.toUpperCase()}:${resource.trim()}:${categoryId}:${testId}`;
  }

  /**
   * Create a key for log matching (uses resource path).
   */
  private createLogKey(
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
    const logKey = this.createLogKey(resource, method, categoryId, testId);

    // Find the detectionId that matches this finding
    for (const [detectionId, key] of detectionToFindingMap.entries()) {
      if (key === logKey) {
        return detectionLogsMap.get(detectionId);
      }
    }

    return undefined;
  }

  private transformData(
    scanResults: ScanResults,
    detectionLogsMap: Map<string, DetectionLogs>,
    detectionToFindingMap: Map<string, string>,
    detectionStatusByKey: Map<string, string>,
    excludedFindingKeys: Set<string>,
    includeInformational: boolean,
    appName?: string,
    hostUrl?: string,
    endpointAuthMap?: Map<string, boolean>
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

        // Skip findings that are resolved or false positive (uses method:resource for matching)
        const exclusionKey = this.createExclusionKey(
          endpoint.method,
          endpoint.resource,
          finding.testDetails.categoryId,
          finding.testDetails.categoryTestId
        );

        if (excludedFindingKeys.has(exclusionKey)) {
          continue;
        }

        // Find logs by matching endpoint + category + test (not executionId)
        const logs = this.findLogsForFinding(
          endpoint.resource,
          endpoint.method,
          finding.testDetails.categoryId,
          finding.testDetails.categoryTestId,
          detectionToFindingMap,
          detectionLogsMap
        );

        const status = this.getDetectionStatus(
          endpoint.resource,
          endpoint.method,
          finding.testDetails.categoryId,
          finding.testDetails.categoryTestId,
          detectionStatusByKey
        );

        const vuln = this.transformFinding(
          endpoint.resource,
          endpoint.method,
          finding,
          logs,
          false,
          scanResults.startTime,
          finding.executionId,
          status
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
    // Force all issues to "Info" severity since they are informational by definition
    if (includeInformational) {
      for (const endpoint of scanResults.issues) {
        for (const finding of endpoint.scanFindings) {
          // Skip findings that are resolved or false positive (uses method:resource for matching)
          const exclusionKey = this.createExclusionKey(
            endpoint.method,
            endpoint.resource,
            finding.testDetails.categoryId,
            finding.testDetails.categoryTestId
          );
          if (excludedFindingKeys.has(exclusionKey)) {
            continue;
          }

          const vuln = this.transformFinding(
            endpoint.resource,
            endpoint.method,
            finding,
            undefined, // Logs are ONLY available for vulnerabilities, not issues
            true, // Force Info severity for all informational findings
            scanResults.startTime,
            finding.executionId,
            this.getDetectionStatus(
              endpoint.resource,
              endpoint.method,
              finding.testDetails.categoryId,
              finding.testDetails.categoryTestId,
              detectionStatusByKey
            )
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

    // Build endpoint summaries for the endpoints scanned table
    const endpointSummaryMap = new Map<string, EndpointSummary>();

    // Helper to get auth status from endpoint config
    const getAuthStatus = (method: string, path: string): "Yes" | "No" | "N/A" => {
      if (!endpointAuthMap || endpointAuthMap.size === 0) return "N/A";
      const key = `${method.toUpperCase()}:${path}`;
      const requiresAuth = endpointAuthMap.get(key);
      if (requiresAuth === true) return "Yes";
      if (requiresAuth === false) return "No";
      return "N/A";
    };

    // Add vulnerability endpoints
    for (const group of vulnerabilityGroups) {
      const key = group.endpoint;
      const existing = endpointSummaryMap.get(key);
      const method = group.vulnerabilities[0]?.method || "GET";
      const authStatus = getAuthStatus(method, key);
      if (existing) {
        existing.vulnCount += group.vulnerabilityCount;
        // Keep existing auth status if already set, otherwise update
        if (existing.authStatus === "N/A" && authStatus !== "N/A") {
          existing.authStatus = authStatus;
        }
      } else {
        endpointSummaryMap.set(key, {
          method,
          endpoint: key,
          vulnCount: group.vulnerabilityCount,
          infoCount: 0,
          authStatus,
        });
      }
    }

    // Add informational endpoints
    for (const group of informationalGroups) {
      const key = group.endpoint;
      const existing = endpointSummaryMap.get(key);
      const method = group.vulnerabilities[0]?.method || "GET";
      const authStatus = getAuthStatus(method, key);
      if (existing) {
        existing.infoCount += group.vulnerabilityCount;
        // Keep existing auth status if already set, otherwise update
        if (existing.authStatus === "N/A" && authStatus !== "N/A") {
          existing.authStatus = authStatus;
        }
      } else {
        endpointSummaryMap.set(key, {
          method,
          endpoint: key,
          vulnCount: 0,
          infoCount: group.vulnerabilityCount,
          authStatus,
        });
      }
    }

    // Convert to array and sort by vulnerability count (desc), then endpoint name
    const endpointSummaries: EndpointSummary[] = Array.from(endpointSummaryMap.values())
      .sort((a, b) => {
        if (b.vulnCount !== a.vulnCount) return b.vulnCount - a.vulnCount;
        if (b.infoCount !== a.infoCount) return b.infoCount - a.infoCount;
        return a.endpoint.localeCompare(b.endpoint);
      });

    return {
      scanId: scanResults.scanId,
      status: scanResults.status,
      appName,
      hostUrl,
      generatedAt: new Date(),
      summary: severityCounts,
      vulnerabilityGroups,
      informationalGroups,
      endpointGroups,
      endpointSummaries,
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

  private getDetectionStatus(
    resource: string,
    method: string,
    categoryId: string,
    testId: string,
    detectionStatusByKey: Map<string, string>
  ): string | undefined {
    const key = this.createLogKey(resource, method, categoryId, testId);
    const raw = detectionStatusByKey.get(key);
    if (!raw) return undefined;

    // Normalize to Title Case
    const normalized = raw.toLowerCase().replace(/_/g, " ").trim();
    return normalized
      .split(" ")
      .filter(Boolean)
      .map(w => w.charAt(0).toUpperCase() + w.slice(1))
      .join(" ");
  }

  private transformFinding(
    resource: string,
    method: string,
    finding: ScanResults["vulnerabilities"][0]["scanFindings"][0],
    logs?: DetectionLogs,
    forceInfoSeverity: boolean = false,
    scanStartTime?: string,
    detectionId?: string,
    status?: string
  ): VulnerabilityDetail {
    const cvssScore = forceInfoSeverity ? 0 : (finding.testResult?.cvssScore ?? 0);
    const severity = forceInfoSeverity
      ? "Info"
      : (finding.testResult?.cvssQualifier ?? getSeverityFromCvss(cvssScore));

    const failingLogs: FailingLog[] = [];

    if (logs?.logs?.testChain) {
      const evidenceCorrelationId = logs.logs.evidence;

      for (const entry of logs.logs.testChain) {
        if (entry.request.correlationId === evidenceCorrelationId) {
          failingLogs.push(this.transformLogEntry(
            entry,
            resource,
            finding.testDetails.categoryName,
            finding.testDetails.categoryTestName
          ));
        }
      }

      if (failingLogs.length === 0 && logs.logs.testChain.length > 0) {
        const lastEntry = logs.logs.testChain[logs.logs.testChain.length - 1];
        failingLogs.push(this.transformLogEntry(
          lastEntry,
          resource,
          finding.testDetails.categoryName,
          finding.testDetails.categoryTestName
        ));
      }
    }

    // Parse detection date with fallback to scan start time
    const rawDate = finding.detectionDate;
    let parsedDate: Date;
    if (rawDate && rawDate.trim() !== "") {
      parsedDate = new Date(rawDate);
    } else if (scanStartTime && scanStartTime.trim() !== "") {
      // Use scan start time as fallback
      parsedDate = new Date(scanStartTime);
    } else {
      // No date available - will show as N/A
      parsedDate = new Date(NaN);
    }

    // Extract auth info from the first failing log (if available)
    const authRole = failingLogs[0]?.authRole;
    const authMethod = failingLogs[0]?.authMethod;

    // Collect injected payloads from all failing logs
    const allPayloads: InjectedPayload[] = [];
    for (const log of failingLogs) {
      if (log.injectedPayloads) {
        allPayloads.push(...log.injectedPayloads);
      }
    }
    // Deduplicate by parameter name + payload value + location.
    // Location matters (e.g., same ID shown in both request body and response body).
    const uniquePayloads = allPayloads.filter((payload, index, self) =>
      index === self.findIndex(p =>
        p.parameterName === payload.parameterName &&
        p.payloadValue === payload.payloadValue &&
        p.location === payload.location
      )
    );

    return {
      testName: finding.testDetails.categoryTestName,
      category: finding.testDetails.categoryName,
      severity: severity as VulnerabilityDetail["severity"],
      cvssScore,
      description: finding.testResult?.detectionDescription ?? "",
      status,
      endpoint: resource,
      method,
      detectionDate: parsedDate,
      owaspTags: finding.testDetails.owaspTags,
      failingLogs,
      detectionId,
      authRole,
      authMethod,
      injectedPayloads: uniquePayloads.length > 0 ? uniquePayloads : undefined,
    };
  }

  private transformLogEntry(
    entry: TestChainEntry,
    endpoint: string,
    categoryName: string,
    testName: string
  ): FailingLog {
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

    const injectedPayloads = extractHighlightedParameters({
      categoryName,
      testName,
      requestUrl: entry.request.url,
      requestBody: entry.request.body,
      requestHeaders: entry.request.headers || {},
      responseBody: entry.response.content,
    });

    return {
      method: entry.request.method,
      endpoint,
      statusCode: entry.response.statusCode,
      requestContent: requestLines.join("\n"),
      responseContent: responseLines.join("\n"),
      authRole: entry.roleName,
      authMethod: entry.authName,
      injectedPayloads: injectedPayloads.length > 0 ? injectedPayloads : undefined,
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

  private humanizeTestName(testName: string, category: string): string {
    const base = testName || category || "";
    const withSpaces = base
      .replace(/[_-]+/g, " ")
      .replace(/([a-z])([A-Z])/g, "$1 $2")
      .trim();
    return withSpaces
      .split(/\s+/)
      .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
      .join(" ");
  }
}
