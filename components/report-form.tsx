"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { ReportConfig } from "@/lib/types";
import { fetchReportData, ApiSecError } from "@/lib/apisec-client";
import { FileDown, Loader2 } from "lucide-react";

interface GenerationState {
  isGenerating: boolean;
  progress: number;
  message: string;
  error: string | null;
}

export function ReportForm() {
  const [config, setConfig] = useState<ReportConfig>({
    token: "",
    tenant: "",
    appId: "",
    instanceId: "",
    scanId: "",
    includeHttpLogs: false,
    includeInformational: true,
  });

  const [state, setState] = useState<GenerationState>({
    isGenerating: false,
    progress: 0,
    message: "",
    error: null,
  });

  const updateConfig = <K extends keyof ReportConfig>(
    key: K,
    value: ReportConfig[K]
  ) => {
    setConfig((prev) => ({ ...prev, [key]: value }));
  };

  const resetForm = () => {
    setConfig({
      token: "",
      tenant: "",
      appId: "",
      instanceId: "",
      scanId: "",
      includeHttpLogs: false,
      includeInformational: true,
    });
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setState({ isGenerating: true, progress: 0, message: "Starting...", error: null });

    try {
      // Step 1: Fetch scan data and logs from API
      const { scanResults, detectionLogsMap, detectionToFindingMap } = await fetchReportData(
        config.token,
        config.tenant,
        config.appId,
        config.instanceId,
        config.scanId,
        config.includeHttpLogs,
        (message, percent) => {
          // Scale fetch progress to 0-60%
          setState((prev) => ({ ...prev, message, progress: Math.round(percent * 0.6) }));
        }
      );

      setState((prev) => ({ ...prev, message: "Generating PDF...", progress: 65 }));

      // Step 2: Generate PDF (dynamic import for client-side only)
      const { generatePDF } = await import("@/lib/pdf-generator");
      await generatePDF({
        scanResults,
        detectionLogsMap,
        detectionToFindingMap,
        includeInformational: config.includeInformational,
        onProgress: (message, percent) => {
          // Scale PDF progress to 65-100%
          const scaledPercent = 65 + Math.round(percent * 0.35);
          setState((prev) => ({ ...prev, message, progress: scaledPercent }));
        },
      });

      // Success - reset form and show completion message
      resetForm();
      setState({
        isGenerating: false,
        progress: 100,
        message: "Report downloaded!",
        error: null,
      });
    } catch (error) {
      console.error("Generation error:", error);
      let errorMessage = "An unexpected error occurred";

      if (error instanceof ApiSecError) {
        if (error.status === 401) {
          errorMessage = "Authentication failed. Please check your token.";
        } else if (error.status === 404) {
          errorMessage = "Resource not found. Please verify your IDs.";
        } else {
          errorMessage = error.message;
        }
      } else if (error instanceof Error) {
        errorMessage = error.message;
      }

      setState({
        isGenerating: false,
        progress: 0,
        message: "",
        error: errorMessage,
      });
    }
  };

  // Scan ID is only required when including informational findings
  const isValid =
    config.token.trim() !== "" &&
    config.appId.trim() !== "" &&
    config.instanceId.trim() !== "" &&
    (!config.includeInformational || config.scanId.trim() !== "");

  return (
    <Card className="w-full max-w-2xl mx-auto bg-zinc-800 text-zinc-100 border-zinc-700">
      <CardHeader>
        <CardTitle>APIsec Report Generator</CardTitle>
        <CardDescription className="text-zinc-400 border-b pb-1">
          Generate PDF vulnerability reports from APIsec scan data
        </CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Report Options - at the top */}
          <div className="space-y-4 rounded-lg">
            <Label className="text-sm font-medium">Report Options</Label>
            <div className="flex items-center space-x-2">
              <Checkbox
                id="includeInformational"
                checked={config.includeInformational}
                onCheckedChange={(checked) => {
                  const isChecked = checked === true;
                  updateConfig("includeInformational", isChecked);
                  // Clear scan ID when unchecking to ensure we use detections-only flow
                  if (!isChecked) {
                    updateConfig("scanId", "");
                  }
                }}
              />
              <Label htmlFor="includeInformational" className="text-sm font-normal">
                Include Informational Findings (requires Scan ID)
              </Label>
            </div>

            <div className="flex items-center space-x-2">
              <Checkbox
                id="includeHttpLogs"
                checked={config.includeHttpLogs}
                onCheckedChange={(checked) =>
                  updateConfig("includeHttpLogs", checked === true)
                }
              />
              <Label htmlFor="includeHttpLogs" className="text-sm font-normal">
                Include HTTP Logs (slower, vulnerabilities only)
              </Label>
            </div>
          </div>

          <div className="space-y-2">
            <Label htmlFor="token">Auth Token</Label>
            <Textarea
              id="token"
              placeholder="Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6Ikp..."
              value={config.token}
              onChange={(e) => updateConfig("token", e.target.value)}
              className="font-mono text-sm min-h-20"
            />
            <p className="text-xs text-zinc-400">
              Paste your Bearer token from the APIsec Network tab
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="tenant">Tenant</Label>
            <Input
              id="tenant"
              placeholder="cloud"
              value={config.tenant}
              onChange={(e) => updateConfig("tenant", e.target.value)}
            />
            <p className="text-xs text-zinc-400">
              Your APIsec tenant name (e.g., &apos;cloud&apos; for cloud.apisec.com)
            </p>
          </div>

          <div className="space-y-2">
            <Label htmlFor="appId">Application ID</Label>
            <Input
              id="appId"
              placeholder="0123abcd-45ef-67gh-89ij-klmnopqrstuv"
              value={config.appId}
              onChange={(e) => updateConfig("appId", e.target.value)}
              className="font-mono"
            />
          </div>

          <div className="space-y-2">
            <Label htmlFor="instanceId">Instance ID</Label>
            <Input
              id="instanceId"
              placeholder="0123abcd-45ef-67gh-89ij-klmnopqrstuv"
              value={config.instanceId}
              onChange={(e) => updateConfig("instanceId", e.target.value)}
              className="font-mono"
            />
          </div>

          {config.includeInformational && (
            <div className="space-y-2">
              <Label htmlFor="scanId">Scan ID</Label>
              <Input
                id="scanId"
                placeholder="0123abcd-45ef-67gh-89ij-klmnopqrstuv"
                value={config.scanId}
                onChange={(e) => updateConfig("scanId", e.target.value)}
                className="font-mono"
              />
              <p className="text-xs text-muted-foreground">
                Required for informational findings
              </p>
            </div>
          )}

          {state.error && (
            <div className="p-3 text-sm text-red-600 bg-red-50 border border-red-200 rounded-md">
              {state.error}
            </div>
          )}

          {state.isGenerating && (
            <div className="space-y-2">
              <div className="flex justify-between text-sm">
                <span>{state.message}</span>
                <span>{state.progress}%</span>
              </div>
              <Progress value={state.progress} />
            </div>
          )}

          <Button
            type="submit"
            disabled={!isValid || state.isGenerating}
            className="w-full flex items-center justify-center cursor-pointer bg-zinc-300 text-zinc-950 text-lg hover:bg-zinc-500"
          >
            {state.isGenerating ? (
              <>
                <Loader2 size={24} className="animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <FileDown size={24} />
                Generate Report
              </>
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  );
}
