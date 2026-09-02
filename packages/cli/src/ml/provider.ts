/**
 * Optional ML inference adapter. Default is disabled — PackageGate must work
 * without Python or model weights.
 *
 * The local provider speaks JSON over stdin/stdout with a trusted PackageGate
 * Python worker. Investigated source is never executed.
 */

import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import type { MlAssessment } from "@packagegate/shared";
import { disabledMlAssessment } from "@packagegate/shared";
import type { PackageGateMlRecordV1 } from "./export.js";

export interface MlProvider {
  assess(input: PackageGateMlRecordV1): Promise<MlAssessment>;
}

export class DisabledMlProvider implements MlProvider {
  assess(_input: PackageGateMlRecordV1): Promise<MlAssessment> {
    return Promise.resolve(disabledMlAssessment());
  }
}

export interface LocalMlProviderOptions {
  readonly pythonBin?: string;
  readonly module?: string;
  readonly timeoutMs?: number;
  /** Validated REVIEW threshold for ALLOW→REVIEW escalation (not BLOCK). */
  readonly reviewThreshold?: number;
}

/**
 * Local Python inference worker. Failures return status ERROR without aborting
 * the deterministic investigation.
 */
export class LocalMlProvider implements MlProvider {
  private readonly pythonBin: string;
  private readonly module: string;
  private readonly timeoutMs: number;
  private readonly reviewThreshold: number;

  constructor(options: LocalMlProviderOptions = {}) {
    const uvPython = join(
      dirname(fileURLToPath(import.meta.url)),
      "../../../../ml/.venv/bin/python",
    );
    this.pythonBin =
      options.pythonBin ??
      process.env.PACKAGEGATE_ML_PYTHON ??
      (existsSync(uvPython) ? uvPython : "python3");
    this.module =
      options.module ??
      process.env.PACKAGEGATE_ML_MODULE ??
      "packagegate_ml.inference.worker";
    this.timeoutMs = options.timeoutMs ?? 60_000;
    this.reviewThreshold = options.reviewThreshold ?? 0.85;
  }

  async assess(input: PackageGateMlRecordV1): Promise<MlAssessment> {
    try {
      const raw = await this.invoke(input);
      const parsed = JSON.parse(raw) as MlAssessment;
      if (parsed.status !== "AVAILABLE") return parsed;
      const probability =
        parsed.calibratedProbability ?? parsed.maliciousProbability ?? 0;
      return {
        ...parsed,
        supportsReviewEscalation: probability >= this.reviewThreshold,
      };
    } catch (error) {
      return {
        status: "ERROR",
        predictedBehaviours: [],
        topSlices: [],
        supportsReviewEscalation: false,
        errorMessage: error instanceof Error ? error.message : "ML inference failed",
      };
    }
  }

  private invoke(input: PackageGateMlRecordV1): Promise<string> {
    return new Promise((resolve, reject) => {
      const child = spawn(this.pythonBin, ["-m", this.module], {
        stdio: ["pipe", "pipe", "pipe"],
        env: { ...process.env },
      });
      let stdout = "";
      let stderr = "";
      const timer = setTimeout(() => {
        child.kill("SIGKILL");
        reject(new Error(`ML worker timed out after ${String(this.timeoutMs)}ms`));
      }, this.timeoutMs);

      child.stdout.on("data", (chunk: Buffer) => {
        stdout += chunk.toString("utf8");
      });
      child.stderr.on("data", (chunk: Buffer) => {
        stderr += chunk.toString("utf8");
      });
      child.on("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      child.on("close", (code) => {
        clearTimeout(timer);
        if (code !== 0) {
          reject(
            new Error(
              `ML worker exited ${String(code)}${stderr ? `: ${stderr.trim()}` : ""}`,
            ),
          );
          return;
        }
        resolve(stdout);
      });
      child.stdin.write(JSON.stringify(input));
      child.stdin.end();
    });
  }
}

export function createMlProviderFromEnv(): MlProvider {
  const mode = (process.env.PACKAGEGATE_ML ?? "disabled").toLowerCase();
  if (mode === "local" || mode === "1" || mode === "true") {
    return new LocalMlProvider();
  }
  return new DisabledMlProvider();
}

export type { PackageGateMlRecordV1 };
