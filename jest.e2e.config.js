import { createDefaultPreset } from "ts-jest";

const tsJestTransformCfg = createDefaultPreset().transform;

/** @type {import("jest").Config} **/
export const preset = "ts-jest";
export const testEnvironment = "node";
export const testMatch = ["**/e2e/**/*.e2e.ts"];
export const testTimeout = 120000;
export const maxWorkers = 1;
export const setupFiles = ["<rootDir>/e2e/setupEnv.js"];