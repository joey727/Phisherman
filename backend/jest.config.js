import { createDefaultPreset } from "ts-jest";

const tsJestTransformCfg = createDefaultPreset().transform;

/** @type {import("jest").Config} **/
export const preset = "ts-jest";
export const testEnvironment = "node";
export const testMatch = ["**/__tests__/**/*.test.ts"];
export const clearMocks = true;
