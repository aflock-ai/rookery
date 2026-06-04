// Shape of a single _generated/catalog/<name>.json entry, produced by
// scripts/gen-catalog.mjs from the CI/lock binary's introspection surface.

export interface CatalogTrigger {
  gate: string; // pre | post
  kind: string; // argv_prefix | env_set | file_exists | probe | exec_observed | product_glob | ...
  value: string;
}

export interface CatalogUpstream {
  name?: string;
  source?: string;
  license?: string;
  vendor?: string;
  format_only?: boolean;
}

export interface CatalogEntry {
  name: string;
  source: 'attestor-backed' | 'catalog-only';
  description: string;
  categories: string[];
  primaryCategory: string | null;
  upstream: CatalogUpstream | null;
  gates: string[];
  recommendedTrace: 'off' | 'light' | 'full' | string;
  triggers: CatalogTrigger[];
  emitsFormats: string[];
  warnings: unknown[];
  llmHints: Record<string, string>;
  predicateType: string | null;
  runType: string | null;
  defaultOn: boolean;
  runExample: string | null;
  detectionCommand: string | null;
  positiveSetup: string | null;
  positiveAssert: string | null;
  negativeSetup: string | null;
  negativeAssert: string | null;
}
