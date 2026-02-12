import rawBranding from "../branding.config.json";

export interface BrandingConfig {
  appName: string;
  shortName: string;
  logoPath: string;
  supportUrl: string;
  footerGithubUrl: string | null;
  footerText: string;
}

const DEFAULT_BRANDING: BrandingConfig = {
  appName: "ZT-IX Internet Exchange",
  shortName: "ZT-IX",
  logoPath: "/branding/logo.svg",
  supportUrl: "mailto:support@example.com",
  footerGithubUrl: null,
  footerText: "Network peering access management",
};

function readNonEmptyString(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }

  const trimmed = value.trim();
  return trimmed ? trimmed : undefined;
}

function normalizeBranding(value: unknown): BrandingConfig {
  const source = value && typeof value === "object" ? (value as Record<string, unknown>) : {};

  return {
    appName: readNonEmptyString(source.appName) ?? DEFAULT_BRANDING.appName,
    shortName: readNonEmptyString(source.shortName) ?? DEFAULT_BRANDING.shortName,
    logoPath: readNonEmptyString(source.logoPath) ?? DEFAULT_BRANDING.logoPath,
    supportUrl: readNonEmptyString(source.supportUrl) ?? DEFAULT_BRANDING.supportUrl,
    footerGithubUrl: readNonEmptyString(source.footerGithubUrl) ?? DEFAULT_BRANDING.footerGithubUrl,
    footerText: readNonEmptyString(source.footerText) ?? DEFAULT_BRANDING.footerText,
  };
}

export const branding = normalizeBranding(rawBranding);
