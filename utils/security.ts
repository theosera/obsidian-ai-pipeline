import path from 'path';

const VAULT_ROOT = '/Users/theosera/Library/Mobile Documents/iCloud~md~obsidian/Documents/iCloud Vault 2026';

/**
 * Resolves a relative folder path against VAULT_ROOT and ensures
 * the result stays strictly within VAULT_ROOT.
 * Throws if the resolved path escapes VAULT_ROOT (path traversal).
 */
export function safePath(relativePath: string): string {
  // Normalize to remove .., ., and redundant separators
  const resolved = path.resolve(VAULT_ROOT, relativePath);

  // Ensure the resolved path is within VAULT_ROOT
  if (!resolved.startsWith(VAULT_ROOT + path.sep) && resolved !== VAULT_ROOT) {
    throw new Error(
      `[Security] Path traversal detected: "${relativePath}" resolves to "${resolved}" which is outside VAULT_ROOT`
    );
  }

  return resolved;
}

/**
 * Validates that a relative path intended as a vault folder doesn't
 * contain dangerous components. Returns the sanitized relative path.
 */
export function sanitizeRelativePath(relativePath: string): string {
  // Reject null bytes
  if (relativePath.includes('\0')) {
    throw new Error('[Security] Null byte in path');
  }

  // Normalize the path and resolve it to verify safety
  const resolved = path.resolve(VAULT_ROOT, relativePath);
  if (!resolved.startsWith(VAULT_ROOT + path.sep) && resolved !== VAULT_ROOT) {
    throw new Error(
      `[Security] Path traversal detected in relative path: "${relativePath}"`
    );
  }

  // Return the relative portion from VAULT_ROOT
  return path.relative(VAULT_ROOT, resolved);
}

/**
 * Sanitizes content that will be embedded into an LLM prompt
 * to mitigate indirect prompt injection.
 *
 * Strips common injection patterns while preserving legitimate article text.
 */
export function sanitizeForPrompt(content: string, maxLength: number): string {
  let sanitized = content;

  // Remove common prompt injection delimiters/patterns
  // These patterns try to close the current context and inject new instructions
  sanitized = sanitized
    .replace(/---\s*(SYSTEM|INSTRUCTIONS?|RULES?|PROMPT|CONTEXT|END)\s*---/gi, '[REMOVED]')
    .replace(/```\s*(system|instruction|prompt|override)/gi, '```$1_REMOVED')
    .replace(/<\/?(?:system|instruction|prompt|override|admin|role|context)>/gi, '[TAG_REMOVED]');

  // Truncate to max length
  return sanitized.substring(0, maxLength);
}

/**
 * Validates that a date string is a legitimate YYYY-MM-DD date.
 * Returns the date string if valid, undefined otherwise.
 */
export function validateDateString(dateStr: string | undefined | null): string | undefined {
  if (!dateStr) return undefined;

  const match = dateStr.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (!match) return undefined;

  const year = parseInt(match[1], 10);
  const month = parseInt(match[2], 10);
  const day = parseInt(match[3], 10);

  // Basic range checks
  if (year < 2000 || year > 2100) return undefined;
  if (month < 1 || month > 12) return undefined;
  if (day < 1 || day > 31) return undefined;

  // Verify it's a real date
  const d = new Date(year, month - 1, day);
  if (d.getFullYear() !== year || d.getMonth() !== month - 1 || d.getDate() !== day) {
    return undefined;
  }

  return dateStr;
}

export { VAULT_ROOT };
