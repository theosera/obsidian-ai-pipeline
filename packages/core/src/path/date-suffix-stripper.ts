export function stripDateSuffix(folderName: string): string {
  const trimmed = folderName.trim();
  return trimmed
    .replace(/[\s/_-]+\d{4}-Q[1-4]$/i, "")
    .replace(/[\s/_-]+\d{4}-(0[1-9]|1[0-2])$/i, "")
    .trim();
}
