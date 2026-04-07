const fs = require('fs');
const path = require('path');

const VAULT_DIR = "/Users/theosera/Library/Mobile Documents/iCloud~md~obsidian/Documents/iCloud Vault 2026";

const EXCLUDED_DIRS = [
    '__skills', '_assets', '_資料系', 'Templates', 'Travel', 'ライフスタイル', '自給自足'
];

function isExcludedPath(filepath) {
    const relativePath = path.relative(VAULT_DIR, filepath);
    const parts = relativePath.split(path.sep);
    for (const part of parts) {
        // Explicitly excluded names
        if (EXCLUDED_DIRS.includes(part)) return true;
        // Dot folders/files (.*) excluding actual '.' and '..'
        if (part.startsWith('.') && part !== '.' && part !== '..') return true;
    }
    return false;
}

function getFilesRecursively(dir, fileList = []) {
    const files = fs.readdirSync(dir);
    for (const file of files) {
        const filepath = path.join(dir, file);
        if (isExcludedPath(filepath)) continue;

        if (fs.statSync(filepath).isDirectory()) {
            getFilesRecursively(filepath, fileList);
        } else if (file.endsWith('.md')) {
            fileList.push(filepath);
        }
    }
    return fileList;
}

function extractDate(filepath) {
    const content = fs.readFileSync(filepath, 'utf8');
    const lines = content.split('\n');
    
    let fmDate = null;
    let inFrontmatter = false;
    for (let i = 0; i < Math.min(lines.length, 50); i++) {
        const line = lines[i];
        if (i === 0 && line.trim() === '---') {
            inFrontmatter = true;
            continue;
        }
        if (inFrontmatter && line.trim() === '---') {
            break;
        }
        if (inFrontmatter) {
            const createdMatch = line.match(/^(?:created|date|published):\s*"?(\d{4})-(\d{2})-(\d{2})"?/);
            if (createdMatch) {
                fmDate = `${createdMatch[2]}-${createdMatch[3]}`;
                break;
            }
        }
    }
    
    if (fmDate) return fmDate;
    
    const stat = fs.statSync(filepath);
    const birthtime = stat.birthtime;
    const m = String(birthtime.getMonth() + 1).padStart(2, '0');
    const d = String(birthtime.getDate()).padStart(2, '0');
    return `${m}-${d}`;
}

function shouldRename(basename) {
    // Avoid files starting with < or other special rule files
    if (basename.startsWith('<')) return false;
    
    // YYYY-MM-DD pattern (already a daily note)
    if (/^\d{4}-\d{2}-\d{2}/.test(basename)) return false;
    
    // Already has _MM-DD
    if (/_\d{2}-\d{2}$/.test(basename)) return false;
    
    // Specific exclusions
    if (['Welcome', 'Obsidianプラグイン'].includes(basename)) return false;

    return true;
}

console.log('--- Starting Rename Optimization ---');
const mdFiles = getFilesRecursively(VAULT_DIR);
const renameOperations = [];
const renameMap = new Map();

for (const filepath of mdFiles) {
    const basename = path.basename(filepath, '.md');
    
    if (!shouldRename(basename)) continue;
    
    const dateStr = extractDate(filepath);
    if (!dateStr || Number.isNaN(parseInt(dateStr.split('-')[0]))) continue;
    
    if (basename.endsWith(`_${dateStr}`)) continue;
    
    const newBasename = `${basename}_${dateStr}`;
    const newFilepath = path.join(path.dirname(filepath), `${newBasename}.md`);
    
    renameOperations.push({ oldFilepath: filepath, newFilepath, oldBasename: basename, newBasename });
    renameMap.set(basename, newBasename);
}

console.log(`[Phase 1] Found ${renameOperations.length} files to rename.`);

// Pass 2: Update Links in ALL vault markdown files (excluding dot folders or explicitly excluded)
let filesUpdated = 0;
const filesToUpdate = getFilesRecursively(VAULT_DIR);

console.log(`[Phase 2] Analyzing ${filesToUpdate.length} markdown files for link updates...`);

for (const filepath of filesToUpdate) {
    let content = fs.readFileSync(filepath, 'utf8');
    let hasChanges = false;
    
    const updatedContent = content.replace(/\[\[(.*?)\]\]/g, (match, innerLink) => {
        let splitPipe = innerLink.split('|');
        let linkAndHash = splitPipe[0]; 
        let alias = splitPipe.length > 1 ? splitPipe.slice(1).join('|') : null;
        
        let splitHash = linkAndHash.split('#');
        let pathPart = splitHash[0]; 
        let hashAndRest = splitHash.length > 1 ? splitHash.slice(1).join('#') : null;
        
        let linkBasename = path.basename(pathPart);
        
        if (renameMap.has(linkBasename)) {
            const newBasename = renameMap.get(linkBasename);
            
            let dirname = path.dirname(pathPart);
            let newPathPart = dirname === '.' ? newBasename : `${dirname}/${newBasename}`;
            
            let newInnerLink = newPathPart;
            if (hashAndRest !== null) {
                newInnerLink += '#' + hashAndRest;
            }
            if (alias !== null) {
                newInnerLink += '|' + alias;
            }
            
            hasChanges = true;
            return `[[${newInnerLink}]]`;
        }
        return match;
    });
    
    if (hasChanges) {
        fs.writeFileSync(filepath, updatedContent, 'utf8');
        filesUpdated++;
    }
}

console.log(`[Phase 2] Updated internal links in ${filesUpdated} files.`);

// Pass 3: Execute Renames
console.log(`[Phase 3] Executing file renames...`);
let filesRenamed = 0;
for (const op of renameOperations) {
    fs.renameSync(op.oldFilepath, op.newFilepath);
    filesRenamed++;
}

console.log(`[Finish] Successfully renamed ${filesRenamed} files.`);
