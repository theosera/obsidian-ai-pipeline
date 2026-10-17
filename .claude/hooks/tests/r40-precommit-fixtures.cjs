'use strict';

// Owned DUMMY fixtures for Hook-input DATA. No proposed command is executed.
// Configure helper selection only after staging ordinary files. The helpers are
// inert local DUMMY programs, never real secret readers or network programs.
const fs = require('node:fs');
const path = require('node:path');

function setupFixtures({ root, mk, git }) {
  const helper = path.join(root, 'r40-dummy-helper.sh');
  fs.writeFileSync(helper, '#!/bin/sh\nprintf DUMMY\n', { mode: 0o700 });
  const dirs = {};
  const definitions = [
    ['r40pcdriver', 'diff.r40dummy.command'],
    ['r40pctextconv', 'diff.r40dummy.textconv'],
    ['r40pcmonitor', 'core.fsmonitor'],
    ['r40pcpager', 'core.pager'],
    ['r40pcpagerstatus', 'pager.status'],
    ['r40pcpagerquery', 'pager.commit'],
    ['r40pcpagergrep', 'pager.grep'],
    ['r40pcforced', 'core.pager'],
    ['r40pcdisabled', 'core.fsmonitor'],
  ];
  for (const [key, config] of definitions) {
    const dir = mk(key, { 'a.txt': 'DUMMY staged\n', '--no-textconv': 'DUMMY ordinary file\n',
      '.gitattributes': '*.txt diff=r40dummy\n' });
    git(dir, 'add', '--', 'a.txt', '--no-textconv');
    git(dir, 'commit', '-q', '-m', 'DUMMY R40 base');
    fs.writeFileSync(path.join(dir, 'a.txt'), 'DUMMY staged change\n');
    git(dir, 'add', '--', 'a.txt');
    fs.writeFileSync(path.join(dir, 'a.txt'), 'DUMMY working copy\n');
    if (key !== 'r40pcpager') git(dir, 'config', 'core.pager', 'cat');
    git(dir, 'config', config, key === 'r40pcdisabled' ? 'false' : helper);
    if (key === 'r40pcforced') {
      git(dir, 'config', 'pager.diff', 'cat');
      git(dir, 'config', 'pager.commit', 'cat');
    }
    dirs[key] = dir;
  }
  // A config command sees an onbranch include after setup, whereas Trace2
  // reads very early config before repository setup. Only owned DUMMY paths
  // enter the explicit fixture environment selector; no proposed shell runs.
  const included = path.join(root, 'r40-trace-disabled.config');
  const conditional = path.join(root, 'r40-trace-conditional.config');
  fs.writeFileSync(included, '[trace2]\n eventTarget = 0\n');
  fs.writeFileSync(conditional, '[trace2]\n eventTarget = ' + path.join(root, 'r40-dummy-trace.json') +
    '\n[includeIf "onbranch:*"]\n path = ' + included + '\n');
  return { dirs, environmentSets: { r40earlytrace: { GIT_CONFIG_GLOBAL: conditional } } };
}

module.exports = { setupFixtures };
