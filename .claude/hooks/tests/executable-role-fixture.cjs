'use strict';
// L1 argv-role tests deliberately isolate filesystem selection. This dependency
// models the former role-test context, not a native executable identity proof.
// Real selection and Hook DATA are covered by the R54 executable tests.
const path = require('node:path');
module.exports = {
  path, baseDir: '/DUMMY-role-fixture', process: { env: {} },
  executableIdentity: { invocationExecutableIdentity(invocation) {
    const word = invocation.nameWord?.text || '';
    return { kind: !word.includes('/') || ['/bin/' + invocation.name, '/usr/bin/' + invocation.name].includes(word)
      ? 'trusted-external' : 'unknown-search' };
  } },
};
