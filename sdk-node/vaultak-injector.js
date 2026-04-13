'use strict';
// This file is auto-loaded by Node.js via NODE_OPTIONS=--require
// It instruments any Node.js process with Vaultak monitoring
const { Vaultak } = require(require('path').join(__dirname, 'index.js'));

const apiKey = process.env.VAULTAK_API_KEY || '';
const agentId = process.env.VAULTAK_AGENT_ID || process.argv[1] || 'node-agent';

if (apiKey) {
  const vt = new Vaultak({
    apiKey,
    agentId,
    alertThreshold: parseInt(process.env.VAULTAK_ALERT_THRESHOLD || '30'),
    pauseThreshold: parseInt(process.env.VAULTAK_PAUSE_THRESHOLD || '60'),
    rollbackThreshold: parseInt(process.env.VAULTAK_ROLLBACK_THRESHOLD || '85'),
    blockedResources: (process.env.VAULTAK_BLOCKED || '').split(',').filter(Boolean),
  });
  vt.monitor(agentId);
  console.log('[Vaultak] Node.js agent monitoring active: ' + agentId);
}
