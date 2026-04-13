'use strict';

const https = require('https');
const http = require('http');
const fs = require('fs');
const { execSync, spawn, exec } = require('child_process');
const path = require('path');

const DEFAULT_API_ENDPOINT = 'https://vaultak.com';
const DEFAULT_ALERT_THRESHOLD = 30;
const DEFAULT_PAUSE_THRESHOLD = 60;
const DEFAULT_ROLLBACK_THRESHOLD = 85;

class Vaultak {
  constructor(options = {}) {
    this.apiKey = options.apiKey || process.env.VAULTAK_API_KEY || '';
    this.agentId = options.agentId || 'default';
    this.alertThreshold = options.alertThreshold || DEFAULT_ALERT_THRESHOLD;
    this.pauseThreshold = options.pauseThreshold || DEFAULT_PAUSE_THRESHOLD;
    this.rollbackThreshold = options.rollbackThreshold || DEFAULT_ROLLBACK_THRESHOLD;
    this.blockedResources = options.blockedResources || [];
    this.allowedResources = options.allowedResources || null;
    this.maxActionsPerMinute = options.maxActionsPerMinute || 60;
    this.apiEndpoint = options.apiEndpoint || DEFAULT_API_ENDPOINT;
    this._actionTimes = [];
    this._fileSnapshots = {};
    this._paused = false;
    this._sessionId = require('crypto').randomUUID();
  }

  // ── Auto-instrumentation ─────────────────────────────────────────────────

  monitor(agentId) {
    const aid = agentId || this.agentId;
    const self = this;
    self._install(aid);
    return {
      agentId: aid,
      approve: () => self._paused = false,
      stop: () => self._uninstall(),
    };
  }

  _install(agentId) {
    const self = this;
    this._agentId = agentId;

    // Patch fs.writeFile
    const origWriteFile = fs.writeFile.bind(fs);
    const origWriteFileSync = fs.writeFileSync.bind(fs);
    const origUnlink = fs.unlink.bind(fs);
    const origUnlinkSync = fs.unlinkSync.bind(fs);

    fs.writeFile = function(filePath, data, options, callback) {
      if (typeof options === 'function') { callback = options; options = {}; }
      self._snapshotFile(filePath);
      const decision = self._intercept('file_write', filePath, { async: true });
      if (decision === 'BLOCK') {
        const err = new Error('Vaultak: file write blocked by policy: ' + filePath);
        if (callback) callback(err);
        return;
      }
      return origWriteFile(filePath, data, options, callback);
    };

    fs.writeFileSync = function(filePath, data, options) {
      self._snapshotFile(filePath);
      const decision = self._intercept('file_write', filePath, { sync: true });
      if (decision === 'BLOCK') {
        throw new Error('Vaultak: file write blocked by policy: ' + filePath);
      }
      return origWriteFileSync(filePath, data, options);
    };

    fs.unlink = function(filePath, callback) {
      const decision = self._intercept('delete', filePath, { async: true });
      if (decision === 'BLOCK') {
        const err = new Error('Vaultak: file delete blocked: ' + filePath);
        if (callback) callback(err);
        return;
      }
      return origUnlink(filePath, callback);
    };

    fs.unlinkSync = function(filePath) {
      const decision = self._intercept('delete', filePath, { sync: true });
      if (decision === 'BLOCK') {
        throw new Error('Vaultak: file delete blocked: ' + filePath);
      }
      return origUnlinkSync(filePath);
    };

    // Patch https.request and http.request
    const origHttpsRequest = https.request.bind(https);
    const origHttpRequest = http.request.bind(http);

    function patchRequest(origRequest, proto) {
      return function(options, callback) {
        const url = typeof options === 'string' ? options :
          (options.href || (options.hostname || options.host || '') + (options.path || ''));
        if (!url.includes('vaultak.com')) {
          const decision = self._intercept('api_call', url, { method: options.method || 'GET' });
          if (decision === 'BLOCK') {
            const err = new Error('Vaultak: HTTP request blocked: ' + url);
            if (callback) callback({ statusCode: 403, error: err });
            throw err;
          }
        }
        return origRequest(options, callback);
      };
    }

    https.request = patchRequest(origHttpsRequest, 'https');
    http.request = patchRequest(origHttpRequest, 'http');

    // Store originals for uninstall
    this._originals = {
      writeFile: origWriteFile,
      writeFileSync: origWriteFileSync,
      unlink: origUnlink,
      unlinkSync: origUnlinkSync,
      httpsRequest: origHttpsRequest,
      httpRequest: origHttpRequest,
    };
  }

  _uninstall() {
    if (!this._originals) return;
    fs.writeFile = this._originals.writeFile;
    fs.writeFileSync = this._originals.writeFileSync;
    fs.unlink = this._originals.unlink;
    fs.unlinkSync = this._originals.unlinkSync;
    https.request = this._originals.httpsRequest;
    http.request = this._originals.httpRequest;
  }

  // ── Core interception logic ──────────────────────────────────────────────

  _intercept(actionType, resource, payload) {
    if (this._paused) return 'BLOCK';

    // Rate limiting
    const now = Date.now();
    this._actionTimes = this._actionTimes.filter(t => now - t < 60000);
    if (this._actionTimes.length >= this.maxActionsPerMinute) {
      this._sendAction(actionType, resource, payload, 90, 'BLOCK');
      return 'BLOCK';
    }

    // Policy checks
    for (const pattern of this.blockedResources) {
      if (this._matchPattern(resource, pattern)) {
        this._sendAction(actionType, resource, payload, 95, 'BLOCK');
        return 'BLOCK';
      }
    }

    if (this.allowedResources) {
      const allowed = this.allowedResources.some(p => this._matchPattern(resource, p));
      if (!allowed) {
        this._sendAction(actionType, resource, payload, 80, 'BLOCK');
        return 'BLOCK';
      }
    }

    // Risk scoring
    const score = this._computeScore(actionType, resource);

    if (score >= this.rollbackThreshold) {
      this._sendAction(actionType, resource, payload, score, 'ROLLBACK');
      this._executeRollback();
      this._paused = true;
      throw new Error('Vaultak: Risk score ' + score + ' exceeded rollback threshold. State restored.');
    } else if (score >= this.pauseThreshold) {
      this._sendAction(actionType, resource, payload, score, 'PAUSE');
      this._paused = true;
      throw new Error('Vaultak: Risk score ' + score + ' exceeded pause threshold. Awaiting review.');
    } else if (score >= this.alertThreshold) {
      this._sendAction(actionType, resource, payload, score, 'ALERT');
    } else {
      this._sendAction(actionType, resource, payload, score, 'ALLOW');
    }

    this._actionTimes.push(now);
    return 'ALLOW';
  }

  _computeScore(actionType, resource) {
    const actionScores = {
      file_write: 40, file_read: 10, delete: 75,
      api_call: 35, execute: 60, database_write: 50,
      database_read: 15, custom: 30,
    };
    let score = actionScores[actionType] || 30;
    const sensitive = ['prod', 'production', 'secret', '.env', 'password', 'key', 'token', 'credential'];
    if (sensitive.some(p => resource.toLowerCase().includes(p))) score += 30;
    return Math.min(score, 100);
  }

  _matchPattern(resource, pattern) {
    if (pattern.includes('*')) {
      const re = new RegExp('^' + pattern.replace(/\./g, '\\.').replace(/\*/g, '.*') + '$');
      return re.test(resource) || resource.includes(pattern.replace(/\*/g, ''));
    }
    return resource.includes(pattern);
  }

  // ── Rollback ─────────────────────────────────────────────────────────────

  _snapshotFile(filePath) {
    try {
      if (fs.existsSync(filePath)) {
        this._fileSnapshots[filePath] = fs.readFileSync(filePath);
      } else {
        this._fileSnapshots[filePath] = null; // file did not exist
      }
    } catch (e) {}
  }

  _executeRollback() {
    // Use stored originals to bypass interceptor during rollback
    const origWrite = this._originals ? this._originals.writeFileSync : fs.writeFileSync.bind(fs);
    const origUnlink = this._originals ? this._originals.unlinkSync : fs.unlinkSync.bind(fs);
    for (const [filePath, snapshot] of Object.entries(this._fileSnapshots)) {
      try {
        if (snapshot === null) {
          if (fs.existsSync(filePath)) origUnlink(filePath);
        } else {
          origWrite(filePath, snapshot);
        }
        console.log('[Vaultak] Rolled back: ' + filePath);
      } catch (e) {
        console.error('[Vaultak] Rollback failed for ' + filePath + ': ' + e.message);
      }
    }
    this._fileSnapshots = {};
  }

  // ── Backend communication ─────────────────────────────────────────────────

  _sendAction(actionType, resource, payload, score, decision) {
    const data = JSON.stringify({
      agent_id: this._agentId || this.agentId,
      session_id: this._sessionId,
      action_type: actionType,
      resource: resource,
      payload: payload || {},
      risk_score: score / 100,
      decision: decision,
      timestamp: new Date().toISOString(),
      source: 'node-sdk',
    });

    try {
      const url = new URL(this.apiEndpoint + '/api/actions');
      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
          'Content-Length': Buffer.byteLength(data),
        },
      };
      const req = (url.protocol === 'https:' ? https : http).request(options);
      req.on('error', () => {});
      req.write(data);
      req.end();
    } catch (e) {}
  }

  async check(actionType, resource) {
    return new Promise((resolve) => {
      const data = JSON.stringify({
        agent_id: this.agentId,
        action_type: actionType,
        resource: resource,
      });
      const url = new URL(this.apiEndpoint + '/api/check');
      const options = {
        hostname: url.hostname,
        port: url.port || 443,
        path: url.pathname,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
          'Content-Length': Buffer.byteLength(data),
        },
      };
      const req = (url.protocol === 'https:' ? https : http).request(options, (res) => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            const result = JSON.parse(body);
            resolve({
              allowed: !['BLOCK', 'ROLLBACK'].includes(result.decision),
              score: result.risk_score || 0,
              decision: result.decision || 'ALLOW',
            });
          } catch (e) {
            resolve({ allowed: true, score: 0, decision: 'ALLOW' });
          }
        });
      });
      req.on('error', () => resolve({ allowed: true, score: 0, decision: 'ALLOW' }));
      req.write(data);
      req.end();
    });
  }

  logAction(actionType, resource, payload) {
    this._sendAction(actionType, resource, payload || {}, 0, 'ALLOW');
  }
}

module.exports = { Vaultak };
