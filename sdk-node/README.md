# Vaultak Node.js SDK

Runtime security for autonomous AI agents.

## Install

```bash
npm install vaultak
```

## Usage

```javascript
const { Vaultak } = require('vaultak');

const vt = new Vaultak({ apiKey: 'vtk_your_key_here' });
const monitor = vt.monitor('my-agent');

// All fs.writeFile, https.request calls are now auto-monitored
myAgent.run();

monitor.stop();
```

## Thresholds

```javascript
const vt = new Vaultak({
  apiKey: 'vtk_your_key_here',
  alertThreshold: 30,
  pauseThreshold: 60,
  rollbackThreshold: 85,
  blockedResources: ['*.env', 'prod.*'],
});
```
