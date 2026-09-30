/**
 * websocket.js - scan progress updates.
 *
 * The platform primarily uses polling (GET /api/scans/{id}/status/) for
 * scan progress, per the spec's guidance to avoid unnecessary WebSocket
 * complexity. This module wraps that polling behind a small interface so
 * a real WebSocket/Channels transport can be swapped in later (e.g. by
 * replacing PollingScanChannel with a WebSocket-backed implementation)
 * without changing call sites in scanner.js.
 */
class PollingScanChannel {
  constructor(scanId, { onProgress, onComplete, onError, intervalMs = 2000 }) {
    this.scanId = scanId;
    this.onProgress = onProgress;
    this.onComplete = onComplete;
    this.onError = onError;
    this.intervalMs = intervalMs;
    this._timer = null;
  }

  start() {
    this._poll();
  }

  stop() {
    if (this._timer) clearTimeout(this._timer);
  }

  async _poll() {
    try {
      const status = await Api.get(`/api/scans/${this.scanId}/status/`);
      this.onProgress && this.onProgress(status);
      if (['completed', 'failed', 'cancelled'].includes(status.status)) {
        this.onComplete && this.onComplete(status);
        return;
      }
    } catch (e) {
      this.onError && this.onError(e);
      return;
    }
    this._timer = setTimeout(() => this._poll(), this.intervalMs);
  }
}

function openScanChannel(scanId, handlers) {
  const channel = new PollingScanChannel(scanId, handlers);
  channel.start();
  return channel;
}
