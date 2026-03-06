// -- Direct HTTP API (no channel, no build step) --

let bookmarks = [];
let s3Config = null;
let activeTag = null;

async function apiAction(json) {
  const res = await fetch('/apps/warc/api/action', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(json),
  });
  if (!res.ok) throw new Error(`Action failed: ${res.status}`);
  return res.json();
}

async function loadBookmarks() {
  const res = await fetch('/apps/warc/api/bookmarks');
  if (!res.ok) throw new Error(`Load failed: ${res.status}`);
  const data = await res.json();
  bookmarks = data.bookmarks || [];
  renderTagFilter();
  renderBookmarks();
}

async function fetchUrls(urls) {
  const res = await fetch('/apps/warc/api/fetch', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(urls),
  });
  if (!res.ok) throw new Error(`Fetch proxy failed: ${res.status}`);
  return res.json();
}

// -- WARC Writer (in-browser, using CompressionStream for gzip) --

class WARCWriter {
  constructor() { this.records = []; }

  addWarcinfo() {
    this._add('warcinfo', null, 'application/warc-fields',
      new TextEncoder().encode('software: warc/1.0 (browser)\r\nformat: WARC/1.1\r\n'));
  }

  addExchange(url, status, statusText, headers, bodyBytes) {
    const ts = new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
    const reqId = `<urn:uuid:${crypto.randomUUID()}>`;
    const respId = `<urn:uuid:${crypto.randomUUID()}>`;

    // Request record
    let parsedUrl;
    try { parsedUrl = new URL(url); } catch { parsedUrl = { pathname: '/', search: '', host: url }; }
    const reqLine = `GET ${parsedUrl.pathname}${parsedUrl.search || ''} HTTP/1.1\r\nHost: ${parsedUrl.host}\r\n\r\n`;
    this._add('request', url, 'application/http; msgtype=request',
      new TextEncoder().encode(reqLine),
      { 'WARC-Record-ID': reqId, 'WARC-Date': ts });

    // Response record
    let respHead = `HTTP/1.1 ${status} ${statusText || 'OK'}\r\n`;
    for (const [k, v] of headers) {
      const kl = k.toLowerCase();
      if (kl === 'content-encoding' || kl === 'transfer-encoding') continue;
      if (kl === 'content-length') continue;
      respHead += `${k}: ${v}\r\n`;
    }
    respHead += `Content-Length: ${bodyBytes.byteLength}\r\n\r\n`;

    const headBytes = new TextEncoder().encode(respHead);
    const payload = new Uint8Array(headBytes.length + bodyBytes.byteLength);
    payload.set(headBytes);
    payload.set(new Uint8Array(bodyBytes), headBytes.length);

    const extra = { 'WARC-Record-ID': respId, 'WARC-Concurrent-To': reqId, 'WARC-Date': ts };
    const ct = headers.find(([k]) => k.toLowerCase() === 'content-type');
    if (ct) extra['WARC-Identified-Payload-Type'] = ct[1];
    this._add('response', url, 'application/http; msgtype=response', payload, extra);
  }

  _add(type, targetURI, contentType, payload, extra = {}) {
    const id = extra['WARC-Record-ID'] || `<urn:uuid:${crypto.randomUUID()}>`;
    const date = extra['WARC-Date'] || new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');

    let hdr = 'WARC/1.1\r\n';
    hdr += `WARC-Type: ${type}\r\n`;
    hdr += `WARC-Record-ID: ${id}\r\n`;
    hdr += `WARC-Date: ${date}\r\n`;
    if (targetURI) hdr += `WARC-Target-URI: ${targetURI}\r\n`;
    if (extra['WARC-Concurrent-To']) hdr += `WARC-Concurrent-To: ${extra['WARC-Concurrent-To']}\r\n`;
    if (extra['WARC-Identified-Payload-Type']) hdr += `WARC-Identified-Payload-Type: ${extra['WARC-Identified-Payload-Type']}\r\n`;
    hdr += `Content-Type: ${contentType}\r\n`;
    hdr += `Content-Length: ${payload.byteLength}\r\n`;
    hdr += '\r\n';

    const hdrBytes = new TextEncoder().encode(hdr);
    const sep = new TextEncoder().encode('\r\n\r\n');
    const record = new Uint8Array(hdrBytes.length + payload.byteLength + sep.length);
    record.set(hdrBytes);
    record.set(payload, hdrBytes.length);
    record.set(sep, hdrBytes.length + payload.byteLength);
    this.records.push(record);
  }

  async toBlob() {
    const parts = [];
    for (const rec of this.records) {
      const cs = new CompressionStream('gzip');
      const writer = cs.writable.getWriter();
      writer.write(rec);
      writer.close();
      parts.push(new Uint8Array(await new Response(cs.readable).arrayBuffer()));
    }
    return new Blob(parts, { type: 'application/warc' });
  }
}

// -- S3 Upload (AWS Signature v4, browser crypto) --

async function uploadToS3(config, key, blob) {
  const { endpoint, bucket, accessKeyId, secretAccessKey, region } = config;
  const body = new Uint8Array(await blob.arrayBuffer());
  const host = new URL(endpoint).host;
  const url = `${endpoint}/${bucket}/${key}`;

  const now = new Date();
  const dateStr = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  const dateShort = dateStr.slice(0, 8);
  const bodyHash = await sha256Hex(body);
  const scope = `${dateShort}/${region}/s3/aws4_request`;

  const signedHeaderKeys = ['content-type', 'host', 'x-amz-acl', 'x-amz-content-sha256', 'x-amz-date'];
  const headerMap = {
    'content-type': 'application/warc',
    'host': host,
    'x-amz-acl': 'public-read',
    'x-amz-content-sha256': bodyHash,
    'x-amz-date': dateStr,
  };

  const canonicalHeaders = signedHeaderKeys.map(k => `${k}:${headerMap[k]}\n`).join('');
  const signedHeaders = signedHeaderKeys.join(';');

  const parsedUrl = new URL(url);
  const canonicalRequest = [
    'PUT', parsedUrl.pathname, '',
    canonicalHeaders, signedHeaders, bodyHash,
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256', dateStr, scope,
    await sha256Hex(new TextEncoder().encode(canonicalRequest)),
  ].join('\n');

  const kDate = await hmac(enc(`AWS4${secretAccessKey}`), enc(dateShort));
  const kRegion = await hmac(kDate, enc(region));
  const kService = await hmac(kRegion, enc('s3'));
  const kSigning = await hmac(kService, enc('aws4_request'));
  const signature = toHex(await hmac(kSigning, enc(stringToSign)));

  const auth = `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}`;

  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/warc',
      'x-amz-acl': 'public-read',
      'x-amz-date': dateStr,
      'x-amz-content-sha256': bodyHash,
      'Authorization': auth,
    },
    body,
  });
  if (!res.ok) throw new Error(`S3 upload failed: ${res.status} ${await res.text()}`);
  return key;
}

function enc(s) { return new TextEncoder().encode(s); }
async function sha256Hex(data) { return toHex(new Uint8Array(await crypto.subtle.digest('SHA-256', data))); }
async function hmac(key, data) {
  const k = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, data));
}
function toHex(buf) { return Array.from(buf).map(b => b.toString(16).padStart(2, '0')).join(''); }

// -- Subresource discovery --

function discoverSubresources(htmlText, baseUrl) {
  const urls = new Set();
  const doc = new DOMParser().parseFromString(htmlText, 'text/html');
  const base = new URL(baseUrl);

  function addUrl(raw) {
    if (!raw || raw.startsWith('data:') || raw.startsWith('javascript:') || raw.startsWith('#')) return;
    try {
      const resolved = new URL(raw, base).href;
      if (resolved.startsWith('http://') || resolved.startsWith('https://')) {
        urls.add(resolved);
      }
    } catch {}
  }

  // Embedded resources (not <a> navigation links)
  for (const el of doc.querySelectorAll('link[href], script[src], img[src], video[src], audio[src], source[src], source[srcset], img[srcset]')) {
    addUrl(el.getAttribute('src') || el.getAttribute('href'));
    // srcset can have multiple URLs
    const srcset = el.getAttribute('srcset');
    if (srcset) {
      for (const part of srcset.split(',')) {
        addUrl(part.trim().split(/\s+/)[0]);
      }
    }
  }

  // Inline style url() references
  for (const style of doc.querySelectorAll('style')) {
    for (const match of style.textContent.matchAll(/url\(['"]?([^'")\s]+)['"]?\)/g)) {
      addUrl(match[1]);
    }
  }

  // Element inline styles
  for (const el of doc.querySelectorAll('[style]')) {
    for (const match of el.getAttribute('style').matchAll(/url\(['"]?([^'")\s]+)['"]?\)/g)) {
      addUrl(match[1]);
    }
  }

  // Remove the page itself
  urls.delete(baseUrl);
  urls.delete(base.href);
  return [...urls];
}

function discoverCssSubresources(cssText, cssUrl) {
  const urls = [];
  const base = new URL(cssUrl);
  for (const match of cssText.matchAll(/url\(['"]?([^'")\s]+)['"]?\)/g)) {
    if (match[1].startsWith('data:')) continue;
    try { urls.push(new URL(match[1], base).href); } catch {}
  }
  for (const match of cssText.matchAll(/@import\s+['"]([^'"]+)['"]/g)) {
    try { urls.push(new URL(match[1], base).href); } catch {}
  }
  return urls;
}

// -- Archive flow --

async function archiveUrl(url, title, tags) {
  const status = document.getElementById('archive-status');
  const progress = document.getElementById('archive-progress');
  const fill = progress.querySelector('.progress-fill');
  const text = progress.querySelector('.progress-text');
  const btn = document.getElementById('archive-btn');

  btn.disabled = true;
  progress.hidden = false;
  status.hidden = true;

  try {
    // Step 1: Fetch main page via Urbit thread
    setProgress(fill, text, 10, 'Fetching page...');
    const mainResp = await fetchUrls([url]);
    const mainResult = mainResp[0];
    if (mainResult.error) throw new Error(`Fetch failed: ${mainResult.error}`);

    const mainBody = base64ToBytes(mainResult.body);
    const mainHeaders = mainResult.headers.map(h => [h[0], h[1]]);
    const htmlText = new TextDecoder().decode(mainBody);

    // Auto-detect title if not provided
    if (!title) {
      const match = htmlText.match(/<title[^>]*>([^<]+)<\/title>/i);
      if (match) title = match[1].trim();
      else title = url;
    }

    // Step 2: Discover and fetch subresources
    setProgress(fill, text, 25, 'Discovering subresources...');
    const subUrls = discoverSubresources(htmlText, url);
    console.log(`Discovered ${subUrls.length} subresources:`, subUrls);

    let subResults = [];
    if (subUrls.length > 0) {
      const batchSize = 8;
      for (let i = 0; i < subUrls.length; i += batchSize) {
        const batch = subUrls.slice(i, i + batchSize);
        const pct = 25 + Math.round(40 * (i / subUrls.length));
        setProgress(fill, text, pct, `Fetching resources (${i}/${subUrls.length})...`);
        const batchResp = await fetchUrls(batch);
        subResults.push(...batchResp);
      }
    }

    // Step 2b: Crawl fetched CSS files for additional resources (fonts, bg images)
    const cssUrls = new Set();
    for (const sub of subResults) {
      if (sub.error || !sub.body) continue;
      const ct = (sub.headers || []).find(h => h[0].toLowerCase() === 'content-type');
      if (ct && ct[1].toLowerCase().includes('css')) {
        const cssText = new TextDecoder().decode(base64ToBytes(sub.body));
        for (const u of discoverCssSubresources(cssText, sub.url)) {
          if (!subUrls.includes(u)) cssUrls.add(u);
        }
      }
    }
    if (cssUrls.size > 0) {
      const cssUrlList = [...cssUrls];
      console.log(`Discovered ${cssUrlList.length} CSS sub-resources:`, cssUrlList);
      setProgress(fill, text, 68, `Fetching CSS resources (${cssUrlList.length})...`);
      const batchSize = 8;
      for (let i = 0; i < cssUrlList.length; i += batchSize) {
        const batch = cssUrlList.slice(i, i + batchSize);
        const batchResp = await fetchUrls(batch);
        subResults.push(...batchResp);
      }
    }

    console.log(`Total subresources fetched: ${subResults.length}, ok: ${subResults.filter(s => !s.error && s.body).length}, failed: ${subResults.filter(s => s.error || !s.body).length}`);

    // Step 3: Create WARC
    setProgress(fill, text, 80, 'Creating WARC archive...');
    const warc = new WARCWriter();
    warc.addWarcinfo();
    warc.addExchange(url, mainResult.status, statusText(mainResult.status), mainHeaders, mainBody);

    for (const sub of subResults) {
      if (sub.error || !sub.body) continue;
      const body = base64ToBytes(sub.body);
      const headers = sub.headers.map(h => [h[0], h[1]]);
      warc.addExchange(sub.url, sub.status, statusText(sub.status), headers, body);
    }

    const blob = await warc.toBlob();
    const domain = new URL(url).hostname.replace(/^www\./, '');
    const ts = Math.floor(Date.now() / 1000);
    const filename = `${domain}-${ts}.warc.gz`;

    // Step 4: Upload to S3 (or download locally if no S3)
    let s3Path = '';
    if (s3Config && s3Config.endpoint && s3Config.bucket) {
      setProgress(fill, text, 90, 'Uploading to S3...');
      try {
        s3Path = await uploadToS3(s3Config, filename, blob);
      } catch (err) {
        console.error('S3 upload failed, falling back to download', err);
        downloadBlob(blob, filename);
        s3Path = `local:${filename}`;
      }
    } else {
      downloadBlob(blob, filename);
      s3Path = `local:${filename}`;
    }

    // Step 5: Record bookmark in agent
    setProgress(fill, text, 95, 'Saving bookmark...');
    const id = '0v' + crypto.randomUUID().replace(/-/g, '').slice(0, 10);
    await apiAction({
      save: {
        id,
        url,
        title,
        tags: tags.filter(t => t.length > 0),
        's3-path': s3Path,
      },
    });
    await loadBookmarks();

    setProgress(fill, text, 100, 'Done!');
    showStatus(status, 'success', `Archived ${filename} (${formatBytes(blob.size)})`);
  } catch (err) {
    console.error(err);
    showStatus(status, 'error', err.message);
  } finally {
    btn.disabled = false;
    setTimeout(() => { progress.hidden = true; }, 2000);
  }
}

// -- UI --

function setProgress(fill, text, pct, msg) {
  fill.style.width = `${pct}%`;
  text.textContent = msg;
}

function showStatus(el, cls, msg) {
  el.className = `status ${cls}`;
  el.textContent = msg;
  el.hidden = false;
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function downloadBlob(blob, filename) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}

function formatBytes(b) {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / (1024 * 1024)).toFixed(1)} MB`;
}

function statusText(code) {
  const m = { 200: 'OK', 301: 'Moved Permanently', 302: 'Found', 304: 'Not Modified', 404: 'Not Found', 500: 'Internal Server Error' };
  return m[code] || 'OK';
}

function renderBookmarks() {
  const list = document.getElementById('bookmark-list');
  const search = document.getElementById('search-input').value.toLowerCase();

  let filtered = bookmarks;
  if (activeTag) {
    filtered = filtered.filter(b => b.tags.includes(activeTag));
  }
  if (search) {
    filtered = filtered.filter(b =>
      b.url.toLowerCase().includes(search) ||
      b.title.toLowerCase().includes(search) ||
      b.tags.some(t => t.toLowerCase().includes(search))
    );
  }

  // Sort newest first
  filtered.sort((a, b) => b.added - a.added);

  if (filtered.length === 0) {
    list.innerHTML = '<div class="empty">No bookmarks yet. Archive a URL to get started.</div>';
    return;
  }

  list.innerHTML = filtered.map(b => `
    <div class="bookmark-card" data-id="${b.id}">
      <div class="title">${escHtml(b.title)}</div>
      <div class="url">${escHtml(b.url)}</div>
      <div class="meta">
        <span class="date">${new Date(b.added * 1000).toLocaleDateString()}</span>
        ${b.tags.map(t => `<span class="tag">${escHtml(t)}</span>`).join('')}
        <div class="actions">
          ${b.s3Path && !b.s3Path.startsWith('local:') ? `<button onclick="viewWarc('${escAttr(b.s3Path)}')">View</button>` : ''}
          <button class="del" onclick="deleteBookmark('${escAttr(b.id)}')">Delete</button>
        </div>
      </div>
    </div>
  `).join('');
}

function renderTagFilter() {
  const allTags = new Set();
  for (const b of bookmarks) for (const t of b.tags) allTags.add(t);
  const el = document.getElementById('tag-filter');
  if (allTags.size === 0) { el.innerHTML = ''; return; }
  el.innerHTML = [...allTags].sort().map(t =>
    `<button class="tag-pill ${activeTag === t ? 'active' : ''}" onclick="toggleTag('${escAttr(t)}')">${escHtml(t)}</button>`
  ).join('');
}

function s3FileUrl(path) {
  if (!s3Config || !s3Config.endpoint) return '#';
  return `${s3Config.endpoint}/${s3Config.bucket}/${path}`;
}

// -- WARC Viewer --

async function viewWarc(s3Path) {
  const url = s3FileUrl(s3Path);
  if (url === '#') return;

  const win = window.open('', '_blank');
  win.document.write('<html><head><title>Loading WARC...</title><style>body{background:#1a1a2e;color:#e0e0e0;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}</style></head><body><p>Loading archive...</p></body></html>');

  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error(`Fetch failed: ${res.status}`);
    const compressed = new Uint8Array(await res.arrayBuffer());
    const records = await parseWarcGz(compressed);

    // Find response records and build a resource map
    const resources = new Map();
    let mainHtml = null;
    let mainUrl = null;

    for (const rec of records) {
      if (rec.type !== 'response') continue;
      const parsed = parseHttpResponse(rec.payload);
      if (!parsed) continue;
      resources.set(rec.targetURI, parsed);
      if (!mainHtml) {
        const ct = (parsed.headers['content-type'] || '').toLowerCase();
        if (ct.includes('text/html')) {
          mainHtml = new TextDecoder().decode(parsed.body);
          mainUrl = rec.targetURI;
        }
      }
    }

    if (!mainHtml) {
      win.document.body.textContent = 'No HTML page found in archive.';
      return;
    }

    // Rewrite subresource URLs to data: URIs
    const base = new URL(mainUrl);
    const rewritten = rewriteHtml(mainHtml, base, resources);

    win.document.open();
    win.document.write(rewritten);
    win.document.close();
  } catch (err) {
    win.document.body.textContent = `Error: ${err.message}`;
  }
}

async function parseWarcGz(compressed) {
  // WARC.gz files are concatenated gzip streams (one per record)
  // We decompress the whole thing, then parse WARC records from the text
  let decompressed;
  try {
    const ds = new DecompressionStream('gzip');
    const writer = ds.writable.getWriter();
    writer.write(compressed);
    writer.close();
    decompressed = new Uint8Array(await new Response(ds.readable).arrayBuffer());
  } catch {
    // Some browsers can't handle concatenated gzip; try manual chunk approach
    decompressed = await decompressChunkedGzip(compressed);
  }

  const text = new TextDecoder().decode(decompressed);
  return parseWarcText(text);
}

async function decompressChunkedGzip(data) {
  // Find gzip stream boundaries (each starts with 1f 8b)
  const chunks = [];
  let start = 0;
  for (let i = 2; i < data.length; i++) {
    if (data[i] === 0x1f && data[i + 1] === 0x8b) {
      chunks.push(data.slice(start, i));
      start = i;
    }
  }
  chunks.push(data.slice(start));

  const parts = [];
  for (const chunk of chunks) {
    try {
      const ds = new DecompressionStream('gzip');
      const writer = ds.writable.getWriter();
      writer.write(chunk);
      writer.close();
      parts.push(new Uint8Array(await new Response(ds.readable).arrayBuffer()));
    } catch { /* skip corrupt chunks */ }
  }

  const total = parts.reduce((s, p) => s + p.length, 0);
  const result = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) { result.set(p, offset); offset += p.length; }
  return result;
}

function parseWarcText(text) {
  const records = [];
  const parts = text.split('WARC/1.1\r\n');

  for (let i = 1; i < parts.length; i++) {
    const part = parts[i];
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd === -1) continue;

    const headerBlock = part.slice(0, headerEnd);
    const headers = {};
    for (const line of headerBlock.split('\r\n')) {
      const colon = line.indexOf(':');
      if (colon === -1) continue;
      headers[line.slice(0, colon).trim().toLowerCase()] = line.slice(colon + 1).trim();
    }

    const contentLength = parseInt(headers['content-length'] || '0', 10);
    const payload = part.slice(headerEnd + 4, headerEnd + 4 + contentLength);

    records.push({
      type: headers['warc-type'] || '',
      targetURI: headers['warc-target-uri'] || '',
      payload,
    });
  }
  return records;
}

function parseHttpResponse(payload) {
  const headerEnd = payload.indexOf('\r\n\r\n');
  if (headerEnd === -1) return null;

  const headerBlock = payload.slice(0, headerEnd);
  const body = payload.slice(headerEnd + 4);
  const lines = headerBlock.split('\r\n');

  const headers = {};
  for (let i = 1; i < lines.length; i++) {
    const colon = lines[i].indexOf(':');
    if (colon === -1) continue;
    headers[lines[i].slice(0, colon).trim().toLowerCase()] = lines[i].slice(colon + 1).trim();
  }

  return { headers, body: new TextEncoder().encode(body) };
}

function rewriteHtml(html, baseUrl, resources) {
  // Strip integrity and crossorigin attributes (they block data: URIs)
  let out = html.replace(/\s+(integrity|crossorigin)=(["'])[^"']*\2/gi, '');
  // Replace src and href attributes with data: URIs where we have the resource
  out = out.replace(/(src|href)=(["'])([^"']*)\2/gi, (match, attr, quote, val) => {
    try {
      const resolved = new URL(val, baseUrl).href;
      const res = resources.get(resolved);
      if (!res) return match;
      const ct = res.headers['content-type'] || 'application/octet-stream';
      const b64 = uint8ToBase64(res.body);
      return `${attr}=${quote}data:${ct};base64,${b64}${quote}`;
    } catch { return match; }
  });
  return out;
}

function toggleTag(tag) {
  activeTag = activeTag === tag ? null : tag;
  renderTagFilter();
  renderBookmarks();
}

async function deleteBookmark(id) {
  if (!confirm('Delete this bookmark?')) return;
  await apiAction({ delete: { id } });
  await loadBookmarks();
}

function escHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function escAttr(s) { return s.replace(/'/g, '&#39;').replace(/"/g, '&quot;'); }
function uint8ToBase64(bytes) {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

// -- Init --

document.addEventListener('DOMContentLoaded', async () => {
  // Tabs
  for (const tab of document.querySelectorAll('.tab')) {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
      tab.classList.add('active');
      document.getElementById(tab.dataset.tab).classList.add('active');
    });
  }

  // Archive form
  document.getElementById('archive-form').addEventListener('submit', (e) => {
    e.preventDefault();
    const url = document.getElementById('url-input').value.trim();
    const title = document.getElementById('title-input').value.trim();
    const tags = document.getElementById('tags-input').value.split(',').map(t => t.trim()).filter(Boolean);
    if (url) archiveUrl(url, title, tags);
  });

  // Search
  document.getElementById('search-input').addEventListener('input', () => renderBookmarks());

  // Load S3 config from system %storage agent
  try {
    const res = await fetch('/apps/warc/api/s3-config');
    if (res.ok) s3Config = await res.json();
  } catch {}

  // Load bookmarks
  try {
    await loadBookmarks();
  } catch (err) {
    console.error('Load bookmarks failed:', err);
  }
});