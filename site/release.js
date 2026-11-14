// GrinSight site: follow the latest GitHub release without editing the HTML.
//
// The HTML carries a working baked-in release (links, sizes, hashes). This script asks
// the GitHub API for the latest release (pre-releases are skipped by /releases/latest)
// and, when it is newer, rewrites in place:
//   - every download link  .../releases/download/v<old>/GrinSight-<old>-<rest>
//   - every release page link .../releases/tag/v<old>
//   - the version in text, <title> and meta descriptions
//   - file sizes and SHA-256 under each download button (.file-meta)
// If the API is unreachable or rate-limited, nothing changes: the baked release stays.
// A hash is shown only when GitHub reports it for that file; otherwise the page points
// to SHA256SUMS.txt instead of showing an old hash next to a new file.
(function () {
  'use strict';
  var REPO = 'DanilaGrinRus/GrinSight';
  var API = 'https://api.github.com/repos/' + REPO + '/releases/latest';
  var CACHE_KEY = 'gs-latest-release';
  var CACHE_MS = 10 * 60 * 1000;
  var meta = document.querySelector('meta[name="gs-version"]');
  var baked = meta ? meta.getAttribute('content') : null;
  if (!baked) return;
  var ru = (document.documentElement.lang || '').indexOf('ru') === 0;

  function cached() {
    try {
      var c = JSON.parse(sessionStorage.getItem(CACHE_KEY) || 'null');
      if (c && Date.now() - c.at < CACHE_MS) return c.data;
    } catch (e) { /* storage unavailable */ }
    return null;
  }
  function remember(data) {
    try { sessionStorage.setItem(CACHE_KEY, JSON.stringify({ at: Date.now(), data: data })); } catch (e) { /* ignore */ }
  }
  function load() {
    var c = cached();
    if (c) return Promise.resolve(c);
    return fetch(API, { headers: { Accept: 'application/vnd.github+json' } })
      .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
      .then(function (j) {
        var data = {
          tag: j.tag_name, url: j.html_url,
          assets: (j.assets || []).map(function (a) {
            return { name: a.name, url: a.browser_download_url, size: a.size, digest: a.digest || null };
          })
        };
        remember(data);
        return data;
      });
  }
  function newer(a, b) { // semantic-ish compare of x.y.z
    var x = a.split(/[.-]/).map(Number), y = b.split(/[.-]/).map(Number);
    for (var i = 0; i < 3; i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) > (y[i] || 0); }
    return false;
  }
  function esc(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }
  function mb(bytes) {
    var v = (bytes / 1048576).toFixed(1);
    return ru ? v.replace('.', ',') + ' МБ' : v + ' MB';
  }
  function shortHash(digest) {
    var h = String(digest).replace(/^sha256:/, '');
    return /^[0-9a-f]{64}$/.test(h) ? 'sha256 ' + h.slice(0, 8) + '…' + h.slice(-6) : null;
  }

  function apply(rel) {
    var ver = String(rel.tag || '').replace(/^v/, '');
    if (!/^\d+\.\d+\.\d+/.test(ver) || !newer(ver, baked)) return;
    var byName = {};
    rel.assets.forEach(function (a) { byName[a.name] = a; });
    var reVer = new RegExp(esc(baked), 'g');

    // Links to files and to the release page.
    var assetFor = new Map();
    document.querySelectorAll('a[href*="/releases/"]').forEach(function (a) {
      var href = a.getAttribute('href');
      var m = href.match(/\/releases\/download\/v[^/]+\/(.+)$/);
      if (m) {
        var name = decodeURIComponent(m[1]).replace(reVer, ver);
        var asset = byName[name];
        if (asset) { a.setAttribute('href', asset.url); assetFor.set(a, asset); }
        else if (/CHECKPOINT\.txt$|SHA256SUMS\.txt$|source\.zip$/.test(name)) { a.setAttribute('href', rel.url); }
        else { a.setAttribute('href', rel.url); } // the file is not in this release: send to its page
        if (/CHECKPOINT\.txt$/.test(name)) a.textContent = ru ? 'Чекпоинт (CHECKPOINT.txt)' : 'Checkpoint (CHECKPOINT.txt)';
      } else if (/\/releases\/tag\/v/.test(href)) {
        a.setAttribute('href', rel.url);
      }
    });

    // Size and hash under each download button.
    document.querySelectorAll('.file-meta').forEach(function (fm) {
      var card = fm.parentElement, link = card && card.querySelector('a[href]');
      var asset = link && assetFor.get(link);
      var spans = fm.querySelectorAll('span');
      if (!asset) return;
      if (spans[0]) spans[0].textContent = mb(asset.size);
      var h = fm.querySelector('.hash');
      if (h) h.textContent = (asset.digest && shortHash(asset.digest)) || (ru ? 'sha256 — в SHA256SUMS.txt' : 'sha256 — see SHA256SUMS.txt');
    });

    // Version in visible text, title and descriptions.
    var walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    var n;
    while ((n = walker.nextNode())) { if (n.nodeValue.indexOf(baked) !== -1) n.nodeValue = n.nodeValue.replace(reVer, ver); }
    document.querySelectorAll('[aria-label],[title]').forEach(function (el) {
      ['aria-label', 'title'].forEach(function (k) { var v = el.getAttribute(k); if (v && v.indexOf(baked) !== -1) el.setAttribute(k, v.replace(reVer, ver)); });
    });
    document.title = document.title.replace(reVer, ver);
    document.querySelectorAll('meta[name="description"],meta[property="og:title"],meta[property="og:description"]').forEach(function (m) {
      m.setAttribute('content', m.getAttribute('content').replace(reVer, ver));
    });
    if (meta) meta.setAttribute('content', ver);
  }

  function start() { load().then(apply).catch(function () { /* keep the baked release */ }); }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start); else start();
})();
