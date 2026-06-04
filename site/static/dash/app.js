/* CI/lock analytics client. Vanilla, dependency-free. Fetches the JWT-gated JSON API
 * at /dash/api with the current filters and renders cards, an SVG traffic chart, a
 * hot/cold site map and dense tables. Filter state lives in the URL so views are
 * shareable. TestifySec traffic is excluded by default (segment=external). */
(function () {
  'use strict';

  var app = document.getElementById('app');
  var user = (app && app.dataset.user) || '';
  var last = null; // last API payload, for resize redraws

  var RANGE_LABELS = { '24h': '24h', '7d': '7d', '30d': '30d', '90d': '90d' };
  var SEG_LABELS = { external: 'External', humans: 'Humans', bots: 'Bots', all: 'All', internal: 'TestifySec' };
  var NET_LABELS = {
    residential: 'Residential', datacenter: 'Datacenter', corporate: 'Corporate',
    mobile: 'Mobile', apple_relay: 'Apple Relay', cgnat: 'CGNAT', tor: 'Tor', unknown: 'Unknown',
  };

  /* ---------- helpers ---------- */
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"]/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
    });
  }
  function fmt(n) { return (Number(n) || 0).toLocaleString('en-US'); }
  function pad(n) { return n < 10 ? '0' + n : '' + n; }
  function dt(ms) { return new Date(Number(ms)); }
  function stamp(ms) { var d = dt(ms); return pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()) + ' ' + pad(d.getUTCHours()) + ':' + pad(d.getUTCMinutes()); }
  function day(ms) { var d = dt(ms); return pad(d.getUTCMonth() + 1) + '-' + pad(d.getUTCDate()); }
  function ago(ms) {
    var s = Math.max(0, (Date.now() - Number(ms)) / 1000);
    if (s < 90) return Math.round(s) + 's ago';
    if (s < 5400) return Math.round(s / 60) + 'm ago';
    if (s < 129600) return Math.round(s / 3600) + 'h ago';
    return Math.round(s / 86400) + 'd ago';
  }
  function niceMax(v) { // round a max up to a "nice" axis bound (1,2,5 x 10^n)
    if (v <= 1) return 1;
    var pow = Math.pow(10, Math.floor(Math.log(v) / Math.LN10));
    var f = v / pow;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * pow;
  }

  /* ---------- filter state ---------- */
  function filters() {
    var p = new URLSearchParams(location.search);
    return {
      range: RANGE_LABELS[p.get('range')] ? p.get('range') : '7d',
      segment: SEG_LABELS[p.get('segment')] ? p.get('segment') : 'external',
      network: p.get('network') || '',
      country: p.get('country') || '',
    };
  }
  function setFilter(patch) {
    var f = filters();
    Object.keys(patch).forEach(function (k) { f[k] = patch[k]; });
    var p = new URLSearchParams();
    Object.keys(f).forEach(function (k) { if (f[k]) p.set(k, f[k]); });
    history.replaceState(null, '', location.pathname + (p.toString() ? '?' + p : ''));
    load();
  }

  /* ---------- data ---------- */
  function load(silent) {
    var f = filters();
    if (!silent && last == null) app.innerHTML = '<div class="boot">Loading analytics…</div>';
    fetch('/dash/api?' + new URLSearchParams(f), { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('API ' + r.status); return r.json(); })
      .then(function (d) { last = d; render(d); })
      .catch(function (e) {
        if (!silent) app.innerHTML = '<div class="wrap"><div class="err">Failed to load: ' + esc(e.message) + '</div></div>';
      });
  }

  /* ---------- controls ---------- */
  function segControl(name, current, opts, labels) {
    var html = '<div class="seg" role="group">';
    opts.forEach(function (o) {
      html += '<button data-f="' + name + '" data-v="' + esc(o) + '" aria-pressed="' + (o === current) + '">' + esc(labels[o] || o) + '</button>';
    });
    return html + '</div>';
  }
  function selControl(name, current, opts, labels, allLabel) {
    var html = '<select class="sel" data-f="' + name + '"><option value="">' + esc(allLabel) + '</option>';
    opts.forEach(function (o) {
      html += '<option value="' + esc(o) + '"' + (o === current ? ' selected' : '') + '>' + esc((labels && labels[o]) || o) + '</option>';
    });
    return html + '</select>';
  }

  /* ---------- charts ---------- */
  function drawChart(box, d) {
    var span = { '24h': 24 * 3600e3, '7d': 7 * 864e5, '30d': 30 * 864e5, '90d': 90 * 864e5 }[d.filters.range];
    var bms = d.bucketMs;
    var now = d.generatedAt;
    var startB = Math.floor((now - span) / bms) * bms;
    var endB = Math.floor(now / bms) * bms;
    var map = {};
    d.series.forEach(function (p) { map[Math.floor(p.t / bms) * bms] = p; });
    var pts = [];
    for (var t = startB; t <= endB; t += bms) { var p = map[t]; pts.push({ t: t, loads: p ? p.loads : 0, returning: p ? p.returning : 0 }); }
    if (pts.length > 120) pts = pts.slice(pts.length - 120);

    var W = box.clientWidth || 800, H = 200, P = { l: 36, r: 10, t: 10, b: 22 };
    var iw = W - P.l - P.r, ih = H - P.t - P.b, n = pts.length;
    var raw = 1;
    pts.forEach(function (q) { if (q.loads > raw) raw = q.loads; });
    var maxY = niceMax(raw);
    var X = function (i) { return P.l + (n <= 1 ? iw / 2 : (i / (n - 1)) * iw); };
    var Y = function (v) { return P.t + ih - (v / maxY) * ih; };

    function path(key) {
      return pts.map(function (q, i) { return (i ? 'L' : 'M') + X(i).toFixed(1) + ' ' + Y(q[key]).toFixed(1); }).join(' ');
    }
    var area = 'M' + X(0).toFixed(1) + ' ' + (P.t + ih) + ' ' + pts.map(function (q, i) { return 'L' + X(i).toFixed(1) + ' ' + Y(q.loads).toFixed(1); }).join(' ') + ' L' + X(n - 1).toFixed(1) + ' ' + (P.t + ih) + ' Z';

    var grid = '';
    var ticks = maxY <= 2 ? [0, maxY] : [0, maxY / 2, maxY];
    ticks.forEach(function (v) {
      var yy = Y(v).toFixed(1);
      grid += '<line x1="' + P.l + '" y1="' + yy + '" x2="' + (W - P.r) + '" y2="' + yy + '"/>';
      grid += '<text class="axis" x="' + (P.l - 6) + '" y="' + (Number(yy) + 3) + '" text-anchor="end">' + fmt(Math.round(v)) + '</text>';
    });
    var xt = '';
    var ticks = n <= 1 ? [0] : [0, Math.floor((n - 1) / 2), n - 1];
    ticks.forEach(function (i) {
      var lab = d.bucket === 'hour' ? pad(dt(pts[i].t).getUTCHours()) + ':00' : day(pts[i].t);
      var anc = i === 0 ? 'start' : i === n - 1 ? 'end' : 'middle';
      xt += '<text class="axis" x="' + X(i).toFixed(1) + '" y="' + (H - 6) + '" text-anchor="' + anc + '">' + esc(lab) + '</text>';
    });

    box.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none">' +
      '<g class="grid">' + grid + '</g>' +
      '<path class="area-loads" d="' + area + '"/>' +
      '<path class="line-loads" d="' + path('loads') + '"/>' +
      '<path class="line-ret" d="' + path('returning') + '"/>' +
      xt + '</svg>';
  }

  /* ---------- heat / site map ---------- */
  function heatColor(t) { // t in (0,1]
    var lo = [34, 42, 54], hi = [240, 110, 45];
    var c = lo.map(function (a, i) { return Math.round(a + (hi[i] - a) * t); });
    return 'rgb(' + c[0] + ',' + c[1] + ',' + c[2] + ')';
  }
  function renderHeat(box, siteMap) {
    if (!siteMap.length) { box.innerHTML = '<div class="empty">No pages yet.</div>'; return; }
    var maxV = 0;
    siteMap.forEach(function (s) { if (s.views > maxV) maxV = s.views; });
    var lmax = Math.log(maxV + 1) || 1;
    var groups = {};
    siteMap.forEach(function (s) { (groups[s.section] = groups[s.section] || []).push(s); });
    var order = Object.keys(groups).sort(function (a, b) {
      var sa = groups[a].reduce(function (x, s) { return x + s.views; }, 0);
      var sb = groups[b].reduce(function (x, s) { return x + s.views; }, 0);
      return sb - sa || a.localeCompare(b);
    });
    var html = '';
    order.forEach(function (sec) {
      html += '<div class="heat-sect"><h3>' + esc(sec) + '</h3><div class="heat-grid">';
      groups[sec].sort(function (a, b) { return b.views - a.views; }).forEach(function (s) {
        var label = s.path === '/' ? '/' : s.path.split('/').slice(-1)[0] || s.path;
        if (s.views === 0) {
          html += '<div class="cell cold" title="' + esc(s.path) + ' — no views"><div class="p">' + esc(label) + '</div><div class="n">cold</div></div>';
        } else {
          var t = Math.log(s.views + 1) / lmax;
          html += '<div class="cell" style="background:' + heatColor(t) + '" title="' + esc(s.path) + ' — ' + fmt(s.views) + ' views"><div class="p">' + esc(label) + '</div><div class="n">' + fmt(s.views) + '</div></div>';
        }
      });
      html += '</div></div>';
    });
    box.innerHTML = html;
  }

  /* ---------- bar list ---------- */
  function barList(items, filterKey, labels) {
    if (!items.length) return '<div class="empty">No data.</div>';
    var maxN = 0;
    items.forEach(function (i) { if (i.n > maxN) maxN = i.n; });
    var html = '<div class="barlist">';
    items.forEach(function (i) {
      var pct = maxN ? Math.max(3, (i.n / maxN) * 100) : 0;
      var lab = (labels && labels[i.k]) || i.k || '(none)';
      html += '<div class="barrow' + (filterKey ? ' clk' : '') + '"' + (filterKey ? ' data-f="' + filterKey + '" data-v="' + esc(i.k) + '"' : '') + '>' +
        '<div class="lab"><span>' + esc(lab) + '</span><div class="track"><div class="fill" style="width:' + pct.toFixed(0) + '%"></div></div></div>' +
        '<div class="ct">' + fmt(i.n) + '</div></div>';
    });
    return html + '</div>';
  }

  /* ---------- tables ---------- */
  function tbl(cols, rows, emptyMsg) {
    if (!rows.length) return '<div class="empty">' + esc(emptyMsg || 'No data yet.') + '</div>';
    var head = cols.map(function (c) { return '<th' + (c.num ? ' class="num"' : '') + '>' + esc(c.h) + '</th>'; }).join('');
    var body = rows.map(function (r) {
      return '<tr>' + cols.map(function (c) {
        return '<td' + (c.num ? ' class="num"' : (c.path ? ' class="path"' : '')) + '>' + c.cell(r) + '</td>';
      }).join('') + '</tr>';
    }).join('');
    return '<table><thead><tr>' + head + '</tr></thead><tbody>' + body + '</tbody></table>';
  }
  function reader(r) {
    var name = esc(r.reader) + (r.internal ? ' <span class="pill int">TestifySec</span>' : '');
    return r.rid ? '<span class="rlink" data-rid="' + esc(r.rid) + '" title="View journey">' + name + '</span>' : name;
  }
  function botPill(k) {
    var cls = k === 'human' ? '' : ' bot';
    return '<span class="pill' + cls + '">' + esc(k) + '</span>';
  }

  /* ---------- render ---------- */
  function render(d) {
    var f = d.filters, s = d.summary;
    var html = '<div class="wrap">';

    // header
    html += '<header><h1>CI/lock · Analytics</h1><span class="spacer"></span>' +
      '<span class="who">' + esc(user) + '</span>' +
      '<span class="gen">updated ' + ago(d.generatedAt) + '</span></header>';

    // filter bar
    html += '<div class="bar">' +
      segControl('range', f.range, d.facets.ranges, RANGE_LABELS) +
      segControl('segment', f.segment, ['external', 'humans', 'bots', 'all', 'internal'], SEG_LABELS) +
      selControl('network', f.network, d.facets.networks, NET_LABELS, 'All networks') +
      selControl('country', f.country, d.facets.countries, null, 'All countries') +
      ((f.network || f.country) ? '<button class="linkbtn" data-act="clear">clear</button>' : '') +
      '<span class="spacer"></span>' +
      (f.segment === 'external' && s.internalExcluded ? '<span class="tag"><b>' + fmt(s.internalExcluded) + '</b> TestifySec hidden</span>' : '') +
      '<button class="linkbtn" data-act="refresh">refresh</button>' +
      '</div>';

    // KPIs
    html += '<div class="kpis">' +
      kpi(fmt(s.loads), 'page loads') +
      kpi(fmt(s.visitors), 'unique visitors') +
      kpi(fmt(s.newVisitors), 'new') +
      kpi(fmt(s.returning), 'returning') +
      '<div class="kpi ghost"><div class="v">' + fmt(s.internalExcluded) + '</div><div class="k">TestifySec (excluded)</div></div>' +
      '</div>';

    // traffic chart
    html += '<div class="panel"><div class="secttl">Traffic <span class="hint">per ' + esc(d.bucket) + ' · ' + esc(SEG_LABELS[f.segment]) + '</span></div>' +
      '<div class="chart" id="chart"></div>' +
      '<div class="legend"><span><i style="background:var(--accent)"></i>loads</span><span><i style="background:var(--returning)"></i>returning</span></div></div>';

    // site map
    html += '<div class="panel"><div class="secttl">Site map · hot &amp; cold <span class="hint">page loads per page · dashed = none</span></div><div id="heat"></div></div>';

    // grid of smaller panels
    html += '<div class="cols">';
    html += panel('Top pages', tbl(
      [{ h: 'Path', path: true, cell: function (r) { return esc(r.path); } }, { h: 'Views', num: true, cell: function (r) { return fmt(r.views); } }],
      d.topPages));
    html += panel('Search queries', tbl(
      [{ h: 'Query', cell: function (r) { return esc(r.query); } }, { h: 'n', num: true, cell: function (r) { return fmt(r.n); } }],
      d.searches, 'No searches in range.'));
    html += panel('Engaged reads', tbl(
      [{ h: 'Path', path: true, cell: function (r) { return esc(r.path); } },
        { h: 'n', num: true, cell: function (r) { return fmt(r.n); } },
        { h: 'avg s', num: true, cell: function (r) { return fmt(r.avgSec); } },
        { h: 'scroll %', num: true, cell: function (r) { return fmt(r.scroll); } }],
      d.engaged, 'No engagement events yet.'));
    html += panel('Links clicked', tbl(
      [{ h: 'Link', path: true, cell: function (r) { return esc(r.k); } }, { h: 'n', num: true, cell: function (r) { return fmt(r.n); } }],
      d.clicks || [], 'No link clicks yet.'));
    html += panel('Copied snippets', tbl(
      [{ h: 'Snippet', path: true, cell: function (r) { return esc(r.k); } }, { h: 'n', num: true, cell: function (r) { return fmt(r.n); } }],
      d.copies || [], 'No copies yet.'));
    html += panel('Network', barList(d.networks, 'network', NET_LABELS));
    html += panel('Human vs bot', barList(d.bots, null, null));
    html += panel('Countries', barList(d.countries, 'country', null));
    html += panel('Referrers', barList(d.referrers, null, null));
    html += '</div>';

    // returning readers
    html += '<div class="panel"><div class="secttl">Returning readers <span class="hint">repeat visitors · stable pseudonyms, no PII</span></div><div class="scroll">' +
      tbl([
        { h: 'Reader', cell: reader },
        { h: 'Loads', num: true, cell: function (r) { return fmt(r.loads); } },
        { h: 'Sessions', num: true, cell: function (r) { return fmt(r.sessions); } },
        { h: 'Favourite page', path: true, cell: function (r) { return esc(r.fav || '—'); } },
        { h: 'First seen', num: true, cell: function (r) { return '<span class="dim">' + esc(day(r.firstSeen)) + '</span>'; } },
        { h: 'Last seen', num: true, cell: function (r) { return '<span class="dim">' + esc(ago(r.lastSeen)) + '</span>'; } },
      ], d.returners, 'No repeat visitors in range.') + '</div></div>';

    // recent visits
    html += '<div class="panel"><div class="secttl">Recent visits</div><div class="scroll">' +
      tbl([
        { h: 'Time', cell: function (r) { return '<span class="dim">' + esc(stamp(r.t)) + '</span>'; } },
        { h: 'Reader', cell: reader },
        { h: 'Path', path: true, cell: function (r) { return esc(r.path); } },
        { h: 'Country', cell: function (r) { return esc(r.country); } },
        { h: 'Network', cell: function (r) { return esc(NET_LABELS[r.network] || r.network); } },
        { h: 'Class', cell: function (r) { return botPill(r.bot); } },
      ], d.recent) + '</div></div>';

    html += '</div>';
    app.innerHTML = html;

    var chart = document.getElementById('chart');
    if (chart) drawChart(chart, d);
    var heat = document.getElementById('heat');
    if (heat) renderHeat(heat, d.siteMap);
    wire();
  }

  function kpi(v, k) { return '<div class="kpi"><div class="v">' + v + '</div><div class="k">' + esc(k) + '</div></div>'; }
  function panel(title, inner) { return '<div class="panel"><div class="secttl">' + esc(title) + '</div>' + inner + '</div>'; }

  /* ---------- events ---------- */
  function wire() {
    app.querySelectorAll('[data-f]').forEach(function (node) {
      var ev = node.tagName === 'SELECT' ? 'change' : 'click';
      node.addEventListener(ev, function () {
        var k = node.getAttribute('data-f');
        var v = node.tagName === 'SELECT' ? node.value : node.getAttribute('data-v');
        var patch = {}; patch[k] = v; setFilter(patch);
      });
    });
    app.querySelectorAll('[data-act]').forEach(function (node) {
      node.addEventListener('click', function () {
        var a = node.getAttribute('data-act');
        if (a === 'refresh') load();
        else if (a === 'clear') setFilter({ network: '', country: '' });
      });
    });
    app.querySelectorAll('[data-rid]').forEach(function (node) {
      node.addEventListener('click', function () { openJourney(node.getAttribute('data-rid')); });
    });
  }

  /* ---------- journey drawer ---------- */
  var drawer, scrim, drawerBody;
  function ensureDrawer() {
    if (drawer) return;
    scrim = document.createElement('div'); scrim.className = 'scrim';
    drawer = document.createElement('aside'); drawer.className = 'drawer';
    drawer.innerHTML = '<div class="drawer-head"><strong>Reader journey</strong><button class="linkbtn" data-jclose>close ✕</button></div><div class="drawer-body"></div>';
    document.body.appendChild(scrim); document.body.appendChild(drawer);
    drawerBody = drawer.querySelector('.drawer-body');
    scrim.addEventListener('click', closeJourney);
    drawer.querySelector('[data-jclose]').addEventListener('click', closeJourney);
  }
  function openJourney(rid) {
    if (!rid) return;
    ensureDrawer();
    drawer.classList.add('open'); scrim.classList.add('open');
    drawerBody.innerHTML = '<div class="boot">Loading journey…</div>';
    fetch('/dash/journey?rid=' + encodeURIComponent(rid), { credentials: 'same-origin' })
      .then(function (r) { if (!r.ok) throw new Error('journey ' + r.status); return r.json(); })
      .then(renderJourney)
      .catch(function (e) { drawerBody.innerHTML = '<div class="err">' + esc(e.message) + '</div>'; });
  }
  function closeJourney() { if (drawer) { drawer.classList.remove('open'); scrim.classList.remove('open'); } }
  function kindMark(k) { return k === 'load' ? '⤓' : k === 'search' ? '⌕' : k === 'read' ? '◉' : k === 'click' ? '↗' : k === 'copy' ? '⧉' : '→'; }
  function jm(v, k) { return '<span class="jm"><b>' + v + '</b>' + esc(k) + '</span>'; }
  function renderJourney(j) {
    if (!j || !j.found) { drawerBody.innerHTML = '<div class="empty">No history found for this reader (it may have aged out).</div>'; return; }
    var p = j.profile;
    var h = '<div class="jhead"><div class="jname">' + esc(j.reader) +
      (j.internal ? ' <span class="pill int">TestifySec</span>' : '') +
      (j.bot ? ' <span class="pill bot">bot</span>' : '') + '</div>';
    h += '<div class="jmeta">' + jm(fmt(p.loads), 'loads') + jm(fmt(p.events), 'events') + jm(fmt(p.sessions), 'sessions') +
      (p.browser ? jm(esc(p.browser), 'browser') : '') + (p.os ? jm(esc(p.os), 'os') : '') +
      (p.viewport ? jm(esc(p.viewport), p.deviceType || 'screen') : '') + '</div>';
    var loc = [p.city, p.region, p.country].filter(Boolean).join(', ');
    var detail = [loc, p.network, p.ip, p.asn].filter(Boolean).map(function (x) { return '<span>' + esc(x) + '</span>'; });
    if (detail.length) h += '<div class="jrow">' + detail.join('<i>·</i>') + '</div>';
    if (p.org) h += '<div class="jorg">' + esc(p.org) + '</div>';
    h += '<div class="jdate">first ' + esc(day(p.firstSeen)) + ' · last ' + esc(ago(p.lastSeen)) + '</div></div>';
    if (!j.sessions.length) h += '<div class="empty">No timeline events.</div>';
    j.sessions.forEach(function (s, i) {
      var mins = Math.max(0, Math.round((s.end - s.start) / 60000));
      var via = s.entry && s.entry !== '(on-site)' ? ' · via ' + esc(s.entry) : '';
      h += '<div class="jsess"><div class="jsess-h">Session ' + (j.sessions.length - i) + ' · ' + esc(stamp(s.start)) + ' · ' + (mins ? mins + 'm' : '<1m') + via + '</div><ul class="jtl">';
      s.items.forEach(function (it) {
        var t = new Date(it.ts);
        var hh = pad(t.getUTCHours()) + ':' + pad(t.getUTCMinutes()) + ':' + pad(t.getUTCSeconds());
        var main = it.kind === 'search' ? '“' + esc(it.query) + '”'
          : it.kind === 'copy' ? '“' + esc(it.query) + '”'
          : it.kind === 'click' ? esc(it.query || it.path)
          : esc(it.path);
        var extra = it.kind === 'read' && (it.dwell || it.scroll) ? ' <span class="dim">· ' + fmt(it.dwell) + 's · ' + fmt(it.scroll) + '%</span>' : '';
        h += '<li><span class="jt">' + hh + '</span><span class="jk jk-' + it.kind + '">' + kindMark(it.kind) + '</span><span class="jp">' + main + extra + '</span></li>';
      });
      h += '</ul></div>';
    });
    drawerBody.innerHTML = h;
  }

  /* ---------- lifecycle ---------- */
  var rt;
  window.addEventListener('resize', function () {
    clearTimeout(rt);
    rt = setTimeout(function () { var c = document.getElementById('chart'); if (c && last) drawChart(c, last); }, 150);
  });
  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { closeJourney(); return; }
    if (e.target && /input|select|textarea/i.test(e.target.tagName)) return;
    if (e.key === 'r') load();
    else if (e.key === '1') setFilter({ range: '24h' });
    else if (e.key === '2') setFilter({ range: '7d' });
    else if (e.key === '3') setFilter({ range: '30d' });
    else if (e.key === '4') setFilter({ range: '90d' });
  });
  setInterval(function () { if (!document.hidden) load(true); }, 60000);

  load();
})();
