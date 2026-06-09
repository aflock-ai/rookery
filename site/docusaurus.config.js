// @ts-check

import {themes as prismThemes} from 'prism-react-renderer';
import path from 'node:path';

/** Webpack alias so MDX/TSX can `import data from '@catalog/<name>.json'`. */
function catalogAliasPlugin() {
  return {
    name: 'catalog-alias',
    configureWebpack() {
      return {
        resolve: {
          alias: {'@catalog': path.resolve('./_generated/catalog')},
        },
      };
    },
  };
}

/**
 * Injects the Factors.ai first-party tracker (faitracker bootstrap + `/t/f.js`,
 * both served first-party by the Pages Function in functions/t/) behind a
 * geo-gated consent check:
 *   - Non-regulated regions: silent auto-grant, tracker loads immediately, no banner.
 *   - Regulated regions (EU/EEA/UK/CH/BR/ZA/KR/JP/IN, or unknown geo): show a banner
 *     and load NOTHING until the visitor accepts. Decline = nothing loads.
 * Geo comes from the cf_country cookie set by functions/_middleware.ts.
 * The same gate governs the first-party cl_vid/cl_sid cookies server-side.
 * Token defaults to the shared Factors project; override with FACTORS_TOKEN at build.
 * NOTE: keep REGULATED below in sync with functions/_middleware.ts.
 */
const FACTORS_TOKEN = process.env.FACTORS_TOKEN || 'gsvbg9jxleama3xv2kewqbvjkeqfchqx';
function factorsPlugin() {
  return {
    name: 'factors-ai',
    injectHtmlTags() {
      return {
        postBodyTags: [
          {
            tagName: 'style',
            innerHTML: `#cl-consent{position:fixed;left:0;right:0;bottom:0;z-index:1000;display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:.75rem;padding:.85rem 1.25rem;background:var(--ifm-background-surface-color,#fff);border-top:1px solid var(--ifm-color-emphasis-300,#ddd);box-shadow:0 -2px 12px rgba(0,0,0,.12);font-size:.9rem}
#cl-consent .cl-consent-msg{margin:0;flex:1 1 320px}
#cl-consent .cl-consent-btns{display:flex;gap:.5rem;flex-shrink:0}
#cl-consent .cl-consent-btn{cursor:pointer;border-radius:6px;padding:.45rem .9rem;font-size:.85rem;font-weight:600;border:1px solid var(--ifm-color-emphasis-300,#ccc)}
#cl-consent .cl-consent-decline{background:transparent;color:var(--ifm-font-color-base,#333)}
#cl-consent .cl-consent-accept{background:var(--ifm-color-primary,#2563eb);color:#fff;border-color:transparent}`,
          },
          {
            tagName: 'script',
            innerHTML: `(function () {
  var TOKEN = '${FACTORS_TOKEN}';
  var REGULATED = ['AT','BE','BG','HR','CY','CZ','DK','EE','FI','FR','DE','GR','HU','IE','IT','LV','LT','LU','MT','NL','PL','PT','RO','SK','SI','ES','SE','IS','LI','NO','GB','CH','BR','ZA','KR','JP','IN'];
  function getCookie(n) { var p = ('; ' + document.cookie).split('; ' + n + '='); return p.length === 2 ? p.pop().split(';')[0] : ''; }
  function setConsent(v) { document.cookie = 'cl_consent=' + v + '; Path=/; Max-Age=15552000; SameSite=Lax'; }
  function loadFactors() {
    window.faitracker = window.faitracker || (function () {
      this.q = [];
      var t = new CustomEvent('FAITRACKER_QUEUED_EVENT');
      return ((this.init = function (t, e, a) { (this.TOKEN = t), (this.INIT_PARAMS = e), (this.INIT_CALLBACK = a), window.dispatchEvent(new CustomEvent('FAITRACKER_INIT_EVENT')); }),
        (this.call = function () { var e = { k: '', a: [] }; if (arguments && arguments.length >= 1) { for (var a = 1; a < arguments.length; a++) e.a.push(arguments[a]); e.k = arguments[0]; } this.q.push(e), window.dispatchEvent(t); }),
        (this.message = function () { window.addEventListener('message', function (t) { 'faitracker' === t.data.origin && this.call('message', t.data.type, t.data.message); }); }),
        this.message(), this);
    })();
    window.faitracker.init(TOKEN, { host: '/t/api' });
    var s = document.createElement('script'); s.src = '/t/f.js'; s.async = true; document.body.appendChild(s);
  }
  function startBeacon() {
    var ep = '/cl/e', now = function () { return (window.performance && performance.now) ? performance.now() : Date.now(); };
    var path = location.pathname, t0 = now(), maxScroll = 0, sent = false, hubVisited = false;
    // Factors anon user id: the _fuid cookie (set by faitracker) is base64 of a UUID, which
    // == the Account Journey API user_id. Decoded + validated, it's the hub's hard join from
    // a docs visitor to its Factors-identified company. Read lazily (set after first paint).
    function fuid() { try { var v = getCookie('_fuid'); if (!v) return ''; var u = atob(v); return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(u) ? u : ''; } catch (e) { return ''; } }
    // Campaign first-touch: cl_cid (our slug) or utm_campaign from the URL, persisted 90d.
    function camp() { try { var q = new URLSearchParams(location.search); var cur = (q.get('cl_cid') || q.get('utm_campaign') || '').slice(0, 64); var ex = getCookie('cl_camp'); if (cur && !ex) { document.cookie = 'cl_camp=' + encodeURIComponent(cur) + '; Path=/; Max-Age=7776000; SameSite=Lax'; return cur; } return ex ? decodeURIComponent(ex) : cur; } catch (e) { return ''; } }
    function send(type, extra) {
      try {
        var b = { t: type, p: path, r: document.referrer || '', ms: Math.round(now() - t0), sd: maxScroll, vw: window.innerWidth, vh: window.innerHeight };
        if (extra) { for (var k in extra) b[k] = extra[k]; }
        if (navigator.sendBeacon) navigator.sendBeacon(ep, JSON.stringify(b));
        // Cross-property analytics hub (analytics.testifysec.com): mirror this event in the
        // hub's schema so cilock.dev shows up alongside testifysec.com. This runs only after
        // the client-side consent gate, so cl_consent:'granted' is truthful; the key is a
        // public anti-noise token (matches the hub's INGEST_WRITE_KEY).
        var HUB = 'https://analytics.testifysec.com/ingest/web', fu = fuid(), cp = camp();
        var hub = { source: 'cilock.dev', kind: 'event', key: 'clk-web-ingest-pub-2026', cl_consent: 'granted', type: type, path: path, referer: b.r, dwell_ms: b.ms, scroll: b.sd, vw: b.vw, vh: b.vh, query: (extra && (extra.q || extra.d)) || '', visitor_id: getCookie('cl_vid') || '', session_id: getCookie('cl_sid') || '', factors_uid: fu, campaign: cp };
        if (navigator.sendBeacon) navigator.sendBeacon(HUB, JSON.stringify(hub));
        // First page view also emits a hub visit row so cilock.dev populates the visits
        // table (summary/series/ASN orgs + the factors_uid hard join), like testifysec.com.
        if (type === 'pv' && !hubVisited) {
          hubVisited = true;
          var hv = { source: 'cilock.dev', kind: 'visit', key: 'clk-web-ingest-pub-2026', cl_consent: 'granted', path: path, referer: b.r, visitor_id: getCookie('cl_vid') || '', session_id: getCookie('cl_sid') || '', is_returning: getCookie('cl_seen') ? 1 : 0, user_agent: navigator.userAgent, factors_uid: fu, campaign: cp };
          if (navigator.sendBeacon) navigator.sendBeacon(HUB, JSON.stringify(hv));
        }
      } catch (e) {}
    }
    window.addEventListener('scroll', function () {
      var h = document.body.scrollHeight || 1, d = Math.round((window.scrollY + window.innerHeight) / h * 100);
      if (d > maxScroll) maxScroll = d > 100 ? 100 : d;
    }, { passive: true });
    function route() { send('eng'); path = location.pathname; t0 = now(); maxScroll = 0; sent = false; send('pv'); }
    ['pushState', 'replaceState'].forEach(function (m) { var o = history[m]; history[m] = function () { route(); return o.apply(this, arguments); }; });
    window.addEventListener('popstate', route);
    document.addEventListener('input', function (ev) {
      var t = ev.target;
      if (t && ((t.className && String(t.className).indexOf('DocSearch-Input') >= 0) || (t.getAttribute && t.getAttribute('type') === 'search'))) {
        clearTimeout(window.__clq); window.__clq = setTimeout(function () { if (t.value && t.value.length >= 3) send('search', { q: t.value.slice(0, 80) }); }, 1200);
      }
    }, true);
    // On-site interaction capture: link clicks (internal nav, outbound, downloads) and
    // copies (code-copy buttons + manual selection). Detail rides in the d field.
    // NB: this whole script is a template literal, so backslashes must be doubled.
    document.addEventListener('click', function (ev) {
      try {
        var tg = ev.target;
        var a = tg && tg.closest && tg.closest('a[href]');
        if (a) { var href = a.getAttribute('href') || ''; if (href && href.charAt(0) !== '#') send('click', { d: href.slice(0, 200) }); return; }
        var btn = tg && tg.closest && tg.closest('[class*="copyButton"], button[aria-label*="opy"]');
        if (btn) {
          var blk = btn.closest('div[class*="codeBlock"], .theme-code-block, pre');
          var code = blk && blk.querySelector ? blk.querySelector('code') : null;
          if (code) send('copy', { d: (code.innerText || '').replace(/\\s+/g, ' ').trim().slice(0, 160) });
        }
      } catch (e) {}
    }, true);
    document.addEventListener('copy', function () {
      try { var sel = (window.getSelection && String(window.getSelection())) || ''; if (sel.length >= 2) send('copy', { d: sel.replace(/\\s+/g, ' ').trim().slice(0, 160) }); } catch (e) {}
    }, true);
    document.addEventListener('visibilitychange', function () { if (document.visibilityState === 'hidden' && !sent) { sent = true; send('eng'); } });
    send('pv');
  }
  function enable() { loadFactors(); startBeacon(); }
  function dismiss() { var b = document.getElementById('cl-consent'); if (b && b.parentNode) b.parentNode.removeChild(b); }
  function accept() { setConsent('granted'); dismiss(); enable(); }
  function decline() { setConsent('denied'); dismiss(); }
  function banner() {
    if (document.getElementById('cl-consent')) return;
    var bar = document.createElement('div'); bar.id = 'cl-consent';
    var msg = document.createElement('p'); msg.className = 'cl-consent-msg';
    msg.appendChild(document.createTextNode('We use cookies to understand site traffic and improve the docs. '));
    var a = document.createElement('a'); a.href = '/privacy'; a.target = '_blank'; a.rel = 'noopener'; a.textContent = 'Privacy Policy';
    msg.appendChild(a);
    var grp = document.createElement('div'); grp.className = 'cl-consent-btns';
    var no = document.createElement('button'); no.type = 'button'; no.textContent = 'Necessary only'; no.className = 'cl-consent-btn cl-consent-decline'; no.onclick = decline;
    var yes = document.createElement('button'); yes.type = 'button'; yes.textContent = 'Accept'; yes.className = 'cl-consent-btn cl-consent-accept'; yes.onclick = accept;
    grp.appendChild(no); grp.appendChild(yes); bar.appendChild(msg); bar.appendChild(grp);
    document.body.appendChild(bar);
  }
  var consent = getCookie('cl_consent');
  var params = new URLSearchParams(location.search);
  var zone = (params.get('consent_zone') || '').toUpperCase();
  var country = zone || getCookie('cf_country');
  var regulated = !country || REGULATED.indexOf(country) >= 0;
  if (consent === 'granted') { enable(); }
  else if (consent === 'denied') { /* respect denial */ }
  else if (!regulated) { setConsent('granted'); enable(); }
  else { banner(); }
})();`,
          },
        ],
      };
    },
  };
}

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'CI/lock',
  tagline:
    'Signed evidence for every step in your software supply chain — build provenance, signed scan evidence, continuous compliance.',
  favicon: '/img/favicon.ico',

  url: 'https://cilock.dev',
  baseUrl: '/',

  headTags: [
    {
      tagName: 'meta',
      attributes: {
        name: 'description',
        content:
          "Cilock is an evidence collector for the software development lifecycle. SLSA-aligned in-toto attestations across CI, pre-production scans, and continuous compliance. Witness-compatible, built on the rookery attestor factory.",
      },
    },
    {
      tagName: 'meta',
      attributes: {
        name: 'keywords',
        content:
          'cilock, build provenance, in-toto, SLSA, DSSE, supply chain security, software supply chain, signed scan evidence, SBOM attestation, SARIF, continuous compliance, audit evidence, witness, rookery, attestor factory, GitHub Actions security, GitLab CI security',
      },
    },
  ],

  organizationName: 'aflock-ai',
  projectName: 'cilock',

  onBrokenLinks: 'warn',

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'warn',
    },
  },

  themes: [
    '@docusaurus/theme-mermaid',
    [
      require.resolve('@easyops-cn/docusaurus-search-local'),
      {
        hashed: true,
        indexBlog: false,
        docsRouteBasePath: '/',
      },
    ],
  ],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  plugins: [catalogAliasPlugin, factorsPlugin],

  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          path: 'docs',
          sidebarPath: './sidebars.js',
          routeBasePath: '/',
        },
        blog: {
          path: 'blog',
          routeBasePath: 'blog',
          blogTitle: 'CI/lock blog',
          blogDescription:
            'Notes on supply-chain security, signed builds, and shipping safely with AI coding agents.',
          showReadingTime: true,
          blogSidebarTitle: 'All posts',
          blogSidebarCount: 'ALL',
          postsPerPage: 10,
          feedOptions: {type: ['rss', 'atom'], title: 'CI/lock blog'},
          onInlineAuthors: 'ignore',
          onUntruncatedBlogPosts: 'ignore',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],

  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      image: 'img/cilock-og.png',
      metadata: [
        {
          name: 'og:type',
          content: 'website',
        },
        {
          name: 'twitter:card',
          content: 'summary_large_image',
        },
      ],
      navbar: {
        title: 'CI/lock',
        logo: {
          alt: 'CI/lock logo',
          src: 'img/logo.svg',
          srcDark: 'img/logo-dark.svg',
        },
        items: [
          {to: '/intro', position: 'left', label: 'Intro'},
          {
            type: 'doc',
            docId: 'getting-started/installation',
            position: 'left',
            label: 'Get Started',
          },
          {
            type: 'doc',
            docId: 'concepts/attestations',
            position: 'left',
            label: 'Concepts',
          },
          {
            type: 'doc',
            docId: 'tools/index',
            position: 'left',
            label: 'Supported Tools',
          },
          {to: '/blog', position: 'left', label: 'Blog'},
          {
            type: 'doc',
            docId: 'reference/cli',
            position: 'left',
            label: 'Reference',
          },
          {
            to: '/download',
            position: 'right',
            label: 'Download',
            className: 'navbar-download-cta',
          },
          {
            href: 'https://aflock.ai',
            position: 'right',
            label: 'aflock',
          },
          {
            href: 'https://github.com/aflock-ai/rookery',
            position: 'right',
            className: 'header-github-link',
            'aria-label': 'GitHub repository',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {label: 'Intro', to: '/intro'},
              {label: 'Get Started', to: '/getting-started/installation'},
              {label: 'Supported Tools', to: '/tools/'},
              {label: 'CLI Reference', to: '/reference/cli'},
              {label: 'FAQ', to: '/faq'},
            ],
          },
          {
            title: 'Ecosystem',
            items: [
              {label: 'aflock', href: 'https://aflock.ai'},
              {label: 'Rookery', href: 'https://github.com/aflock-ai/rookery'},
              {label: 'Witness', href: 'https://witness.dev'},
              {label: 'Archivista', href: 'https://github.com/in-toto/archivista'},
            ],
          },
          {
            title: 'Community',
            items: [
              {label: 'GitHub', href: 'https://github.com/aflock-ai/rookery'},
              {
                label: 'Discussions',
                href: 'https://github.com/orgs/aflock-ai/discussions',
              },
              {label: 'TestifySec', href: 'https://testifysec.com'},
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} TestifySec, Inc. Built with Docusaurus.`,
      },
      prism: {
        theme: prismThemes.github,
        darkTheme: prismThemes.dracula,
        additionalLanguages: ['json', 'bash', 'go', 'yaml', 'rego'],
      },
      mermaid: {
        theme: {light: 'neutral', dark: 'dark'},
      },
    }),
};

export default config;
