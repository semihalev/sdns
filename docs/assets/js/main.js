/* sdns.dev — theme switch, generated table of contents, copy buttons, and the
   live repository counters. No dependencies, no analytics, no cookies. */
(function () {
  'use strict';

  document.addEventListener('DOMContentLoaded', function () {
    requestAnimationFrame(function () { document.body.classList.remove('preload'); });
    themeToggle();
    mobileMenu();
    tableOfContents();
    copyButtons();
    repoStats();
    search();
  });

  /* The stored value is removed when the choice matches the system, so the
     page goes back to following the OS instead of freezing on a copy of it. */
  function themeToggle() {
    var button = document.querySelector('.theme-toggle');
    if (!button) return;
    button.addEventListener('click', function () {
      var next = document.documentElement.getAttribute('theme') === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('theme', next);
      try {
        var system = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        if (next === system) localStorage.removeItem('theme');
        else localStorage.setItem('theme', next);
      } catch (e) {}
    });
  }

  /* The drawer is dismissable four ways — the button, the scrim, Escape, and
     following a link — because a panel that can only be closed by the control
     that opened it is a trap on a narrow screen. */
  function mobileMenu() {
    var button = document.querySelector('.menu-toggle');
    var nav = document.getElementById('site-nav');
    var scrim = document.querySelector('.nav-scrim');
    if (!button || !nav) return;

    if (scrim) scrim.removeAttribute('hidden');

    function set(open) {
      document.body.classList.toggle('nav-open', open);
      button.setAttribute('aria-expanded', open ? 'true' : 'false');
      /* The glyph says "close" once it is a cross; the accessible name has to
         say the same thing rather than staying "Open menu". */
      button.setAttribute('aria-label', open ? 'Close menu' : 'Open menu');
      if (open) {
        var first = nav.querySelector('a');
        if (first) first.focus();
      } else if (document.activeElement && nav.contains(document.activeElement)) {
        button.focus();
      }
    }

    button.addEventListener('click', function () {
      set(!document.body.classList.contains('nav-open'));
    });
    if (scrim) scrim.addEventListener('click', function () { set(false); });
    nav.addEventListener('click', function (e) {
      if (e.target.closest('a')) set(false);
    });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape' && document.body.classList.contains('nav-open')) set(false);
    });
    /* Leaving the breakpoint with the drawer open would otherwise strand
       body{overflow:hidden} on a desktop layout. Older WebKit has no
       addEventListener on MediaQueryList; calling it unguarded threw here and
       took the table of contents, the copy buttons and the counters with it. */
    var mq = window.matchMedia('(max-width: 900px)');
    var onChange = function (e) { if (!e.matches) set(false); };
    if (mq.addEventListener) mq.addEventListener('change', onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }

  /* Built from the rendered headings rather than written by hand, so a page
     cannot carry a contents list that disagrees with its own sections. */
  function tableOfContents() {
    var article = document.querySelector('.doc-main');
    if (!article) return;
    var headings = article.querySelectorAll('h2, h3');
    if (headings.length < 3) return;

    var nav = document.createElement('nav');
    nav.className = 'toc';
    nav.setAttribute('aria-label', 'On this page');
    var list = document.createElement('ul');
    nav.innerHTML = '<div class="toc-title">On this page</div>';

    Array.prototype.forEach.call(headings, function (h, i) {
      if (!h.id) h.id = 'section-' + i;
      var li = document.createElement('li');
      li.className = 'lvl-' + h.tagName.charAt(1);
      var a = document.createElement('a');
      a.href = '#' + h.id;
      a.textContent = h.textContent;
      li.appendChild(a);
      list.appendChild(li);
    });

    nav.appendChild(list);
    var lede = article.querySelector('.doc-lede');
    var anchor = lede || article.querySelector('h1');
    if (anchor && anchor.nextSibling) anchor.parentNode.insertBefore(nav, anchor.nextSibling);
    else article.insertBefore(nav, article.firstChild);
  }

  function copyButtons() {
    if (!navigator.clipboard) return;
    document.querySelectorAll('.doc-main pre, .home pre').forEach(function (pre) {
      if (pre.closest('.terminal')) return;
      var wrap = document.createElement('div');
      wrap.className = 'code-wrap';
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);

      var button = document.createElement('button');
      button.className = 'copy-button';
      button.type = 'button';
      button.textContent = 'copy';
      button.addEventListener('click', function () {
        navigator.clipboard.writeText(pre.innerText).then(function () {
          button.textContent = 'copied';
          setTimeout(function () { button.textContent = 'copy'; }, 1400);
        }).catch(function () {
          /* Denied permission, an unfocused document, Safari's gesture rules.
             Say so rather than leaving an uncaught rejection and a button
             that appears to have done nothing. */
          button.textContent = 'press \u2318C';
          setTimeout(function () { button.textContent = 'copy'; }, 1800);
        });
      });
      wrap.appendChild(button);
    });
  }

  /* Counters come from the API at view time rather than from the build, so
     the page cannot show a number that was true only when it was published.
     Unauthenticated and public-repo only; on any failure the placeholder
     simply stays. */
  function repoStats() {
    var container = document.querySelector('[data-repo]');
    if (!container) return;
    var repo = container.getAttribute('data-repo');

    /* One scrape per tab rather than one per page view. The unauthenticated
       API allows 60 requests an hour per address, and a reader walking ten
       documentation pages would otherwise spend a third of that. */
    var cached = readCache();
    if (cached) { paint(cached); return; }

    Promise.all([
      json('https://api.github.com/repos/' + repo),
      json('https://api.github.com/repos/' + repo + '/releases/latest')
    ]).then(function (r) {
      var d = { stars: r[0] && r[0].stargazers_count, forks: r[0] && r[0].forks_count,
                issues: r[0] && r[0].open_issues_count, release: r[1] && r[1].tag_name };
      writeCache(d);
      paint(d);
    }).catch(function () {});

    function json(url) {
      return fetch(url, { headers: { Accept: 'application/vnd.github+json' } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .catch(function () { return null; });
    }
    function readCache() {
      try {
        var raw = sessionStorage.getItem('repo:' + repo);
        return raw ? JSON.parse(raw) : null;
      } catch (e) { return null; }
    }
    /* Only a complete result is cached. A rate-limited or offline fetch
       resolves to nulls rather than rejecting, and storing that would make
       readCache truthy for the rest of the session — one failed load would
       freeze the counters until the tab was closed. */
    function writeCache(d) {
      if (typeof d.stars !== 'number' || !d.release) return;
      try { sessionStorage.setItem('repo:' + repo, JSON.stringify(d)); } catch (e) {}
    }

    function paint(d) {
      set('stars', d.stars);
      set('forks', d.forks);
      set('issues', d.issues);

      /* The star pill is on every page; the repository panel is only on the
         homepage. Both read the same fetch. */
      var star = document.querySelector('[data-stars]');
      if (star && typeof d.stars === 'number') star.textContent = compact(d.stars);

      if (!d.release) return;
      var el = document.querySelector('[data-stat="release"]');
      if (el) { el.textContent = d.release; el.removeAttribute('data-loading'); }
      /* The header pill renders a config value, which is correct until the
         next release and wrong forever after. Correct it from the real tag. */
      var pill = document.querySelector('.version-pill');
      if (pill) pill.textContent = d.release;
    }

    function compact(v) {
      return v >= 1000 ? (v / 1000).toFixed(1) + 'k' : String(v);
    }

    function set(name, value) {
      var el = document.querySelector('[data-stat="' + name + '"]');
      if (!el || typeof value !== 'number') return;
      el.textContent = compact(value);
      el.removeAttribute('data-loading');
    }
  }

  /* Section-level search over /search.json. No library: the index is 169
     entries, so a scan per keystroke is cheaper than shipping a search engine
     to every reader. Fetched on first open — most visitors never search.

     The panel is a native <dialog> opened with showModal, which supplies the
     focus trap, Escape, and an inert page behind it. Hand-rolling those is how
     the first version let Tab wander out of the modal. */
  function search() {
    var dialog = document.querySelector('[data-search-dialog]');
    var input = document.querySelector('[data-search-input]');
    var results = document.querySelector('[data-search-results]');
    var count = document.querySelector('[data-search-count]');
    if (!dialog || !input || !results || !dialog.showModal) return;

    var index = null, hits = [], active = -1, timer = null;

    var mac = /Mac|iPhone|iPad/.test(navigator.userAgent);
    var keyHint = document.querySelector('[data-search-key]');
    if (keyHint) keyHint.textContent = mac ? '\u2318K' : 'Ctrl K';

    document.querySelectorAll('[data-search-open]').forEach(function (b) {
      b.addEventListener('click', open);
    });
    document.querySelectorAll('[data-search-close]').forEach(function (b) {
      b.addEventListener('click', function () { dialog.close(); });
    });

    /* Clicking the backdrop closes. The dialog element covers only the panel,
       so a click whose coordinates fall outside its box came from the
       backdrop — on mobile the panel is the whole screen and this never
       fires, which is why the close button exists. */
    dialog.addEventListener('click', function (e) {
      var r = dialog.getBoundingClientRect();
      if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) {
        dialog.close();
      }
    });
    dialog.addEventListener('close', function () {
      document.documentElement.style.overflow = '';
      input.setAttribute('aria-expanded', 'false');
      input.removeAttribute('aria-activedescendant');
      active = -1;
    });

    document.addEventListener('keydown', function (e) {
      var typing = /^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName) || e.target.isContentEditable;
      if ((e.metaKey || e.ctrlKey) && (e.key === 'k' || e.key === 'K')) { e.preventDefault(); open(); return; }
      if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey && !e.altKey) { e.preventDefault(); open(); }
    });

    /* Arrow and Enter handling belongs to the input, not the document. A
       document-level Enter opened the internally selected hit even when the
       reader had tabbed to a different result — so a focused link now
       activates natively, and only the input drives the selection. */
    input.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
      else if (e.key === 'Enter' && active >= 0 && hits[active]) {
        e.preventDefault();
        window.location.href = hits[active].u;
      }
    });

    input.addEventListener('input', function () {
      clearTimeout(timer);
      timer = setTimeout(function () { run(input.value); }, 90);
    });

    function open() {
      if (dialog.open) { input.focus(); input.select(); return; }
      input.value = '';
      render([], '');
      dialog.showModal();
      document.documentElement.style.overflow = 'hidden';
      input.focus();
      load();
    }

    function load() {
      if (index) return;
      var base = document.querySelector('link[rel="icon"]');
      var prefix = '';
      if (base) {
        var href = base.getAttribute('href');
        var cut = href.indexOf('/assets/');
        if (cut > 0) prefix = href.substring(0, cut);
      }
      fetch(prefix + '/search.json')
        .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
        .then(function (data) {
          /* strip_html leaves &lt; and &amp; behind, so the index held the
             encoded form: a reader searching "<token>" or "&&" matched
             nothing, and a snippet could render as &amp;lt;token&gt;. Decode
             once here — everything downstream then works on visible text and
             escapes only what it puts into the DOM. */
          var box = document.createElement('textarea');
          var decode = function (s) { box.innerHTML = s; return box.value; };
          index = data.map(function (e) {
            return { t: decode(e.t), p: decode(e.p), c: decode(e.c), u: e.u, b: decode(e.b) };
          });
          if (input.value) run(input.value);
        })
        .catch(function () {
          results.innerHTML = '<div class="search-empty">The search index could not be loaded.</div>';
        });
    }

    function run(q) {
      q = q.trim();
      if (!q) { render([], ''); return; }
      if (!index) { results.innerHTML = '<div class="search-empty">Loading\u2026</div>'; return; }
      var terms = q.toLowerCase().split(/\s+/).filter(Boolean);
      var scored = [];
      for (var i = 0; i < index.length; i++) {
        var e = index[i];
        var t = e.t.toLowerCase(), p = e.p.toLowerCase(), b = e.b.toLowerCase();
        var score = 0, all = true;
        for (var j = 0; j < terms.length; j++) {
          var term = terms[j], sc = 0;
          /* A heading match is what the reader is usually after; the page
             title next; the body last and only once, so a long section does
             not outrank a precise heading by repetition. */
          if (t.indexOf(term) >= 0) sc += t.indexOf(term) === 0 ? 12 : 8;
          if (p.indexOf(term) >= 0) sc += 4;
          if (b.indexOf(term) >= 0) sc += 1;
          if (sc === 0) { all = false; break; }
          score += sc;
        }
        if (all) scored.push({ e: e, score: score });
      }
      scored.sort(function (a, b) { return b.score - a.score; });
      hits = scored.slice(0, 30).map(function (x) { return x.e; });
      render(hits, terms[0]);
    }

    function render(list, term) {
      active = -1;
      input.removeAttribute('aria-activedescendant');
      input.setAttribute('aria-expanded', list.length ? 'true' : 'false');
      if (count) count.textContent = list.length ? list.length + (list.length === 30 ? '+ results' : ' results') : '';
      if (!list.length) {
        results.innerHTML = '<div class="search-empty">' +
          (input.value.trim() ? 'Nothing matched.' : 'Search headings and text across every page.') +
          '</div>';
        return;
      }
      var html = '';
      for (var i = 0; i < list.length; i++) {
        var e = list[i];
        html += '<a class="search-hit" role="option" id="search-hit-' + i + '" aria-selected="false" href="' + e.u + '">' +
          '<span class="search-hit-top"><span class="search-hit-title">' + mark(e.t, term) + '</span>' +
          '<span class="search-hit-page">' + esc(e.c) + ' \u00b7 ' + esc(e.p) + '</span></span>' +
          '<span class="search-hit-body">' + mark(snippet(e.b, term), term) + '</span></a>';
      }
      results.innerHTML = html;
      Array.prototype.forEach.call(results.children, function (el, i) {
        el.addEventListener('mouseenter', function () { select(i); });
      });
      select(0);
    }

    /* Show the text around the match rather than the start of the section:
       sections are indexed whole, so the match is often far into one. */
    function snippet(body, term) {
      if (!term) return body.slice(0, 160);
      var at = body.toLowerCase().indexOf(term);
      if (at < 0) return body.slice(0, 160);
      var from = Math.max(0, at - 60);
      return (from > 0 ? '\u2026' : '') + body.slice(from, from + 170);
    }

    function esc(s) {
      return String(s).replace(/[&<>"]/g, function (c) {
        return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c];
      });
    }

    /* Find the match in the plain text, then escape each piece separately.
       Escaping first and searching the escaped string made the offsets wrong
       for any text containing < & or ", and could split an entity in half. */
    function mark(text, term) {
      if (!term) return esc(text);
      var at = text.toLowerCase().indexOf(term.toLowerCase());
      if (at < 0) return esc(text);
      return esc(text.slice(0, at)) + '<mark>' + esc(text.slice(at, at + term.length)) +
             '</mark>' + esc(text.slice(at + term.length));
    }

    function select(i) {
      var items = results.children;
      if (!items.length) return;
      if (active >= 0 && items[active]) items[active].setAttribute('aria-selected', 'false');
      active = Math.max(0, Math.min(i, items.length - 1));
      items[active].setAttribute('aria-selected', 'true');
      input.setAttribute('aria-activedescendant', items[active].id);
      items[active].scrollIntoView({ block: 'nearest' });
    }

    function move(step) {
      if (!results.children.length) return;
      var next = active + step;
      if (next < 0) next = results.children.length - 1;
      if (next >= results.children.length) next = 0;
      select(next);
    }
  }
})();
