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
       body{overflow:hidden} on a desktop layout. */
    window.matchMedia('(max-width: 900px)').addEventListener('change', function (e) {
      if (!e.matches) set(false);
    });
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
})();
