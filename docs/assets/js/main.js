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

  function mobileMenu() {
    var button = document.querySelector('.menu-toggle');
    if (!button) return;
    button.addEventListener('click', function () {
      var open = document.body.classList.toggle('nav-open');
      button.setAttribute('aria-expanded', open ? 'true' : 'false');
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

    fetch('https://api.github.com/repos/' + repo, { headers: { Accept: 'application/vnd.github+json' } })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) {
        set('stars', d.stargazers_count);
        set('forks', d.forks_count);
        set('issues', d.open_issues_count);
      })
      .catch(function () {});

    fetch('https://api.github.com/repos/' + repo + '/releases/latest', { headers: { Accept: 'application/vnd.github+json' } })
      .then(function (r) { return r.ok ? r.json() : Promise.reject(r.status); })
      .then(function (d) {
        if (!d.tag_name) return;
        var el = container.querySelector('[data-stat="release"]');
        if (el) {
          el.textContent = d.tag_name;
          el.removeAttribute('data-loading');
        }
        /* The header pill is built from a config value, which is correct until
           the next release and wrong forever after. Correct it here rather
           than relying on someone remembering to edit _config.yml. */
        var pill = document.querySelector('.version-pill');
        if (pill) pill.textContent = d.tag_name;
      })
      .catch(function () {});

    function set(name, value) {
      var el = container.querySelector('[data-stat="' + name + '"]');
      if (!el || typeof value !== 'number') return;
      el.textContent = value >= 1000 ? (value / 1000).toFixed(1) + 'k' : String(value);
      el.removeAttribute('data-loading');
    }
  }
})();
