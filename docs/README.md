# sdns.dev

The site behind <https://sdns.dev>: a Jekyll build deployed to GitHub Pages by
`.github/workflows/pages.yml` on every push to `main`.

## Running it locally

```bash
cd docs
bundle install
bundle exec jekyll serve --livereload
```

Then open <http://127.0.0.1:4000>. Edits to pages and assets rebuild on save;
changes to `_config.yml` need a restart.

## Adding a documentation page

Create `_docs/<category-slug>/<page>.md`:

```yaml
---
layout: doc
title: Serve-stale
category: Features          # must match a name in _data/doc_categories.yml
order: 5                    # position within that category
description: One line shown under the title.  # optional
---
```

The sidebar order comes from `_data/doc_categories.yml` (the order of the list
is the order on screen); pages sort inside a category by `order`. The table of
contents and the previous/next links are generated, do not write them by hand.
