# Agent Circuit Breaker Website

Static product website for local preview and future static hosting.

Run from the repository root:

```bash
python -m http.server 8080
```

Then open:

```text
http://localhost:8080/docs/
```

The site intentionally has no frontend build step or runtime dependency. Before
publishing to a different domain, update the canonical URL, Open Graph URL,
`robots.txt`, and `sitemap.xml`.
