# DetLab static website deployment

DetLab is now prepared to deploy as a static website.

## What changed
- `web/next.config.mjs` uses `output: 'export'`
- `web/next.config.mjs` uses `trailingSlash: true`
- `npm run build` produces a deployable artifact under `web/out/`
- `npm run start` previews that static artifact locally with Python's built-in HTTP server

## Local verification workflow

```bash
cd web
npm install
npm test
npm run build
npm run start
```

Then open:
- `http://127.0.0.1:3000/`

## Deployable artifact

After a successful build, deploy the contents of:

```text
web/out/
```

That directory can be served by:
- Nginx
- Caddy
- Cloudflare Pages
- GitHub Pages
- Netlify
- any static file host

## GitHub Pages target

This repo is prepared to publish via GitHub Actions to GitHub Pages.

Current test URL:
- `https://egrexsec.github.io/DetLab-DAC/`

Supporting files:
- `.github/workflows/pages.yml`
- `web/public/.nojekyll`

The Pages workflow builds with a project-repo base path so the exported site works correctly under `/DetLab-DAC/`.

## Minimal VPS deployment shape

Example target path:

```bash
/var/www/detlab-dac/current
```

Example publish flow from the repo root:

```bash
cd web
npm ci
npm run build
sudo mkdir -p /var/www/detlab-dac
sudo rsync -av --delete out/ /var/www/detlab-dac/current/
```

## Example Nginx server block

```nginx
server {
    listen 80;
    server_name detlab.example.com;

    root /var/www/detlab-dac/current;
    index index.html;

    location / {
        try_files $uri $uri/ =404;
    }
}
```

Because the site is exported with trailing slashes, nested routes like `/content/detections/` map cleanly to static `index.html` files.

## Operational notes
- No Node.js app server is required in production if you deploy `web/out/` to a static host.
- Re-deploy means rebuilding `web/out/` and syncing that directory to the host.
- This is the safest deployment shape for the current repo because the site is content-first and fully static.
