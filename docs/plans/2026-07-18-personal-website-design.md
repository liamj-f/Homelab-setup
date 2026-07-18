# Personal website — design

## Goal

A personal portfolio/homelab site for Liam James-Fagg, modeled on
georgedenton.co.uk's structure and "engineering blueprint" aesthetic, but with
original content and CSS. Containerized so it runs alongside the other
services in this repo, reverse-proxied through the existing Nginx Proxy
Manager instance.

## Architecture

- **Astro** static site generator. No server-side runtime, no database — the
  build output is plain HTML/CSS/JS.
- New top-level folder `website/`, following the existing per-service
  convention (`grampsweb/`, `nextcloud/`, etc.):
  - `website/src/` — Astro source (pages, components, content data files)
  - `website/Dockerfile` — multi-stage build: a Node image runs `astro build`,
    then the static `dist/` output is copied into a slim `nginx:alpine` image
    that serves the files
  - `website/website-compose.yml` — compose file matching the shape of the
    other `*-compose.yml` files in this repo
- The container joins the existing external `nginx_network` (the same network
  `nginx-proxy-manager` uses in `nginx-compose.yml`), so a Proxy Host entry in
  the NPM UI is all that's needed to route a hostname to it. Exact hostname
  (subdomain of an existing domain, or something new) is decided later by the
  user directly in NPM — out of scope for this build.
- No persistent volumes needed. Redeploying is: rebuild image, `docker compose
  up -d`.

## Content structure

Single page, five anchored sections, matching the reference site's shape:

1. **About** — tagline from CV ("Technical manager for data; engineering,
   analytics, science, administration and governance. Making data warehouses
   useful.") plus a short bio blending the data-leadership career with the
   homelab/outdoors grounding (Explorer Scout Leader).
2. **Experience** — full timeline, in reverse-chronological order:
   - Allpay Ltd — Head of Data (Mar 2026–present) / Data & Insights Manager
     (Oct 2022–Mar 2026) / Business Intelligence Analyst (May 2020–Oct 2022)
   - Operose Health — Business Intelligence Analyst (Apr 2018–May 2020)
   - The Zinc Group — Client Services Administrator (Jan 2017–Apr 2018) /
     Customer Account Manager (Aug 2016–Jan 2017)
   - British Army — Officer Cadet, Wales Universities OTC (Sep 2014–Sep 2015)
   - St John Ambulance — Emergency Medical Technician & District Training
     Officer (Aug 2016–Jan 2022)
   - The Scout Association — Assistant Explorer Scout Leader, volunteer (Aug
     2016–current)
3. **Projects** — case studies sourced from this repo:
   - Homelab-setup — the overall multi-site Docker/Keepalived/Rathole
     infrastructure (this repo as a whole)
   - OCI Cert Updater (`oci-cert-updater/`) — automated certificate rotation
     script
   - Dynamic IP Updater (`dynamic-ip-updater/`) — OCI security list updater
     for a dynamic home IP
   - GrampsWeb deployment (`grampsweb/`) — self-hosted genealogy app with
     custom bootstrap/owner provisioning
4. **Homelab** — deep dive reusing the README's architecture description
   (Dell E7270 + Raspberry Pi 4 keepalived failover pair, Oracle Cloud tunnel
   via Rathole, WAF/load balancer front door) plus the existing Mermaid
   diagram from `README.md`, rendered as an actual diagram on the page.
5. **Stack** — categorized skills combining the professional data stack
   (Power BI, Azure Data Factory, Databricks, T-SQL/Python/R/KQL, etc., from
   the CV) with the homelab stack (Docker, Nginx Proxy Manager, Keepalived,
   Portainer, Traefik, Pi-hole, DuckDNS, Rathole).

Content lives in typed data files (`src/data/experience.ts`, `projects.ts`,
`stack.ts`) separate from layout/presentation components, so future content
edits don't require touching markup.

## Visual theme

Same "engineering blueprint" aesthetic as the reference: monospace type,
sparse palette, "FIG. NN" figure numbering, "//—" section-heading prefixes, a
"REV" date marker. Built as original CSS/components (not copied from George
Denton's site), with a distinct accent color so it reads as its own thing.

## Out of scope

- Choosing/configuring the final public hostname and NPM proxy host entry —
  user will do this after the container is running.
- CI/CD for auto-deploying on push — not requested; can be a future addition.
- CMS or dynamic content editing — content is static and edited in-repo.
