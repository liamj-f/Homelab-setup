# Personal Website Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build and containerize a personal portfolio/homelab site for Liam James-Fagg (Astro static site, blueprint aesthetic), deployable through this repo's existing Nginx Proxy Manager + Portainer GitOps pipeline.

**Architecture:** Astro static site in `website/`, built to plain HTML/CSS/JS with zero client-side JS except a single Mermaid-powered diagram island in the Homelab section. Multi-stage Dockerfile (Node build → `nginx:alpine` runtime) produces `ghcr.io/liamj-f/website`. A `website-compose.yml` joins the existing external `nginx_network`. A GitHub Actions workflow builds/pushes the image to GHCR and redeploys the Portainer stack via webhook, mirroring `oci-containers-deploy.yml` (build+push) and `dovetrek-pwa-redeploy.yml` (Portainer GitOps redeploy).

**Tech Stack:** Astro (TypeScript), plain CSS (custom properties, no framework), `mermaid` npm package for the one diagram, Docker multi-stage build, `nginx:alpine`, GitHub Actions (`docker/build-push-action`, Portainer REST API).

**Design doc:** `docs/plans/2026-07-18-personal-website-design.md`

---

## Content reference (from CV and this repo — use verbatim in data files)

**Tagline:** "Technical manager for data; engineering, analytics, science, administration and governance. Making data warehouses useful."

**Experience (reverse chronological):**
1. Allpay Ltd — Head of Data (Mar 2026–Present)
2. Allpay Ltd — Data & Insights Manager (Oct 2022–Mar 2026)
3. Allpay Ltd — Business Intelligence Analyst (May 2020–Oct 2022)
4. Operose Health — Business Intelligence Analyst (Apr 2018–May 2020)
5. The Zinc Group — Client Services Administrator (Jan 2017–Apr 2018)
6. The Zinc Group — Customer Account Manager (Aug 2016–Jan 2017)
7. British Army — Officer Cadet, Wales Universities OTC (Sep 2014–Sep 2015)
8. St John Ambulance — Emergency Medical Technician & District Training Officer (Aug 2016–Jan 2022)
9. The Scout Association — Assistant Explorer Scout Leader, volunteer (Aug 2016–Present)

**Stack (professional):** Data Warehousing & Modelling (Kimball & Inmon), Data Architecture, Power BI & Power Query, Tableau, Crystal Reports, SSRS/SSIS, Power Automate & Logic Apps, Azure Data Factory, Databricks, NoSQL (CosmosDB), Machine Learning & AI, CI/CD pipelines, ELT, Agile/Scrum, T-SQL/MySQL/SparkSQL, Python, R, KQL, M Formula, VBA.

**Stack (homelab):** Docker & Docker Compose, Nginx Proxy Manager, Keepalived, Portainer, Traefik, Pi-hole, DuckDNS, Rathole, GitHub Actions/Portainer GitOps.

**Projects (from this repo):**
- **Homelab-setup** — multi-site Docker infrastructure across a Dell E7270 + Raspberry Pi 4 Keepalived failover pair (on-prem) and an Oracle Cloud VM (tunnel/WAF front door via Rathole).
- **OCI Cert Updater** (`oci-cert-updater/`) — Python service that uploads Nginx Proxy Manager's renewed Let's Encrypt certs to OCI's Certificate Service so the OCI Load Balancer can serve them.
- **Dynamic IP Updater** (`dynamic-ip-updater/`) — Python service that keeps an OCI Network Security Group whitelist in sync with a dynamic home IP.
- **GrampsWeb deployment** (`grampsweb/`) — self-hosted genealogy app with a custom bootstrap script for owner/tree provisioning.

**Homelab architecture summary (sanitized — no internal IPs/hostnames):** Public traffic resolves via Porkbun/DuckDNS nameservers to an Oracle Cloud Load Balancer sitting behind a Web Application Firewall. That forwards to an Nginx Proxy Manager instance on an OCI VM, which either serves OCI-hosted apps directly or tunnels (via Rathole) back to the home network. On-prem, a Raspberry Pi 4 and Dell E7270 run Keepalived for failover, each running their own Nginx Proxy Manager + Pi-hole + Rathole client, fronting services like Nextcloud, GrampsWeb, and Portainer.

---

## Task 1: Scaffold the Astro project

**Files:**
- Create: `website/package.json`
- Create: `website/astro.config.mjs`
- Create: `website/tsconfig.json`
- Create: `website/.gitignore`

**Step 1: Create the directory and package.json**

```json
{
  "name": "liamjamesfagg-website",
  "private": true,
  "type": "module",
  "scripts": {
    "dev": "astro dev",
    "build": "astro build",
    "preview": "astro preview"
  },
  "dependencies": {
    "astro": "^5.2.0",
    "mermaid": "^11.4.1"
  }
}
```

**Step 2: Create astro.config.mjs**

```js
import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://liam.james-fagg.uk',
  output: 'static',
});
```

**Step 3: Create tsconfig.json**

```json
{
  "extends": "astro/tsconfigs/strict"
}
```

**Step 4: Create .gitignore**

```
node_modules/
dist/
.astro/
```

**Step 5: Install dependencies and verify the dev server boots**

Run (from `website/`): `npm install && npm run build`
Expected: build succeeds, producing `website/dist/` (it will just contain a 404 since there's no page yet — that's fine, this step only proves the toolchain works). If `astro build` errors because there are zero pages, add a placeholder `src/pages/index.astro` containing `<h1>placeholder</h1>` first, confirm the build succeeds, then continue to Task 2 where it gets replaced.

**Step 6: Commit**

```bash
git add website/package.json website/astro.config.mjs website/tsconfig.json website/.gitignore website/package-lock.json
git commit -m "Scaffold Astro project for personal website"
```

---

## Task 2: Base layout and blueprint theme CSS

**Files:**
- Create: `website/src/styles/global.css`
- Create: `website/src/layouts/BaseLayout.astro`

**Step 1: Write the theme CSS**

```css
/* website/src/styles/global.css */
:root {
  --color-bg: #f4f2ec;
  --color-ink: #1a1a1a;
  --color-line: #1a1a1a33;
  --color-accent: #2f5d50; /* distinct from georgedenton.co.uk's accent */
  --color-muted: #5c5850; /* AA-contrast (6.3:1) against --color-bg, unlike an opacity trick */
  --font-mono: "JetBrains Mono", "Consolas", "SFMono-Regular", monospace;
  --content-width: 760px;
}

@media (prefers-color-scheme: dark) {
  :root {
    --color-bg: #14171a;
    --color-ink: #e8e6df;
    --color-line: #e8e6df33;
    --color-accent: #6fbf9a;
    --color-muted: #a8a49a; /* AA-contrast (7.2:1) against dark --color-bg */
  }
}

* { box-sizing: border-box; }

body {
  margin: 0;
  background: var(--color-bg);
  color: var(--color-ink);
  font-family: var(--font-mono);
  line-height: 1.5;
}

main {
  max-width: var(--content-width);
  margin: 0 auto;
  padding: 2rem 1.25rem 6rem;
}

a { color: var(--color-accent); }

.fig-label {
  font-size: 0.75rem;
  letter-spacing: 0.05em;
  color: var(--color-muted);
}

.section-heading::before {
  content: "//\2014 ";
  color: var(--color-accent);
}

section {
  border-top: 1px solid var(--color-line);
  padding: 2.5rem 0;
}
```

**Step 2: Write the base layout**

```astro
---
// website/src/layouts/BaseLayout.astro
import '../styles/global.css';

interface Props {
  title: string;
}
const { title } = Astro.props;
---
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{title}</title>
  </head>
  <body>
    <slot />
  </body>
</html>
```

**Step 3: Wire a placeholder page to the layout and verify the build**

Replace `website/src/pages/index.astro` with:

```astro
---
import BaseLayout from '../layouts/BaseLayout.astro';
---
<BaseLayout title="Liam James-Fagg">
  <main><p class="fig-label">FIG. 00 LJF — REV 2026</p></main>
</BaseLayout>
```

Run: `npm run build` (from `website/`)
Expected: build succeeds, `dist/index.html` contains `FIG. 00 LJF`.

**Step 4: Commit**

```bash
git add website/src/styles/global.css website/src/layouts/BaseLayout.astro website/src/pages/index.astro
git commit -m "Add base layout and blueprint theme styles"
```

---

## Task 3: Header/nav and footer components

**Files:**
- Create: `website/src/components/Header.astro`
- Create: `website/src/components/Footer.astro`

**Step 1: Write Header.astro**

```astro
---
const navItems = [
  { href: '#about', label: 'About' },
  { href: '#experience', label: 'Experience' },
  { href: '#projects', label: 'Projects' },
  { href: '#homelab', label: 'Homelab' },
  { href: '#stack', label: 'Stack' },
];
---
<header>
  <p class="fig-label">FIG. 00 LJF — REV 2026</p>
  <nav>
    <ul style="display:flex; gap:1.25rem; list-style:none; padding:0; margin:0.5rem 0 0;">
      {navItems.map((item) => (
        <li><a href={item.href}>{item.label}</a></li>
      ))}
    </ul>
  </nav>
</header>
```

**Step 2: Write Footer.astro**

```astro
---
const year = new Date().getFullYear();
---
<footer style="border-top:1px solid var(--color-line); margin-top:2rem; padding-top:1.5rem; display:flex; justify-content:space-between; font-size:0.85rem;">
  <span>&copy; {year} Liam James-Fagg</span>
  <span>
    <a href="https://github.com/liamj-f" target="_blank" rel="noopener" aria-label="GitHub (opens in new tab)">GitHub</a>
    &nbsp;·&nbsp;
    <a href="https://www.linkedin.com/in/liam-james-fagg/" target="_blank" rel="noopener" aria-label="LinkedIn (opens in new tab)">LinkedIn</a>
  </span>
</footer>
```

**Step 3: Drop both into the page and verify**

Update `index.astro`'s `<main>` to include `<Header />` above the placeholder paragraph and `<Footer />` below it (import both at the top). Run `npm run build`, expected: succeeds, `dist/index.html` contains `Experience` and `Liam James-Fagg`.

**Step 4: Commit**

```bash
git add website/src/components/Header.astro website/src/components/Footer.astro website/src/pages/index.astro
git commit -m "Add header nav and footer components"
```

---

## Task 4: Content data files

**Files:**
- Create: `website/src/data/experience.ts`
- Create: `website/src/data/projects.ts`
- Create: `website/src/data/stack.ts`

**Step 1: experience.ts**

```ts
export interface ExperienceEntry {
  org: string;
  role: string;
  dates: string;
  bullets?: string[];
}

export const experience: ExperienceEntry[] = [
  {
    org: 'Allpay Ltd',
    role: 'Head of Data',
    dates: 'Mar 2026 – Present',
    bullets: [
      'Grew the data function into four areas: analytics, engineering, Power Platform, and database administration.',
      'Set data strategy and AI adoption direction, and brought data governance (lineage, cataloguing, classification) into regular practice.',
      'Chairs the Change Approval Board and acts as Incident Manager for major business/client-facing incidents.',
    ],
  },
  {
    org: 'Allpay Ltd',
    role: 'Data & Insights Manager',
    dates: 'Oct 2022 – Mar 2026',
  },
  {
    org: 'Allpay Ltd',
    role: 'Business Intelligence Analyst',
    dates: 'May 2020 – Oct 2022',
    bullets: [
      'Shifted the business to a Power BI-first analytics culture, moving off SSRS and Crystal Reports.',
      'Modelled data marts using Kimball methodology and slowly changing dimensions.',
      'Automated prepaid card reconciliation into a stored-procedure endpoint, saving the payments team ~2 hours/day.',
    ],
  },
  {
    org: 'Operose Health',
    role: 'Business Intelligence Analyst',
    dates: 'Apr 2018 – May 2020',
    bullets: [
      'Built clinician-facing dashboards for Forward Thinking Birmingham (under-25s mental health partnership) at Birmingham Children’s Hospital.',
      'Used R (network3d, rpart) to surface cyclical service usage patterns by diagnosis.',
    ],
  },
  { org: 'The Zinc Group', role: 'Client Services Administrator', dates: 'Jan 2017 – Apr 2018' },
  { org: 'The Zinc Group', role: 'Customer Account Manager', dates: 'Aug 2016 – Jan 2017' },
  { org: 'British Army', role: 'Officer Cadet, Wales Universities OTC', dates: 'Sep 2014 – Sep 2015' },
  {
    org: 'St John Ambulance',
    role: 'Emergency Medical Technician & District Training Officer',
    dates: 'Aug 2016 – Jan 2022',
  },
  {
    org: 'The Scout Association',
    role: 'Assistant Explorer Scout Leader (Volunteer)',
    dates: 'Aug 2016 – Present',
  },
];
```

**Step 2: projects.ts**

```ts
export interface Project {
  name: string;
  description: string;
  tags: string[];
  link?: string;
}

export const projects: Project[] = [
  {
    name: 'Homelab-setup',
    description:
      'Multi-site Docker infrastructure spanning a Keepalived failover pair on-prem (Dell E7270 + Raspberry Pi 4) and an Oracle Cloud VM acting as tunnel and WAF front door.',
    tags: ['Docker Compose', 'Keepalived', 'Rathole', 'OCI'],
    link: 'https://github.com/liamj-f/homelab-setup',
  },
  {
    name: 'OCI Cert Updater',
    description:
      'Python service that uploads Nginx Proxy Manager’s renewed Let’s Encrypt certificates to OCI’s Certificate Service so the OCI Load Balancer can serve current SSL.',
    tags: ['Python', 'OCI', 'Automation'],
  },
  {
    name: 'Dynamic IP Updater',
    description:
      'Python service that keeps an OCI Network Security Group whitelist synchronised with a dynamic home IP address.',
    tags: ['Python', 'OCI', 'Networking'],
  },
  {
    name: 'GrampsWeb Deployment',
    description:
      'Self-hosted genealogy application with a custom bootstrap script handling owner and family-tree provisioning.',
    tags: ['Docker', 'Postgres', 'Genealogy'],
  },
];
```

**Step 3: stack.ts**

```ts
export interface StackGroup {
  category: string;
  items: string[];
}

export const stack: StackGroup[] = [
  {
    category: 'Data & Analytics',
    items: [
      'Data Warehousing (Kimball & Inmon)',
      'Power BI & Power Query',
      'Tableau',
      'SSRS / SSIS',
      'Azure Data Factory',
      'Databricks',
      'CosmosDB',
    ],
  },
  {
    category: 'Languages',
    items: ['T-SQL / MySQL / SparkSQL', 'Python', 'R', 'KQL', 'M Formula', 'VBA'],
  },
  {
    category: 'Practices',
    items: ['CI/CD Pipelines', 'ELT', 'Agile/Scrum', 'Data Governance'],
  },
  {
    category: 'Homelab',
    items: [
      'Docker & Docker Compose',
      'Nginx Proxy Manager',
      'Keepalived',
      'Portainer',
      'Traefik',
      'Pi-hole',
      'DuckDNS',
      'Rathole',
      'GitHub Actions / Portainer GitOps',
    ],
  },
];
```

**Step 4: Verify the data files type-check**

Run: `npx astro check` (from `website/`)
Expected: no type errors referencing these three files.

**Step 5: Commit**

```bash
git add website/src/data/experience.ts website/src/data/projects.ts website/src/data/stack.ts
git commit -m "Add experience, projects, and stack content data"
```

---

## Task 5: About and Experience section components

**Files:**
- Create: `website/src/components/About.astro`
- Create: `website/src/components/Experience.astro`

**Step 1: About.astro**

```astro
<section id="about">
  <h2 class="section-heading">About</h2>
  <p>
    Technical manager for data; engineering, analytics, science, administration
    and governance. Making data warehouses useful.
  </p>
  <p>
    I lead the data function at a UK payments processor, having grown it from
    a team of two into four specialist areas covering analytics, engineering,
    low-code Power Platform delivery, and database administration. Outside of
    work I ground myself outdoors as an Explorer Scout Leader, and I run this
    homelab as a place to keep building hands-on with infrastructure I don't
    touch day-to-day.
  </p>
</section>
```

**Step 2: Experience.astro**

```astro
---
import { experience } from '../data/experience';
---
<section id="experience">
  <h2 class="section-heading">Experience</h2>
  {experience.map((entry) => (
    <article style="margin-bottom:1.5rem;">
      <p style="margin-bottom:0.15rem;">
        <strong>{entry.org}</strong> — <em>{entry.role}</em>
      </p>
      <p class="fig-label" style="margin-top:0;">{entry.dates}</p>
      {entry.bullets && (
        <ul>
          {entry.bullets.map((bullet) => <li>{bullet}</li>)}
        </ul>
      )}
    </article>
  ))}
</section>
```

**Step 3: Add both to index.astro and verify**

Import and render `<About />` and `<Experience />` inside `<main>`, between `<Header />` and `<Footer />`. Run `npm run build`.
Expected: succeeds, `dist/index.html` contains "Making data warehouses useful" and "Allpay Ltd".

**Step 4: Commit**

```bash
git add website/src/components/About.astro website/src/components/Experience.astro website/src/pages/index.astro
git commit -m "Add About and Experience sections"
```

---

## Task 6: Projects section component

**Files:**
- Create: `website/src/components/Projects.astro`

**Step 1: Write the component**

```astro
---
import { projects } from '../data/projects';
---
<section id="projects">
  <h2 class="section-heading">Projects</h2>
  {projects.map((project) => (
    <article style="margin-bottom:1.5rem;">
      <p style="margin-bottom:0.15rem;">
        <strong>{project.link ? <a href={project.link} target="_blank" rel="noopener">{project.name}</a> : project.name}</strong>
      </p>
      <p style="margin:0.25rem 0;">{project.description}</p>
      <p class="fig-label">{project.tags.join(' · ')}</p>
    </article>
  ))}
</section>
```

**Step 2: Add to index.astro and verify**

Import and render `<Projects />` after `<Experience />`. Run `npm run build`.
Expected: succeeds, `dist/index.html` contains "GrampsWeb Deployment".

**Step 3: Commit**

```bash
git add website/src/components/Projects.astro website/src/pages/index.astro
git commit -m "Add Projects section"
```

---

## Task 7: Homelab section with diagram

**Files:**
- Create: `website/src/components/HomelabDiagram.astro`
- Create: `website/src/components/Homelab.astro`

**Step 1: Write the diagram component**

Sanitized flowchart — no internal LAN IPs or private subdomains, matching the "Homelab architecture summary" content note at the top of this plan.

```astro
---
// website/src/components/HomelabDiagram.astro
const diagram = `flowchart TB
    internet((Public Internet)) --> ns((Porkbun / DuckDNS Nameservers))
    ns --> lb([OCI Load Balancer])
    lb --> waf([Web Application Firewall])
    waf --> npm_oci(Nginx Proxy Manager - OCI VM)
    npm_oci -->|Rathole tunnel| npm_home(Nginx Proxy Manager - Home)
    subgraph home[Home Network - Keepalived Failover Pair]
        npm_home --> nextcloud(Nextcloud)
        npm_home --> gramps(GrampsWeb)
        npm_home --> portainer(Portainer)
        npm_home --> pihole(Pi-hole)
    end
`;
---
<div class="mermaid">{diagram}</div>
<script>
  import mermaid from 'mermaid';
  mermaid.initialize({ startOnLoad: true, theme: 'neutral', securityLevel: 'strict' });
</script>
```

**Step 2: Write the Homelab section**

```astro
---
import HomelabDiagram from './HomelabDiagram.astro';
---
<section id="homelab">
  <h2 class="section-heading">Homelab</h2>
  <p>
    Self-hosted services run across a Keepalived failover pair on-prem (a
    Dell E7270 and a Raspberry Pi 4) with an Oracle Cloud VM acting as the
    public tunnel and WAF front door. Everything is deployed and redeployed
    through GitHub Actions talking to Portainer's API — pushing to this repo
    is enough to roll out a change.
  </p>
  <HomelabDiagram />
</section>
```

**Step 3: Add to index.astro and verify**

Import and render `<Homelab />` after `<Projects />`. Run `npm run build`.
Expected: succeeds, `dist/index.html` contains `class="mermaid"` and the diagram source text.

**Step 4: Manual browser check**

Run `npm run preview` (from `website/`) and open the printed local URL. Confirm the Mermaid diagram actually renders as a diagram (not raw text) — this is the one part of the site with client-side JS, so it's worth eyeballing once.

**Step 5: Commit**

```bash
git add website/src/components/HomelabDiagram.astro website/src/components/Homelab.astro website/src/pages/index.astro
git commit -m "Add Homelab section with architecture diagram"
```

---

## Task 8: Stack section component

**Files:**
- Create: `website/src/components/Stack.astro`

**Step 1: Write the component**

```astro
---
import { stack } from '../data/stack';
---
<section id="stack">
  <h2 class="section-heading">Stack</h2>
  {stack.map((group) => (
    <div style="margin-bottom:1.25rem;">
      <p class="fig-label" style="margin-bottom:0.25rem;">{group.category}</p>
      <p style="margin:0;">{group.items.join(' · ')}</p>
    </div>
  ))}
</section>
```

**Step 2: Add to index.astro, replace the leftover placeholder paragraph, and verify**

Import and render `<Stack />` after `<Homelab />`. Remove the `FIG. 00 LJF` placeholder `<p>` left over from Task 2 (the Header component already shows this). Run `npm run build`.
Expected: succeeds, `dist/index.html` contains "Power BI & Power Query" and no longer duplicates the FIG label.

**Step 3: Commit**

```bash
git add website/src/components/Stack.astro website/src/pages/index.astro
git commit -m "Add Stack section and clean up placeholder page content"
```

---

## Task 9: Dockerfile

**Files:**
- Create: `website/Dockerfile`
- Create: `website/.dockerignore`

**Step 1: Write the Dockerfile**

Uses `npm install` rather than `npm ci`: no `package-lock.json` has been committed, since Task 1's local `npm install` was skipped (no Node.js on the dev machine) and CI is the first place dependencies actually get resolved. `npm ci` requires a pre-existing lockfile and would fail here.

```dockerfile
FROM node:20-alpine AS build
WORKDIR /app
COPY package.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
HEALTHCHECK --interval=30s --timeout=3s CMD wget -q -O- http://localhost/ || exit 1
```

**Step 2: Write .dockerignore**

```
node_modules
dist
.astro
```

**Step 3: Build and verify locally**

Run (from `website/`): `docker build -t website-local .`
Expected: build completes successfully through both stages.

Run: `docker run --rm -d -p 8080:80 --name website-local-test website-local`
Then: `curl -s http://localhost:8080/ | grep -o "Liam James-Fagg"`
Expected: prints `Liam James-Fagg`.

Clean up: `docker stop website-local-test`

**Step 4: Commit**

```bash
git add website/Dockerfile website/.dockerignore
git commit -m "Add multi-stage Dockerfile for the website"
```

---

## Task 10: Compose file

**Files:**
- Create: `website-compose.yml` (repo root, alongside the other `*-compose.yml` files)

**Step 1: Write the compose file**

Port `90` is the next free host port after the existing services (80/81/85–89/443 are already taken — see other `*-compose.yml` files in this repo).

```yaml
services:
  website:
    image: ghcr.io/liamj-f/website:latest
    container_name: website
    networks:
      - nginx_network
    ports:
      - "90:80"
    restart: unless-stopped

networks:
  nginx_network:
    external: true
```

**Step 2: Verify against the local image**

Run: `docker compose -f website-compose.yml up -d` (after retagging the local build: `docker tag website-local ghcr.io/liamj-f/website:latest`)
Then: `curl -s http://localhost:90/ | grep -o "Liam James-Fagg"`
Expected: prints `Liam James-Fagg`.

Clean up: `docker compose -f website-compose.yml down`

**Step 3: Commit**

```bash
git add website-compose.yml
git commit -m "Add website-compose.yml for Portainer/Docker deployment"
```

---

## Task 11: GitHub Actions — build, push, and redeploy

**Files:**
- Create: `.github/workflows/website-deploy.yml`

This mirrors `.github/workflows/oci-containers-deploy.yml` (build-and-push job) combined with `.github/workflows/dovetrek-pwa-redeploy.yml` (Portainer GitOps redeploy job), pointed at the `website` image/stack, defaulting to `ljfcloud-server` and `liam.james-fagg.uk` — the same host as Dovetrek-PWA, the closest existing analog (a small public-facing site behind the OCI tunnel).

**Step 1: Write the workflow**

```yaml
name: Build and Redeploy Website via Portainer GitOps
on:
  push:
    branches:
      - main
      - '**'
    paths:
      - 'website/**'
      - 'website-compose.yml'
      - '.github/workflows/website-deploy.yml'
  workflow_dispatch:
    inputs:
      host_machine:
        required: true
        type: string
      domain:
        required: true
        type: string

jobs:
  build-image-and-push:
    name: Build and push website image to ghcr.io
    runs-on: ubuntu-latest
    permissions:
      contents: read
      packages: write
    steps:
      - name: Checkout
        uses: actions/checkout@v6.0.2

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v3
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Extract metadata
        id: meta
        uses: docker/metadata-action@v5
        with:
          images: ghcr.io/liamj-f/website
          tags: |
            type=sha,prefix=sha-
            type=raw,value=latest

      - name: Build and push website image
        uses: docker/build-push-action@v6
        with:
          context: ./website
          push: true
          tags: ${{ steps.meta.outputs.tags }}
          labels: ${{ steps.meta.outputs.labels }}

  deploy:
    needs: build-image-and-push
    runs-on: ubuntu-latest
    env:
      host_machine: ${{ inputs.host_machine || 'ljfcloud-server' }}
      domain: ${{ inputs.domain || 'liam.james-fagg.uk' }}
    steps:
      - name: Checkout repo
        uses: actions/checkout@v4

      - name: Install WireGuard
        run: |
          sudo apt-get install -y wireguard || (sudo apt-get update && sudo apt-get install -y wireguard)

      - name: Write WireGuard config
        run: |
          cat > wg0.conf << EOF
          [Interface]
          PrivateKey = ${{ secrets.WG_PRIVATE_KEY }}
          Address = 10.5.5.5/32
          DNS = 10.5.5.1
          MTU = 1250

          [Peer]
          PublicKey = ${{ secrets.WG_PUBLIC_KEY }}
          PresharedKey = ${{ secrets.WG_PRESHARED_KEY }}
          AllowedIPs = 192.168.0.0/24, 145.241.244.229/32
          Endpoint = ${{ vars.WG_ENDPOINT }}:51820
          PersistentKeepalive = 25
          EOF

      - name: Bring up VPN on runner
        run: |
          sudo wg-quick up ./wg0.conf
          sudo wg show

      - name: Override system DNS resolver on runner
        run: |
          sudo rm /etc/resolv.conf
          echo "nameserver 1.1.1.1" | sudo tee /etc/resolv.conf

      - name: Add host key to known_hosts of runner
        run: |
          mkdir -p ~/.ssh
          ssh-keyscan -H ${{ vars.LJFCLOUD_IP }} >> ~/.ssh/known_hosts

      - name: Authenticate to Portainer
        id: auth
        run: |
          RESPONSE=$(curl -X POST "http://${{ vars.RPI4_IP }}:83/api/auth" \
            -H "Content-Type: application/json" \
            -d '{
                 "Username":"${{ vars.APP_USER }}",
                 "Password":"${{ secrets.APP_PASSWORD }}"
                 }')
          TOKEN=$(echo "$RESPONSE" | jq -r '.jwt')
          echo "token=$TOKEN" >> $GITHUB_OUTPUT

      - name: Get Portainer EndpointId
        id: endpoint
        run: |
          RESPONSE=$(curl -s -X GET "http://${{ vars.RPI4_IP }}:83/api/endpoints" \
            -H "Authorization: Bearer ${{ steps.auth.outputs.token }}")
          ENDPOINT_ID=$(echo "$RESPONSE" | jq -r --arg host_machine "$host_machine" '.[] | select(.Name==$host_machine) | .Id')
          echo "endpoint_id=$ENDPOINT_ID" >> $GITHUB_OUTPUT

      - name: Get Stack ID (if exists)
        id: get_stack_id
        run: |
          STACKS=$(curl --fail -s -X GET "http://${{ vars.RPI4_IP }}:83/api/stacks" \
          -H "Authorization: Bearer ${{ steps.auth.outputs.token }}" || echo "[]")

          STACK_ID=$(echo "$STACKS" | jq -r '.[] | select(.Name=="website" and .EndpointId==${{ steps.endpoint.outputs.endpoint_id }}) | .Id')

          if [ -z "$STACK_ID" ] || [ "$STACK_ID" = "null" ]; then
            echo "Stack not found for this endpoint."
            echo "stack_id=0" >> $GITHUB_OUTPUT
          else
            echo "Stack found with ID: $STACK_ID"
            echo "stack_id=$STACK_ID" >> $GITHUB_OUTPUT
          fi

      - name: Get stack webhook token
        if: ${{ steps.get_stack_id.outputs.stack_id != '0' }}
        id: get_webhook
        run: |
          WEBHOOK_TOKEN=$(curl -s \
            --max-time 10 \
            -H "Authorization: Bearer ${{ steps.auth.outputs.token }}" \
            "http://${{ vars.RPI4_IP }}:83/api/stacks/${{ steps.get_stack_id.outputs.stack_id }}?endpointId=${{ steps.endpoint.outputs.endpoint_id }}" \
            | jq -r '.AutoUpdate.Webhook')

          echo "webhook_token=$WEBHOOK_TOKEN" >> $GITHUB_OUTPUT

      - name: Generate UUID
        if: ${{ steps.get_stack_id.outputs.stack_id == '0' }}
        id: uuid
        run: |
          echo "uuid=$(uuidgen)" >> $GITHUB_OUTPUT

      - name: Create Stack from GitHub
        if: ${{ steps.get_stack_id.outputs.stack_id == '0' }}
        run: |
          RESPONSE=$(curl -v -s -S -X POST "http://${{ vars.RPI4_IP }}:83/api/stacks/create/standalone/repository?endpointId=${{ steps.endpoint.outputs.endpoint_id }}" \
          -H "Authorization: Bearer ${{ steps.auth.outputs.token }}" \
          -H "Content-Type: application/json" \
          -d '{
               "Name": "website",
               "RepositoryURL": "https://github.com/liamj-f/homelab-setup",
               "RepositoryReferenceName": "${{ github.ref }}",
               "ComposeFile": "website-compose.yml",
               "RepositoryAuthentication": false,
               "AutoUpdate": {
                              "forcePullImage": true,
                              "forceUpdate": true,
                              "Webhook": "{${{ steps.uuid.outputs.uuid }}}"
                             },
               "Env": [
                     ],
               "Prune": true,
               "StackFileVersion": "3"
              }')

          echo "API Response: $RESPONSE"

      - name: Update Stack Environment Variables
        if: ${{ steps.get_stack_id.outputs.stack_id != '0' }}
        run: |
          curl -s -X PUT "http://${{ vars.RPI4_IP }}:83/api/stacks/${{ steps.get_stack_id.outputs.stack_id }}/git?endpointId=${{ steps.endpoint.outputs.endpoint_id }}" \
          -H "Authorization: Bearer ${{ steps.auth.outputs.token }}" \
          -H "Content-Type: application/json" \
          -d '{
               "AutoUpdate": {
                              "forcePullImage": true,
                              "forceUpdate": true,
                              "Webhook": "{${{ steps.uuid.outputs.uuid }}}"
                             },
               "PullImage": true,
               "RepositoryReferenceName": "${{ github.ref }}",
               "repositoryAuthentication": false,
               "Env": [
                     ],
               "Prune": true
              }'

      - name: Redeploy Stack using webhook
        if: ${{ steps.get_stack_id.outputs.stack_id != '0' }}
        run: |
          RESPONSE=$(curl -s -i -v --max-time 300 -X POST "http://${{ vars.RPI4_IP }}:83/api/stacks/webhooks/${{ steps.get_webhook.outputs.webhook_token }}?pullimage=true" \
          -H "Authorization: Bearer ${{ steps.auth.outputs.token }}" )

          echo "API Response: $RESPONSE"

      - name: Bring down VPN
        if: always()
        run: |
          sudo wg-quick down ./wg0.conf
          sudo wg show
```

**Step 2: Validate workflow syntax**

Run: `gh workflow view website-deploy.yml` if the branch is already pushed, or at minimum lint the YAML locally with a tool like `yamllint .github/workflows/website-deploy.yml` if available. At minimum, visually diff the structure against `oci-containers-deploy.yml` and `dovetrek-pwa-redeploy.yml` to confirm indentation and job dependencies (`needs: build-image-and-push`) are correct.

**Step 3: Commit**

```bash
git add .github/workflows/website-deploy.yml
git commit -m "Add GitOps workflow to build, push, and redeploy the website"
```

**Note for the user:** this workflow reuses your existing `WG_PRIVATE_KEY`/`WG_PUBLIC_KEY`/`WG_PRESHARED_KEY`/`APP_PASSWORD` secrets and `WG_ENDPOINT`/`RPI4_IP`/`LJFCLOUD_IP`/`APP_USER` vars — no new GitHub secrets to configure, since it targets the same `ljfcloud-server` Portainer endpoint Dovetrek-PWA already uses. You will still need to create the Nginx Proxy Manager Proxy Host entry for `liam.james-fagg.uk` pointing at the `website` container's port `90`, since NPM config isn't managed by this repo.

---

## Task 12: Update root README

**Files:**
- Modify: `README.md`

**Step 1: Add the service to the LJFCloud list**

In the `### LJFCloud` section (currently listing Portainer-Agent, Nginx Proxy Manager, Dovetrek-PWA, DuckDNS), add a `Website` entry alongside Dovetrek-PWA.

**Step 2: Commit**

```bash
git add README.md
git commit -m "Document website service in README"
```

---

## Task 13: Final full-stack verification

**Step 1: Full local rebuild**

Run: `docker build -t ghcr.io/liamj-f/website:latest ./website`
Expected: succeeds.

**Step 2: Full compose up and content check**

Run: `docker compose -f website-compose.yml up -d`
Run: `curl -s http://localhost:90/ | grep -oE "Liam James-Fagg|Allpay Ltd|Homelab-setup|Power BI"`
Expected: all four strings print, confirming About/Experience/Projects/Stack content is present in the built page.

**Step 3: Clean up**

```bash
docker compose -f website-compose.yml down
```

**Step 4: Final review**

Read through `website/src/pages/index.astro` top to bottom to confirm all five sections (`About`, `Experience`, `Projects`, `Homelab`, `Stack`) render in order with the `Header` above and `Footer` below.
