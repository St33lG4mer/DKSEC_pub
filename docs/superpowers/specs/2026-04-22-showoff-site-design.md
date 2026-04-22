# DKSec Sigma vs Elastic Showoff Site Design

Date: 2026-04-22
Status: Approved for implementation planning
Target path: `showoff_site/`

## Purpose

Build a public, static, cinematic SOC-style microsite that showcases the ongoing "Sigma detection rules vs Elastic detection rules" experiment for Kasper's security portfolio.

The current Streamlit dashboard remains the internal operational dashboard. It can later connect to Elastic, Sliver, and lab automation. The new public site is a separate portfolio artifact focused on presentation, storytelling, and safe interactive exploration.

## Product Direction

The approved direction is a cinematic attack replay command center:

- The first screen feels like a live SOC replay interface.
- The site opens with the attack chain, not with a generic article page.
- The visitor can see the lab topology, attack phase, MITRE technique, Sigma hits, Elastic hits, overlaps, misses, and gap queue at a glance.
- Deeper sections explain the method and findings with enough rigor to support the linked technical write-up.

The experience should be exciting, but not misleading. If real experiment output is not ready, the site must label values as sample, draft, or in-progress snapshots.

Working public slug/subdomain placeholder: `sigma-vs-elastic`.

## Audience

Primary audience:

- Security hiring managers, peers, and portfolio visitors who should quickly understand that the project is hands-on, technical, and structured.

Secondary audience:

- Detection engineers and blue team practitioners who may inspect methodology, rule overlap logic, and final recommendations.

## Goals

- Create a public-safe showcase under `showoff_site/`.
- Preserve the existing internal Streamlit app unchanged for lab use.
- Use static data snapshots rather than live infrastructure.
- Make the experiment memorable through an attack replay interface.
- Support later replacement of sample data with exported experiment results.
- Deploy cleanly through GitHub Pages or Cloudflare Pages, with Cloudflare Pages preferred for a subdomain.

## Non-Goals

- No live Elastic/Kibana access from the public site.
- No public Sliver, C2, or lab control functionality.
- No credentials, internal hostnames, raw command secrets, or private lab IPs.
- No backend requirement for the initial version.
- No attempt to replace the full technical write-up on `kaspergissel.dk`.

## Recommended Stack

Use Vite, React, and TypeScript in `showoff_site/`.

Reasoning:

- Static build output works well for Cloudflare Pages and GitHub Pages.
- React gives enough structure for a polished interactive dashboard.
- TypeScript helps keep snapshot data shapes explicit.
- Client-side animation and charting are enough for the public experience.

Potential libraries:

- `lucide-react` for restrained security/UI icons.
- `framer-motion` for playback and section transitions.
- `recharts` or lightweight custom SVG for charts.
- Plain CSS modules or a local CSS file unless the project already adds a broader frontend style system.

Avoid adding a backend or server-side framework unless later requirements prove static output insufficient.

## Information Architecture

### 1. Cinematic Replay Hero

The first viewport presents:

- Product label: `DKSec Attack Replay`
- Experiment label: `Sigma vs Elastic detection experiment`
- Headline: "Replay the attack. Watch the rules compete."
- Sanitized snapshot badge
- Current replay time
- Current MITRE technique
- Current detection status
- Sigma, Elastic, and gap bars
- Lab map with attacker, OPNsense/Squid, Windows victim, and Elastic SIEM
- Technique/phase counters

The hero must leave a hint of the next section visible on normal desktop and mobile viewports.

### 2. Mission Brief

Short explanation of the project:

- A local SOCLAB executes a controlled Windows-focused attack chain.
- Logs are enriched from endpoint, shell, network, proxy, and firewall sources.
- PowerShell and Bash activity are tracked across the lab: near-complete telemetry on the Windows victim and broad telemetry on the Linux attacker.
- Translated Sigma rules and Elastic prebuilt rules are applied in Elasticsearch.
- The experiment compares which rules fire, overlap, miss, or need tuning.

### 3. Lab Architecture

Interactive or diagram-like section showing:

- Windows victim
- Linux attacker
- OPNsense firewall/proxy
- Squid proxy
- Sysmon, endpoint telemetry, shell history/activity, and process execution
- Elasticsearch/SIEM collection

This section should explain the system without exposing sensitive infrastructure details.

### 4. Attack Replay

Timeline section with attack steps:

- Phase
- MITRE technique
- Safe command label or behavioral description
- Expected telemetry
- Expected Sigma and Elastic coverage
- Actual hit/miss status when real data exists

The timeline should feel like playback, not just a static table. It can use animation, scrub-like selection, and event cards.

### 5. Detection Race

Comparison section focused on outcomes:

- Sigma alerts
- Elastic alerts
- Shared detections
- Sigma-only detections
- Elastic-only detections
- Missed expected detections

This section should emphasize interpretable results over raw volume.

### 6. Overlap and Gap Analysis

Analyst-oriented section:

- Rules that overlap and may not both be needed
- Rules that fired but were noisy
- Rules that did not fire during expected behavior
- Areas where custom rules are needed
- Gaps by MITRE tactic/technique

### 7. Findings and Recommendations

Final section:

- Keep
- Tune
- Remove or disable due to overlap/noise
- Create custom rule
- Needs more testing

These findings may start as draft findings until the attack chain and automated flow mature.

### 8. Write-Up CTA

Link back to the portfolio write-up on `kaspergissel.dk`.

The site should present itself as the interactive companion to the report, not the full report.

## Data Model

Initial data lives as static JSON in `showoff_site/src/data/` or `showoff_site/public/data/`.

### `summary.json`

Fields:

- `experimentStatus`
- `snapshotLabel`
- `lastUpdated`
- `isSampleData`
- `attackStepCount`
- `mitreTechniqueCount`
- `sigmaHitCount`
- `elasticHitCount`
- `overlapCount`
- `gapCount`
- `draftFindingCount`

### `attack_steps.json`

Fields:

- `id`
- `order`
- `phase`
- `techniqueId`
- `techniqueName`
- `safeActionLabel`
- `telemetrySources`
- `shellTelemetry`
- `expectedDetections`
- `sigmaHits`
- `elasticHits`
- `gapCount`
- `status`

### `detections.json`

Fields:

- `id`
- `source`
- `ruleName`
- `severity`
- `techniqueIds`
- `attackStepIds`
- `hitCount`
- `overlapGroupId`
- `classification`
- `notes`

### `findings.json`

Fields:

- `id`
- `category`
- `title`
- `description`
- `relatedRuleIds`
- `relatedTechniqueIds`
- `recommendation`
- `confidence`
- `status`

## Data Safety Rules

- Public data must be sanitized.
- No internal hostnames, private IP addresses, credentials, tokens, or raw payloads.
- Commands should be shown as behavior labels unless they are safe, common, and intentional to publish.
- Sample values must be visually labeled as sample or draft.
- When real results replace sample data, the site should show the snapshot date and experiment status.

## Visual Direction

Tone:

- Cinematic
- Technical
- Dense
- Credible
- Security-lab oriented

Palette:

- Deep near-black base
- Cyan/teal for active telemetry
- Blue for Sigma
- Amber/yellow for Elastic
- Rose/red for misses or gaps
- Green only for confirmed coverage or success

Avoid:

- Generic purple SaaS gradients
- Cartoonish hacker visuals
- Stock imagery
- Overly playful effects
- Huge empty landing-page spacing

UI rules:

- Keep cards compact and purposeful.
- Use icons for navigation and status where appropriate.
- Make charts and topology readable on mobile.
- Text must not overlap on narrow screens.
- Animations should support the replay concept and not obscure the data.

## Plugin and Tool Use

Figma:

- Optional during implementation for refining the visual system or producing a design reference.
- Use if the layout needs a proper reusable component map before code implementation.

Canva:

- Not needed for the site itself.
- Useful later for social cards, portfolio thumbnails, or a presentation asset promoting the project.

Remotion:

- Strong candidate for a later hero/replay video or animated portfolio teaser.
- Do not block the initial static site on Remotion.
- If used, render a short reusable attack replay asset that can be embedded as video or used for social promotion.

CodeRabbit:

- Useful after implementation for review before publishing.

## Deployment

Preferred deployment:

- Cloudflare Pages connected to the repo or a future split-out repo.
- Working subdomain placeholder: `sigma-vs-elastic.kaspergissel.dk`.

Alternative:

- GitHub Pages if the static build output and routing remain simple.

The site should work from a static build without a server.

## Implementation Boundaries

Create everything under `showoff_site/` except for optional export scripts or documentation added later.

Do not modify the existing Streamlit dashboard as part of this public-site implementation unless a future export step needs a small shared utility.

## Verification Criteria

The initial implementation is acceptable when:

- `showoff_site` builds successfully.
- The first viewport matches the approved cinematic direction.
- The page is responsive on desktop and mobile.
- Data is loaded from static JSON or typed static data, not hardcoded across components.
- Sample or draft data is clearly labeled.
- No private lab values or credentials appear in the public site.
- The site can be served locally and opened in a browser.
- A production static build can be generated.

## Open Implementation Decisions

- Exact subdomain name can be decided later.
- Whether to use Figma before code implementation depends on how quickly the coded prototype reaches the desired polish.
- Whether to create a Remotion replay asset should be decided after the first static site exists.
