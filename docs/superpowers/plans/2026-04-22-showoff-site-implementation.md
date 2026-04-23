# Showoff Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first static cinematic SOC-style public microsite for the Sigma vs Elastic experiment under `showoff_site/`.

**Architecture:** Create a self-contained Vite + React + TypeScript app that reads sanitized static experiment snapshots from typed local data. Keep the existing Streamlit dashboard unchanged. The public app is static-only and deployable through Cloudflare Pages or GitHub Pages.

**Tech Stack:** Vite, React, TypeScript, CSS, lucide-react icons, local typed data, Vitest smoke tests, static production build.

---

## File Structure

- Create `showoff_site/package.json`: frontend scripts and dependencies.
- Create `showoff_site/index.html`: Vite HTML entry.
- Create `showoff_site/tsconfig.json`, `showoff_site/tsconfig.node.json`, `showoff_site/vite.config.ts`: TypeScript and Vite config.
- Create `showoff_site/src/main.tsx`: React mount entry.
- Create `showoff_site/src/App.tsx`: page composition and section order.
- Create `showoff_site/src/styles.css`: full responsive visual system and cinematic layout.
- Create `showoff_site/src/data/experiment.ts`: sanitized typed public snapshot data.
- Create `showoff_site/src/types.ts`: shared data types.
- Create `showoff_site/src/components/HeroReplay.tsx`: first viewport cinematic command center.
- Create `showoff_site/src/components/LabArchitecture.tsx`: lab topology section.
- Create `showoff_site/src/components/AttackTimeline.tsx`: interactive replay timeline.
- Create `showoff_site/src/components/DetectionRace.tsx`: Sigma vs Elastic comparison section.
- Create `showoff_site/src/components/Findings.tsx`: recommendations and gap queue.
- Create `showoff_site/src/components/SectionShell.tsx`: reusable section wrapper.
- Create `showoff_site/src/App.test.tsx`: basic render/smoke tests.
- Create `showoff_site/src/test/setup.ts`: test setup.
- Create `showoff_site/README.md`: local dev, build, deployment notes, and data safety rules.

## Task 1: Scaffold Static React App

**Files:**
- Create: `showoff_site/package.json`
- Create: `showoff_site/index.html`
- Create: `showoff_site/tsconfig.json`
- Create: `showoff_site/tsconfig.node.json`
- Create: `showoff_site/vite.config.ts`
- Create: `showoff_site/src/main.tsx`
- Create: `showoff_site/src/App.tsx`
- Create: `showoff_site/src/styles.css`

- [ ] **Step 1: Create package manifest**

Create `showoff_site/package.json`:

```json
{
  "name": "sigma-vs-elastic-showoff",
  "private": true,
  "version": "0.1.0",
  "type": "module",
  "scripts": {
    "dev": "vite --host 127.0.0.1",
    "build": "tsc -b && vite build",
    "preview": "vite preview --host 127.0.0.1",
    "test": "vitest run",
    "test:watch": "vitest"
  },
  "dependencies": {
    "@vitejs/plugin-react": "^5.0.0",
    "lucide-react": "^0.468.0",
    "vite": "^6.0.0",
    "react": "^19.0.0",
    "react-dom": "^19.0.0"
  },
  "devDependencies": {
    "@testing-library/jest-dom": "^6.6.3",
    "@testing-library/react": "^16.1.0",
    "@types/react": "^19.0.0",
    "@types/react-dom": "^19.0.0",
    "jsdom": "^25.0.1",
    "typescript": "^5.7.0",
    "vitest": "^2.1.8"
  }
}
```

- [ ] **Step 2: Create Vite HTML entry**

Create `showoff_site/index.html`:

```html
<!doctype html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta
      name="description"
      content="Interactive public showcase for a Sigma vs Elastic detection rule experiment in a local SOC lab."
    />
    <title>DKSec Sigma vs Elastic</title>
  </head>
  <body>
    <div id="root"></div>
    <script type="module" src="/src/main.tsx"></script>
  </body>
</html>
```

- [ ] **Step 3: Create TypeScript config**

Create `showoff_site/tsconfig.json`:

```json
{
  "compilerOptions": {
    "target": "ES2020",
    "useDefineForClassFields": true,
    "lib": ["DOM", "DOM.Iterable", "ES2020"],
    "allowJs": false,
    "skipLibCheck": true,
    "esModuleInterop": true,
    "allowSyntheticDefaultImports": true,
    "strict": true,
    "forceConsistentCasingInFileNames": true,
    "module": "ESNext",
    "moduleResolution": "Node",
    "resolveJsonModule": true,
    "isolatedModules": true,
    "noEmit": true,
    "jsx": "react-jsx"
  },
  "include": ["src"],
  "references": [{ "path": "./tsconfig.node.json" }]
}
```

Create `showoff_site/tsconfig.node.json`:

```json
{
  "compilerOptions": {
    "composite": true,
    "module": "ESNext",
    "moduleResolution": "Node",
    "allowSyntheticDefaultImports": true
  },
  "include": ["vite.config.ts"]
}
```

- [ ] **Step 4: Create Vite config**

Create `showoff_site/vite.config.ts`:

```ts
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  test: {
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    globals: true,
  },
});
```

- [ ] **Step 5: Create minimal React entry and app**

Create `showoff_site/src/main.tsx`:

```tsx
import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
```

Create `showoff_site/src/App.tsx`:

```tsx
export default function App() {
  return (
    <main className="app-shell">
      <section className="splash-screen">
        <p className="eyebrow">DKSec Attack Replay</p>
        <h1>Replay the attack. Watch the rules compete.</h1>
        <p>
          Static cinematic showcase for the Sigma vs Elastic detection
          experiment.
        </p>
      </section>
    </main>
  );
}
```

Create `showoff_site/src/styles.css`:

```css
:root {
  color-scheme: dark;
  font-family:
    Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI",
    sans-serif;
  background: #05080d;
  color: #e5eef8;
}

* {
  box-sizing: border-box;
}

body {
  margin: 0;
  min-width: 320px;
  min-height: 100vh;
  background: #05080d;
}

button,
input,
select,
textarea {
  font: inherit;
}

.app-shell {
  min-height: 100vh;
}

.splash-screen {
  display: grid;
  align-content: center;
  min-height: 100vh;
  padding: 48px;
  background:
    radial-gradient(circle at 72% 20%, rgba(94, 234, 212, 0.14), transparent 28%),
    linear-gradient(135deg, rgba(96, 165, 250, 0.08), transparent 40%),
    #05080d;
}

.eyebrow {
  margin: 0 0 14px;
  color: #5eead4;
  font-size: 0.75rem;
  font-weight: 800;
  letter-spacing: 0.16em;
  text-transform: uppercase;
}

h1 {
  max-width: 900px;
  margin: 0;
  color: #f8fafc;
  font-size: clamp(3rem, 8vw, 6.5rem);
  line-height: 0.96;
  letter-spacing: 0;
}

.splash-screen p:last-child {
  max-width: 640px;
  margin: 22px 0 0;
  color: #a8b8c7;
  font-size: 1.05rem;
  line-height: 1.6;
}
```

- [ ] **Step 6: Install dependencies**

Run:

```powershell
npm install
```

from `showoff_site/`.

Expected: `node_modules/` and `package-lock.json` are created.

- [ ] **Step 7: Verify initial build**

Run:

```powershell
npm run build
```

Expected: TypeScript passes and Vite writes `showoff_site/dist/`.

- [ ] **Step 8: Commit scaffold**

Run:

```powershell
git add showoff_site
git commit -m "Scaffold showoff site"
```

Expected: commit succeeds with the initial static app files.

## Task 2: Add Typed Public Experiment Data

**Files:**
- Create: `showoff_site/src/types.ts`
- Create: `showoff_site/src/data/experiment.ts`
- Modify: `showoff_site/src/App.tsx`
- Create: `showoff_site/src/test/setup.ts`
- Create: `showoff_site/src/App.test.tsx`

- [ ] **Step 1: Define data types**

Create `showoff_site/src/types.ts`:

```ts
export type DetectionSource = "Sigma" | "Elastic" | "Both" | "Gap";

export type DetectionStatus = "sample" | "draft" | "observed" | "missed";

export type Summary = {
  experimentStatus: string;
  snapshotLabel: string;
  slug: string;
  lastUpdated: string;
  isSampleData: boolean;
  attackStepCount: number;
  mitreTechniqueCount: number;
  sigmaHitCount: number;
  elasticHitCount: number;
  overlapCount: number;
  gapCount: number;
  draftFindingCount: number;
};

export type AttackStep = {
  id: string;
  order: number;
  phase: string;
  techniqueId: string;
  techniqueName: string;
  safeActionLabel: string;
  telemetrySources: string[];
  shellTelemetry: string;
  expectedDetections: string[];
  sigmaHits: number;
  elasticHits: number;
  gapCount: number;
  status: DetectionStatus;
};

export type Detection = {
  id: string;
  source: DetectionSource;
  ruleName: string;
  severity: "critical" | "high" | "medium" | "low";
  techniqueIds: string[];
  attackStepIds: string[];
  hitCount: number;
  overlapGroupId?: string;
  classification: "keep" | "tune" | "overlap" | "gap" | "observe";
  notes: string;
};

export type Finding = {
  id: string;
  category: "Keep" | "Tune" | "Remove overlap" | "Create custom rule" | "Needs more testing";
  title: string;
  description: string;
  relatedRuleIds: string[];
  relatedTechniqueIds: string[];
  recommendation: string;
  confidence: "low" | "medium" | "high";
  status: "draft" | "validated";
};
```

- [ ] **Step 2: Add sanitized sample snapshot**

Create `showoff_site/src/data/experiment.ts`:

```ts
import type { AttackStep, Detection, Finding, Summary } from "../types";

export const summary: Summary = {
  experimentStatus: "Attack chain automation in progress",
  snapshotLabel: "Sanitized public sample",
  slug: "sigma-vs-elastic",
  lastUpdated: "2026-04-22",
  isSampleData: true,
  attackStepCount: 54,
  mitreTechniqueCount: 17,
  sigmaHitCount: 142,
  elasticHitCount: 118,
  overlapCount: 37,
  gapCount: 11,
  draftFindingCount: 9,
};

export const attackSteps: AttackStep[] = [
  {
    id: "initial-access-scripted-exec",
    order: 1,
    phase: "Initial Access",
    techniqueId: "T1059.001",
    techniqueName: "PowerShell",
    safeActionLabel: "Scripted PowerShell execution on Windows victim",
    telemetrySources: ["Sysmon", "PowerShell", "Windows Event Log", "Elastic Agent"],
    shellTelemetry: "Near-complete PowerShell telemetry on victim",
    expectedDetections: ["Suspicious PowerShell", "Encoded command pattern"],
    sigmaHits: 8,
    elasticHits: 5,
    gapCount: 1,
    status: "sample",
  },
  {
    id: "defense-evasion-lolbin",
    order: 2,
    phase: "Defense Evasion",
    techniqueId: "T1218",
    techniqueName: "System Binary Proxy Execution",
    safeActionLabel: "LOLBIN-style execution path",
    telemetrySources: ["Sysmon", "Process Creation", "Windows Event Log"],
    shellTelemetry: "Process and command-line telemetry on victim",
    expectedDetections: ["Suspicious LOLBIN", "Unusual parent process"],
    sigmaHits: 11,
    elasticHits: 9,
    gapCount: 0,
    status: "sample",
  },
  {
    id: "credential-access-dump-attempt",
    order: 3,
    phase: "Credential Access",
    techniqueId: "T1003",
    techniqueName: "OS Credential Dumping",
    safeActionLabel: "Credential access behavior simulation",
    telemetrySources: ["Sysmon", "Security Log", "Elastic Defend"],
    shellTelemetry: "PowerShell and process execution telemetry on victim",
    expectedDetections: ["Credential dumping behavior", "Sensitive process access"],
    sigmaHits: 14,
    elasticHits: 10,
    gapCount: 2,
    status: "sample",
  },
  {
    id: "command-and-control-beacon",
    order: 4,
    phase: "Command and Control",
    techniqueId: "T1071",
    techniqueName: "Application Layer Protocol",
    safeActionLabel: "Outbound beacon-like network pattern",
    telemetrySources: ["OPNsense", "Squid", "Elastic Network Events"],
    shellTelemetry: "Bash activity broadly tracked on attacker",
    expectedDetections: ["Suspicious outbound connection", "Beaconing pattern"],
    sigmaHits: 6,
    elasticHits: 8,
    gapCount: 1,
    status: "sample",
  },
  {
    id: "collection-compression",
    order: 5,
    phase: "Collection",
    techniqueId: "T1560",
    techniqueName: "Archive Collected Data",
    safeActionLabel: "Archive creation from staged files",
    telemetrySources: ["Sysmon", "File Events", "Process Creation"],
    shellTelemetry: "Command-line telemetry on victim",
    expectedDetections: ["Archive utility execution", "Sensitive file staging"],
    sigmaHits: 5,
    elasticHits: 3,
    gapCount: 2,
    status: "sample",
  },
];

export const detections: Detection[] = [
  {
    id: "sigma-powershell-suspicious",
    source: "Sigma",
    ruleName: "Suspicious PowerShell Execution Pattern",
    severity: "high",
    techniqueIds: ["T1059.001"],
    attackStepIds: ["initial-access-scripted-exec"],
    hitCount: 8,
    overlapGroupId: "powershell-exec",
    classification: "keep",
    notes: "Strong coverage for the scripted execution phase.",
  },
  {
    id: "elastic-powershell-suspicious",
    source: "Elastic",
    ruleName: "Potential PowerShell Obfuscation",
    severity: "medium",
    techniqueIds: ["T1059.001"],
    attackStepIds: ["initial-access-scripted-exec"],
    hitCount: 5,
    overlapGroupId: "powershell-exec",
    classification: "overlap",
    notes: "Overlaps with Sigma coverage but may add context.",
  },
  {
    id: "sigma-credential-access",
    source: "Sigma",
    ruleName: "Credential Access Behavior",
    severity: "critical",
    techniqueIds: ["T1003"],
    attackStepIds: ["credential-access-dump-attempt"],
    hitCount: 14,
    classification: "keep",
    notes: "High-signal rule candidate for final ruleset.",
  },
  {
    id: "gap-shell-to-network",
    source: "Gap",
    ruleName: "Shell-to-network correlation gap",
    severity: "high",
    techniqueIds: ["T1071", "T1059"],
    attackStepIds: ["command-and-control-beacon"],
    hitCount: 0,
    classification: "gap",
    notes: "Candidate for custom correlation across shell and proxy telemetry.",
  },
];

export const findings: Finding[] = [
  {
    id: "keep-high-signal-powershell",
    category: "Keep",
    title: "Keep high-signal PowerShell detections",
    description:
      "PowerShell telemetry on the Windows victim creates useful signal for the initial execution phase.",
    relatedRuleIds: ["sigma-powershell-suspicious"],
    relatedTechniqueIds: ["T1059.001"],
    recommendation: "Keep Sigma coverage and compare Elastic overlap during full attack-chain runs.",
    confidence: "medium",
    status: "draft",
  },
  {
    id: "create-shell-network-correlation",
    category: "Create custom rule",
    title: "Correlate shell activity with outbound network behavior",
    description:
      "The lab tracks shell activity and network/proxy logs, making a custom correlation rule a likely gap filler.",
    relatedRuleIds: ["gap-shell-to-network"],
    relatedTechniqueIds: ["T1071", "T1059"],
    recommendation: "Create a custom rule once repeatable attack-chain output is available.",
    confidence: "medium",
    status: "draft",
  },
  {
    id: "tune-overlapping-powershell",
    category: "Tune",
    title: "Tune overlapping PowerShell coverage",
    description:
      "Sigma and Elastic both cover suspicious PowerShell behavior; final tuning should keep the highest signal and context.",
    relatedRuleIds: ["sigma-powershell-suspicious", "elastic-powershell-suspicious"],
    relatedTechniqueIds: ["T1059.001"],
    recommendation: "Compare fired alerts across repeated runs before removing either rule.",
    confidence: "low",
    status: "draft",
  },
];
```

- [ ] **Step 3: Wire App to data**

Replace `showoff_site/src/App.tsx` with:

```tsx
import { summary } from "./data/experiment";

export default function App() {
  return (
    <main className="app-shell">
      <section className="splash-screen">
        <p className="eyebrow">DKSec Attack Replay</p>
        <h1>Replay the attack. Watch the rules compete.</h1>
        <p>
          {summary.snapshotLabel} for the {summary.slug} experiment. The public
          build uses sanitized static data while the lab automation matures.
        </p>
      </section>
    </main>
  );
}
```

- [ ] **Step 4: Add test setup**

Create `showoff_site/src/test/setup.ts`:

```ts
import "@testing-library/jest-dom/vitest";
```

Create `showoff_site/src/App.test.tsx`:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import App from "./App";

describe("App", () => {
  it("renders the public experiment headline", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", {
        name: /replay the attack\. watch the rules compete\./i,
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(/sanitized static data/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 5: Run tests**

Run:

```powershell
npm test
```

from `showoff_site/`.

Expected: `App` test passes.

- [ ] **Step 6: Run build**

Run:

```powershell
npm run build
```

Expected: TypeScript and Vite build pass.

- [ ] **Step 7: Commit typed data**

Run:

```powershell
git add showoff_site
git commit -m "Add showoff site public data model"
```

Expected: commit succeeds.

## Task 3: Build Cinematic Replay Hero

**Files:**
- Create: `showoff_site/src/components/HeroReplay.tsx`
- Modify: `showoff_site/src/App.tsx`
- Modify: `showoff_site/src/styles.css`
- Modify: `showoff_site/src/App.test.tsx`

- [ ] **Step 1: Create hero component**

Create `showoff_site/src/components/HeroReplay.tsx`:

```tsx
import { Activity, AlertTriangle, Network, Radar, ShieldCheck } from "lucide-react";
import type { AttackStep, Summary } from "../types";

type HeroReplayProps = {
  summary: Summary;
  activeStep: AttackStep;
};

export function HeroReplay({ summary, activeStep }: HeroReplayProps) {
  const totalHits = summary.sigmaHitCount + summary.elasticHitCount;
  const sigmaWidth = Math.round((summary.sigmaHitCount / totalHits) * 100);
  const elasticWidth = Math.round((summary.elasticHitCount / totalHits) * 100);

  return (
    <section className="hero-replay" aria-labelledby="hero-title">
      <div className="topbar">
        <a className="brand-mark" href="#top" aria-label="DKSec attack replay home">
          <span className="pulse-dot" />
          <span>DKSec Attack Replay</span>
        </a>
        <nav className="nav-links" aria-label="Showcase sections">
          <a href="#lab">Lab</a>
          <a href="#timeline">Replay</a>
          <a href="#race">Detection Race</a>
          <a href="#findings">Findings</a>
        </nav>
      </div>

      <div className="hero-grid">
        <div className="hero-copy">
          <p className="eyebrow">Sigma vs Elastic detection experiment</p>
          <h1 id="hero-title">Replay the attack. Watch the rules compete.</h1>
          <p className="hero-lede">
            A controlled Windows attack chain runs through a local SOCLAB. Each
            phase is mapped to telemetry, detections, overlaps, misses, and
            engineering decisions.
          </p>

          <div className="status-row" aria-label="Current replay status">
            <div className="status-tile">
              <span>Replay</span>
              <strong>00:{String(activeStep.order * 7 + 24).padStart(2, "0")}</strong>
            </div>
            <div className="status-tile">
              <span>Technique</span>
              <strong>{activeStep.techniqueId}</strong>
            </div>
            <div className="status-tile status-live">
              <span>Status</span>
              <strong>{summary.isSampleData ? "Sample" : "Observed"}</strong>
            </div>
          </div>

          <div className="comparison-bars">
            <div className="bar-line">
              <span>Sigma</span>
              <div className="bar-track">
                <span className="bar-fill sigma" style={{ width: `${sigmaWidth}%` }} />
              </div>
              <strong>{summary.sigmaHitCount}</strong>
            </div>
            <div className="bar-line">
              <span>Elastic</span>
              <div className="bar-track">
                <span className="bar-fill elastic" style={{ width: `${elasticWidth}%` }} />
              </div>
              <strong>{summary.elasticHitCount}</strong>
            </div>
            <div className="bar-line">
              <span>Gaps</span>
              <div className="bar-track">
                <span className="bar-fill gap" style={{ width: `${Math.min(summary.gapCount * 6, 100)}%` }} />
              </div>
              <strong>{summary.gapCount}</strong>
            </div>
          </div>
        </div>

        <div className="lab-map-card" aria-label="Lab kill chain map">
          <div className="panel-heading">
            <span>Lab Kill Chain Map</span>
            <small>{summary.snapshotLabel}</small>
          </div>
          <div className="lab-map">
            <div className="node attacker">
              <Radar size={18} />
              <span>Attacker</span>
              <strong>Linux</strong>
            </div>
            <div className="node firewall">
              <Network size={18} />
              <span>Control</span>
              <strong>OPNsense</strong>
            </div>
            <div className="node victim">
              <AlertTriangle size={18} />
              <span>Victim</span>
              <strong>Windows</strong>
            </div>
            <div className="node siem">
              <ShieldCheck size={18} />
              <span>Detection</span>
              <strong>Elastic SIEM</strong>
            </div>
            <svg className="map-lines" viewBox="0 0 640 360" aria-hidden="true">
              <path d="M140 140 C220 100, 260 82, 340 86" />
              <path d="M360 98 C440 108, 488 136, 540 168" />
              <path d="M530 208 C486 284, 394 298, 324 270" />
              <path d="M320 122 C320 178, 318 220, 318 266" />
            </svg>
          </div>
          <div className="mini-metrics">
            <span><Activity size={14} /> {summary.attackStepCount} steps</span>
            <span>{summary.mitreTechniqueCount} techniques</span>
            <span>{summary.overlapCount} overlaps</span>
          </div>
        </div>
      </div>
    </section>
  );
}
```

- [ ] **Step 2: Use hero in App**

Replace `showoff_site/src/App.tsx` with:

```tsx
import { attackSteps, summary } from "./data/experiment";
import { HeroReplay } from "./components/HeroReplay";

export default function App() {
  return (
    <main id="top" className="app-shell">
      <HeroReplay summary={summary} activeStep={attackSteps[2]} />
      <section className="next-hint" aria-label="Next section preview">
        <p className="eyebrow">Mission Brief</p>
        <h2>From lab telemetry to detection engineering decisions.</h2>
      </section>
    </main>
  );
}
```

- [ ] **Step 3: Replace CSS with hero styles**

Append these hero styles to `showoff_site/src/styles.css`:

```css
.hero-replay {
  min-height: 92vh;
  padding: 16px clamp(16px, 3vw, 40px) 42px;
  background:
    radial-gradient(circle at 76% 18%, rgba(94, 234, 212, 0.14), transparent 28%),
    linear-gradient(135deg, rgba(96, 165, 250, 0.08), transparent 42%),
    #05080d;
  border-bottom: 1px solid #1f3347;
}

.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 18px;
  max-width: 1440px;
  margin: 0 auto 34px;
  padding: 12px 0;
}

.brand-mark,
.nav-links a {
  color: #dbeafe;
  text-decoration: none;
}

.brand-mark {
  display: inline-flex;
  align-items: center;
  gap: 12px;
  font-weight: 800;
}

.pulse-dot {
  width: 10px;
  height: 10px;
  border-radius: 999px;
  background: #fb7185;
  box-shadow: 0 0 20px #fb7185;
}

.nav-links {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  justify-content: flex-end;
}

.nav-links a {
  padding: 7px 10px;
  border: 1px solid #263d52;
  border-radius: 999px;
  background: rgba(11, 23, 33, 0.86);
  color: #9fb4c7;
  font-size: 0.78rem;
}

.hero-grid {
  display: grid;
  grid-template-columns: minmax(0, 0.92fr) minmax(420px, 1.08fr);
  gap: clamp(22px, 4vw, 52px);
  align-items: center;
  max-width: 1440px;
  margin: 0 auto;
}

.hero-lede {
  max-width: 650px;
  margin: 22px 0 0;
  color: #a8b8c7;
  font-size: 1.05rem;
  line-height: 1.6;
}

.status-row {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  margin: 28px 0 24px;
}

.status-tile {
  min-width: 112px;
  padding: 13px 15px;
  border: 1px solid #234154;
  border-radius: 7px;
  background: rgba(13, 27, 36, 0.9);
}

.status-tile span,
.bar-line span,
.node span {
  display: block;
  color: #7d94a7;
  font-size: 0.68rem;
  font-weight: 800;
  letter-spacing: 0.08em;
  text-transform: uppercase;
}

.status-tile strong {
  display: block;
  margin-top: 4px;
  color: #f8fafc;
  font-size: 1.55rem;
}

.status-live strong {
  color: #5eead4;
}

.comparison-bars {
  display: grid;
  max-width: 560px;
  gap: 11px;
}

.bar-line {
  display: grid;
  grid-template-columns: 76px minmax(120px, 1fr) 54px;
  gap: 10px;
  align-items: center;
}

.bar-line strong {
  color: #e5eef8;
  text-align: right;
}

.bar-track {
  height: 10px;
  overflow: hidden;
  border-radius: 999px;
  background: #132536;
}

.bar-fill {
  display: block;
  height: 100%;
  border-radius: inherit;
}

.bar-fill.sigma {
  background: #60a5fa;
}

.bar-fill.elastic {
  background: #facc15;
}

.bar-fill.gap {
  background: #fb7185;
}

.lab-map-card {
  min-height: 430px;
  padding: 16px;
  border: 1px solid #24445b;
  border-radius: 10px;
  background: rgba(6, 17, 26, 0.92);
}

.panel-heading,
.mini-metrics {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}

.panel-heading span {
  color: #f8fafc;
  font-weight: 800;
}

.panel-heading small {
  color: #5eead4;
  font-size: 0.7rem;
  font-weight: 800;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}

.lab-map {
  position: relative;
  height: 330px;
  margin-top: 12px;
}

.node {
  position: absolute;
  z-index: 1;
  display: grid;
  gap: 4px;
  width: 132px;
  padding: 12px;
  border: 1px solid #2a526b;
  border-radius: 8px;
  background: #081b27;
}

.node svg {
  color: #5eead4;
}

.node strong {
  color: #f8fafc;
  font-size: 1.05rem;
}

.attacker {
  left: 4%;
  top: 24%;
}

.firewall {
  left: 40%;
  top: 10%;
}

.victim {
  right: 4%;
  top: 32%;
}

.siem {
  left: 39%;
  bottom: 2%;
  width: 156px;
}

.map-lines {
  position: absolute;
  inset: 0;
  width: 100%;
  height: 100%;
}

.map-lines path {
  fill: none;
  stroke: #60a5fa;
  stroke-width: 2;
  stroke-linecap: round;
  opacity: 0.82;
}

.map-lines path:nth-child(2) {
  stroke: #fb7185;
}

.map-lines path:nth-child(3) {
  stroke: #facc15;
}

.map-lines path:nth-child(4) {
  stroke: #5eead4;
}

.mini-metrics {
  flex-wrap: wrap;
  color: #9fb4c7;
  font-size: 0.78rem;
}

.mini-metrics span {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}

.next-hint {
  max-width: 1440px;
  margin: 0 auto;
  padding: 32px clamp(16px, 3vw, 40px) 56px;
}

h2 {
  max-width: 840px;
  margin: 0;
  color: #f8fafc;
  font-size: clamp(2rem, 4vw, 4rem);
  line-height: 1;
}

@media (max-width: 920px) {
  .topbar {
    align-items: flex-start;
    flex-direction: column;
  }

  .hero-grid {
    grid-template-columns: 1fr;
  }

  .lab-map-card {
    min-height: 390px;
  }
}

@media (max-width: 620px) {
  .hero-replay {
    padding-inline: 14px;
  }

  h1 {
    font-size: clamp(2.6rem, 15vw, 4rem);
  }

  .status-row {
    display: grid;
    grid-template-columns: 1fr;
  }

  .bar-line {
    grid-template-columns: 64px minmax(80px, 1fr) 42px;
  }

  .lab-map {
    height: auto;
    display: grid;
    gap: 10px;
  }

  .node {
    position: static;
    width: auto;
  }

  .map-lines {
    display: none;
  }
}
```

- [ ] **Step 4: Update smoke test**

Replace `showoff_site/src/App.test.tsx` with:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import App from "./App";

describe("App", () => {
  it("renders the cinematic replay hero", () => {
    render(<App />);

    expect(
      screen.getByRole("heading", {
        name: /replay the attack\. watch the rules compete\./i,
      }),
    ).toBeInTheDocument();
    expect(screen.getByText(/lab kill chain map/i)).toBeInTheDocument();
    expect(screen.getByText(/sanitized public sample/i)).toBeInTheDocument();
  });
});
```

- [ ] **Step 5: Verify hero**

Run:

```powershell
npm test
npm run build
```

Expected: both commands pass.

- [ ] **Step 6: Commit hero**

Run:

```powershell
git add showoff_site
git commit -m "Build cinematic showoff hero"
```

Expected: commit succeeds.

## Task 4: Add Core Story Sections

**Files:**
- Create: `showoff_site/src/components/SectionShell.tsx`
- Create: `showoff_site/src/components/LabArchitecture.tsx`
- Create: `showoff_site/src/components/AttackTimeline.tsx`
- Create: `showoff_site/src/components/DetectionRace.tsx`
- Create: `showoff_site/src/components/Findings.tsx`
- Modify: `showoff_site/src/App.tsx`
- Modify: `showoff_site/src/styles.css`
- Modify: `showoff_site/src/App.test.tsx`

- [ ] **Step 1: Create section wrapper**

Create `showoff_site/src/components/SectionShell.tsx`:

```tsx
import type { ReactNode } from "react";

type SectionShellProps = {
  id: string;
  eyebrow: string;
  title: string;
  children: ReactNode;
};

export function SectionShell({ id, eyebrow, title, children }: SectionShellProps) {
  return (
    <section id={id} className="content-section" aria-labelledby={`${id}-title`}>
      <div className="section-heading">
        <p className="eyebrow">{eyebrow}</p>
        <h2 id={`${id}-title`}>{title}</h2>
      </div>
      {children}
    </section>
  );
}
```

- [ ] **Step 2: Create lab architecture section**

Create `showoff_site/src/components/LabArchitecture.tsx`:

```tsx
import { Server, Shield, Terminal, Workflow } from "lucide-react";
import { SectionShell } from "./SectionShell";

const nodes = [
  {
    icon: Terminal,
    title: "Linux attacker",
    body: "Broad Bash and operator activity tracking for attacker-side context.",
  },
  {
    icon: Shield,
    title: "OPNsense + Squid",
    body: "Firewall and proxy telemetry enrich network paths and egress behavior.",
  },
  {
    icon: Server,
    title: "Windows victim",
    body: "Near-complete PowerShell, Sysmon, process, and Windows event telemetry.",
  },
  {
    icon: Workflow,
    title: "Elastic SIEM",
    body: "Translated Sigma rules and Elastic prebuilt detections are compared.",
  },
];

export function LabArchitecture() {
  return (
    <SectionShell
      id="lab"
      eyebrow="Lab Architecture"
      title="A local SOCLAB built for repeatable detection experiments."
    >
      <div className="architecture-grid">
        {nodes.map(({ icon: Icon, title, body }) => (
          <article className="info-card" key={title}>
            <Icon size={22} />
            <h3>{title}</h3>
            <p>{body}</p>
          </article>
        ))}
      </div>
    </SectionShell>
  );
}
```

- [ ] **Step 3: Create attack timeline**

Create `showoff_site/src/components/AttackTimeline.tsx`:

```tsx
import type { AttackStep } from "../types";
import { SectionShell } from "./SectionShell";

type AttackTimelineProps = {
  steps: AttackStep[];
};

export function AttackTimeline({ steps }: AttackTimelineProps) {
  return (
    <SectionShell
      id="timeline"
      eyebrow="Attack Replay"
      title="Each behavior is mapped to telemetry and expected detection coverage."
    >
      <div className="timeline-list">
        {steps.map((step) => (
          <article className="timeline-card" key={step.id}>
            <div className="timeline-index">{String(step.order).padStart(2, "0")}</div>
            <div>
              <p className="timeline-phase">{step.phase}</p>
              <h3>{step.techniqueId} · {step.techniqueName}</h3>
              <p>{step.safeActionLabel}</p>
              <p className="telemetry-line">{step.shellTelemetry}</p>
            </div>
            <div className="timeline-score">
              <span className="sigma-text">S {step.sigmaHits}</span>
              <span className="elastic-text">E {step.elasticHits}</span>
              <span className="gap-text">G {step.gapCount}</span>
            </div>
          </article>
        ))}
      </div>
    </SectionShell>
  );
}
```

- [ ] **Step 4: Create detection race**

Create `showoff_site/src/components/DetectionRace.tsx`:

```tsx
import type { Detection, Summary } from "../types";
import { SectionShell } from "./SectionShell";

type DetectionRaceProps = {
  summary: Summary;
  detections: Detection[];
};

export function DetectionRace({ summary, detections }: DetectionRaceProps) {
  const keepCount = detections.filter((detection) => detection.classification === "keep").length;
  const gapCount = detections.filter((detection) => detection.classification === "gap").length;

  return (
    <SectionShell
      id="race"
      eyebrow="Detection Race"
      title="The public view compares signal, overlap, and gaps without exposing the lab."
    >
      <div className="race-grid">
        <article className="score-card sigma-card">
          <span>Sigma hits</span>
          <strong>{summary.sigmaHitCount}</strong>
          <p>{keepCount} high-signal candidates in the sample set.</p>
        </article>
        <article className="score-card elastic-card">
          <span>Elastic hits</span>
          <strong>{summary.elasticHitCount}</strong>
          <p>{summary.overlapCount} overlapping rule pairs to evaluate.</p>
        </article>
        <article className="score-card gap-card">
          <span>Gap queue</span>
          <strong>{summary.gapCount}</strong>
          <p>{gapCount} custom-rule candidates represented in sample data.</p>
        </article>
      </div>
      <div className="detection-table" role="table" aria-label="Detection sample">
        {detections.map((detection) => (
          <div className="detection-row" role="row" key={detection.id}>
            <span>{detection.source}</span>
            <strong>{detection.ruleName}</strong>
            <em>{detection.classification}</em>
            <span>{detection.hitCount} hits</span>
          </div>
        ))}
      </div>
    </SectionShell>
  );
}
```

- [ ] **Step 5: Create findings section**

Create `showoff_site/src/components/Findings.tsx`:

```tsx
import type { Finding } from "../types";
import { SectionShell } from "./SectionShell";

type FindingsProps = {
  findings: Finding[];
};

export function Findings({ findings }: FindingsProps) {
  return (
    <SectionShell
      id="findings"
      eyebrow="Draft Findings"
      title="The end goal is fewer overlaps, better signal, and custom rules where both sets miss."
    >
      <div className="findings-grid">
        {findings.map((finding) => (
          <article className="finding-card" key={finding.id}>
            <span>{finding.category}</span>
            <h3>{finding.title}</h3>
            <p>{finding.description}</p>
            <strong>{finding.recommendation}</strong>
          </article>
        ))}
      </div>
      <a className="writeup-link" href="https://kaspergissel.dk" target="_blank" rel="noreferrer">
        Read the technical write-up on kaspergissel.dk
      </a>
    </SectionShell>
  );
}
```

- [ ] **Step 6: Compose sections in App**

Replace `showoff_site/src/App.tsx` with:

```tsx
import { attackSteps, detections, findings, summary } from "./data/experiment";
import { AttackTimeline } from "./components/AttackTimeline";
import { DetectionRace } from "./components/DetectionRace";
import { Findings } from "./components/Findings";
import { HeroReplay } from "./components/HeroReplay";
import { LabArchitecture } from "./components/LabArchitecture";

export default function App() {
  return (
    <main id="top" className="app-shell">
      <HeroReplay summary={summary} activeStep={attackSteps[2]} />
      <section className="mission-brief" aria-labelledby="mission-title">
        <p className="eyebrow">Mission Brief</p>
        <h2 id="mission-title">From lab telemetry to detection engineering decisions.</h2>
        <p>
          The public showcase is a sanitized snapshot of an ongoing experiment:
          compare translated Sigma detections against Elastic prebuilt rules
          during a controlled Windows-focused attack chain.
        </p>
      </section>
      <LabArchitecture />
      <AttackTimeline steps={attackSteps} />
      <DetectionRace summary={summary} detections={detections} />
      <Findings findings={findings} />
    </main>
  );
}
```

- [ ] **Step 7: Add section CSS**

Append to `showoff_site/src/styles.css`:

```css
.mission-brief,
.content-section {
  max-width: 1440px;
  margin: 0 auto;
  padding: 72px clamp(16px, 3vw, 40px);
}

.mission-brief p:last-child {
  max-width: 780px;
  color: #a8b8c7;
  font-size: 1.05rem;
  line-height: 1.7;
}

.section-heading {
  margin-bottom: 28px;
}

.architecture-grid,
.race-grid,
.findings-grid {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: 14px;
}

.info-card,
.score-card,
.finding-card {
  border: 1px solid #24445b;
  border-radius: 8px;
  background: rgba(8, 27, 39, 0.72);
  padding: 18px;
}

.info-card svg {
  color: #5eead4;
}

.info-card h3,
.timeline-card h3,
.finding-card h3 {
  margin: 12px 0 8px;
  color: #f8fafc;
}

.info-card p,
.timeline-card p,
.score-card p,
.finding-card p {
  color: #a8b8c7;
  line-height: 1.55;
}

.timeline-list {
  display: grid;
  gap: 12px;
}

.timeline-card {
  display: grid;
  grid-template-columns: 48px minmax(0, 1fr) auto;
  gap: 18px;
  align-items: center;
  border: 1px solid #24445b;
  border-radius: 8px;
  background: rgba(8, 27, 39, 0.72);
  padding: 16px;
}

.timeline-index {
  color: #5eead4;
  font-weight: 900;
}

.timeline-phase,
.telemetry-line {
  margin: 0;
}

.timeline-score {
  display: flex;
  gap: 8px;
  font-weight: 900;
}

.sigma-text,
.sigma-card strong {
  color: #60a5fa;
}

.elastic-text,
.elastic-card strong {
  color: #facc15;
}

.gap-text,
.gap-card strong {
  color: #fb7185;
}

.score-card span,
.finding-card span {
  color: #7d94a7;
  font-size: 0.72rem;
  font-weight: 900;
  letter-spacing: 0.1em;
  text-transform: uppercase;
}

.score-card strong {
  display: block;
  margin: 8px 0;
  font-size: 2.8rem;
}

.detection-table {
  display: grid;
  gap: 8px;
  margin-top: 18px;
}

.detection-row {
  display: grid;
  grid-template-columns: 90px minmax(0, 1fr) 120px 80px;
  gap: 12px;
  align-items: center;
  padding: 12px 14px;
  border: 1px solid #1f3347;
  border-radius: 7px;
  background: rgba(5, 8, 13, 0.64);
}

.detection-row strong {
  color: #f8fafc;
}

.detection-row em {
  color: #5eead4;
  font-style: normal;
}

.finding-card strong {
  display: block;
  margin-top: 14px;
  color: #e5eef8;
}

.writeup-link {
  display: inline-flex;
  margin-top: 24px;
  color: #05080d;
  background: #5eead4;
  border-radius: 999px;
  padding: 11px 16px;
  font-weight: 900;
  text-decoration: none;
}

@media (max-width: 980px) {
  .architecture-grid,
  .race-grid,
  .findings-grid {
    grid-template-columns: repeat(2, minmax(0, 1fr));
  }

  .detection-row {
    grid-template-columns: 1fr;
  }
}

@media (max-width: 620px) {
  .mission-brief,
  .content-section {
    padding-block: 52px;
  }

  .architecture-grid,
  .race-grid,
  .findings-grid {
    grid-template-columns: 1fr;
  }

  .timeline-card {
    grid-template-columns: 1fr;
  }

  .timeline-score {
    justify-content: flex-start;
  }
}
```

- [ ] **Step 8: Update tests**

Replace `showoff_site/src/App.test.tsx` with:

```tsx
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import App from "./App";

describe("App", () => {
  it("renders the full public showcase structure", () => {
    render(<App />);

    expect(screen.getByRole("heading", { name: /replay the attack/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /local soclab/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /mapped to telemetry/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /compares signal/i })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: /fewer overlaps/i })).toBeInTheDocument();
  });
});
```

- [ ] **Step 9: Verify sections**

Run:

```powershell
npm test
npm run build
```

Expected: both commands pass.

- [ ] **Step 10: Commit sections**

Run:

```powershell
git add showoff_site
git commit -m "Add showoff site story sections"
```

Expected: commit succeeds.

## Task 5: Add README and Deployment Safety Notes

**Files:**
- Create: `showoff_site/README.md`
- Modify: `showoff_site/package.json`

- [ ] **Step 1: Create README**

Create `showoff_site/README.md`:

```md
# Sigma vs Elastic Showoff Site

Static public showcase for the DKSec Sigma detection rules vs Elastic detection rules experiment.

This site is the public portfolio artifact. It is separate from the internal Streamlit dashboard and must not connect to Elastic, Kibana, Sliver, or private lab infrastructure.

## Local Development

```powershell
npm install
npm run dev
```

## Verification

```powershell
npm test
npm run build
```

## Deployment Target

Working slug/subdomain: `sigma-vs-elastic`.

Preferred deployment is Cloudflare Pages. The production build output is `dist/`.

## Data Safety Rules

- Use sanitized static data only.
- Do not publish credentials, tokens, internal hostnames, private IP addresses, or raw payloads.
- Label sample data as sample data until real experiment snapshots are exported.
- Keep the internal Streamlit dashboard for live Elastic and lab operations.
```

- [ ] **Step 2: Add homepage metadata**

Modify `showoff_site/package.json` to include:

```json
"homepage": "https://sigma-vs-elastic.kaspergissel.dk",
```

directly after the `version` field.

Expected top of file:

```json
{
  "name": "sigma-vs-elastic-showoff",
  "private": true,
  "version": "0.1.0",
  "homepage": "https://sigma-vs-elastic.kaspergissel.dk",
  "type": "module",
```

- [ ] **Step 3: Verify docs do not affect build**

Run:

```powershell
npm test
npm run build
```

Expected: both commands pass.

- [ ] **Step 4: Commit docs**

Run:

```powershell
git add showoff_site
git commit -m "Document showoff site deployment safety"
```

Expected: commit succeeds.

## Task 6: Local Visual Verification and Final Polish

**Files:**
- Modify as needed: `showoff_site/src/styles.css`
- Modify as needed: `showoff_site/src/components/*.tsx`

- [ ] **Step 1: Start local dev server**

Run:

```powershell
npm run dev
```

from `showoff_site/`.

Expected: Vite prints a local URL, usually `http://127.0.0.1:5173/`.

- [ ] **Step 2: Inspect desktop viewport**

Open the Vite URL in a browser at a desktop-sized viewport.

Expected:

- The first viewport is cinematic and readable.
- The lab topology is visible and not clipped.
- The next section is hinted below the fold.
- Navigation links jump to sections.
- The sample-data label is visible.

- [ ] **Step 3: Inspect mobile viewport**

Use browser responsive tools around 390px wide.

Expected:

- No text overlaps.
- Cards stack cleanly.
- Lab map nodes stack rather than cramping.
- Navigation wraps without covering the hero.

- [ ] **Step 4: Apply small polish fixes**

If desktop or mobile inspection shows spacing, overflow, or readability problems, adjust only the affected CSS selectors in `showoff_site/src/styles.css`.

For example, if the hero title is too large on mobile, adjust:

```css
@media (max-width: 620px) {
  h1 {
    font-size: clamp(2.4rem, 14vw, 3.8rem);
  }
}
```

If the topology card clips on tablet, adjust:

```css
@media (max-width: 920px) {
  .lab-map-card {
    min-height: 420px;
  }
}
```

- [ ] **Step 5: Run final verification**

Stop the dev server after visual inspection, then run:

```powershell
npm test
npm run build
```

Expected: both commands pass.

- [ ] **Step 6: Commit final polish**

Run:

```powershell
git status --short
git add showoff_site
git commit -m "Polish showoff site responsive layout"
```

Expected: commit succeeds if polish changes were made. If no files changed, do not create an empty commit.

## Self-Review Notes

Spec coverage:

- Cinematic first viewport: Task 3.
- Static public-safe architecture: Tasks 1, 2, and 5.
- Lab architecture: Task 4.
- Attack replay: Task 4.
- Detection race: Task 4.
- Findings and recommendations: Task 4.
- Sample/draft labeling: Tasks 2 and 3.
- `sigma-vs-elastic` working slug: Tasks 2 and 5.
- Build and verification: Tasks 1 through 6.

Type consistency:

- `Summary`, `AttackStep`, `Detection`, and `Finding` are defined in Task 2 and reused by later components.
- Component prop names match the exported data names from `experiment.ts`.

Execution boundary:

- All implementation work stays under `showoff_site/`.
- The existing Streamlit dashboard remains untouched.
