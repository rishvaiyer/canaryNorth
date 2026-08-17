const LINES = [
  { id: "guide-1", text: "PenTel Supply", x: 90, y: 340, size: 96, width: 80, pool: "pool-1" },
  { id: "guide-2", text: "We sell pens.", x: 100, y: 446, size: 58, width: 56, pool: "pool-2" },
];

const FONT_STACK = '"Pinyon Script", "Allura", "Snell Roundhand", "Apple Chancery", cursive';
const ASC = /[PTltbdfhkWS]/;
const DESC = /[gjpqy,.]/;

const FIXTURES = [
  {
    id: "fixture-01",
    filename: "invoice_update.txt",
    category: "prompt-injection-example",
    severity: "review",
    state: "synthetic",
    signal: "example-only",
    safeSummary: "A fictional invoice note used to stand in for a PenTel instruction-conflict attempt.",
    scanner: "not-connected",
    scannerVersion: null,
    evidenceHash: "demo-hash-a18c",
    redacted: true,
    rawPayload: false,
  },
  {
    id: "fixture-02",
    filename: "customer_export.json",
    category: "data-shape-example",
    severity: "review",
    state: "synthetic",
    signal: "example-only",
    safeSummary: "Invented field names only. No personal or customer records are present.",
    scanner: "not-connected",
    scannerVersion: null,
    evidenceHash: "demo-hash-b22e",
    redacted: true,
    rawPayload: false,
  },
  {
    id: "fixture-03",
    filename: "invoice_macro.docm",
    category: "macro-document-example",
    severity: "blocked",
    state: "not-run",
    signal: "review-only",
    safeSummary: "Example office file used to show a PenTel delivery stopping at the policy gate. Not opened or executed.",
    scanner: "not-run",
    scannerVersion: null,
    evidenceHash: "demo-hash-c09f",
    redacted: true,
    rawPayload: false,
  },
  {
    id: "fixture-04",
    filename: "holiday_photo.png",
    category: "image-fixture",
    severity: "idle",
    state: "synthetic",
    signal: "not-run",
    safeSummary: "Decorative image fixture. No steganography result is claimed because no detector ran.",
    scanner: "not-connected",
    scannerVersion: null,
    evidenceHash: "demo-hash-d44b",
    redacted: true,
    rawPayload: false,
  },
  {
    id: "fixture-05",
    filename: "tool_chain.json",
    category: "agent-plan-example",
    severity: "review",
    state: "synthetic",
    signal: "example-only",
    safeSummary: "A fictional tool-call outline for a PenTel attempt. No live tools are invoked.",
    scanner: "not-connected",
    scannerVersion: null,
    evidenceHash: "demo-hash-e71a",
    redacted: true,
    rawPayload: false,
  },
];

const CHAIN = ["input", "normalize", "classify", "policy", "ledger"];

const CODE_WALK = `# synthetic · not-run · scanner=offline
# actor = PenTel Supply (fictional)

from seal import normalize, classify, policy, ledger

fixture = Fixture(
    name="invoice_macro.docm",
    kind="example-only",
    execute=False,
)

normalized = normalize(fixture)
label = classify(normalized)

decision = policy.gate(
    actor="PenTel Supply",
    label=label,
    network="disabled",
)

if decision == BLOCK:
    ledger.write(redact(fixture.meta), raw=False)
    halt(at="policy_gate")
`;

const AGENT_LOG = `session  pentesting.local
runtime  redhat-agent/2026
network  disabled
mode     synthetic rehearsal

load fixture invoice_macro.docm
note     example-only · not opened
normalize
classify label=macro-document-example
policy   BLOCK
halt     policy_gate
ledger   redacted evidence placeholder
`;

const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

let phase = "idle";
let timers = [];
let selectedId = "fixture-03";
let writing = false;
let generating = false;
let lastPen = { x: 240, y: 300 };
let bubbleAt = { x: 0, y: 0 };
let audioCtx = null;
let inkCanvasCtx = null;

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

function announce(text) {
  $(".live").textContent = text;
}

function readyPhases() {
  return [
    "ready-to-enter",
    "rehearsal-starting",
    "inspecting-fixture",
    "blocked-by-policy",
    "sent-to-human-review",
    "evidence-saved",
  ].includes(phase);
}

function setPhase(next) {
  phase = next;
  document.body.dataset.phase = next;
  document.body.classList.toggle("is-writing", next === "pen-writing");
  document.body.classList.toggle("is-ready", readyPhases());
}

function clearTimers() {
  timers.forEach((id) => clearTimeout(id));
  timers = [];
}

function later(fn, ms) {
  const id = setTimeout(fn, reduced ? 0 : ms);
  timers.push(id);
}

function pause(ms) {
  return new Promise((resolve) => later(resolve, ms));
}

// Web Audio API Sound Synthesizers
function getAudioContext() {
  if (!audioCtx) {
    audioCtx = new (window.AudioContext || window.webkitAudioContext)();
  }
  if (audioCtx.state === "suspended") {
    audioCtx.resume();
  }
  return audioCtx;
}

function playNibScratch(speed = 1.0, pressure = 0.5) {
  try {
    const ctx = getAudioContext();
    if (!ctx) return;
    const dur = 0.05 + Math.random() * 0.04;
    const buffer = ctx.createBuffer(1, Math.floor(ctx.sampleRate * dur), ctx.sampleRate);
    const data = buffer.getChannelData(0);
    for (let i = 0; i < data.length; i++) {
      data[i] = (Math.random() * 2 - 1) * Math.pow(1 - i / data.length, 1.2) * 0.08;
    }
    const src = ctx.createBufferSource();
    src.buffer = buffer;
    const filter = ctx.createBiquadFilter();
    filter.type = "bandpass";
    filter.frequency.setValueAtTime(2200 + Math.random() * 800, ctx.currentTime);
    filter.Q.value = 1.8;
    const gain = ctx.createGain();
    const vol = Math.min(0.04, 0.015 * pressure * speed);
    gain.gain.setValueAtTime(vol, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.0001, ctx.currentTime + dur);
    src.connect(filter).connect(gain).connect(ctx.destination);
    src.start();
  } catch {}
}

function playInkDripSound() {
  try {
    const ctx = getAudioContext();
    if (!ctx) return;
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.type = "sine";
    const startFreq = 680 + Math.random() * 60;
    osc.frequency.setValueAtTime(startFreq, ctx.currentTime);
    osc.frequency.exponentialRampToValueAtTime(180, ctx.currentTime + 0.12);
    gain.gain.setValueAtTime(0.18, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + 0.15);
    osc.connect(gain).connect(ctx.destination);
    osc.start();
    osc.stop(ctx.currentTime + 0.16);
  } catch {}
}

function playTear() {
  try {
    const ctx = getAudioContext();
    if (!ctx) return;
    const dur = 1.3;
    const buffer = ctx.createBuffer(1, Math.floor(ctx.sampleRate * dur), ctx.sampleRate);
    const data = buffer.getChannelData(0);
    for (let i = 0; i < data.length; i += 1) {
      const t = i / data.length;
      const envelope = Math.pow(1 - t, 1.4) * (0.35 + 0.65 * Math.random());
      data[i] = (Math.random() * 2 - 1) * envelope * 0.45;
    }
    const src = ctx.createBufferSource();
    src.buffer = buffer;
    const filter = ctx.createBiquadFilter();
    filter.type = "bandpass";
    filter.frequency.setValueAtTime(880, ctx.currentTime);
    filter.frequency.exponentialRampToValueAtTime(200, ctx.currentTime + dur);
    filter.Q.value = 1.2;
    const gain = ctx.createGain();
    gain.gain.setValueAtTime(0.001, ctx.currentTime);
    gain.gain.exponentialRampToValueAtTime(0.26, ctx.currentTime + 0.05);
    gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + dur);
    src.connect(filter).connect(gain).connect(ctx.destination);
    src.start();
  } catch {}
}

// Canvas Live Ink Rendering
function initInkCanvas() {
  const canvas = $("#ink-canvas");
  const paper = $("#paper");
  if (!canvas || !paper) return;
  const rect = paper.getBoundingClientRect();
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  canvas.width = Math.floor(rect.width * dpr);
  canvas.height = Math.floor(rect.height * dpr);
  inkCanvasCtx = canvas.getContext("2d");
  inkCanvasCtx.setTransform(dpr, 0, 0, dpr, 0, 0);
}

function drawLiveInkDeposit(x, y, radius, opacity = 1.0) {
  if (!inkCanvasCtx) return;
  const ctx = inkCanvasCtx;
  const g = ctx.createRadialGradient(x, y, 0, x, y, radius);
  g.addColorStop(0, `rgba(4, 18, 38, ${0.9 * opacity})`);
  g.addColorStop(0.65, `rgba(12, 48, 98, ${0.75 * opacity})`);
  g.addColorStop(1, `rgba(20, 75, 145, 0)`);
  ctx.fillStyle = g;
  ctx.beginPath();
  ctx.arc(x, y, radius, 0, Math.PI * 2);
  ctx.fill();
}

function drawSatelliteDroplets(cx, cy) {
  if (!inkCanvasCtx) return;
  const ctx = inkCanvasCtx;
  const count = 4 + Math.floor(Math.random() * 3);
  for (let i = 0; i < count; i++) {
    const angle = Math.random() * Math.PI * 2;
    const dist = 38 + Math.random() * 42;
    const sx = cx + Math.cos(angle) * dist;
    const sy = cy + Math.sin(angle) * dist * 0.85;
    const r = 1.2 + Math.random() * 2.2;
    
    const g = ctx.createRadialGradient(sx, sy, 0, sx, sy, r);
    g.addColorStop(0, "rgba(4, 18, 40, 0.95)");
    g.addColorStop(0.7, "rgba(12, 52, 105, 0.7)");
    g.addColorStop(1, "rgba(18, 70, 140, 0)");
    ctx.fillStyle = g;
    ctx.beginPath();
    ctx.arc(sx, sy, r, 0, Math.PI * 2);
    ctx.fill();
  }
}

// Pen Placement & Hand Kinematics
function placePen(x, y, angle, pressure = 0.6, isLift = false) {
  lastPen = { x, y };
  const pen = $("#pen");
  const shadow = $("#pen-contact-shadow");
  if (!pen) return;

  pen.classList.add("is-on");
  pen.classList.remove("is-away");
  pen.style.left = `${x}px`;
  pen.style.top = `${y}px`;

  // Natural pen banking: slight tilt reaction to stroke tangent
  const bankAngle = 14 + Math.sin(angle * Math.PI / 180) * 8;
  const liftOffset = isLift ? -12 : 0;
  const scale = isLift ? 1.02 : 1.0;

  pen.style.transform = `translate(-99.86%, -99.57%) translateY(${liftOffset}px) rotate(${bankAngle}deg) scale(${scale})`;

  if (shadow) {
    if (isLift) {
      shadow.style.opacity = "0.2";
      shadow.style.transform = `translate(50%, 50%) scale(1.6) translateY(8px)`;
      shadow.style.filter = "blur(4px)";
    } else {
      const shadowSize = 0.8 + pressure * 0.4;
      shadow.style.opacity = String(0.45 + pressure * 0.45);
      shadow.style.transform = `translate(50%, 50%) scale(${shadowSize})`;
      shadow.style.filter = "blur(1.2px)";
    }
  }
}

function pointOnSheet(path, dist) {
  const ctm = path.getCTM();
  if (!ctm) return { x: 100, y: 100 };
  const p = path.getPointAtLength(Math.min(dist, path.getTotalLength()));
  return {
    x: ctm.a * p.x + ctm.c * p.y + ctm.e,
    y: ctm.b * p.x + ctm.d * p.y + ctm.f,
  };
}

function tangent(path, dist) {
  const len = path.getTotalLength();
  const a = pointOnSheet(path, dist);
  const b = pointOnSheet(path, Math.min(len, dist + 2));
  return Math.atan2(b.y - a.y, b.x - a.x) * (180 / Math.PI);
}

function measureGuide(line) {
  const ctx = document.createElement("canvas").getContext("2d");
  ctx.font = `400 ${line.size}px ${FONT_STACK}`;
  let d = "";
  let x = line.x;
  const base = line.y - line.size * 0.36;
  
  for (const ch of line.text) {
    const width = Math.max(ctx.measureText(ch).width, 10);
    if (ch === " ") {
      x += width;
      continue;
    }
    let y0 = base;
    let y1 = base;
    if (ASC.test(ch)) y0 = base - line.size * 0.44;
    if (DESC.test(ch)) y1 = base + line.size * 0.4;
    const lift = ch === ch.toUpperCase() ? line.size * 0.14 : 0;
    d += `${d ? " L" : "M"} ${x} ${base + lift * 0.2}`;
    d += ` C ${x + width * 0.24} ${y0}, ${x + width * 0.58} ${y1}, ${x + width * 0.94} ${base}`;
    x += width * 0.94;
  }
  return d;
}

function traceGuide(path, size) {
  path.style.strokeDasharray = "1";
  path.style.strokeDashoffset = reduced ? "0" : "1";
  if (reduced) {
    const end = pointOnSheet(path, path.getTotalLength());
    placePen(end.x, end.y, tangent(path, path.getTotalLength()), 0.7);
    return Promise.resolve();
  }
  
  const len = Math.max(path.getTotalLength(), 1);
  const duration = Math.min(3400, Math.max(1400, size * 28));
  const start = performance.now();
  let lastScratch = 0;
  
  return new Promise((resolve) => {
    function frame(now) {
      if (!writing) return resolve();
      const t = Math.min(1, (now - start) / duration);
      // Fluid easing with human kinematic acceleration & deceleration
      const eased = 1 - Math.pow(1 - t, 2.6);
      path.style.strokeDashoffset = String(1 - eased);
      const dist = len * eased;
      const pt = pointOnSheet(path, dist);
      const angle = tangent(path, dist);
      
      // Calculate dynamic nib pressure based on stroke direction (downstroke vs upstroke)
      const isDownstroke = angle > 20 && angle < 140;
      const pressure = isDownstroke ? 0.95 : 0.4;
      
      placePen(pt.x, pt.y, angle, pressure, false);
      
      // Dynamic audio & subtle micro-ink deposits
      if (now - lastScratch > 65) {
        lastScratch = now;
        playNibScratch(1.0, pressure);
        drawLiveInkDeposit(pt.x, pt.y, isDownstroke ? 4.5 : 2.0, 0.4);
      }
      
      if (t < 1) requestAnimationFrame(frame);
      else resolve();
    }
    requestAnimationFrame(frame);
  });
}

function poolInk(line) {
  const pool = $(`#${line.pool}`);
  if (!pool) return;
  const path = $(`#${line.id}`);
  const end = pointOnSheet(path, path.getTotalLength());
  pool.setAttribute("cx", String(end.x - 4));
  pool.setAttribute("cy", String(end.y + 3));
  pool.setAttribute("r", String(line.size * 0.09));
  pool.style.opacity = "0.7";
  drawLiveInkDeposit(end.x - 4, end.y + 3, line.size * 0.1, 0.85);
}

// Realistic Fluid Droplet Physics Sequence
async function dripInkSequence() {
  const dropRig = $("#drop-rig");
  const halo = $("#impact-halo");
  const bubble = $("#bubble");
  const paper = $("#paper");
  
  const hoverX = Math.min(paper.clientWidth - 130, Math.max(80, lastPen.x - 14));
  const hoverY = lastPen.y + 85;
  const impactY = hoverY + Math.max(160, paper.clientHeight * 0.32);
  const fallDist = impactY - hoverY;
  
  // 1. Move pen to deliberate hover position above the letter
  placePen(hoverX, hoverY, 18, 0.2, true);
  await pause(reduced ? 0 : 450);
  
  // Position drop rig at the nib tip
  dropRig.style.left = `${hoverX}px`;
  dropRig.style.top = `${hoverY}px`;
  dropRig.style.setProperty("--fall", `${fallDist}px`);
  
  // 2. Accretion Phase (Liquid bead forms and swells at the nib tip)
  dropRig.className = "ink-drop-rig is-beading";
  await pause(reduced ? 0 : 750);
  
  // 3. Necking & Pinch-off Phase (Liquid filament stretches)
  dropRig.className = "ink-drop-rig is-stretching";
  await pause(reduced ? 0 : 850);
  
  // 4. Free Fall Phase (Gravitational acceleration)
  dropRig.className = "ink-drop-rig is-falling";
  await pause(reduced ? 0 : 1050);
  dropRig.className = "ink-drop-rig";
  
  // 5. Impact, Audio, Splatter & Capillary Bloom
  playInkDripSound();
  
  // Activate capillary wetting halo on paper
  halo.style.left = `${hoverX}px`;
  halo.style.top = `${impactY}px`;
  halo.classList.add("is-active");
  
  // Draw organic micro-splatter droplets on ink canvas
  drawSatelliteDroplets(hoverX, impactY);
  
  // 6. 3D Glossy Liquid Dome Bubble Blossom
  bubbleAt = { x: hoverX, y: impactY };
  bubble.style.left = `${hoverX}px`;
  bubble.style.top = `${impactY}px`;
  bubble.hidden = false;
  bubble.classList.add("is-in");
  
  later(() => {
    bubble.classList.remove("is-in");
    bubble.classList.add("is-idle");
  }, 1000);
  
  announce("An authentic sapphire ink droplet gathers on the letter.");
}

async function writeEntrance() {
  writing = true;
  generating = false;
  setPhase("pen-writing");
  
  const bubble = $("#bubble");
  const halo = $("#impact-halo");
  const dropRig = $("#drop-rig");
  
  bubble.hidden = true;
  bubble.classList.remove("is-in", "is-idle");
  halo.classList.remove("is-active");
  dropRig.className = "ink-drop-rig";
  
  $("#pen").classList.remove("is-away");
  $("#cracks").classList.remove("is-on", "is-grow");
  
  $$(".ink-pool").forEach((p) => {
    p.setAttribute("r", "0");
    p.style.opacity = "0";
  });
  
  initInkCanvas();
  await document.fonts.ready.catch(() => {});
  announce("The David Oscarson fountain pen writes in royal Prussian blue on the letter.");
  
  for (const line of LINES) {
    const path = $(`#${line.id}`);
    path.setAttribute("d", measureGuide(line));
    path.setAttribute("stroke-width", String(line.width));
    path.style.strokeDashoffset = "1";
  }
  
  await pause(320);
  
  for (let i = 0; i < LINES.length; i++) {
    const line = LINES[i];
    await traceGuide($(`#${line.id}`), line.size);
    poolInk(line);
    if (i < LINES.length - 1) {
      // Graceful lift between lines
      const nextLine = LINES[i + 1];
      placePen(nextLine.x, nextLine.y - 20, 15, 0.2, true);
      await pause(260);
    }
  }
  
  writing = false;
  setPhase("ready-to-enter");
  
  // Lift and begin realistic drip sequence
  await dripInkSequence();
  
  // Pen glides away to top-right
  await pause(600);
  $("#pen").classList.add("is-away");
}

function colorCode(src) {
  const escaped = src
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
  const tokenPattern = /("(?:[^"\\]|\\.)*")|(^#.*$)|\b(from|import|if|return|normalize|classify|policy|ledger|Fixture|redact|halt|gate|write)\b/gm;
  return escaped.replace(tokenPattern, (token, stringToken, commentToken, wordToken) => {
    if (stringToken) return `<span class="st">${stringToken}</span>`;
    if (commentToken) return `<span class="cm">${commentToken}</span>`;
    if (["from", "import", "if", "return"].includes(wordToken)) return `<span class="kw">${wordToken}</span>`;
    return `<span class="fn">${wordToken}</span>`;
  });
}

function setGutter(lines) {
  const gutter = $("#gutter");
  gutter.replaceChildren();
  for (let i = 1; i <= Math.max(lines, 1); i += 1) {
    const li = document.createElement("li");
    li.textContent = String(i);
    gutter.appendChild(li);
  }
}

async function typeInto(el, text, htmlFn, ms = 8) {
  el.textContent = "";
  if (reduced) {
    el.innerHTML = htmlFn ? htmlFn(text) : text;
    return;
  }
  let out = "";
  for (const ch of text) {
    if (!generating) return;
    out += ch;
    // Keep the in-progress stream as text. Re-highlighting partial HTML
    // escapes the spans that were inserted on the previous keystroke.
    el.textContent = out;
    if (el.id === "codegen") setGutter(out.split("\n").length);
    el.scrollTop = el.scrollHeight;
    await pause(ch === "\n" ? ms * 6 : ms);
  }
  if (htmlFn) el.innerHTML = htmlFn(text);
}

function renderCards() {
  const root = $(".files");
  root.replaceChildren();
  FIXTURES.forEach((item) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "file";
    btn.dataset.id = item.id;
    if (item.id === selectedId) btn.classList.add("is-on");
    btn.innerHTML = `
      <b>${item.filename}</b>
      <span class="tag">${item.signal}</span>
      <small>${item.safeSummary}</small>
    `;
    btn.addEventListener("click", () => inspect(item.id));
    root.appendChild(btn);
  });
}

function decisionFor(item) {
  if (item.id === "fixture-03" && phase === "blocked-by-policy") return "blocked";
  if (item.id === "fixture-03" && (phase === "sent-to-human-review" || phase === "evidence-saved")) return "review";
  return "review-only";
}

function renderEvidence(item) {
  const scanner =
    item.scanner === "not-connected" || item.scanner === "not-run"
      ? item.scanner
      : "synthetic result";

  $(".evidence-body").innerHTML = `
    <div class="row"><span>category</span><b>${item.category}</b></div>
    <div class="row"><span>summary</span><b>${item.safeSummary}</b></div>
    <div class="row"><span>decision</span><b>${decisionFor(item)}</b></div>
    <div class="row"><span>redaction</span><b>${item.redacted ? "redacted" : "visible"}</b></div>
    <div class="row"><span>hash</span><b>${item.evidenceHash}</b></div>
    <div class="row"><span>timestamp</span><b>2026-08-16T00:00:00Z</b></div>
    <div class="row"><span>scanner</span><b>${scanner}</b></div>
    <div class="row"><span>payload</span><b>not displayed</b></div>
  `;
}

function paintChain() {
  $$(".step").forEach((step) => {
    const id = step.dataset.id;
    step.classList.remove("is-on", "is-halt");
    const idx = CHAIN.indexOf(id);
    const blocked = ["blocked-by-policy", "sent-to-human-review", "evidence-saved"].includes(phase);
    const reviewing = phase === "sent-to-human-review" || phase === "evidence-saved";
    if (phase === "inspecting-fixture" && idx <= 2) step.classList.add("is-on");
    if (blocked && idx <= 3) step.classList.add("is-on");
    if (blocked && id === "policy") step.classList.add("is-halt");
    if (reviewing && id === "ledger") step.classList.add("is-on");
  });
}

function inspect(id) {
  selectedId = id;
  const item = FIXTURES.find((f) => f.id === id);
  $$(".file").forEach((row) => row.classList.toggle("is-on", row.dataset.id === id));
  renderEvidence(item);
  if (document.body.classList.contains("is-lab")) {
    setPhase("inspecting-fixture");
    announce(`Inspecting synthetic PenTel fixture ${item.filename}. Example only.`);
    paintChain();
  }
}

async function generateWalk() {
  generating = true;
  selectedId = "fixture-03";
  setPhase("rehearsal-starting");
  $("#gen-pill").textContent = "generating";
  $("#log-status").textContent = "streaming";
  announce("Generating a synthetic walk. No scanner is connected.");
  inspect("fixture-03");
  const log = $("#agent-log");
  const code = $("#codegen");
  log.textContent = "";
  code.textContent = "";
  setGutter(1);

  later(() => {
    setPhase("inspecting-fixture");
    paintChain();
  }, 400);

  await Promise.all([
    typeInto(log, AGENT_LOG, null, 7),
    typeInto(code, CODE_WALK, colorCode, 6),
  ]);

  if (!generating) return;
  setPhase("blocked-by-policy");
  paintChain();
  renderEvidence(FIXTURES[2]);
  $("#gen-pill").textContent = "halted";
  $("#log-status").textContent = "policy_gate";
  announce("Policy gate blocked the example fixture. The path stops here.");
  await pause(500);
  setPhase("sent-to-human-review");
  paintChain();
  await pause(400);
  setPhase("evidence-saved");
  paintChain();
  renderEvidence(FIXTURES[2]);
  $("#gen-pill").textContent = "saved";
  announce("Redacted evidence placeholder saved. Synthetic result only.");
}

function startRehearsal() {
  clearTimers();
  generateWalk();
}

function tearPolygons(w, h, x) {
  const jagged = [];
  for (let y = 0; y <= h; y += 14) {
    const j = x + Math.sin(y / 24) * 20 + ((y * 19) % 16) - 8;
    jagged.push([Math.max(20, Math.min(w - 20, j)), y]);
  }
  jagged.push([x, h]);
  const seam = jagged.map(([jx, y]) => `${jx}px ${y}px`);
  return {
    left: `polygon(0px 0px, ${seam.join(", ")}, 0px ${h}px)`,
    right: `polygon(${w}px 0px, ${seam.join(", ")}, ${w}px ${h}px)`,
  };
}

function drawCracks(paper, bx, by) {
  const w = 900;
  const h = 1160;
  const x = (bx / paper.clientWidth) * w;
  const y = (by / paper.clientHeight) * h;
  $("#crack-1").setAttribute(
    "d",
    `M ${x} ${y} C ${x - 36} ${y - 110}, ${x + 18} ${y - 220}, ${x - 12} 4`,
  );
  $("#crack-2").setAttribute(
    "d",
    `M ${x} ${y} C ${x + 48} ${y + 90}, ${x - 24} ${y + 240}, ${x + 22} ${h - 6}`,
  );
  $("#crack-3").setAttribute(
    "d",
    `M ${x} ${y} C ${x - 90} ${y + 30}, ${x - 180} ${y - 12}, 6 ${y + 12}`,
  );
  $("#crack-4").setAttribute(
    "d",
    `M ${x} ${y} C ${x + 100} ${y - 20}, ${x + 220} ${y + 40}, ${w - 10} ${y - 10}`,
  );
  const cracks = $("#cracks");
  cracks.classList.add("is-on", "is-grow");
}

function clearRip() {
  $("#paper-clone")?.remove();
  const paper = $("#paper");
  paper.classList.remove("rip-half", "fly-left", "fly-right");
  paper.style.clipPath = "";
  paper.style.position = "";
  $("#page").classList.remove("is-rumbling");
  $("#cracks").classList.remove("is-on", "is-grow");
}

function resetDemo() {
  writing = false;
  generating = false;
  clearTimers();
  selectedId = "fixture-03";
  document.body.classList.remove("is-lab", "is-ripping");
  clearRip();
  $("#gen-pill").textContent = "idle";
  $("#log-status").textContent = "awaiting generation";
  $("#agent-log").textContent = "";
  $("#codegen").textContent = "";
  setGutter(1);
  renderCards();
  renderEvidence(FIXTURES[2]);
  paintChain();
  writeEntrance();
}

async function enterLab() {
  if (phase !== "ready-to-enter" && !readyPhases()) return;
  const paper = $("#paper");
  const page = $("#page");
  const revealTerminal = () => window.location.assign("/pen-console/gate.html");
  
  announce("The letter begins to tear.");
  document.body.classList.add("is-ripping");
  playTear();
  
  if (reduced) {
    revealTerminal();
    return;
  }
  
  page.classList.add("is-rumbling");
  drawCracks(paper, bubbleAt.x, bubbleAt.y);
  await pause(950);
  
  page.classList.remove("is-rumbling");
  $("#bubble").hidden = true;
  $("#pen").classList.add("is-away");

  const clone = paper.cloneNode(true);
  clone.id = "paper-clone";
  clone.querySelectorAll("[id]").forEach((el) => {
    if (el.id) el.id = `${el.id}-c`;
  });
  clone.querySelector("button")?.remove();
  
  page.appendChild(clone);
  
  const tearX = bubbleAt.x;
  const clips = tearPolygons(paper.clientWidth, paper.clientHeight, tearX);
  
  paper.classList.add("rip-half");
  clone.classList.add("rip-half");
  paper.style.clipPath = clips.left;
  clone.style.clipPath = clips.right;
  
  void paper.offsetWidth;
  paper.classList.add("fly-left");
  clone.classList.add("fly-right");
  
  await pause(1250);
  revealTerminal();
}

function boot() {
  document.documentElement.classList.remove("no-js");
  renderCards();
  renderEvidence(FIXTURES[2]);
  paintChain();
  writeEntrance();

  window.addEventListener("resize", () => {
    if (!document.body.classList.contains("is-lab")) {
      initInkCanvas();
    }
  });

  $("#start").addEventListener("click", startRehearsal);
  $("#reset").addEventListener("click", resetDemo);
  $("#bubble").addEventListener("click", enterLab);
}

boot();
