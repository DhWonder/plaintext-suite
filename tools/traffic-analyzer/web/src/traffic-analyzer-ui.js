/* =====================================================================
   The page. Everything here is presentation: it asks the worker for
   numbers and draws them. No analysis happens on this thread, which is
   why the page stays usable while a big capture is being read.
   ===================================================================== */

const el = id => document.getElementById(id);
const fmt = n => (n === null || n === undefined) ? "-" : Number(n).toLocaleString("en-US");
const esc = s => String(s === null || s === undefined ? "" : s)
  .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");

function bytes(n){
  if(n === null || n === undefined) return "-";
  if(n < 1024) return n + " B";
  if(n < 1048576) return (n/1024).toFixed(1) + " KB";
  if(n < 1073741824) return (n/1048576).toFixed(1) + " MB";
  return (n/1073741824).toFixed(2) + " GB";
}
function clockTime(seconds){
  if(!seconds) return "-";
  const d = new Date(seconds * 1000);
  return d.toLocaleTimeString("en-GB", {hour12:false});
}

const LEVEL_COLOUR = {critical:"#FB7185", high:"#FBBF24", watch:"#22D3EE", normal:"#34D399"};

/* ---------------------------------------------------------------------
   Talking to the worker. Every request gets an id so the answers cannot
   get crossed when several are in flight.
   --------------------------------------------------------------------- */
let engine = null;
let engineKind = "";
let nextId = 1;
const waiting = new Map();

function fromEngine(message){
  if(message.type === "progress"){ showProgress(message); return; }
  const pending = waiting.get(message.id);
  if(!pending) return;
  waiting.delete(message.id);
  if(message.type === "error") pending.reject(new Error(message.message));
  else pending.resolve(message);
}

/* Start the analysis on its own thread if the browser will let us.

   Safari will not: a page opened straight from disk has no origin, and it
   refuses to load a worker from a blob URL in that situation. That is most of
   why this page used to do nothing at all on an iPhone. So if the worker does
   not come up, the same engine runs on the page thread instead. Slower, and
   the page pauses while a big capture is read, but it works. */
let workerUsable = null;      // null until we know, false once proven otherwise
let engineReady = null;       // resolves once we know which engine we have

/* Start the engine and report when it is genuinely answering.

   Nothing gets handed a capture file until this settles. That matters: Safari
   can leave a Worker object looking perfectly healthy while the script behind
   it never loaded, and a file posted into that hole comes back as a read
   error that points nowhere near the real problem. Prove it is alive first,
   with a message that costs nothing, then send it work. */
function startEngine(){
  stopEngine();

  if(workerUsable === false || !startWorkerEngine()){
    startInlineEngine();
    engineReady = Promise.resolve();
    return engineReady;
  }

  engineReady = new Promise((resolve) => {
    let settled = false;
    const finish = () => { if(!settled){ settled = true; resolve(); } };
    // Only believe the worker is healthy if the answer came back while the
    // worker was still the engine. A pending ping gets replayed on the way
    // down to the inline engine, and that reply proves nothing about the worker.
    ask({cmd:"ping"}).then(() => {
      if(engineKind === "worker") workerUsable = true;
      finish();
    }).catch(finish);
    setTimeout(() => {
      if(!settled && engineKind === "worker") startInlineEngine();
      finish();
    }, 1200);
  });
  return engineReady;
}

function startWorkerEngine(){
  if(typeof Worker === "undefined" || typeof Blob === "undefined") return false;
  let worker;
  try {
    const blob = new Blob([WORKER_SOURCE], {type:"application/javascript"});
    worker = new Worker(URL.createObjectURL(blob));
  } catch(err){
    return false;
  }
  worker.onmessage = (event) => fromEngine(event.data);
  worker.onerror = () => {
    // Safari reports this asynchronously, after we have already asked it
    // something, so whatever was in flight gets asked again inline.
    if(engineKind === "worker") startInlineEngine();
  };
  engine = { post: (m) => worker.postMessage(m), stop: () => worker.terminate() };
  engineKind = "worker";
  return true;
}

function startInlineEngine(){
  if(engineKind === "inline") return;
  workerUsable = false;
  const previous = [...waiting.values()];
  stopEngine();

  const shim = { onmessage: null, postMessage: (message) => fromEngine(message) };
  try {
    (new Function("self", WORKER_SOURCE))(shim);
  } catch(err){
    showError("The analysis engine would not start.", " " + (err.message || ""));
    return;
  }

  engine = {
    post: (message) => { if(shim.onmessage) shim.onmessage({data: message}); },
    stop: () => {}
  };
  engineKind = "inline";
  const note = el("inline");
  if(note) note.classList.add("on");

  // Anything already asked for went to a worker that never woke up. Ask again.
  for(const pending of previous) engine.post(pending.request);
}

function stopEngine(){
  if(engine && engine.stop) engine.stop();
  engine = null;
  engineKind = "";
}

function ask(request){
  return new Promise((resolve, reject) => {
    const id = nextId++;
    const full = Object.assign({id}, request);
    waiting.set(id, {resolve, reject, request: full});
    if(!engine) startEngine();
    engine.post(full);
  });
}

/* ---------------------------------------------------------------------
   State
   --------------------------------------------------------------------- */
const state = {
  summary: null,
  mode: "browser",        // browser, session or live
  sessionId: null,
  serverUp: false,
  live: false,
  liveTimer: null,
  points: null,
  filter: {level:"all", q:"", order:"score", network:null, fingerprint:null},
  loaded: 0,
  total: 0,
  selected: null,
  revealed: null          // during playback: the addresses seen so far
};

/* Exposed so the parity test can read the numbers out of a real browser and
   compare them against the Python. Nothing on the page uses this. */
window.__state = state;

/* ---------------------------------------------------------------------
   Chrome: errors, notes, progress
   --------------------------------------------------------------------- */
function showError(headline, detail){
  const node = el("err");
  node.innerHTML = "<b>" + esc(headline) + "</b>" + (detail ? esc(detail) : "");
  node.classList.add("on");
}
function clearError(){ el("err").classList.remove("on"); }
function showNote(text){
  const node = el("note");
  if(!text){ node.classList.remove("on"); return; }
  node.textContent = text;
  node.classList.add("on");
}

function showProgress(p){
  const box = el("prog");
  box.classList.add("on");
  const fill = el("progFill");
  if(p.total){
    fill.classList.remove("spin");
    fill.style.width = Math.min(100, 100 * p.bytes / p.total).toFixed(1) + "%";
  } else {
    fill.classList.add("spin");
  }
  el("progWhat").textContent = "reading the capture...";
  el("progNum").textContent = fmt(p.frames) + " frames, " + fmt(p.used) + " usable, "
    + fmt(p.sources) + " sources";
}
function hideProgress(){ el("prog").classList.remove("on"); }

/* ---------------------------------------------------------------------
   Loading a capture
   --------------------------------------------------------------------- */
async function loadFile(file){
  clearError();
  showNote("");
  el("clock").innerHTML = "reading <b>" + esc(file.name) + "</b>";
  await startEngine();
  const started = Date.now();
  try {
    let answer;
    try {
      answer = await ask({cmd:"parse", file});
    } catch(err){
      // Safari will accept a file handed to a background worker and then be
      // unable to read it. Try again on this thread before believing the file
      // is at fault, but only claim that is what happened if it then works.
      if(engineKind !== "worker") throw err;
      startInlineEngine();
      try {
        answer = await ask({cmd:"parse", file});
        const note = el("inline");
        if(note) note.classList.add("on");
      } catch(second){
        const note = el("inline");
        if(note) note.classList.remove("on");
        throw second;
      }
    }
    hideProgress();
    state.mode = "browser";
    state.sessionId = null;
    stopLive();
    adopt(answer.summary, file.name, (Date.now() - started)/1000);
    return true;
  } catch(err){
    hideProgress();
    showError("That capture could not be read.", " " + explainReadFailure(err.message));
    el("clock").textContent = "nothing loaded";
    return false;
  }
}

/* Turn a browser file error into something you can act on.

   "The requested file could not be read, typically due to permission problems
   that have occurred after a reference to a file was acquired" is a real
   sentence a browser really says, and it tells you nothing. It almost always
   means one of three ordinary things. */
function explainReadFailure(message){
  const text = String(message || "");
  const unreadable = /could not be read|NotReadableError|permission|I\/O/i.test(text);
  if(!unreadable) return " " + text;
  return " The browser could not read the file off the disk. That is not about the capture's "
    + "contents, it happens when the file is still being written by tcpdump or Wireshark, when it "
    + "lives on a cloud folder that has not finished syncing, or when it moved or was renamed after "
    + "you picked it. Stop the capture, copy the file to an ordinary local folder, and choose it "
    + "again. (The browser's own words were: " + text + ")";
}

function buildExamples(){
  el("exGrid").innerHTML = EXAMPLES.map((e, i) =>
    "<button class='ex' data-example='" + i + "'><b>" + esc(e.title) + "</b>"
    + "<span>" + esc(e.blurb) + "</span><i>" + esc(e.file) + "</i></button>").join("");
}

async function loadExample(index, attempt){
  const example = EXAMPLES[index];
  if(!example) return;
  clearError();
  el("clock").textContent = "unpacking " + example.title + "...";
  let file;
  try {
    const raw = Uint8Array.from(atob(example.data), c => c.charCodeAt(0));
    file = new File([raw], example.file);
  } catch(err){
    showError("That example would not unpack.", " " + err.message);
    return;
  }

  const ok = await loadFile(file);
  if(ok){
    el("examples").classList.remove("on");
    showNote(example.title + ": " + example.blurb
      + " This is traffic I generated to show the pattern, not a real network.");
    return;
  }
  // Safari, on a page opened straight from a file, sometimes cannot read a
  // blob that was only just built. A moment later it can.
  if(!attempt){
    await new Promise(done => setTimeout(done, 600));
    clearError();
    return loadExample(index, 1);
  }
}

/* Back to nothing. Stops a running capture first, and keeps it, because
   throwing away a recording somebody was in the middle of taking is not a
   reset, it is a mistake with a friendly name. */
async function resetEverything(){
  if(state.live){
    await stopLiveCapture();
  }
  stopReplay(true);
  replay.data = null;
  el("playbar").classList.remove("on");

  state.summary = null;
  state.mode = "browser";
  state.sessionId = null;
  state.revealed = null;
  state.loaded = 0;
  state.total = 0;
  mapPoints = null;
  view.scale = 1; view.x = 0; view.y = 0;
  closePanel();

  clearError();
  showNote("");
  el("scope").classList.remove("on");
  el("inline").classList.remove("on");
  el("clock").textContent = "nothing loaded";
  el("file").value = "";
  if(el("sessions")) el("sessions").value = "";
  el("resetBtn").style.display = "none";
  showEmpty();
}

function showEmpty(){
  ["k1","k2","k3","k4","k5"].forEach(id => el(id).textContent = "0");
  el("verdictHead").textContent = "Nothing loaded";
  el("verdictHead").className = "verdict";
  el("verdictBody").textContent = "Drop a capture in, or open one of the examples to see what "
    + "each kind of trouble looks like.";
  el("verdictCard").className = "card";
  const status = el("status");
  status.className = "status calm";
  status.querySelector("b").textContent = "Waiting for a capture";
  el("statusText").textContent = "Nothing is loaded yet.";
  ["topBody","srcBody","feed","regionBars","portBars","protoBars","recs","fileFacts"]
    .forEach(id => { if(el(id)) el(id).innerHTML = ""; });
  el("cohortCard").style.display = "none";
  el("srcCount").textContent = "";
  const canvas = el("tlChart");
  if(canvas) canvas.getContext("2d").clearRect(0, 0, canvas.width, canvas.height);
  if(currentView() === "map") drawMap();
}

function adopt(summary, label, elapsed){
  state.summary = summary;
  state.filter = {level:"all", q:"", order:"score", network:null, fingerprint:null};
  el("q").value = "";
  document.querySelectorAll(".chip").forEach(c =>
    c.classList.toggle("on", c.dataset.level === "all"));
  el("activeFilter").style.display = "none";

  const read = summary.read || {};
  let what = label || summary.origin || "capture";
  el("clock").innerHTML = "<b>" + esc(what) + "</b> &middot; "
    + fmt(summary.total_packets) + " packets"
    + (elapsed ? " in " + elapsed.toFixed(1) + "s" : "");

  if(read.truncated){
    showNote("This capture ends in the middle of a packet, so it was cut short when it was saved. "
      + "Everything up to that point was read and is in the report.");
  } else if(summary.capped){
    showNote(summary.capped.note);
  }

  renderAll();
  refreshSources(true);
  el("resetBtn").style.display = "";

  // Throw away the old map. Forgetting this is why a second capture used to
  // show the first one's dots: every other view rebuilt itself, the map sat
  // there holding a cache nobody cleared.
  mapPoints = null;
  view.scale = 1; view.x = 0; view.y = 0;
  state.revealed = null;
  loadReplay();
  if(currentView() === "map") drawMap();
}

/* ---------------------------------------------------------------------
   Playing the capture back.

   A finished report tells you what happened. Watching it happen tells you
   something the report cannot: how fast it arrived, and in what order. The
   sources light up on the map as they first appear, the alert feed fills
   in, and the counters climb.
   --------------------------------------------------------------------- */
const replay = {
  data: null, index: 0, playing: false, raf: null, last: 0, carry: 0,
  packets: 0, seen: [], hostile: 0
};

async function loadReplay(){
  stopReplay(true);
  el("playbar").classList.remove("on");
  replay.data = null;

  // Live is already the present, and a saved session's numbers live on the
  // server rather than in the worker, so asking the worker would replay
  // whatever capture it happens to still be holding. Neither gets a playbar.
  if(state.mode !== "browser") return;
  try {
    const answer = await ask({cmd:"replay", steps:400});
    if(!answer.replay || !answer.replay.steps.length) return;
    replay.data = answer.replay;
    resetReplay();
    el("playbar").classList.add("on");
  } catch(err){
    /* no replay is not worth an error message, the report still works */
  }
}

function resetReplay(){
  replay.index = 0;
  replay.packets = 0;
  replay.seen = [];
  replay.hostile = 0;
  replay.carry = 0;
  state.revealed = null;
  el("pfill").style.width = "0%";
  el("pclock").textContent = "0:00";
  el("restartBtn").style.display = "none";
}

function replayClock(seconds){
  const whole = Math.max(0, Math.round(seconds));
  return Math.floor(whole / 60) + ":" + String(whole % 60).padStart(2, "0");
}

function startReplay(){
  if(!replay.data) return;
  if(replay.index >= replay.data.steps.length) resetReplay();

  if(replay.index === 0){
    // Start from an empty page so there is something to watch fill up.
    state.revealed = new Set();
    replay.seen = [];
    el("feed").innerHTML = "";
    el("topBody").innerHTML = "";
  }
  replay.playing = true;
  replay.last = 0;
  el("playBtn").textContent = "Pause";
  el("playbar").classList.add("running");
  el("restartBtn").style.display = "";
  el("phint").textContent = "playing back. the map fills in as each address first appears";
  replay.raf = requestAnimationFrame(replayTick);
  ensureMapLoop();
}

function stopReplay(silent){
  replay.playing = false;
  if(replay.raf){ cancelAnimationFrame(replay.raf); replay.raf = null; }
  el("playBtn").textContent = replay.index && replay.data
    && replay.index < replay.data.steps.length ? "Resume" : "Play it through";
  el("playbar").classList.remove("running");
  if(!silent) el("phint").textContent = "paused. the report below shows the whole capture";
}

function finishReplay(){
  stopReplay(true);
  state.revealed = null;                    // back to showing everything
  replay.index = replay.data ? replay.data.steps.length : 0;
  el("playBtn").textContent = "Play again";
  el("pfill").style.width = "100%";
  el("phint").textContent = "finished. this is the whole capture again";
  renderAll();
  if(currentView() === "map") drawMap();
}

function replayTick(now){
  if(!replay.playing || !replay.data) return;
  const stepMs = Number(el("speed").value) || 62;
  if(!replay.last) replay.last = now;
  replay.carry += now - replay.last;
  replay.last = now;

  let advanced = false;
  while(replay.carry >= stepMs && replay.index < replay.data.steps.length){
    replay.carry -= stepMs;
    applyStep(replay.data.steps[replay.index]);
    replay.index++;
    advanced = true;
  }

  if(advanced) paintReplay();

  if(replay.index >= replay.data.steps.length){ finishReplay(); return; }
  replay.raf = requestAnimationFrame(replayTick);
}

function applyStep(step){
  replay.packets += step.packets;
  for(const source of step.sources){
    if(state.revealed) state.revealed.add(source.ip);
    replay.seen.push(source);
    if(source.level === "critical" || source.level === "high") replay.hostile++;
  }
}

function paintReplay(){
  const data = replay.data;
  const elapsed = replay.index * data.seconds_per_step;
  const total = data.total_seconds;

  el("pfill").style.width = (100 * replay.index / data.steps.length).toFixed(1) + "%";
  el("pclock").textContent = replayClock(elapsed) + " / " + replayClock(total);

  el("k1").textContent = fmt(replay.packets);
  el("k2").textContent = fmt(replay.seen.length);
  el("k3").textContent = fmt(replay.hostile);

  // The busiest step so far, converted back to packets per second.
  let peak = 0;
  for(let i = 0; i < replay.index; i++){
    const rate = data.steps[i].packets / data.seconds_per_step;
    if(rate > peak) peak = rate;
  }
  el("k4").textContent = fmt(Math.round(peak));

  const status = el("status");
  const share = replay.packets ? 100 * replay.hostile / Math.max(replay.seen.length, 1) : 0;
  status.className = "status " + (replay.hostile ? (share > 40 ? "bad" : "warn") : "calm");
  status.querySelector("b").textContent = replay.hostile
    ? ("Attack in progress: " + fmt(replay.hostile) + " hostile sources so far")
    : "Watching. Nothing hostile yet";
  el("statusText").textContent = replayClock(elapsed) + " into the capture, "
    + fmt(replay.packets) + " packets from " + fmt(replay.seen.length) + " addresses.";

  drawReplayTrace();
  paintReplayTables();
  if(currentView() === "map") drawMap();
}

function drawReplayTrace(){
  const data = replay.data;
  if(!data || !state.summary) return;
  const partial = [];
  for(let i = 0; i < replay.index; i++) partial.push(data.steps[i].packets);
  const kept = state.summary.timeline;
  state.summary.timeline = partial;
  drawTimeline();
  state.summary.timeline = kept;
  el("tlSub").textContent = "packets per "
    + (data.seconds_per_step > 1 ? data.seconds_per_step + " seconds" : "second")
    + ", up to " + replayClock(replay.index * data.seconds_per_step);
}

function paintReplayTables(){
  const worst = replay.seen.slice().sort((a, b) => b.score - a.score || b.packets - a.packets);
  el("topBody").innerHTML = worst.slice(0, 12).map(r =>
    "<tr data-ip='" + esc(r.ip) + "'>"
    + "<td class='ipcell'>" + esc(r.ip) + "</td>"
    + "<td><span class='pill " + r.level + "'>" + r.level + "</span></td>"
    + "<td class='num'>" + fmt(r.packets) + "</td>"
    + "<td class='num'>" + fmt(r.rate) + "</td>"
    + "<td>" + esc(r.protocol) + "</td>"
    + "<td style='color:var(--muted)'>" + esc(r.region) + "</td>"
    + "<td style='color:var(--muted);max-width:280px;overflow:hidden;text-overflow:ellipsis;"
    + "white-space:nowrap'>" + esc(r.reason) + "</td></tr>").join("");

  const hostile = replay.seen.filter(r => r.level === "critical" || r.level === "high");
  el("feed").innerHTML = hostile.slice(-60).reverse().map(a =>
    "<div class='ln' data-ip='" + esc(a.ip) + "'>"
    + "<span class='t'>" + replayClock(replay.index * replay.data.seconds_per_step) + "</span>"
    + "<span><span class='rule " + (a.level === "critical" ? "critical" : "") + "'>"
    + esc(a.rule) + "</span> <span class='mono' style='color:var(--cyan)'>" + esc(a.ip) + "</span>"
    + "<span class='msg'>" + esc(a.message) + "</span></span></div>").join("");
}

/* ---------------------------------------------------------------------
   Report view
   --------------------------------------------------------------------- */
function renderAll(){
  const s = state.summary;
  if(!s) return;

  el("k1").textContent = fmt(s.total_packets);
  el("k2").textContent = fmt(s.sources_total);
  el("k3").textContent = fmt(s.hostile_sources);
  el("k4").textContent = fmt(s.peak_per_second);
  el("k5").textContent = fmt((s.vectors || []).length);

  const [head, body] = s.verdict;
  const attack = (s.hostile_sources || 0) > 0;
  el("verdictHead").textContent = head;
  el("verdictHead").className = "verdict " + (attack ? "bad" : "good");
  el("verdictBody").textContent = body;
  el("verdictCard").className = "card" + (attack ? " bad" : "");

  const status = el("status");
  status.className = "status " + (attack ? (s.hostile_share > 40 ? "bad" : "warn") : "calm");
  status.querySelector("b").textContent = head;
  el("statusText").textContent = attack
    ? (fmt(s.hostile_packets) + " of " + fmt(s.total_packets) + " packets came from sources that do not behave like visitors.")
    : "Nothing here looks like an attack.";

  drawTimeline();
  renderFileFacts();
  renderTop();
  renderBars();
  renderCohorts();
  renderRecs();
  renderConsole();
}

function renderScope(snapshot){
  const box = el("scope");
  if(!snapshot){ box.classList.remove("on"); return; }
  const mine = (snapshot.local_ips || []).filter(a => a !== "127.0.0.1" && a !== "::1");
  box.classList.add("on");
  box.innerHTML =
    "<div class='row'>"
    + "<span>This machine: <b class='mono'>" + (mine.length ? esc(mine.join(", ")) : "unknown")
    + "</b></span>"
    + (snapshot.public_ip
        ? "<span>Seen from the internet as: <b class='mono'>" + esc(snapshot.public_ip) + "</b></span>"
        : "")
    + (snapshot.loopback_dropped
        ? "<span>" + fmt(snapshot.loopback_dropped) + " packets this machine sent to itself, left out</span>"
        : "")
    + "</div>"
    + "<details><summary>What this capture can and cannot see</summary>"
    + "<div class='sbody'>A network card only sees traffic that is going to or from this machine, "
    + "plus anything sent to everybody at once. That is how a switch works: it delivers each packet "
    + "to the one port it belongs to, so your other devices' traffic never reaches here to be read. "
    + "<b>So this is a picture of this computer, not of your whole network.</b> To see everything, "
    + "the capture has to run somewhere all the traffic passes: a mirror or SPAN port on a managed "
    + "switch, a network tap, or the router itself. On most home routers you cannot do that without "
    + "replacing the firmware, which is a bigger job than it sounds and worth being honest about."
    + "</div></details>";
}

function renderFileFacts(){
  const s = state.summary, read = s.read || {};
  const live = read.format === "live";
  const rows = [];
  const add = (k, v) => rows.push("<div class='r'><span>" + esc(k) + "</span><span>" + esc(v) + "</span></div>");

  // The same card answers two different questions depending on where the
  // traffic came from, so it should not keep saying "file" during a live run.
  const card = el("fileFacts").closest(".card");
  card.querySelector("h3").textContent = live ? "What is being watched" : "What the file actually was";
  card.querySelector(".sub").textContent = live
    ? "the interface this is listening on right now"
    : "read straight from the capture, not assumed";

  if(live){
    const names = read.interfaces && read.interfaces.length ? read.interfaces[0].name : "unknown";
    add("source", "live capture");
    add("interface", names);
    add("packets seen", fmt(read.frames));
    add("listening for", s.duration_seconds + " s");
  } else {
    add("format", (read.format || "unknown") + (read.compressed ? ", gzipped" : ""));
    const links = read.interfaces && read.interfaces.length
      ? [...new Set(read.interfaces.map(i => i.name))].join(", ") : "unknown";
    add("link layer", links);
    add("frames in file", fmt(read.frames));
    add("frames used", fmt(read.used));
    if(read.frames && read.used !== read.frames){
      const skipped = Object.entries(read.skipped || {}).sort((a,b) => b[1]-a[1])[0];
      if(skipped) add("most skipped", skipped[0] + " (" + fmt(skipped[1]) + ")");
    }
    add("capture length", s.duration_seconds + " s");
  }
  add("total volume", bytes(s.total_bytes));
  add("average rate", fmt(s.average_per_second) + " packets/s");
  add("main target", s.main_target);
  if(read.truncated) add("note", "file ends mid packet");
  if(live) add("saved to", "the traffic-analyzer database");
  el("fileFacts").innerHTML = rows.join("");
}

function renderTop(){
  const s = state.summary;
  el("topBody").innerHTML = (s.sources || []).slice(0, 12).map(r =>
    "<tr data-ip='" + esc(r.ip) + "'>"
    + "<td class='ipcell'>" + esc(r.ip) + "</td>"
    + "<td><span class='pill " + r.level + "'>" + r.level + "</span></td>"
    + "<td class='num'>" + fmt(r.packets) + "</td>"
    + "<td class='num'>" + fmt(r.rate) + "</td>"
    + "<td>" + esc(r.protocol) + "</td>"
    + "<td style='color:var(--muted)'>" + esc(r.region) + "</td>"
    + "<td style='color:var(--muted);max-width:280px;overflow:hidden;text-overflow:ellipsis;"
    + "white-space:nowrap'>" + esc((r.reasons || [""])[0]) + "</td></tr>").join("");
}

function barBlock(pairs, labelFn, valueFn){
  if(!pairs || !pairs.length) return "<div style='color:var(--muted);font-size:.84rem'>nothing to show</div>";
  const top = Math.max(...pairs.map(p => p[1])) || 1;
  return pairs.map(p =>
    "<div class='barrow'><div class='lab'>" + esc(labelFn(p)) + "</div>"
    + "<div class='tk'><div class='fl' style='width:" + (100*p[1]/top).toFixed(1) + "%'></div></div>"
    + "<div class='vl'>" + esc(valueFn ? valueFn(p) : fmt(p[1])) + "</div></div>").join("");
}

function renderBars(){
  const s = state.summary;
  const PORT_LABEL = {22:"SSH",25:"mail",53:"DNS",80:"web",123:"NTP",443:"web (secure)",
    445:"file sharing",1900:"SSDP",3306:"database",3389:"Remote Desktop",11211:"memcached"};
  el("regionBars").innerHTML = barBlock(s.regions, p => p[0]);
  el("portBars").innerHTML = barBlock(s.ports, p =>
    "port " + p[0] + (PORT_LABEL[p[0]] ? " (" + PORT_LABEL[p[0]] + ")" : ""));
  el("protoBars").innerHTML = barBlock(s.protocols, p => p[0]);
}

function renderCohorts(){
  const s = state.summary;
  const groups = s.cohorts || [];
  if(!groups.length){ el("cohortCard").style.display = "none"; return; }
  el("cohortCard").style.display = "";
  el("cohortList").innerHTML = groups.map(g =>
    "<div class='peer' data-print=\"" + esc(g.fingerprint) + "\" style='align-items:flex-start;"
    + "padding:9px 8px;border-bottom:1px solid var(--line)'>"
    + "<span class='pill " + g.level + "' style='margin-top:2px'>" + fmt(g.members) + "</span>"
    + "<span style='flex:1'><span style='font-size:.86rem'>" + esc(g.description) + "</span>"
    + "<span style='display:block;color:var(--muted);font-size:.76rem;margin-top:2px'>"
    + fmt(g.packets) + " packets &middot; example " + esc(g.example)
    + (g.regions && g.regions.length ? " &middot; mostly " + esc(g.regions[0][0]) : "")
    + "</span></span></div>").join("");
}

function renderRecs(){
  const s = state.summary;
  const colour = {high:"var(--red)", medium:"var(--amber)", low:"var(--cyan)"};
  el("recs").innerHTML = (s.recommendations || []).map(r => {
    const [title, detail, urgency] = r;
    return "<div style='padding:10px 0;border-bottom:1px solid var(--line)'>"
      + "<div style='display:flex;gap:9px;align-items:baseline;flex-wrap:wrap'>"
      + "<span class='pill' style='background:rgba(255,255,255,.06);color:"
      + (colour[urgency] || "var(--muted)") + "'>" + esc(urgency || "") + "</span>"
      + "<b style='font-size:.94rem'>" + esc(title) + "</b></div>"
      + "<p style='color:var(--muted);font-size:.86rem;margin-top:4px'>" + esc(detail) + "</p></div>";
  }).join("");
}

/* ---------------------------------------------------------------------
   Timeline chart
   --------------------------------------------------------------------- */
function drawTimeline(){
  const s = state.summary;
  const canvas = el("tlChart");
  if(!s || !canvas) return;
  const data = s.timeline || [];
  const ratio = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 500, h = 150;
  canvas.width = w * ratio; canvas.height = h * ratio;
  const g = canvas.getContext("2d");
  g.setTransform(ratio, 0, 0, ratio, 0, 0);
  g.clearRect(0, 0, w, h);

  el("tlSub").textContent = data.length
    ? ("packets per " + (s.timeline_step > 1 ? s.timeline_step + " seconds" : "second")
       + " across " + s.duration_seconds + " seconds")
    : "no timing information in this capture";
  if(!data.length) return;

  const peak = Math.max(...data) || 1;
  const pad = 6;
  const plotH = h - pad * 2;

  g.strokeStyle = "rgba(255,255,255,.06)";
  g.lineWidth = 1;
  for(let i = 1; i < 4; i++){
    const y = pad + plotH * i / 4;
    g.beginPath(); g.moveTo(0, y); g.lineTo(w, y); g.stroke();
  }

  const gradient = g.createLinearGradient(0, pad, 0, h - pad);
  gradient.addColorStop(0, "rgba(34,211,238,.45)");
  gradient.addColorStop(1, "rgba(34,211,238,.02)");

  g.beginPath();
  g.moveTo(0, h - pad);
  data.forEach((v, i) => {
    const x = data.length === 1 ? w/2 : (i / (data.length - 1)) * w;
    g.lineTo(x, h - pad - plotH * (v / peak));
  });
  g.lineTo(w, h - pad);
  g.closePath();
  g.fillStyle = gradient; g.fill();

  g.beginPath();
  data.forEach((v, i) => {
    const x = data.length === 1 ? w/2 : (i / (data.length - 1)) * w;
    const y = h - pad - plotH * (v / peak);
    i ? g.lineTo(x, y) : g.moveTo(x, y);
  });
  g.strokeStyle = "#22D3EE"; g.lineWidth = 2; g.stroke();

  g.fillStyle = "rgba(147,164,191,.9)";
  g.font = "11px 'JetBrains Mono', monospace";
  g.fillText(fmt(peak) + "/s peak", 6, 14);
}

/* ---------------------------------------------------------------------
   Source browser
   --------------------------------------------------------------------- */
let sourceRequest = 0;

async function fetchPage(offset, limit){
  if(state.mode === "session" && state.serverUp){
    const params = new URLSearchParams({offset, limit, order: state.filter.order});
    if(state.filter.level !== "all") params.set("level", state.filter.level);
    if(state.filter.q) params.set("q", state.filter.q);
    if(state.filter.network) params.set("network", state.filter.network);
    if(state.filter.fingerprint) params.set("fingerprint", state.filter.fingerprint);
    const response = await fetch("/api/session/" + state.sessionId + "/sources?" + params);
    const data = await response.json();
    return {total: data.total, rows: data.rows, offset};
  }
  const answer = await ask(Object.assign({cmd:"page", offset, limit}, state.filter));
  return answer.page;
}

async function refreshSources(reset){
  const mine = ++sourceRequest;
  const box = el("srcScroll");
  const keepScroll = reset ? box.scrollTop : 0;

  const page = await fetchPage(reset ? 0 : state.loaded, 200);
  if(mine !== sourceRequest) return;

  if(reset){
    // Replace the rows in one go rather than emptying the table first.
    // Clearing it collapses the page to nothing for a frame, which is what
    // made everything jump every couple of seconds during a live capture.
    el("srcBody").innerHTML = page.rows.map(rowHtml).join("");
    state.loaded = page.rows.length;
    box.scrollTop = keepScroll;
  } else {
    el("srcBody").insertAdjacentHTML("beforeend", page.rows.map(rowHtml).join(""));
    state.loaded += page.rows.length;
  }

  state.total = page.total;
  el("srcCount").textContent = fmt(state.total) + " addresses"
    + (state.loaded < state.total ? ", showing " + fmt(state.loaded) : "");
  el("loadMore").style.display = state.loaded < state.total ? "" : "none";
  if(!state.total) el("srcBody").innerHTML =
    "<tr><td colspan='9' class='empty'>Nothing matches that filter.</td></tr>";
}

function rowHtml(r){
  return "<tr data-ip='" + esc(r.ip) + "'>"
    + "<td class='ipcell'>" + esc(r.ip)
    + (r.hostname ? "<span style='display:block;color:var(--muted);font-size:.72rem'>"
       + esc(r.hostname) + "</span>" : "")
    + "</td>"
    + "<td><span class='pill " + r.level + "'>" + r.level + "</span></td>"
    + "<td class='num'>" + fmt(r.packets) + "</td>"
    + "<td class='num'>" + bytes(r.bytes) + "</td>"
    + "<td class='num'>" + fmt(r.rate) + "</td>"
    + "<td class='num'>" + fmt(r.ports_touched) + "</td>"
    + "<td>" + esc(r.protocol) + "</td>"
    + "<td class='mono' style='font-size:.76rem;color:var(--muted)'>" + esc(r.network) + "</td>"
    + "<td style='color:var(--muted);font-size:.78rem'>" + esc(r.region) + "</td></tr>";
}

function setFilter(changes, label){
  Object.assign(state.filter, changes);
  const box = el("activeFilter");
  if(label){
    box.style.display = "";
    box.innerHTML = "<span class='chip on' id='clearFilter'>" + esc(label) + " &times;</span>";
    el("clearFilter").onclick = () => setFilter({network:null, fingerprint:null}, null);
  } else {
    box.style.display = "none";
  }
  refreshSources(true);
}

/* ---------------------------------------------------------------------
   The detail panel: everything known about one address
   --------------------------------------------------------------------- */
async function openIp(ip){
  state.selected = ip;
  el("panel").classList.add("on");
  el("backdrop").classList.add("on");
  el("pIp").textContent = ip;
  el("pSub").textContent = "loading...";
  el("pBody").innerHTML = "<div class='empty'>looking it up...</div>";

  let detail = null, related = null, rule = null;
  try {
    if(state.mode === "session" && state.serverUp){
      const response = await fetch("/api/session/" + state.sessionId + "/source/" + encodeURIComponent(ip));
      const data = await response.json();
      detail = data.detail; related = data.related;
    } else {
      const answer = await ask({cmd:"detail", ip});
      detail = answer.detail; related = answer.related; rule = answer.rule;
    }
  } catch(err){
    el("pBody").innerHTML = "<div class='empty'>Could not load that address: " + esc(err.message) + "</div>";
    return;
  }
  if(!detail || !detail.ip){
    el("pBody").innerHTML = "<div class='empty'>Nothing recorded for that address.</div>";
    return;
  }
  renderPanel(detail, related || {}, rule);
}

function renderPanel(d, related, rule){
  el("pIp").textContent = d.ip;
  el("pSub").innerHTML = "<span class='pill " + d.level + "'>" + d.level + "</span> "
    + "score " + d.score + " &middot; " + esc(d.region)
    + (d.hostname ? " &middot; " + esc(d.hostname) : "");

  const parts = [];

  /* What it did */
  parts.push("<div class='psec'><h4>what it did</h4><div class='facts'>"
    + fact("packets", fmt(d.packets))
    + fact("volume", bytes(d.bytes))
    + fact("rate", fmt(d.rate) + "/s")
    + fact("share of capture", d.share_of_capture + "%")
    + fact("active for", d.duration + " s")
    + fact("first seen", clockTime(d.first))
    + "</div></div>");

  if(rule){
    parts.push("<div class='psec'><h4>rule matched</h4>"
      + "<div class='card' style='margin:0;padding:11px 13px'>"
      + "<div class='mono' style='color:var(--amber);font-weight:700;font-size:.86rem'>"
      + esc(rule[0]) + "</div>"
      + "<div style='color:var(--muted);font-size:.84rem;margin-top:3px'>" + esc(rule[1]) + "</div>"
      + "</div></div>");
  }

  /* Why it was flagged */
  parts.push("<div class='psec'><h4>why it was flagged</h4><ul class='why'>"
    + (d.reasons || []).map(r => "<li>" + esc(r) + "</li>").join("") + "</ul></div>");

  /* Its own activity over time */
  if(d.timeline && d.timeline.length){
    parts.push("<div class='psec'><h4>when it was active</h4>"
      + "<canvas class='spark' id='pSpark'></canvas>"
      + "<div style='color:var(--muted);font-size:.75rem;margin-top:4px'>"
      + "packets per second from this address, across the capture</div></div>");
  }

  /* The host itself */
  const host = d.host || {};
  parts.push("<div class='psec'><h4>about the host</h4><div class='facts'>"
    + fact("looks like", host.os_guess || "unknown")
    + fact("hops away", host.hops_away)
    + fact("TTL seen", host.observed_ttl)
    + fact("address family", "IPv" + d.family)
    + fact("network", d.network)
    + fact("kind", d.private ? "private or local" : "public internet")
    + "</div>"
    + "<div style='color:var(--muted);font-size:.75rem;margin-top:6px'>"
    + "The operating system guess comes from the starting TTL, which is 64 on Linux and Unix, "
    + "128 on Windows and 255 on network equipment. It is a strong hint, not proof, and a "
    + "firewall in the middle can change it."
    + (host.distinct_ttls > 3 ? " This address showed " + host.distinct_ttls + " different TTLs, "
       + "which usually means the source address is forged and the traffic is really coming from "
       + "several different machines." : "")
    + "</div></div>");

  /* What it aimed at */
  if(d.dports && d.dports.length){
    parts.push("<div class='psec'><h4>ports it aimed at</h4><div class='plist'>"
      + d.dports.map(p => "<div class='r'><span>port " + p[0]
        + (p[2] ? " &middot; " + esc(p[2]) : "") + "</span><span>" + fmt(p[1]) + "</span></div>").join("")
      + "</div></div>");
  }
  if(d.targets && d.targets.length){
    parts.push("<div class='psec'><h4>machines it talked to</h4><div class='plist'>"
      + d.targets.map(t => "<div class='r'><span class='mono'>" + esc(t[0]) + "</span><span>"
        + fmt(t[1]) + "</span></div>").join("") + "</div></div>");
  }

  /* Connection shape */
  const f = d.flags || {};
  if(f.syn || f.ack || f.rst || f.fin){
    parts.push("<div class='psec'><h4>connection behaviour</h4><div class='facts'>"
      + fact("opened (SYN)", fmt(f.syn))
      + fact("completed (ACK)", fmt(f.ack))
      + fact("refused (RST)", fmt(f.rst))
      + fact("closed (FIN)", fmt(f.fin))
      + "</div>"
      + (f.syn > 10 && !f.ack ? "<div style='color:var(--muted);font-size:.75rem;margin-top:6px'>"
         + "Opening connections without ever completing them is what a flood does to fill up the "
         + "connection table. A real visitor completes almost all of them.</div>" : "")
      + "</div>");
  }

  /* Behaving the same way */
  if(related.peer_total){
    parts.push("<div class='psec'><h4>" + fmt(related.peer_total)
      + " other addresses behaving identically</h4>"
      + "<div style='color:var(--muted);font-size:.79rem;margin-bottom:7px'>"
      + "Same protocol, same target port, same packet size, same connection shape, same speed. "
      + "In a flood that usually means one botnet or one tool."
      + (related.peer_packets ? " Together they sent " + fmt(related.peer_packets)
         + " packets." : "") + "</div>"
      + (related.peers || []).map(peerRow).join("")
      + (related.peer_total > (related.peers || []).length
         ? "<div class='peer' data-print=\"" + esc(d.fingerprint) + "\" "
           + "style='color:var(--cyan);font-size:.79rem'>see all " + fmt(related.peer_total)
           + " in the source list &rarr;</div>" : "")
      + "</div>");
  }

  /* Same neighbourhood */
  if(related.neighbour_total){
    parts.push("<div class='psec'><h4>" + fmt(related.neighbour_total)
      + " others in " + esc(d.network) + "</h4>"
      + "<div style='color:var(--muted);font-size:.79rem;margin-bottom:7px'>"
      + "Addresses next door to this one. When a lot of them show up together, blocking the whole "
      + "range is more use than blocking addresses one at a time.</div>"
      + (related.neighbours || []).map(peerRow).join("")
      + (related.neighbour_total > (related.neighbours || []).length
         ? "<div class='peer' data-net=\"" + esc(d.network) + "\" "
           + "style='color:var(--cyan);font-size:.79rem'>see the whole range &rarr;</div>" : "")
      + "</div>");
  }

  /* Aiming at the same machine */
  if(related.co_target_total){
    parts.push("<div class='psec'><h4>" + fmt(related.co_target_total)
      + " others aiming at " + esc(related.main_target || "the same machine") + "</h4>"
      + (related.co_targets || []).map(peerRow).join("") + "</div>");
  }

  /* A sample of the actual packets */
  if(d.recent && d.recent.length){
    parts.push("<div class='psec'><h4>a sample of what it sent</h4>"
      + "<table class='tbl' style='font-size:.75rem'><thead><tr><th>time</th><th>to</th>"
      + "<th>port</th><th class='num'>size</th><th>flags</th></tr></thead><tbody>"
      + d.recent.map(p => "<tr style='cursor:default'><td class='mono'>"
        + (p.ts ? p.ts.toFixed(3) : "-") + "</td>"
        + "<td class='mono' style='font-size:.72rem'>" + esc(p.dst) + "</td>"
        + "<td class='mono'>" + (p.dport === null ? "-" : p.dport) + "</td>"
        + "<td class='num'>" + p.size + "</td>"
        + "<td class='mono'>" + flagNames(p.flags) + "</td></tr>").join("")
      + "</tbody></table>"
      + (d.counters_pruned ? "<div style='color:var(--muted);font-size:.72rem;margin-top:6px'>"
         + "This address sent so many different ports or sizes that the detail counters were "
         + "trimmed to the busiest ones. The totals above are still exact.</div>" : "")
      + "</div>");
  }

  /* The signature itself, for anyone who wants it */
  parts.push("<div class='psec'><h4>behaviour signature</h4>"
    + "<div class='mono' style='font-size:.74rem;color:var(--muted);word-break:break-all;"
    + "background:rgba(255,255,255,.03);border:1px solid var(--line);border-radius:8px;padding:8px 10px'>"
    + esc(d.fingerprint) + "</div></div>");

  el("pBody").innerHTML = parts.join("");
  if(d.timeline && d.timeline.length) drawSpark(d.timeline);
}

function fact(k, v){
  return "<div class='fact'><div class='k'>" + esc(k) + "</div><div class='v'>"
    + esc(v === null || v === undefined ? "-" : v) + "</div></div>";
}
function peerRow(p){
  return "<div class='peer' data-ip='" + esc(p.ip) + "'>"
    + "<span class='pill " + p.level + "'>" + p.level.slice(0,4) + "</span>"
    + "<span class='pip'>" + esc(p.ip) + "</span>"
    + "<span class='pn'>" + fmt(p.packets) + " pkts</span></div>";
}
function flagNames(flags){
  if(!flags) return "-";
  const names = [];
  if(flags & 0x02) names.push("SYN");
  if(flags & 0x10) names.push("ACK");
  if(flags & 0x04) names.push("RST");
  if(flags & 0x01) names.push("FIN");
  if(flags & 0x08) names.push("PSH");
  return names.join("+") || "-";
}

function drawSpark(timeline){
  const canvas = el("pSpark");
  if(!canvas) return;
  const ratio = window.devicePixelRatio || 1;
  const w = canvas.clientWidth || 400, h = 56;
  canvas.width = w * ratio; canvas.height = h * ratio;
  const g = canvas.getContext("2d");
  g.setTransform(ratio, 0, 0, ratio, 0, 0);
  g.clearRect(0, 0, w, h);

  const first = timeline[0][0], last = timeline[timeline.length-1][0];
  const span = Math.max(last - first, 1);
  const peak = Math.max(...timeline.map(t => t[1])) || 1;

  g.fillStyle = "rgba(34,211,238,.55)";
  for(const [second, count] of timeline){
    const x = 3 + ((second - first) / span) * (w - 6);
    const barH = Math.max(2, (h - 10) * count / peak);
    g.fillRect(x - 1, h - 4 - barH, 2.5, barH);
  }
  g.fillStyle = "rgba(147,164,191,.85)";
  g.font = "10px 'JetBrains Mono', monospace";
  g.fillText(peak + "/s", 4, 11);
}

function closePanel(){
  el("panel").classList.remove("on");
  el("backdrop").classList.remove("on");
  state.selected = null;
}

/* ---------------------------------------------------------------------
   The console view
   --------------------------------------------------------------------- */
async function renderConsole(){
  const s = state.summary;
  if(!s){ el("feed").innerHTML = ""; el("sevBars").innerHTML = ""; return; }

  const share = s.hostile_share || 0;
  el("gaugeVal").textContent = share + "%";
  el("gaugeLbl").textContent = "of packets are hostile";
  drawGauge(share);

  const counts = s.counts || {};
  const order = ["critical","high","watch","normal"];
  const pairs = order.filter(k => counts[k]).map(k => [k, counts[k]]);
  const top = Math.max(...pairs.map(p => p[1]), 1);
  el("sevBars").innerHTML = pairs.map(p =>
    "<div class='barrow'><div class='lab'>" + p[0] + "</div>"
    + "<div class='tk'><div class='fl' style='width:" + (100*p[1]/top).toFixed(1) + "%;"
    + "background:" + LEVEL_COLOUR[p[0]] + "'></div></div>"
    + "<div class='vl'>" + fmt(p[1]) + "</div></div>").join("")
    || "<div style='color:var(--muted);font-size:.84rem'>nothing to show</div>";

  let alerts = [];
  try {
    if(state.mode === "session" && state.serverUp){
      const response = await fetch("/api/session/" + state.sessionId + "/alerts?limit=150");
      alerts = (await response.json()).alerts || [];
    } else {
      alerts = (await ask({cmd:"alerts", limit:150})).alerts || [];
    }
  } catch(err){ alerts = []; }

  el("feed").innerHTML = alerts.length ? alerts.map(a =>
    "<div class='ln' data-ip='" + esc(a.ip) + "'>"
    + "<span class='t'>" + clockTime(a.at) + "</span>"
    + "<span><span class='rule " + (a.level === "critical" ? "critical" : "") + "'>"
    + esc(a.rule) + "</span> <span class='mono' style='color:var(--cyan)'>" + esc(a.ip) + "</span>"
    + "<span class='msg'>" + esc(a.message) + "</span></span></div>").join("")
    : "<div class='empty'>No alerts. Nothing in this capture crossed the line.</div>";
}

function drawGauge(percent){
  const canvas = el("gauge");
  const ratio = window.devicePixelRatio || 1;
  canvas.width = 150 * ratio; canvas.height = 150 * ratio;
  const g = canvas.getContext("2d");
  g.setTransform(ratio, 0, 0, ratio, 0, 0);
  g.clearRect(0, 0, 150, 150);

  const cx = 75, cy = 75, radius = 56;
  const start = Math.PI * 0.75, sweep = Math.PI * 1.5;

  g.lineWidth = 13; g.lineCap = "round";
  g.strokeStyle = "rgba(255,255,255,.07)";
  g.beginPath(); g.arc(cx, cy, radius, start, start + sweep); g.stroke();

  const fraction = Math.min(percent, 100) / 100;
  const colour = percent >= 60 ? "#FB7185" : percent >= 25 ? "#FBBF24" : "#34D399";
  g.strokeStyle = colour;
  g.beginPath(); g.arc(cx, cy, radius, start, start + sweep * fraction); g.stroke();

  g.fillStyle = "rgba(147,164,191,.8)";
  g.font = "10px 'JetBrains Mono', monospace";
  g.textAlign = "center";
  g.fillText("0%", 26, 122); g.fillText("100%", 126, 122);
}

/* ---------------------------------------------------------------------
   The map. Zoom with the wheel, drag to pan, click a dot to open it.
   --------------------------------------------------------------------- */
const REGION_BOX = {
 "ARIN (North America)":       [25, 55, -125, -70],
 "RIPE (Europe, Middle East)": [36, 62,  -8,   45],
 "APNIC (Asia Pacific)":       [-38, 45,  70,  150],
 "AFRINIC (Africa)":           [-32, 32, -16,   45],
 "LACNIC (Latin America)":     [-40, 18, -78,  -38],
 "private or local":           [20, 50,  -10,  30],
 "documentation range":        [20, 50,  -10,  30],
 "unknown":                    [0, 30,   -20,  20]
};

const view = {scale: 1, x: 0, y: 0, dragging: false, lastX: 0, lastY: 0, moved: false};
let mapPoints = null;
const MAX_DRAWN = 4000;

function hashOf(str){
  let h = 2166136261;
  for(let i = 0; i < str.length; i++){ h ^= str.charCodeAt(i); h = Math.imul(h, 16777619); }
  return h >>> 0;
}
function isLand(lat, lon){
  const x = Math.floor((lon + 180) / 360 * LAND_W);
  const y = Math.floor((90 - lat) / 180 * LAND_H);
  if(x < 0 || x >= LAND_W || y < 0 || y >= LAND_H) return false;
  return LAND.charAt(y * LAND_W + x) === "#";
}
function latLonFor(ip, region){
  const box = REGION_BOX[region] || REGION_BOX["ARIN (North America)"];
  const h = hashOf(ip);
  for(let attempt = 0; attempt < 12; attempt++){
    const a = ((h >> (attempt*2)) & 0xFFFF) / 65535;
    const b = ((h >> (attempt*2+7)) & 0xFFFF) / 65535;
    const lat = box[0] + a * (box[1] - box[0]);
    const lon = box[2] + b * (box[3] - box[2]);
    if(isLand(lat, lon)) return [lat, lon];
  }
  return [(box[0]+box[1])/2, (box[2]+box[3])/2];
}

function mapSize(){
  const canvas = el("map");
  const w = canvas.clientWidth || 900;
  const h = Math.max(360, Math.min(560, Math.round(w * 0.5)));
  return [w, h];
}

async function ensurePoints(){
  if(mapPoints) return mapPoints;
  let rows = [];
  if(state.mode === "session" && state.serverUp){
    const response = await fetch("/api/session/" + state.sessionId
      + "/sources?limit=1000&order=packets");
    rows = (await response.json()).rows || [];
  } else if(state.mode === "live"){
    // A live capture's numbers live on the server, not in the worker. Asking
    // the worker gets an empty map, which is what it used to draw.
    rows = (state.summary && state.summary.sources) || [];
  } else {
    rows = (await ask({cmd:"mapPoints"})).points || [];
  }
  rows.sort((a,b) => b.packets - a.packets);
  const drawn = rows.slice(0, MAX_DRAWN);
  mapPoints = drawn.map(r => {
    const [lat, lon] = latLonFor(r.ip, r.region);
    return {ip:r.ip, level:r.level, packets:r.packets, region:r.region,
            u:(lon + 180)/360, v:(90 - lat)/180};
  });
  el("mapCount").textContent = rows.length > drawn.length
    ? fmt(drawn.length) + " of " + fmt(rows.length) + " addresses drawn, busiest first"
    : fmt(drawn.length) + " addresses";
  return mapPoints;
}

function toScreen(u, v, w, h){
  return [u * w * view.scale + view.x, v * h * view.scale + view.y];
}

function clampView(w, h){
  view.scale = Math.max(1, Math.min(40, view.scale));
  const spanW = w * view.scale, spanH = h * view.scale;
  view.x = Math.min(0, Math.max(w - spanW, view.x));
  view.y = Math.min(0, Math.max(h - spanH, view.y));
  if(spanW <= w) view.x = 0;
  if(spanH <= h) view.y = 0;
}

async function drawMap(){
  const canvas = el("map");
  const [w, h] = mapSize();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = w * ratio; canvas.height = h * ratio;
  canvas.style.height = h + "px";
  const g = canvas.getContext("2d");
  g.setTransform(ratio, 0, 0, ratio, 0, 0);
  g.clearRect(0, 0, w, h);

  clampView(w, h);
  el("zoomLbl").textContent = view.scale.toFixed(1) + "x";

  /* the continents, as dots */
  const dot = Math.max(1.1, Math.min(5, (w / LAND_W) * view.scale * 0.42));
  g.fillStyle = "rgba(120,160,210,.20)";
  for(let y = 0; y < LAND_H; y++){
    for(let x = 0; x < LAND_W; x++){
      if(LAND.charAt(y * LAND_W + x) !== "#") continue;
      const [sx, sy] = toScreen((x + 0.5)/LAND_W, (y + 0.5)/LAND_H, w, h);
      if(sx < -6 || sx > w + 6 || sy < -6 || sy > h + 6) continue;
      g.fillRect(sx - dot/2, sy - dot/2, dot, dot);
    }
  }

  const all = await ensurePoints();

  // During playback only the addresses seen so far are on the map, and each
  // one pings once as it arrives. That ping is the whole point of watching.
  let points = all;
  if(state.revealed){
    points = [];
    for(const p of all){
      if(!state.revealed.has(p.ip)){ p._seen = 0; continue; }
      if(!p._seen) p._seen = performance.now();
      points.push(p);
    }
  }

  if(!points.length){
    g.fillStyle = "rgba(147,164,191,.7)";
    g.font = "13px Inter, sans-serif"; g.textAlign = "center";
    g.fillText("no sources to place yet", w/2, h/2);
    return;
  }

  /* the machine under pressure, drawn where the eye lands */
  const [tx, ty] = toScreen(0.5, 0.46, w, h);
  const targetName = state.summary ? state.summary.main_target : "";

  /* arcs from the worst offenders, kept few so the map stays readable */
  const hostile = points.filter(p => p.level === "critical" || p.level === "high").slice(0, 40);
  g.lineWidth = 1;
  for(const p of hostile){
    const [sx, sy] = toScreen(p.u, p.v, w, h);
    if((sx < -50 && tx < -50) || (sx > w + 50 && tx > w + 50)) continue;
    const midX = (sx + tx)/2, midY = (sy + ty)/2 - Math.abs(sx - tx) * 0.18;
    const gradient = g.createLinearGradient(sx, sy, tx, ty);
    gradient.addColorStop(0, (LEVEL_COLOUR[p.level] || "#22D3EE") + "00");
    gradient.addColorStop(1, (LEVEL_COLOUR[p.level] || "#22D3EE") + "70");
    g.strokeStyle = gradient;
    g.beginPath(); g.moveTo(sx, sy); g.quadraticCurveTo(midX, midY, tx, ty); g.stroke();
  }

  /* the sources themselves */
  const peak = Math.max(...points.map(p => p.packets)) || 1;
  for(const p of points){
    const [sx, sy] = toScreen(p.u, p.v, w, h);
    if(sx < -10 || sx > w + 10 || sy < -10 || sy > h + 10) continue;
    const weight = Math.sqrt(p.packets / peak);
    const radius = (2 + weight * 5) * Math.min(2.2, Math.sqrt(view.scale));
    const colour = LEVEL_COLOUR[p.level] || "#34D399";
    g.beginPath(); g.arc(sx, sy, radius, 0, Math.PI * 2);
    g.fillStyle = colour + "cc"; g.fill();
    if(p.level === "critical"){
      g.beginPath(); g.arc(sx, sy, radius + 3, 0, Math.PI * 2);
      g.strokeStyle = colour + "40"; g.lineWidth = 1.5; g.stroke();
    }

    // The arrival ping, for about a second after an address first shows up.
    if(p._seen){
      const age = (performance.now() - p._seen) / 1000;
      if(age < 1){
        const grow = radius + age * 26;
        g.beginPath(); g.arc(sx, sy, grow, 0, Math.PI * 2);
        g.strokeStyle = colour + Math.round((1 - age) * 190).toString(16).padStart(2, "0");
        g.lineWidth = 2 - age;
        g.stroke();
      }
    }
    p._x = sx; p._y = sy; p._r = radius;
  }

  /* the target */
  g.beginPath(); g.arc(tx, ty, 7, 0, Math.PI * 2);
  g.fillStyle = "#E8EEF7"; g.fill();
  g.beginPath(); g.arc(tx, ty, 12, 0, Math.PI * 2);
  g.strokeStyle = "rgba(232,238,247,.35)"; g.lineWidth = 1.5; g.stroke();
  g.fillStyle = "rgba(232,238,247,.85)";
  g.font = "11px 'JetBrains Mono', monospace"; g.textAlign = "center";
  g.fillText(targetName || "target", tx, ty + 26);
}

function pointAt(clientX, clientY){
  if(!mapPoints) return null;
  const rect = el("map").getBoundingClientRect();
  const x = clientX - rect.left, y = clientY - rect.top;
  let best = null, bestDistance = 14;
  for(const p of mapPoints){
    if(p._x === undefined) continue;
    const distance = Math.hypot(p._x - x, p._y - y);
    if(distance < Math.max(bestDistance, p._r + 4) && distance < bestDistance + p._r){
      best = p; bestDistance = distance;
    }
  }
  return best;
}

function wireMap(){
  const canvas = el("map");

  canvas.addEventListener("wheel", (event) => {
    event.preventDefault();
    const [w, h] = mapSize();
    const rect = canvas.getBoundingClientRect();
    const px = event.clientX - rect.left, py = event.clientY - rect.top;
    const before = view.scale;
    view.scale *= event.deltaY < 0 ? 1.18 : 1/1.18;
    view.scale = Math.max(1, Math.min(40, view.scale));
    const factor = view.scale / before;
    view.x = px - (px - view.x) * factor;
    view.y = py - (py - view.y) * factor;
    drawMap();
  }, {passive:false});

  canvas.addEventListener("pointerdown", (event) => {
    view.dragging = true; view.moved = false;
    view.lastX = event.clientX; view.lastY = event.clientY;
    canvas.classList.add("drag");
    canvas.setPointerCapture(event.pointerId);
  });

  canvas.addEventListener("pointermove", (event) => {
    if(view.dragging){
      const dx = event.clientX - view.lastX, dy = event.clientY - view.lastY;
      if(Math.abs(dx) + Math.abs(dy) > 3) view.moved = true;
      view.x += dx; view.y += dy;
      view.lastX = event.clientX; view.lastY = event.clientY;
      drawMap();
      return;
    }
    const hit = pointAt(event.clientX, event.clientY);
    const tip = el("tip");
    if(hit){
      tip.classList.add("on");
      tip.style.left = (event.clientX + 14) + "px";
      tip.style.top = (event.clientY + 14) + "px";
      tip.innerHTML = "<b style='color:" + (LEVEL_COLOUR[hit.level]) + "'>" + esc(hit.ip) + "</b><br>"
        + fmt(hit.packets) + " packets &middot; " + hit.level + "<br>"
        + "<span style='color:#93A4BF'>" + esc(hit.region) + "</span><br>"
        + "<span style='color:#93A4BF'>click to open</span>";
      canvas.style.cursor = "pointer";
    } else {
      tip.classList.remove("on");
      canvas.style.cursor = "grab";
    }
  });

  const release = (event) => {
    if(view.dragging){
      view.dragging = false;
      canvas.classList.remove("drag");
      try { canvas.releasePointerCapture(event.pointerId); } catch(e){}
    }
  };
  canvas.addEventListener("pointerup", (event) => {
    const wasDragging = view.dragging, moved = view.moved;
    release(event);
    if(wasDragging && !moved){
      const hit = pointAt(event.clientX, event.clientY);
      if(hit) openIp(hit.ip);
    }
  });
  canvas.addEventListener("pointercancel", release);
  canvas.addEventListener("pointerleave", () => el("tip").classList.remove("on"));

  /* Two fingers, because a phone has no scroll wheel. Zooms around the point
     between the fingers, the way every map on a phone does. */
  let pinch = null;
  canvas.addEventListener("touchstart", (event) => {
    if(event.touches.length !== 2) return;
    view.dragging = false;
    canvas.classList.remove("drag");
    const [a, b] = event.touches;
    pinch = { gap: Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY) || 1,
              scale: view.scale };
    event.preventDefault();
  }, {passive:false});

  canvas.addEventListener("touchmove", (event) => {
    if(!pinch || event.touches.length !== 2) return;
    const [a, b] = event.touches;
    const gap = Math.hypot(a.clientX - b.clientX, a.clientY - b.clientY) || 1;
    const rect = canvas.getBoundingClientRect();
    const midX = (a.clientX + b.clientX) / 2 - rect.left;
    const midY = (a.clientY + b.clientY) / 2 - rect.top;
    const before = view.scale;
    view.scale = Math.max(1, Math.min(40, pinch.scale * (gap / pinch.gap)));
    const change = view.scale / before;
    view.x = midX - (midX - view.x) * change;
    view.y = midY - (midY - view.y) * change;
    drawMap();
    event.preventDefault();
  }, {passive:false});

  const endPinch = (event) => { if(!event.touches || event.touches.length < 2) pinch = null; };
  canvas.addEventListener("touchend", endPinch);
  canvas.addEventListener("touchcancel", endPinch);

  el("zIn").onclick = () => { zoomBy(1.5); };
  el("zOut").onclick = () => { zoomBy(1/1.5); };
  el("zFit").onclick = () => { view.scale = 1; view.x = 0; view.y = 0; drawMap(); };
}

/* While the capture plays back, the map needs to redraw on its own so the
   arrival pings animate instead of jumping one step at a time. Thirty frames
   a second is plenty and leaves the machine alone. */
let mapLoop = null, lastMapFrame = 0;
function ensureMapLoop(){
  if(mapLoop) return;
  const tick = (now) => {
    if(!(replay.playing && currentView() === "map")){ mapLoop = null; return; }
    if(now - lastMapFrame > 33){ lastMapFrame = now; drawMap(); }
    mapLoop = requestAnimationFrame(tick);
  };
  mapLoop = requestAnimationFrame(tick);
}

function zoomBy(factor){
  const [w, h] = mapSize();
  const before = view.scale;
  view.scale = Math.max(1, Math.min(40, view.scale * factor));
  const change = view.scale / before;
  view.x = w/2 - (w/2 - view.x) * change;
  view.y = h/2 - (h/2 - view.y) * change;
  drawMap();
}

/* ---------------------------------------------------------------------
   Server mode: saved sessions and live capture, when the page is being
   served by flood_watch.py rather than opened from disk.
   --------------------------------------------------------------------- */
async function detectServer(){
  // Opened straight from disk there is no server to ask, and trying anyway
  // just puts a confusing cross origin error in the console.
  if(location.protocol !== "http:" && location.protocol !== "https:"){
    el("offline").classList.add("on");
    return;
  }
  try {
    const response = await fetch("/api/health", {cache:"no-store"});
    if(!response.ok) return;
    const health = await response.json();
    if(!health.ok) return;
    state.serverUp = true;
    el("sessions").style.display = "";
    el("liveBtn").style.display = "";
    await loadSessionList();
  } catch(err){
    state.serverUp = false;
    el("offline").classList.add("on");
  }
}

async function loadSessionList(){
  const response = await fetch("/api/sessions", {cache:"no-store"});
  const sessions = (await response.json()).sessions || [];
  const select = el("sessions");
  select.innerHTML = "<option value=''>saved captures...</option>"
    + sessions.map(s => "<option value='" + s.id + "'>"
      + esc(s.label) + " &middot; " + fmt(s.packets) + " packets"
      + (s.running ? " (running)" : "") + "</option>").join("");
}

async function openSession(id){
  clearError();
  const response = await fetch("/api/session/" + id);
  const record = await response.json();
  if(!record.summary || !record.summary.total_packets){
    showError("That session has no saved report yet.", " It may still be running.");
    return;
  }
  stopLive();
  state.mode = "session";
  state.sessionId = id;
  mapPoints = null;
  adopt(record.summary, record.label, 0);
}

async function toggleLive(){
  if(state.live){ await stopLiveCapture(); return; }
  clearError();
  try {
    const response = await fetch("/api/live/start", {
      method:"POST", headers:{"Content-Type":"application/json"},
      body: JSON.stringify({interface:"any"})
    });
    const answer = await response.json();
    if(!answer.ok){ showError("Live capture would not start.", " " + (answer.error || "")); return; }
    state.live = true;
    state.mode = "live";
    state.sessionId = answer.session_id;
    el("liveBtn").textContent = "Stop live capture";
    showNote("Listening now. The report refreshes every couple of seconds. Everything is being "
      + "written to the database as it happens, so you can come back to it later.");
    state.liveTimer = setInterval(pollLive, 2000);
    pollLive();
  } catch(err){
    showError("Live capture would not start.", " " + err.message);
  }
}

async function stopLiveCapture(){
  try { await fetch("/api/live/stop", {method:"POST", headers:{"Content-Type":"application/json"},
                                        body:"{}"}); } catch(e){}
  stopLive();
  await loadSessionList();
  showNote("Live capture stopped. It is saved, and you can reopen it from the saved captures list.");
}

function stopLive(){
  if(state.liveTimer){ clearInterval(state.liveTimer); state.liveTimer = null; }
  state.live = false;
  el("liveBtn").textContent = "Start live capture";
}

async function pollLive(){
  try {
    const response = await fetch("/api/live", {cache:"no-store"});
    const snapshot = await response.json();
    if(snapshot.error){ showError("Live capture stopped.", " " + snapshot.error); stopLive(); return; }
    if(!snapshot.running && !snapshot.packets) return;

    const summary = snapshot.summary;
    summary.read = {format:"live", compressed:false, frames:snapshot.packets,
                    used:snapshot.packets, skipped:{}, interfaces:[{name:snapshot.interface}]};
    state.summary = summary;

    // Throw the map away every poll. It is drawn from a cached list of dots,
    // and a live capture changes that list constantly. Leaving the cache in
    // place is what made the map sit there showing the previous capture.
    mapPoints = null;
    renderScope(snapshot);

    el("clock").innerHTML = "<b>live on " + esc(snapshot.interface) + "</b> &middot; "
      + fmt(snapshot.packets) + " packets &middot; " + fmt(snapshot.packets_per_second_now) + "/s now";
    el("resetBtn").style.display = "";

    renderAll();
    if(snapshot.window && snapshot.window.length) drawLiveTrace(snapshot.window);
    refreshSources(true);
    if(currentView() === "map") drawMap();
  } catch(err){
    /* a poll that fails once is not worth shouting about */
  }
}

function drawLiveTrace(window){
  const s = state.summary;
  s.timeline = window.map(w => w.packets);
  s.timeline_step = 1;
  drawTimeline();
  el("tlSub").textContent = "packets per second, the last " + window.length + " seconds";
}

/* ---------------------------------------------------------------------
   Wiring
   --------------------------------------------------------------------- */
function currentView(){
  const on = document.querySelector(".tab.on");
  return on ? on.dataset.view : "report";
}

function wire(){
  /* tabs */
  el("tabs").addEventListener("click", (event) => {
    const tab = event.target.closest(".tab");
    if(!tab) return;
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("on"));
    tab.classList.add("on");
    document.querySelectorAll(".view").forEach(v => v.classList.remove("on"));
    el("v-" + tab.dataset.view).classList.add("on");
    if(tab.dataset.view === "map"){ drawMap(); ensureMapLoop(); }
    if(tab.dataset.view === "report") drawTimeline();
  });

  /* file input and drag and drop */
  const drop = el("drop"), input = el("file");
  input.addEventListener("change", () => { if(input.files[0]) loadFile(input.files[0]); });
  ["dragenter","dragover"].forEach(name => drop.addEventListener(name, (e) => {
    e.preventDefault(); drop.classList.add("over"); }));
  ["dragleave","drop"].forEach(name => drop.addEventListener(name, (e) => {
    e.preventDefault(); drop.classList.remove("over"); }));
  drop.addEventListener("drop", (e) => {
    if(e.dataTransfer.files[0]) loadFile(e.dataTransfer.files[0]); });
  ["dragover","drop"].forEach(name =>
    document.body.addEventListener(name, (e) => e.preventDefault()));

  el("examplesBtn").onclick = () => el("examples").classList.toggle("on");
  el("liveBtn").onclick = toggleLive;
  el("resetBtn").onclick = resetEverything;
  el("exGrid").addEventListener("click", (event) => {
    const card = event.target.closest("[data-example]");
    if(card) loadExample(Number(card.dataset.example));
  });

  /* playback */
  el("playBtn").onclick = () => { replay.playing ? stopReplay() : startReplay(); };
  el("restartBtn").onclick = () => {
    stopReplay(true);
    resetReplay();
    startReplay();
  };
  el("speed").onchange = () => { replay.carry = 0; };
  el("ptrack").onclick = (event) => {
    if(!replay.data) return;
    const box = el("ptrack").getBoundingClientRect();
    const fraction = Math.max(0, Math.min(1, (event.clientX - box.left) / box.width));
    const target = Math.round(fraction * replay.data.steps.length);
    const wasPlaying = replay.playing;
    stopReplay(true);
    resetReplay();
    state.revealed = new Set();
    for(let i = 0; i < target; i++) applyStep(replay.data.steps[i]);
    replay.index = target;
    paintReplay();
    if(wasPlaying) startReplay();
    else if(target >= replay.data.steps.length) finishReplay();
  };
  el("sessions").onchange = (e) => { if(e.target.value) openSession(e.target.value); };

  /* search and filters */
  let searchTimer = null;
  el("q").addEventListener("input", (e) => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.filter.q = e.target.value.trim();
      refreshSources(true);
    }, 180);
  });
  document.querySelectorAll(".chip[data-level]").forEach(chip => {
    chip.onclick = () => {
      document.querySelectorAll(".chip[data-level]").forEach(c => c.classList.remove("on"));
      chip.classList.add("on");
      state.filter.level = chip.dataset.level;
      refreshSources(true);
    };
  });
  document.querySelectorAll("th[data-sort]").forEach(th => {
    th.onclick = () => {
      document.querySelectorAll("th[data-sort]").forEach(o => o.classList.remove("sorted"));
      th.classList.add("sorted");
      state.filter.order = th.dataset.sort;
      refreshSources(true);
    };
  });
  el("loadMore").onclick = () => refreshSources(false);
  el("srcScroll").addEventListener("scroll", (e) => {
    const box = e.target;
    if(box.scrollTop + box.clientHeight > box.scrollHeight - 90
       && state.loaded < state.total) refreshSources(false);
  });

  /* anything with a data-ip opens the panel */
  document.body.addEventListener("click", (event) => {
    const printed = event.target.closest("[data-print]");
    if(printed){
      setFilter({fingerprint: printed.dataset.print, network: null, level: "all"},
                "group: " + printed.dataset.print.split("|").slice(0,3).join(" "));
      showView("sources");
      closePanel();
      return;
    }
    const net = event.target.closest("[data-net]");
    if(net){
      setFilter({network: net.dataset.net, fingerprint: null, level: "all"},
                "network: " + net.dataset.net);
      showView("sources");
      closePanel();
      return;
    }
    const holder = event.target.closest("[data-ip]");
    if(holder && holder.dataset.ip){
      document.querySelectorAll("tr.pick").forEach(t => t.classList.remove("pick"));
      if(holder.tagName === "TR") holder.classList.add("pick");
      openIp(holder.dataset.ip);
    }
  });

  el("pClose").onclick = closePanel;
  el("backdrop").onclick = closePanel;
  document.addEventListener("keydown", (e) => { if(e.key === "Escape") closePanel(); });

  wireMap();

  let resizeTimer = null;
  window.addEventListener("resize", () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      if(currentView() === "map") drawMap();
      if(currentView() === "report") drawTimeline();
    }, 160);
  });
}

function showView(name){
  document.querySelectorAll(".tab").forEach(t => t.classList.toggle("on", t.dataset.view === name));
  document.querySelectorAll(".view").forEach(v => v.classList.remove("on"));
  el("v-" + name).classList.add("on");
  if(name === "map") drawMap();
}

wire();
startEngine();
detectServer();

buildExamples();
showEmpty();
