"""
Turning the analysis into something a person reads.

Two outputs. The terminal report is what you look at while you are still in the
middle of it. The HTML dashboard is what you send to the client afterwards,
which is why it is one self contained file with no links out to anything.

Neither of them invents anything. Every number here came from the capture and
every sentence next to a number explains what the number means, because a
report that needs me standing next to it to be understood is not finished.
"""

import sys

from .analyse import AMPLIFIER_PORTS, LEVELS, SENSITIVE_PORTS

# ----------------------------------------------------------------------------
# Console output
# ----------------------------------------------------------------------------
COLOR = {"critical": "\033[91m", "high": "\033[93m", "watch": "\033[96m",
         "normal": "\033[92m", "reset": "\033[0m", "dim": "\033[2m"}


def supports_colour():
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def paint(text, level):
    if not supports_colour():
        return text
    return COLOR.get(level, "") + text + COLOR["reset"]


def print_report(a, show=12):
    head, body = a["verdict"]
    print()
    print("=" * 74)
    print("  traffic-analyzer: %s" % head)
    print("=" * 74)
    print()
    for line in wrap(body, 72):
        print("  " + line)
    print()
    print("  Traffic seen:     %s packets from %d sources over %s seconds"
          % (f"{a['total_packets']:,}", a["sources_total"], a["duration_seconds"]))
    print("  Busiest second:   %s packets" % f"{a['peak_per_second']:,}")
    print("  Main target:      %s" % a["main_target"])
    print("  Hostile share:    %.0f%% of all packets" % a["hostile_share"])
    print()
    print("  %-16s %-8s %-9s %-11s %s" % ("SOURCE", "LEVEL", "PACKETS", "RATE/S", "REGION"))
    print("  " + "-" * 70)
    for r in a["sources"][:show]:
        line = "  %-16s %-8s %-9s %-11s %s" % (
            r["ip"], r["level"].upper(), f"{r['packets']:,}", r["rate"], r["region"])
        print(paint(line, r["level"]))
    if a["all_source_count"] > show:
        print("  ... and %d more sources" % (a["all_source_count"] - show))
    print()

    worst = [r for r in a["sources"] if r["level"] in ("critical", "high")][:3]
    if worst:
        print("  Why the worst offenders were flagged")
        print("  " + "-" * 70)
        for r in worst:
            print("  %s" % paint(r["ip"], r["level"]))
            for reason in r["reasons"]:
                for i, line in enumerate(wrap(reason, 66)):
                    print("      %s%s" % ("- " if i == 0 else "  ", line))
        print()

    print_reputation(a)

    print("  What to change")
    print("  " + "-" * 70)
    for title, detail, urgency in a["recommendations"]:
        print("  [%s] %s" % (urgency.upper(), title))
        for line in wrap(detail, 68):
            print("      " + line)
        print()


def print_reputation(a):
    """What VirusTotal said about the flagged sources, if it was asked at all.

    Only runs when --vt-key put a `reputation` block on at least one source. It
    leads with the known-bad ones, because "already reported as an attacker" is
    the sentence that changes what somebody does next.
    """
    from . import reputation as rep_module

    rated = [r for r in a.get("sources", []) if r.get("reputation")]
    if not rated:
        return

    # Known bad first, then suspicious, then the rest, so the strongest
    # corroboration is what the eye lands on.
    def rank(row):
        result = row["reputation"]
        if result.get("known"):
            return 0
        if result.get("suspicious"):
            return 1
        return 2
    rated.sort(key=rank)

    print("  What VirusTotal knows about the flagged sources")
    print("  " + "-" * 70)
    for row in rated:
        result = row["reputation"]
        headline, body = rep_module.verdict(result)
        level = "critical" if result.get("known") else row.get("level", "normal")
        print("  %s  %s" % (paint(row["ip"], level), headline))
        for line in wrap(body, 66):
            print("      " + line)
    coverage = a.get("reputation_coverage")
    if coverage:
        print()
        for line in wrap("Coverage: " + coverage + ".", 68):
            print("  " + line)
    print()


def wrap(text, width):
    words, lines, current = text.split(), [], ""
    for w in words:
        if len(current) + len(w) + 1 > width:
            lines.append(current)
            current = w
        else:
            current = (current + " " + w).strip()
    if current:
        lines.append(current)
    return lines



# ----------------------------------------------------------------------------
# HTML dashboard
# ----------------------------------------------------------------------------
def level_colour(level):
    for name, colour in LEVELS:
        if name == level:
            return colour
    return "#93A4BF"


def render_html(a, path):
    head, body = a["verdict"]
    peak = max(a["timeline"]) if a["timeline"] else 1

    bars = "".join(
        '<i style="height:%.1f%%" title="%d packets in this second"></i>'
        % (max(2.0, 100.0 * v / peak), v) for v in a["timeline"]
    )

    rows = []
    for r in a["sources"]:
        reasons = "".join("<li>%s</li>" % esc(x) for x in r["reasons"])
        rows.append("""
        <tr class="lvl-{level}">
          <td class="ip">{ip}</td>
          <td><span class="pill" style="background:{colour}1F;color:{colour};border-color:{colour}55">{level}</span></td>
          <td class="num">{packets:,}</td>
          <td class="num">{rate}</td>
          <td>{proto}</td>
          <td class="num">{dport}</td>
          <td class="region">{region}</td>
          <td class="why"><ul>{reasons}</ul></td>
        </tr>""".format(level=r["level"], colour=level_colour(r["level"]), ip=esc(r["ip"]),
                        packets=r["packets"], rate=r["rate"], proto=esc(r["protocol"]),
                        dport=r["top_dport"] if r["top_dport"] is not None else "",
                        region=esc(r["region"]), reasons=reasons))

    def bar_list(pairs, total, label_fn=str):
        if not pairs:
            return ""
        top = max(n for _, n in pairs) or 1
        out = []
        for key, n in pairs:
            out.append("""<div class="brow"><span class="bl">{label}</span>
              <span class="bt"><i style="width:{pct:.1f}%"></i></span>
              <span class="bn">{n:,}</span></div>""".format(
                label=esc(label_fn(key)), pct=100.0 * n / top, n=n))
        return "".join(out)

    def port_label(p):
        name = SENSITIVE_PORTS.get(p) or AMPLIFIER_PORTS.get(p)
        return "%d (%s)" % (p, name) if name else str(p)

    recs = "".join("""
      <div class="rec rec-{urgency}">
        <div class="rt"><span class="ru">{urgency}</span>{title}</div>
        <p>{detail}</p>
      </div>""".format(urgency=u, title=esc(t), detail=esc(d)) for t, d, u in a["recommendations"])

    counts = a["counts"]
    chips = "".join(
        '<span class="chip" style="color:{c};border-color:{c}55;background:{c}14">{n} {lvl}</span>'
        .format(c=level_colour(lvl), n=counts.get(lvl, 0), lvl=lvl)
        for lvl, _ in LEVELS if counts.get(lvl))

    html = """<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>traffic-analyzer report</title>
<style>
 :root{{--bg:#0B1220;--surface:#121C2F;--line:rgba(255,255,255,.09);--text:#E8EEF7;
   --muted:#93A4BF;--cyan:#22D3EE;--violet:#A78BFA;--mint:#34D399;--red:#FB7185;--amber:#FBBF24;}}
 *{{margin:0;padding:0;box-sizing:border-box}}
 body{{background:var(--bg);color:var(--text);font-family:'Inter',-apple-system,'Segoe UI',sans-serif;
   line-height:1.65;padding:34px 20px 70px}}
 .wrap{{max-width:1080px;margin:0 auto}}
 .brand{{font-family:'JetBrains Mono',monospace;color:var(--cyan);font-size:.85rem;letter-spacing:.1em;
   text-transform:uppercase;margin-bottom:10px}}
 h1{{font-size:1.9rem;font-weight:800;letter-spacing:-.02em;margin-bottom:8px}}
 .sub{{color:var(--muted);max-width:760px;margin-bottom:6px}}
 .meta{{color:#6D7F9C;font-size:.85rem;margin-bottom:24px}}
 .banner{{background:linear-gradient(135deg,rgba(251,113,133,.14),rgba(167,139,250,.10));
   border:1px solid rgba(251,113,133,.35);border-radius:18px;padding:24px 26px;margin-bottom:24px}}
 .banner h2{{font-size:1.2rem;margin-bottom:8px;color:#FFC9D2}}
 .banner p{{color:#E3D9DE;font-size:.97rem}}
 .chips{{margin-top:14px;display:flex;gap:8px;flex-wrap:wrap}}
 .chip{{border:1px solid;border-radius:999px;padding:4px 13px;font-size:.8rem;font-weight:700;
   text-transform:uppercase;letter-spacing:.06em}}
 .stats{{display:grid;grid-template-columns:repeat(auto-fit,minmax(165px,1fr));gap:14px;margin-bottom:26px}}
 .stat{{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:18px}}
 .stat .n{{font-size:1.65rem;font-weight:800;color:var(--cyan)}}
 .stat .l{{color:var(--muted);font-size:.83rem}}
 h3{{font-size:1.05rem;margin:26px 0 12px}}
 .panel{{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:20px}}
 .tl{{display:flex;align-items:flex-end;gap:2px;height:130px}}
 .tl i{{flex:1;background:linear-gradient(180deg,var(--cyan),rgba(34,211,238,.25));border-radius:2px 2px 0 0;
   min-width:2px;transition:opacity .2s}}
 .tl i:hover{{opacity:.6}}
 .tlx{{display:flex;justify-content:space-between;color:#6D7F9C;font-size:.78rem;margin-top:8px}}
 .cols{{display:grid;grid-template-columns:1fr 1fr;gap:18px}}
 .brow{{display:flex;align-items:center;gap:10px;margin:7px 0;font-size:.88rem}}
 .bl{{width:190px;color:var(--muted);flex:none;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
 .bt{{flex:1;height:9px;background:rgba(255,255,255,.06);border-radius:999px;overflow:hidden}}
 .bt i{{display:block;height:100%;background:linear-gradient(90deg,var(--cyan),var(--violet));border-radius:999px}}
 .bn{{width:74px;text-align:right;color:var(--text);font-variant-numeric:tabular-nums}}
 table{{width:100%;border-collapse:collapse;font-size:.86rem}}
 th{{text-align:left;color:var(--muted);font-weight:600;padding:10px;border-bottom:1px solid var(--line);
   font-size:.78rem;text-transform:uppercase;letter-spacing:.06em}}
 td{{padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:top}}
 td.num{{text-align:right;font-variant-numeric:tabular-nums}}
 td.ip{{font-family:'JetBrains Mono',monospace;color:var(--text);white-space:nowrap}}
 td.region{{color:var(--muted);font-size:.82rem}}
 td.why{{color:var(--muted);font-size:.82rem;max-width:330px}}
 td.why ul{{margin:0;padding-left:16px}}
 td.why li{{margin:2px 0}}
 .pill{{border:1px solid;border-radius:999px;padding:2px 10px;font-size:.72rem;font-weight:800;
   text-transform:uppercase;letter-spacing:.05em}}
 tr.lvl-critical td{{background:rgba(251,113,133,.05)}}
 tr.lvl-high td{{background:rgba(251,191,36,.04)}}
 .rec{{background:var(--surface);border:1px solid var(--line);border-left:3px solid var(--muted);
   border-radius:0 14px 14px 0;padding:16px 20px;margin-bottom:12px}}
 .rec-high{{border-left-color:var(--red)}}
 .rec-medium{{border-left-color:var(--amber)}}
 .rec-low{{border-left-color:var(--cyan)}}
 .rt{{font-weight:700;margin-bottom:6px;display:flex;align-items:center;gap:10px}}
 .ru{{font-size:.68rem;letter-spacing:.08em;text-transform:uppercase;border:1px solid var(--line);
   border-radius:999px;padding:2px 9px;color:var(--muted);font-weight:700}}
 .rec p{{color:var(--muted);font-size:.9rem}}
 .foot{{margin-top:34px;color:#6D7F9C;font-size:.83rem;border-top:1px solid var(--line);padding-top:18px}}
 @media (max-width:820px){{.cols{{grid-template-columns:1fr}}td.why{{display:none}}}}
</style></head><body><div class="wrap">
 <div class="brand">traffic-analyzer report</div>
 <h1>{head}</h1>
 <p class="sub">Traffic analysis of {target}. Every finding below was worked out from the packets
 themselves, and every source is scored with the reasons written out.</p>
 <p class="meta">Generated {generated}. Capture covers {duration} seconds.</p>

 <div class="banner"><h2>What is happening</h2><p>{body}</p>
   <div class="chips">{chips}</div></div>

 <div class="stats">
  <div class="stat"><div class="n">{packets:,}</div><div class="l">packets analysed</div></div>
  <div class="stat"><div class="n">{sources}</div><div class="l">sources seen</div></div>
  <div class="stat"><div class="n">{hostile}</div><div class="l">hostile sources</div></div>
  <div class="stat"><div class="n">{share}%</div><div class="l">of traffic hostile</div></div>
  <div class="stat"><div class="n">{peak:,}</div><div class="l">peak packets per second</div></div>
 </div>

 <h3>Traffic over time</h3>
 <div class="panel"><div class="tl">{bars}</div>
  <div class="tlx"><span>start of capture</span><span>peak {peak:,} packets per second</span><span>end</span></div></div>

 <div class="cols">
  <div><h3>Where it came from</h3><div class="panel">{regions}
    <p style="color:#6D7F9C;font-size:.78rem;margin-top:12px">Region comes from how the address space
    was allocated. It is a good guide to whether traffic is coming from places your customers live,
    not a precise location.</p></div></div>
  <div><h3>What was targeted</h3><div class="panel">{ports}</div>
   <h3>Protocols used</h3><div class="panel">{protocols}</div></div>
 </div>

 <h3>Every source, scored</h3>
 <div class="panel" style="overflow-x:auto">
 <table><tr><th>Source</th><th>Level</th><th>Packets</th><th>Per sec</th><th>Protocol</th>
 <th>Port</th><th>Region</th><th>Why it was flagged</th></tr>{rows}</table></div>

 <h3>What to change</h3>
 {recs}

 <div class="foot">Produced by traffic-analyzer, a free tool from Plaintext IT. The analysis runs entirely
 on your own machine and nothing about your network is sent anywhere.</div>
</div></body></html>""".format(
        head=esc(head), body=esc(body), target=esc(a["main_target"]), generated=a["generated"],
        duration=a["duration_seconds"], chips=chips, packets=a["total_packets"],
        sources=a["sources_total"], hostile=a["hostile_sources"], share=int(a["hostile_share"]),
        peak=a["peak_per_second"], bars=bars, rows="".join(rows), recs=recs,
        regions=bar_list(a["regions"], a["total_packets"]),
        ports=bar_list(a["ports"], a["total_packets"], port_label),
        protocols=bar_list(a["protocols"], a["total_packets"]))

    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)


def esc(text):
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


