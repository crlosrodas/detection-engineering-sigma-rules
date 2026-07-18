#!/usr/bin/env python3
"""
gen_report.py - Render a Zircolite JSON detection result (one rule x one log)
into a self-contained HTML detection report suitable for screenshotting.

Every value shown comes directly from Zircolite's genuine JSON output
(results/raw/<rule>__<log>.json). Nothing is synthesised.

Usage:
    python3 gen_report.py <zircolite_result.json> <log_label> <out.html> [field,field,...]
"""
import html
import json
import sys


def esc(v):
    if v is None:
        return ""
    return html.escape(str(v))


def main():
    src, log_label, out = sys.argv[1], sys.argv[2], sys.argv[3]
    fields = sys.argv[4].split(",") if len(sys.argv) > 4 else None

    max_ev = int(sys.argv[5]) if len(sys.argv) > 5 else 0  # 0 = all

    data = json.load(open(src))
    if not data:
        raise SystemExit(f"No detections in {src}")
    rule = data[0]
    all_matches = rule.get("matches", [])
    total = sum(r.get("count", 0) for r in data)
    matches = all_matches[:max_ev] if max_ev else all_matches
    truncated = len(all_matches) - len(matches)

    tags = " ".join(
        f'<span class="tag">{esc(t)}</span>' for t in rule.get("tags", [])
    )

    # Build event cards
    if fields is None:
        # sensible default order, only keep present keys
        pref = ["EventID", "Channel", "Hostname", "UtcTime", "TimeCreated"]
        seen = set()
        fields = []
        for m in matches:
            for k in list(pref) + sorted(m.keys()):
                if k not in seen and k in m and k not in ("row_id", "RuleName"):
                    seen.add(k)
                    fields.append(k)

    cards = []
    for i, m in enumerate(matches, 1):
        rows = []
        for f in fields:
            if f not in m:
                continue
            val = m[f]
            val = str(val)
            long = len(val) > 90
            cls = "val long" if long else "val"
            rows.append(
                f'<tr><td class="k">{esc(f)}</td>'
                f'<td class="{cls}">{esc(val)}</td></tr>'
            )
        cards.append(
            f'<div class="event"><div class="ev-hd">Matched event #{i}</div>'
            f'<table class="ev">{"".join(rows)}</table></div>'
        )

    level = esc(rule.get("rule_level", "")).upper()
    doc = f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{esc(rule['title'])}</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font-family: 'Segoe UI', system-ui, sans-serif;
         background:#0e1117; color:#e6edf3; padding:28px 32px; }}
  .brand {{ font-size:13px; letter-spacing:2px; color:#7d8590;
            text-transform:uppercase; margin-bottom:4px; }}
  h1 {{ font-size:23px; margin:0 0 14px; color:#fff; }}
  .badges {{ margin-bottom:18px; }}
  .lvl {{ display:inline-block; padding:4px 12px; border-radius:5px;
          font-weight:700; font-size:12px; letter-spacing:1px;
          background:#b62324; color:#fff; margin-right:8px; }}
  .lvl.MEDIUM {{ background:#b5820b; }}
  .tag {{ display:inline-block; background:#21262d; color:#9db4d0;
          padding:3px 9px; border-radius:4px; font-size:12px;
          margin-right:6px; font-family:monospace; }}
  .summary {{ display:flex; gap:14px; margin-bottom:20px; flex-wrap:wrap; }}
  .stat {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
           padding:12px 18px; min-width:120px; }}
  .stat .n {{ font-size:26px; font-weight:700; color:#3fb950; }}
  .stat .l {{ font-size:11px; color:#7d8590; text-transform:uppercase;
              letter-spacing:1px; margin-top:2px; }}
  .desc {{ background:#161b22; border-left:3px solid #388bfd;
           padding:12px 16px; border-radius:0 6px 6px 0; margin-bottom:20px;
           font-size:13px; color:#c9d1d9; line-height:1.5; max-width:1000px; }}
  .event {{ background:#161b22; border:1px solid #30363d; border-radius:8px;
            margin-bottom:14px; overflow:hidden; }}
  .ev-hd {{ background:#1f6feb22; color:#79c0ff; padding:8px 14px;
            font-size:13px; font-weight:600; border-bottom:1px solid #30363d; }}
  table.ev {{ width:100%; border-collapse:collapse; }}
  table.ev td {{ padding:7px 14px; border-bottom:1px solid #21262d;
                 vertical-align:top; font-size:13px; }}
  td.k {{ color:#7d8590; width:180px; font-family:monospace; }}
  td.val {{ color:#e6edf3; font-family:monospace; }}
  td.long {{ font-size:11.5px; color:#f0d0a0; word-break:break-all; }}
  .foot {{ margin-top:18px; color:#7d8590; font-size:12px; }}
  code {{ color:#a5d6ff; }}
</style></head><body>
  <div class="brand">Zircolite &middot; Sigma Detection Report</div>
  <h1>{esc(rule['title'])}</h1>
  <div class="badges"><span class="lvl {level}">{level}</span>{tags}</div>
  <div class="summary">
    <div class="stat"><div class="n">{total}</div><div class="l">Matches</div></div>
    <div class="stat"><div class="n" style="color:#79c0ff">EID {esc(matches[0].get('EventID','') if matches else '')}</div><div class="l">Event ID</div></div>
    <div class="stat"><div class="n" style="color:#d2a8ff;font-size:15px;padding-top:6px">{esc(log_label)}</div><div class="l">Test log</div></div>
  </div>
  <div class="desc">{esc(rule.get('description','')).replace(chr(10),'<br>')}</div>
  {"".join(cards)}
  {f'<div class="foot" style="color:#d2a8ff">+ {truncated} more matched event(s) not shown (total {total}).</div>' if truncated else ''}
  <div class="foot">Rule ID <code>{esc(rule.get('id',''))}</code> &middot;
     Sigma source <code>{esc(rule.get('sigmafile',''))}</code> &middot;
     Source log <code>{esc(matches[0].get('OriginalLogfile','') if matches else '')}</code></div>
</body></html>"""
    open(out, "w").write(doc)
    print(f"wrote {out} ({len(matches)} events, total count {total})")


if __name__ == "__main__":
    main()
