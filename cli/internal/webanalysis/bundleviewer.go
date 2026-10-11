package webanalysis

// bundleviewer.go holds the one static page a bundle carries, which reads its data.js and loads nothing from a network.

const bundleViewerHTML = `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Web analysis bundle</title>
<style>
:root { color-scheme: light dark; --fg: #16160f; --bg: #fbfbf7; --muted: #5f5e5a;
  --line: #d3d1c7; --card: #ffffff; }
@media (prefers-color-scheme: dark) {
  :root { --fg: #f1efe8; --bg: #16160f; --muted: #b4b2a9; --line: #3a3a34; --card: #1f1f18; }
}
* { box-sizing: border-box; }
body { margin: 0; padding: 24px; background: var(--bg); color: var(--fg);
  font: 15px/1.6 ui-sans-serif, system-ui, sans-serif; }
h1 { font-size: 20px; font-weight: 500; margin: 0 0 4px; }
p.sub { color: var(--muted); margin: 0 0 24px; font-size: 13px; }
.counts { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
  gap: 8px; margin-bottom: 24px; }
.count { background: var(--card); border: 1px solid var(--line); border-radius: 8px; padding: 10px 12px; }
.count b { display: block; font-size: 20px; font-weight: 500; }
.count span { color: var(--muted); font-size: 12px; }
nav { display: flex; flex-wrap: wrap; gap: 6px; margin-bottom: 16px; }
button { font: inherit; font-size: 13px; padding: 5px 11px; border: 1px solid var(--line);
  border-radius: 6px; background: transparent; color: inherit; cursor: pointer; }
button[aria-pressed="true"] { background: var(--card); border-color: var(--fg); }
pre { background: var(--card); border: 1px solid var(--line); border-radius: 8px;
  padding: 12px; overflow-x: auto; font-size: 12px; margin: 0 0 8px; }
.note { color: var(--muted); font-size: 12px; margin: 16px 0 0; }
</style>
<h1>Web analysis bundle</h1>
<p class="sub" id="sub"></p>
<div class="counts" id="counts"></div>
<nav id="nav"></nav>
<div id="records"></div>
<p class="note" id="note"></p>
<script src="data.js"></script>
<script>
(function () {
  var data = window.BLK_BUNDLE;
  var sub = document.getElementById("sub");
  if (!data) {
    sub.textContent = "data.js did not load; open this page from the bundle directory.";
    return;
  }
  sub.textContent = data.version + ", showing up to " + data.limit +
    " records per kind; every record is in the shards under records/.";
  var names = Object.keys(data.counts).sort();
  var counts = document.getElementById("counts");
  names.forEach(function (name) {
    var el = document.createElement("div");
    el.className = "count";
    var b = document.createElement("b");
    b.textContent = String(data.counts[name]);
    var s = document.createElement("span");
    s.textContent = name;
    el.appendChild(b);
    el.appendChild(s);
    counts.appendChild(el);
  });
  var nav = document.getElementById("nav");
  var out = document.getElementById("records");
  var note = document.getElementById("note");
  var buttons = {};
  function show(name) {
    names.forEach(function (n) { buttons[n].setAttribute("aria-pressed", String(n === name)); });
    out.textContent = "";
    var rows = data.kinds[name] || [];
    if (!rows.length) {
      note.textContent = "No " + name + " records in this bundle.";
      return;
    }
    rows.forEach(function (row) {
      var pre = document.createElement("pre");
      pre.textContent = JSON.stringify(row, null, 1);
      out.appendChild(pre);
    });
    var total = data.counts[name] || 0;
    note.textContent = total > rows.length
      ? "Showing " + rows.length + " of " + total + "; the rest are in records/" + name + ".*.jsonl.gz."
      : "Showing all " + total + " " + name + " records.";
  }
  names.forEach(function (name) {
    var b = document.createElement("button");
    b.type = "button";
    b.textContent = name + " (" + data.counts[name] + ")";
    b.addEventListener("click", function () { show(name); });
    buttons[name] = b;
    nav.appendChild(b);
  });
  var first = names.filter(function (n) { return (data.counts[n] || 0) > 0; })[0] || names[0];
  if (first) { show(first); }
})();
</script>
</html>
`
