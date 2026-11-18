"""Build silver-shield.html: index.html with the engine and model inlined, so it works as one file."""
import pathlib
root = pathlib.Path(__file__).resolve().parent.parent
s = (root / "index.html").read_text()
for f in ["checker/model.js", "checker/engine.js"]:
    s = s.replace(f'<script src="{f}"></script>', "<script>\n" + (root / f).read_text() + "\n</script>")
(root / "silver-shield.html").write_text(s)
print("Wrote silver-shield.html")
