import sys, pathlib; sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
import sys, re
from xenolith.sources import notices
from xenolith import catalog
cat = catalog.load()
for u in sys.argv[1:]:
    try:
        b, ct = notices._get(u)
        comps, used, kind = notices.extract(b, ct, u)
        hits = sorted({cat.match_component(c["name"], c["version"]) for c in comps} - {None})
        print(f"OK   {len(b):>8} {ct[:22]:22} comps={len(comps):<5} via={used} hits={hits}  {u}")
        if comps[:3]: print("      sample:", [(c["name"], c["version"]) for c in comps[:5]])
    except Exception as e:
        print(f"ERR  {str(e)[:110]}  {u}")
