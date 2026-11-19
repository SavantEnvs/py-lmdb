#!/usr/bin/env python3
"""Print the bundled LMDB engines and their patch series, as setup.py applies them.

Reads setup.py's ENGINES table statically (ast, nothing executed) so the
mayhem build patches each tree exactly like upstream's own build, in the
same order, at whatever commit is checked out.  Output, one line per engine:
    <tree> <patch> <patch> ...
"""
import ast
import sys

src = open(sys.argv[1] if len(sys.argv) > 1 else 'setup.py').read()
for node in ast.walk(ast.parse(src)):
    d = {}
    if isinstance(node, ast.Dict):          # {'tree': ..., 'patch_names': [...]}
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant) and isinstance(k.value, str):
                d[k.value] = v
    elif (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
          and node.func.id == 'dict'):      # dict(tree=..., patch_names=[...])
        d = {kw.arg: kw.value for kw in node.keywords if kw.arg}
    else:
        continue
    tree, names = d.get('tree'), d.get('patch_names')
    if not (isinstance(tree, ast.Constant) and isinstance(names, ast.List)):
        continue
    print(' '.join([tree.value] + [e.value for e in names.elts
                                    if isinstance(e, ast.Constant)]))
