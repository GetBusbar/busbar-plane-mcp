"""Run the frozen Python control closure without pip, a venv install, or PYTHONPATH."""
import pathlib
import runpy
import sys

if sys.version_info[:2] != (3, 11):
    raise SystemExit("frozen MCP control requires Python 3.11")
sys.dont_write_bytecode = True
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "site-packages"))
args = sys.argv[1:]
if args and args[0] == "-I":
    args.pop(0)
if not args:
    raise SystemExit("frozen control launcher requires a script, -c, -m, or -")
mode = args.pop(0)
if mode == "-c":
    source = args.pop(0)
    sys.argv = ["-c", *args]
    exec(compile(source, "<string>", "exec"), {"__name__": "__main__"})
elif mode == "-m":
    module = args.pop(0)
    sys.argv = [module, *args]
    runpy.run_module(module, run_name="__main__", alter_sys=True)
elif mode == "-":
    sys.argv = ["-", *args]
    exec(compile(sys.stdin.read(), "<stdin>", "exec"), {"__name__": "__main__"})
else:
    sys.argv = [mode, *args]
    sys.path.insert(0, str(pathlib.Path(mode).resolve().parent))
    runpy.run_path(mode, run_name="__main__")
