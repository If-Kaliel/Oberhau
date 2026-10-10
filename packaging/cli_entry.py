from oberhau.cli import main
from oberhau.frozen import prepare_runtime
from oberhau.parser_worker import dispatch

if __name__ == "__main__":
    dispatch()
    prepare_runtime()
    raise SystemExit(main())
