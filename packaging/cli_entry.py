from oberhau.cli import main
from oberhau.frozen import prepare_runtime

if __name__ == "__main__":
    prepare_runtime()
    raise SystemExit(main())
