# Third-party components

Core operates without paid licenses/services. Distribution must retain applicable notices and
license texts. The portable Windows directory includes full license/copyright notices and complete unmodified Qtbase, QtSvg and PySide/Shiboken 6.10.2 sources; the libraries remain dynamic and replaceable. See [WINDOWS_BUILD.md](WINDOWS_BUILD.md). This is a portable directory, not an installer.

| Component | License / integration |
|---|---|
| Python | PSF; runtime interpreter |
| PySide6 Essentials / Qt | LGPLv3/GPL/commercial options; dynamic open-source modules only |
| Pydantic | MIT |
| Tree-sitter binding / TypeScript / JavaScript / Java / C# grammars | MIT; pinned local parsing wheels; notices retained by Windows build |
| SQLite | Public domain |
| Semgrep CE engine | LGPL-2.1; optional subprocess; our bundled rules are original MIT |
| OSV-Scanner | Apache-2.0; optional subprocess |
| Gitleaks | MIT; optional subprocess |
| Trivy | Apache-2.0; optional subprocess |
| pytest / Ruff / coverage.py | MIT / MIT / Apache-2.0; development tools |

Primary references checked 2026-10-10:
[Qt for Python licensing](https://doc.qt.io/qtforpython-6),
[Qt module licenses](https://doc.qt.io/qt-6/licensing.html),
[Semgrep CE](https://semgrep.dev/products/community-edition),
[Gitleaks license](https://github.com/gitleaks/gitleaks/blob/master/LICENSE),
[OSV license](https://github.com/google/osv-scanner/blob/main/LICENSE),
[Trivy license](https://github.com/aquasecurity/trivy/blob/main/LICENSE).

No community registry packs are redistributed. CodeQL licensing is not evaluated because it is
not integrated. Optional binary installation is explicit; no silent privilege escalation occurs.

PyInstaller 6.22.3 uses GPLv2 with its bootloader exception; it is a build tool, not a paid runtime service. No PyInstaller source modifications are made. Supporting Pydantic packages use MIT; their license texts and the Python runtime license are copied into the release. The application provides a Licenses control and permits replacement/debugging of LGPL libraries.
