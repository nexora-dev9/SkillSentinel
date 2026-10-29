# Contributing

Requires Python 3.10+. Runtime code uses the standard library.

```text
python -m unittest discover -s tests -v
python skill/build_skill.py
python tools/build_release.py
```

Keep changes focused. For a scanner or repair change, add an inert regression
case that verifies observable behavior, coverage, redaction, or source
preservation. Never execute fixture scripts or add real secrets.

The engine lives in `engine/`; setuptools installs it as `skillsentinel` and
the Skill builder bundles it as `skillsentinel_engine`. Do not edit generated
copies in `artifacts/`. Update instructions, CLI examples, and decision policy
together when behavior changes. Document breaking changes in `CHANGELOG.md`.

Generated audit records, client sessions, screenshots, machine paths, and
competition delivery archives belong outside the public source package.
Contributions are distributed under the project's MIT license.
