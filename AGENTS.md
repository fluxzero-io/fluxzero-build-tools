# Agent instructions

Keep common authentication and proxy behavior in `common`; keep build-tool adapters thin.
Run `./gradlew check publishAllPublicationsToFixtureRepository` and `python3 scripts/acceptance.py` before release.
Never commit tokens, local sessions or private IDP fixtures. Preserve explicit support limits in README.
Use Conventional Commits.
