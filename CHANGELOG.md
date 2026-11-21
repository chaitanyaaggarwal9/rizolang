# Changelog

All notable changes to Rizo Lang are documented here.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html). Before 1.0, minor versions may include breaking language changes.

## [Unreleased]

### Added

- Contributor guide, Code of Conduct, issue and pull request templates, and CODEOWNERS.
- CodeQL and dependency review workflows, and Dependabot updates for npm and GitHub Actions.

### Security

- Dependency install scripts are disabled (`.npmrc`), and CI verifies npm registry signatures.

## [0.1.0] - 2026-11-20

### Added

- Milestone 1: `model` blocks compile to a PostgreSQL schema and TypeScript types.
- Field types `Text`, `Number`, `Bool`, `Email`, `Password`, `Date`, `ID`, and modifiers `unique`, `optional`, `min`, `max`.
- Public types (`User.public`) never contain Password fields.
- `rizolang build file.rz` CLI.
- Language spec (`docs/SPEC.md`) and compact spec for AI system prompts (`docs/SPEC-COMPACT.md`).
- CI on Node 22, 24 and 26, plus a PostgreSQL schema check.
