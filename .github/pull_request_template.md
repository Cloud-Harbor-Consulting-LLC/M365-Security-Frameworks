## Summary

<!-- One or two sentences: what changes and why. -->

## Type of change

- [ ] Bug fix (script, template, or doc)
- [ ] New policy template
- [ ] Change to existing policy template
- [ ] Documentation
- [ ] Tooling / repo hygiene

## Design principle cited

<!-- If this is a policy change, cite the principle from Policy-Design.md it serves. -->

## Checklist

- [ ] Policy changes include a report-only deployment step and rollout notes.
- [ ] Placeholders use the `REPLACE_WITH_*_OBJECT_ID` / `REPLACE_WITH_*_STRENGTH_ID` convention.
- [ ] No tenant-specific IDs, user principal names, or internal URLs committed.
- [ ] `Deploy-CABaseline.ps1 -WhatIf` still parses every template without error.
- [ ] CHANGELOG.md updated under `## [Unreleased]`.
- [ ] Docs updated if behavior, required scopes, or prerequisites changed.
- [ ] markdownlint clean (or justified exemption in `.markdownlint.json`).

## Test evidence

<!-- WhatIf output, screenshot, or tenant result. Redact identifiers. -->