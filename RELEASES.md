# Sentinel Blue defender releases

## 1.9.42

[Download the runnable defender bundle](releases/sentinel-blue-defender-1.9.42.zip).
The bundle includes the Python zip application, matching source, regression tests, and local validation evidence.

Bundle SHA-256: `220a25adcd3da6056ef8381e1970e6b9b0b9bda1299f669d7fc3041ed3f721ef`

Runtime SHA-256: `d410e4b1312fde354f60f756d1cbd18b8eaebaf5ab3b81c686e000d549789238`

The source tree on this branch is the expanded 1.9.42 defender source. The new `defender-validation` workflow runs the complete supplied POSIX suite, packaged local controller/agent continuity and deadline tests, and focused native Windows integrity tests.

The bundled validation report is a snapshot from before publication authorization. Its statement that publication was blocked is historical; publication was explicitly authorized on 11 September 2026. Its local test results and limits remain applicable. Later CI and Azure results must identify the exact runtime tested.

1.9.41 Azure setup, SMB timing and Windows collection-load failures remain open until new evidence resolves them. Local tests do not establish complete competition readiness.
