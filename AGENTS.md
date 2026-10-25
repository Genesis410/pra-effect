# AGENTS.md — Canonical AI Agent Context & Routing Contract

> **PURPOSE:** Entry-point kontekstual berbiaya token minimal (<800 tokens) untuk model AI / subagent baru. Memastikan model langsung memahami arsitektur, batasan, status kerja, dan file routing tanpa perlu membaca seluruh dokumen perencanaan berulang kali.

---

## 1. Project Invariants & Hard Rules
1. **Zero External Dependencies:** Python Standard Library murni (3.9+). Dilarang menginstal atau mengimpor package pihak ketiga di kode inti `pra_effect.py`.
2. **Confidentiality:** Folder `.confidential/` dan `.pra-effect/` berstatus **LOCAL ONLY**. Dilarang di-push ke GitHub repository publik (`.gitignore` wajib menjaganya).
3. **Execution Guardrails:** 
   - Line truncation: 4,096 char (mencegah ReDoS).
   - ANSI stripping: otomatis di stream reader.
   - Max file input backstop: `--max-input-mb` (default 500 MB).
   - Exit codes: 0 (analisis selesai & 0 error), 1 (ada error ditemukan), 2 (CLI error), 130 (SIGINT).

---

## 2. Token-Saving Navigation Architecture (Cache Friendly)
Untuk menghemat quota, TPM, dan context window model AI:
1. **JANGAN membaca ulang `PRD.md`, `DECISIONS.md`, atau `TASKS.md` secara keseluruhan.**
2. **Gunakan Knowledge Graph sebagai Indeks Primer:**
   - Baca `.confidential/knowledge/INDEX.md` (bagian Current Execution State).
   - Baca node relevan di `.confidential/knowledge/graph.json`.
   - Buka dokumen spesifik HANYA berdasarkan path node yang sedang dikerjakan.
3. **Status Tasks & Gates:**
   - `INDEX.md` adalah **single source of truth** untuk status aktif.
   - Jangan menyalin ulang detail pengujian antar dokumen.

---

## 3. Current State & Version Roadmap
- **Published on GitHub & PyPI:** `v1.0.1` (Patch release).
- **Current Development Version:** `v1.1.0` (Security & CI Quality Gate: `--scrub-secrets`, `--fail-if-groups-exceed`).
- **Target Selanjutnya:**
  - `TSK-024` -> `v1.2.0` (Run Diffing: `pra-effect diff <run1> <run2>`).
  - `TSK-025` -> `v1.3.0` (Diagnostic Intelligence: `--explain` via heuristics/LLM-ready prompt).

---

## 4. Verification & Testing Commands
Setiap perubahan wajib lolos regression test tanpa merusak suite yang ada:
```bash
python -m unittest discover -s . -p "test_*.py"
git status --short
```
Semua test menggunakan library standar `unittest` dan wajib lulus 100%.
