<div align="center">

# PRAMANA

### From Digital Traces to Defensible Investigation.

**Forensics first. AI second.**

PRAMANA is a local-first, AI-assisted platform for cyber investigation and digital forensics.
It hash-verifies evidence at intake, normalizes it into structured events, correlates it across sources,
and produces findings that link back to the exact artifact they came from, so every conclusion can be defended.

![Python](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-3178C6?logo=typescript&logoColor=white)
![React](https://img.shields.io/badge/React-18-61DAFB?logo=react&logoColor=black)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)

[Problem](#the-problem) · [Approach](#the-pramana-approach) · [Features](#core-features) · [Architecture](#architecture) · [Traceability](#evidence-to-finding-traceability) · [Contracts](#data-and-api-contracts) · [Getting Started](#getting-started)

</div>

<br/>

Built for SUTRAM 2026.

---

## The Problem

Digital evidence is scattered across devices, logs, applications, metadata, communications and timelines. Established forensic tools extract that evidence extremely well. The hard part comes afterwards: connecting artifacts across sources, reconstructing what happened and when, spotting contradictions, and turning all of it into a narrative an investigator can defend.

PRAMANA is designed around that gap.

---

## The PRAMANA Approach

```mermaid
flowchart TB

    E["EVIDENCE<br/><small>Digital traces</small>"]

    subgraph S1["01 · VERIFY & EXTRACT"]
        direction LR
        V["VERIFY<br/><small>SHA-256 + custody</small>"]
        X["EXTRACT<br/><small>Deterministic parsers</small>"]
        V --> X
    end

    subgraph S2["02 · STRUCTURE"]
        direction LR
        N["NORMALIZE<br/><small>Structured Event JSON</small>"]
        G["EVIDENCE GRAPH<br/><small>Entities + relationships</small>"]
        N --> G
    end

    subgraph S3["03 · INVESTIGATE"]
        direction LR
        C["CORRELATE<br/><small>Cross-source signals</small>"]
        A["AI ASSISTANCE<br/><small>Findings + hypotheses</small>"]
        C --> A
    end

    F["EVIDENCE-BACKED FINDING<br/><small>Finding JSON</small>"]

    H["HUMAN VERIFICATION<br/><small>Investigator remains in control</small>"]

    E --> V
    X --> N
    G --> C
    A --> F
    F --> H

    classDef evidence fill:#111827,stroke:#58a6ff,color:#ffffff,stroke-width:2px
    classDef deterministic fill:#0b3d63,stroke:#58a6ff,color:#ffffff,stroke-width:2px
    classDef intelligence fill:#321b52,stroke:#c084fc,color:#ffffff,stroke-width:2px
    classDef finding fill:#3b2368,stroke:#d2a8ff,color:#ffffff,stroke-width:2px
    classDef human fill:#123c2a,stroke:#56d364,color:#ffffff,stroke-width:2px

    class E evidence
    class V,X,N,G,C deterministic
    class A intelligence
    class F finding
    class H human
