# PhishDefender-PhishingResponseSystem

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Flask](https://img.shields.io/badge/Flask-3.0.3-lightgrey?style=flat-square&logo=flask)
![LightGBM](https://img.shields.io/badge/LightGBM-GPU%20Accelerated-green?style=flat-square)
![XGBoost](https://img.shields.io/badge/XGBoost-GPU%20Accelerated-orange?style=flat-square)
![Chrome Extension](https://img.shields.io/badge/Chrome-Extension%20MV3-yellow?style=flat-square&logo=googlechrome)
![License](https://img.shields.io/badge/License-MIT-red?style=flat-square)

> An end-to-end AI-powered phishing detection and response
> platform built as a Chrome browser extension.
> Combines machine learning, threat intelligence APIs,
> and rule-based automation to detect, analyze, and respond
> to phishing emails in real time directly inside Gmail.

---
## Table of Contents

1. [Problem Statement](#1-problem-statement)
2. [Proposed Solution](#2-proposed-solution)
3. [How It Works — Architecture Overview](#3-how-it-works--architecture-overview)
4. [Project Structure](#4-project-structure)
5. [Tech Stack](#5-tech-stack)
6. [Datasets Used](#6-datasets-used)
7. [Machine Learning Pipeline](#7-machine-learning-pipeline)
8. [Backend Modules — Deep Dive](#8-backend-modules--deep-dive)
9. [Browser Extension — Deep Dive](#9-browser-extension--deep-dive)
10. [API Endpoints](#10-api-endpoints)
11. [Threat Scoring System](#11-threat-scoring-system)
12. [Installation and Setup](#12-installation-and-setup)
13. [Running the Project](#13-running-the-project)
14. [Loading the Extension](#14-loading-the-extension)
15. [How to Use](#15-how-to-use)
16. [Free Deployment Alternatives](#16-free-deployment-alternatives)
17. [Resume Highlights](#17-resume-highlights)
18. [Known Limitations](#18-known-limitations)
19. [Future Improvements](#19-future-improvements)
20. [License](#20-license)

---
## 1. Problem Statement

Phishing attacks remain one of the most prevalent and
damaging forms of cybercrime worldwide. According to
industry reports, over 3.4 billion phishing emails are
sent every single day, and phishing is responsible for
more than 90% of all data breaches globally.

Despite the existence of spam filters and basic email
security tools, modern phishing attacks have become
increasingly sophisticated. Attackers now craft emails
that:

- Pass SPF, DKIM, and DMARC authentication checks by
  abusing legitimate email infrastructure
- Use legitimate URL shorteners and redirect chains to
  hide malicious destinations from static filters
- Employ social engineering tactics that exploit urgency,
  fear, and authority to bypass human judgment
- Target individuals specifically using information
  harvested from social media (spear phishing)
- Deploy payloads with advanced capabilities including
  keylogging, screen capture, memory inspection, and
  GUI spoofing

The core problem is that existing solutions operate
reactively — they either block known bad domains using
static blocklists, or they rely entirely on human
judgment which is prone to error under social pressure.
Neither approach scales well against zero-day phishing
campaigns that use freshly registered domains and
never-before-seen payloads.

Additionally, most enterprise-grade phishing detection
tools are expensive, require complex IT infrastructure,
and are inaccessible to individual users, small
organizations, and security students who need to learn
these concepts hands-on.

There is a clear need for an intelligent, automated,
real-time phishing detection system that:

- Operates at the point of attack (the inbox itself)
- Combines multiple detection signals rather than
  relying on a single method
- Is accessible and free to deploy
- Produces actionable, human-readable output including
  identified IOCs and recommended responses
- Can be extended and improved as new attack patterns
  emerge

---
## 2. Proposed Solution

This project proposes a full-stack AI-powered phishing
detection platform delivered as a Chrome browser
extension with a Python backend.

The core philosophy of the solution is
**defence in depth** — rather than relying on any single
detection method, the platform layers five independent
detection signals and combines them into a unified
threat score:

| Layer | Method | Signal Type |
|-------|--------|-------------|
| 1 | Email header analysis | SPF, DKIM, DMARC, Reply-To |
| 2 | LightGBM email classifier | NLP + text features |
| 3 | LightGBM URL classifier | Structural URL features |
| 4 | VirusTotal API | External threat intelligence |
| 5 | AbuseIPDB API | IP reputation intelligence |

The five signals are then fed into a rule-based triage
engine that assigns weighted scores to each signal and
produces a final verdict of **Malicious**,
**Suspicious**, or **Benign** with a score from 0 to 100.

For malicious and suspicious emails the platform
automatically generates a professional PDF incident
report containing all identified Indicators of
Compromise (IOCs), the full rule trace, ML model
confidence scores, and recommended response actions —
exactly the kind of output a real SOC analyst would
produce after investigating a phishing alert.

The architecture is deliberately split into two layers:

- **Browser Extension (JavaScript)** — a thin layer that
  reads the open email from the Gmail DOM and displays
  results. It contains no ML logic and no API keys.
- **Python Backend (Flask)** — handles all intelligence
  processing including ML inference, API calls, rule
  evaluation, and report generation. This is where the
  real work happens and where all sensitive credentials
  are stored.

This split architecture means the extension itself is
lightweight, fast, and secure — it simply reads and
displays. All the heavy computation runs on the Python
side which can be improved, extended, or replaced
without touching the extension code.

---
