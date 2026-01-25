# 🧠 SirenScan — Backend README (Phishing Intelligence Platform)

SirenScan is a **P2B Phishing Intelligence Platform** designed to help organizations **detect, investigate, and mitigate email-based threats**. Users forward suspicious emails to the platform, where it is analyzed using a combination of:

* **Machine Learning (Transformers + PyTorch)**
* **Threat Intelligence Enrichment (VirusTotal)**
* **Breach Exposure Checks (HaveIBeenPwned)**
* **AI-Assisted Reporting (OpenAI API)**
* **Cloud Storage + Audit Logs (Firebase)**
* **Inbound/Outbound Email Handling (Mailgun + Resend)**

> ⚠️ This README documents the **backend only** (no frontend included).

---

## 📌 Table of Contents

1. [Project Overview](#-project-overview)
2. [Backend Tech Stack](#-backend-tech-stack)
3. [System Architecture](#-system-architecture)
4. [Backend Flow (How It Works)](#-backend-flow-how-it-works)
5. [API Integrations](#-api-integrations)
6. [Data Stored in Firebase](#-data-stored-in-firebase)
7. [Security Notes](#-security-notes)
8. [Future Improvements](#-future-improvements)

---

## 🔥 Project Overview

Phishing attacks remain one of the most common entry points for breaches. SirenScan helps organizations respond faster by providing:

✅ **Fast phishing classification** using a trained NLP model
✅ **Indicator extraction** (URLs, domains, sender data)
✅ **External verification** through threat intelligence APIs
✅ **Actionable security output** (verdict + reasoning + next steps)
✅ **Case logging** for tracking investigations over time

---

## 🛠 Backend Tech Stack

### **Backend Framework**

* **FastAPI** — REST API service for receiving emails, processing analysis, and returning results.

### **Model Frameworks**

* **Transformers** — NLP model framework for phishing detection.
* **PyTorch** — Model inference engine.

### **Database**

* **Firebase** — Stores scan history, extracted indicators, results, and investigation metadata.

### **Tools**

* **Git and Github** - Version control + collaboration. 

---

## 🏗 System Architecture

SirenScan backend acts as the central “analysis engine” that connects multiple services:

```
[User / Organization]
        |
        | (forward suspicious email / submit payload)
        v
   [FastAPI Backend]
        |
        |--> Extract Indicators (URLs, domains, sender info)
        |
        |--> ML Classification (Transformers + PyTorch)
        |
        |--> Threat Enrichment
        |      ├─ VirusTotal API
        |      └─ HaveIBeenPwned API
        |
        |--> AI Summary + Recommendations (OpenAI API)
        |
        |--> Store Results (Firebase)
        |
        └--> Notify (Resend / Mailgun)
```

---

## 🔄 Backend Flow (How It Works)

This is the **end-to-end backend flow** of SirenScan:

### **Step 1 — Email Intake**

Suspicious emails are submitted to SirenScan via:

* **Forwarded email** (Mailgun inbound pipeline), or
* **Direct API request** (raw email / JSON payload)

**Goal:** capture email content + metadata for analysis.

---

### **Step 2 — Parsing + Extraction**

The backend parses the email and extracts important indicators:

* Sender email address
* Subject
* Body text (plain text + cleaned HTML)
* URLs and domains inside the content
* Header signals (optional, if provided)
* Attachment metadata (optional)

**Goal:** create a clean input for the model + enrichment APIs.

---

### **Step 3 — ML Phishing Detection**

The cleaned email content is passed into the phishing detection model:

* **Transformers-based classifier**
* Runs using **PyTorch inference**
* Produces:

  * `phishing` verdict (Yes/No)
  * `confidence score`
  * detection signals (optional)

**Goal:** fast and consistent phishing prediction.

---

### **Step 4 — Threat Intelligence Enrichment**

To strengthen reliability, SirenScan enriches extracted indicators using external sources:

#### ✅ VirusTotal API

Checks reputation of:

* URLs
* Domains
* IPs (if extracted)

Returns evidence such as:

* malicious / suspicious / harmless votes
* detection stats

#### ✅ HaveIBeenPwned API

Checks if the sender email has appeared in known breaches.

Returns:

* breach presence (Yes/No)
* breach count / exposure context (depending on API response)

**Goal:** add real-world validation beyond the ML prediction.

---

### **Step 5 — AI Explanation + Recommended Actions**

SirenScan generates an investigation-friendly report using **OpenAI API**, such as:

* Why the email is suspicious (human-readable)
* Which indicators are risky
* Suggested actions:

  * block domain
  * quarantine sender
  * reset credentials
  * alert staff / SOC

**Goal:** turn raw data into actionable security decisions.

---

### **Step 6 — Save Case + Results (Firebase)**

The backend stores scan outputs in **Firebase** for:

* audit logs
* scan history
* investigation tracking
* reporting dashboards

**Goal:** build an organization’s phishing intelligence database over time.

---

### **Step 7 — Notifications (Optional)**

The backend can notify responders or admins via:

* **Resend API** (email notifications)
* **Mailgun API** (email workflows / routing)

Examples:

* “⚠️ High Risk Phishing Detected”
* “Scan Completed — View Report”

**Goal:** faster response and better visibility.

---

## 🔌 API Integrations

### **VirusTotal API**

**Purpose:** threat intelligence + reputation scoring
**Used for:** URLs, domains, IP indicators extracted from email content

---

### **HaveIBeenPwned API**

**Purpose:** breach exposure check
**Used for:** sender email risk context and trust scoring

---

### **OpenAI API**

**Purpose:** security explanation + report generation
**Used for:** summarizing results into readable investigation output

---

### **Mailgun API**

**Purpose:** inbound email capture and routing
**Used for:** forwarding suspicious emails into the platform

---

### **Resend API**

**Purpose:** outbound alert delivery
**Used for:** scan results notifications, high-risk alerts

---

## 🗃 Data Stored in Firebase

Firebase is used to store structured scan results such as:

* scan ID
* timestamp
* sender email + subject
* extracted URLs/domains
* ML prediction + confidence score
* VirusTotal results
* HaveIBeenPwned results
* AI summary + recommended actions

This allows:

* historical search
* repeated indicator tracking
* incident documentation

---

---

## 🔐 Security Notes

Because SirenScan processes potentially malicious content, the backend should always:

* Treat all email input as **untrusted**
* Validate and sanitize URLs before scanning/enrichment
* Never execute attachments
* Rate-limit requests to prevent abuse
* Avoid logging sensitive email content unnecessarily
* Protect API keys and Firebase credentials

---

## 🚧 Future Improvements (Optional Roadmap)

* Add sandbox analysis for attachments
* Add URL detonation + screenshot scanning
* Add organization-based multi-tenant support
* Add role-based access control (RBAC)
* Improve explainability (feature importance / model reasoning)
* Add indicator correlation across multiple cases

---

## 📍 Summary

SirenScan backend combines **ML detection + threat intelligence + breach checks + AI reporting** to deliver a phishing verdict that is:

✅ accurate
✅ evidence-based
✅ easy to understand
✅ actionable for organizations

---
