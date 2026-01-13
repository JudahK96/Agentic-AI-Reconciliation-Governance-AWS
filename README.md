# Agentic-AI-Reconciliation-Governance-AWS
## Objective
This lab demonstrates how to design and implement an **agentic, event-driven AI system** for **data reconciliation, governance, and exception triage** using fully managed AWS services.
The goal was not to build a demo model, but to show **production-oriented decision-making**: separating deterministic data processing from AI reasoning, enforcing security best practices, enabling observability, and exposing results through an API that could support a real UI.
This design mirrors real enterprise use cases in **financial services, compliance, and operations**, where explain-ability, auditability, and cost control matter as much as AI capability.

### Problem Statement
Organizations routinely need to reconcile data across multiple systems (e.g., source vs. target, upstream vs. downstream). As data volume and system complexity grow, traditional reconciliation approaches begin to fail.
Common challenges include:
- Missing or mismatched records between systems
- Duplicate transactions caused by partial failures or reprocessing
- Manual, slow exception review that does not scale
- Poor governance with unclear ownership and remediation steps
- Limited explainability when AI is introduced into decision-making

These issues increase operational risk, reduce trust in data, and make audits and compliance significantly harder. This lab solves those problems by combining:
- **Rule-based reconciliation**
- **Event-driven orchestration**
- **Agentic AI reasoning grounded in policy (RAG)**
- **Secure, observable, serverless infrastructure**

### Skills Demonstrated & Learned
| **Domain**                         | **Skills & Technologies**                                                                                                                                                                                                                                                                                                                                                                   | **Domain**                       | **Skills & Technologies**                                                                                                                                                                                                                                                        |
| ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **AI & Agentic Systems**           | • Agentic AI workflow design (autonomous triage and decisioning)<br>• Retrieval-Augmented Generation (RAG) using Amazon Bedrock Knowledge Bases<br>• Prompt engineering for policy-grounded, explainable AI outputs<br>• Separation of deterministic logic from probabilistic AI reasoning<br>• AI guardrails and model misuse prevention<br>• AI explainability and audit-friendly outputs | **AWS Cloud Architecture**       | • Serverless, event-driven architecture on AWS<br>• Service orchestration using AWS Step Functions<br>• Event-based automation with Amazon EventBridge<br>• API design using Amazon API Gateway (HTTP APIs)<br>• Cloud-native design patterns for scalable systems               |
| **Data Engineering & Analytics**   | • Data reconciliation using SQL (Amazon Athena)<br>• Schema-aware data organization in Amazon S3<br>• Data quality checks and exception detection<br>• Batch processing and fan-out patterns<br>• Handling structured (CSV) and semi-structured (JSON) data                                                                                                                                 | **Data Governance & Compliance** | • Policy-driven decision making using RAG<br>• Data governance and quality rule enforcement<br>• Exception classification and lifecycle management<br>• Audit-ready reasoning and documentation<br>• Governance-aware AI design for regulated environments                       |
| **Security & IAM**                 | • IAM role design and least-privilege access control<br>• Customer-managed encryption using AWS KMS (SSE-KMS)<br>• Secure service-to-service access patterns<br>• Understanding which services require encryption key access and why<br>• Defense-in-depth security mindset                                                                                                                 | **API & Integration**            | • Designing backend APIs for frontend consumption<br>• Enabling and configuring CORS for browser-based UIs<br>• RESTful endpoint design and query parameter handling<br>• JSON response normalization for UI compatibility<br>• Integration patterns for Angular / SPA frontends |
| **Observability & Reliability**    | • CloudWatch Logs for distributed debugging<br>• AWS X-Ray tracing for end-to-end request visibility<br>• Step Functions execution monitoring<br>• Error handling, retries, and failure isolation<br>• Operational visibility in agentic workflows                                                                                                                                          | **DevOps & Cost Awareness**      | • Cost-efficient service selection (Athena vs. SageMaker)<br>• Zero-idle-cost serverless architectures<br>• Safe shutdown and resource cleanup practices<br>• Budget awareness and billing guardrails<br>• Designing systems that can scale down to $0                           |
| **Software Engineering Practices** | • Clean separation of concerns<br>• Defensive programming and validation<br>• JSON schema enforcement<br>• Stateless Lambda function design<br>• Production-oriented error handling                                                                                                                                                                                                         |                                  |                                                                                                                                                                                                                                                                                  |
### Creating LAB Data
I prompted ChatGPT to create two data csv files: `source_system.csv` & `target_system.csv`
```
| trade_id  | Source (account / date / amount)   | Target (account / date / amount)     | Intentional Data Issue |
| --------- | ---------------------------------- | ------------------------------------ | ---------------------- |
| T0001     | ACCT1001 · 2025-12-01 · 1250.50    | ACCT1001 · 2025-12-01 · 1250.50      | —                      |
| T0002     | ACCT1002 · 2025-12-01 · -300.00    | ACCT1002 · 2025-12-01 · -300.00      | —                      |
| T0003     | ACCT1003 · 2025-12-02 · 9800.00    | ACCT1003 · 2025-12-02 · 9800.00      | —                      |
| T0004     | ACCT1001 · 2025-12-02 · 75.25      | ACCT1001 · 2025-12-02 · 75.25        | —                      |
| **T0005** | ACCT1004 · 2025-12-03 · **450.00** | ACCT1004 · 2025-12-03 · **475.00**   | ⚠️ Amount mismatch     |
| T0006     | ACCT1005 · 2025-12-03 · 2100.10    | ACCT1005 · 2025-12-03 · 2100.10      | —                      |
| **T0007** | ACCT1002 · 2025-12-04 · 600.00     | ❌ Missing                            | ⚠️ Missing in target   |
| T0008     | ACCT1006 · 2025-12-04 · -125.75    | ACCT1006 · 2025-12-04 · -125.75      | —                      |
| T0009     | ACCT1007 · 2025-12-05 · 3200.00    | ACCT1007 · 2025-12-05 · 3200.00      | —                      |
| T0010     | ACCT1003 · 2025-12-05 · 150.00     | ACCT1003 · 2025-12-05 · 150.00       | —                      |
| T0011     | ACCT1008 · 2025-12-06 · 999.99     | ACCT1008 · 2025-12-06 · 999.99       | —                      |
| **T0012** | ACCT1009 · 2025-12-06 · 5000.00    | ACCT1009 · 2025-12-06 · 5000.00 (×2) | ⚠️ Duplicate in target |
| T0013     | ACCT1010 · 2025-12-07 · 40.00      | ACCT1010 · 2025-12-07 · 40.00        | —                      |
| **T0014** | ACCT1005 · 2025-12-07 · -75.00     | ❌ Missing                            | ⚠️ Missing in target   |
| T0015     | ACCT1001 · 2025-12-08 · 860.00     | ACCT1001 · 2025-12-08 · 860.00       | —                      |
| T0016     | ACCT1006 · 2025-12-08 · 120.12     | ACCT1006 · 2025-12-08 · 120.12       | —                      |
| T0017     | ACCT1007 · 2025-12-09 · 2300.00    | ACCT1007 · 2025-12-09 · 2300.00      | —                      |
| **T0018** | ACCT1002 · 2025-12-09 · **310.00** | ACCT1002 · 2025-12-09 · **295.00**   | ⚠️ Amount mismatch     |
| T0019     | ACCT1008 · 2025-12-10 · -20.00     | ACCT1008 · 2025-12-10 · -20.00       | —                      |
| T0020     | ACCT1010 · 2025-12-10 · 7100.00    | ACCT1010 · 2025-12-10 · 7100.00      | —                      |
```
- Intentional issues in `target_system.csv`:
  - **Missing trade_ids:** `T0007`, `T0014`
  - **Amount mismatches:** `T0005` (450.00 → 475.00), `T0018` (310.00 → 295.00)
  - **Duplicate row:** `T0012` appears twice (exact duplicate)
I prompted ChatGPT to create three policiy csv files: `recon-policy.txt`, `data-quality-rules.txt` & `exception-handling-runbook.txt`


### Creating S3 Bucket/Uploading Data
Created two s3 Buckets `ai-recon-lab-data-jk-agentic-2026` & `ai-recon-lab-docs-jk-agentic-2026`
- Enabled Bucket versioning
- Enable Default Encryption SSE-S3 (will harden security and update to an SSE-KMS)

1. S3 Bucket `ai-recon-lab-data-jk-agentic-2026`
  - Created Folders: `incoming/` `processed/` `athena-results/`
  - In the `incoming/` folder created folders `source/` & `target/`
  - Uploaded the `source_system.csv` & `target_system.csv` files to their respective folders
    - Prevents accidental cross-reading in Athena
    - Mirrors real data lake zone design
    - Improves clarity and governance
    - ***Adding both CSVs in the same `incoming/`folder(no sub-folder), Athena will read both unless you separate them; so it’s better to create subfolders and point each table to its folder***

| `ai-recon-lab-data-jk-agentic-2026`| `source/`| `target/`|
|----------------------------|----------------------------|----------------------------|
|<img width="1893" height="714" alt="image" src="https://github.com/user-attachments/assets/7cc8f338-7e04-466a-9659-1570633f7a0b" />|<img width="1918" height="609" alt="image" src="https://github.com/user-attachments/assets/0bc9aaa5-c4ae-4003-824c-0b19dcb174a1" />|<img width="1918" height="604" alt="image" src="https://github.com/user-attachments/assets/f45fb316-3d08-4751-8145-2ba8456761de" />|

2. S3 Bucket `ai-recon-lab-docs-jk-agentic-2026`
  - Created Folders: `policies/`
  - In the `policies/`uploaded created polocy files `recon-policy.txt` `data-quality-rules.txt` `exception-handling-runbook.txt`
<img width="1893" height="714" alt="image" src="https://github.com/user-attachments/assets/478b7fb7-a55e-47aa-a118-a230a2120e86" />


### Folder-scoped S3 layout (`incoming/source/` vs `incoming/target/`)
**Decision:** Separate data sources into explicit S3 prefixes.
**Why:**
- Prevents accidental cross-reading in Athena
- Mirrors real data lake zone design
- Improves clarity and governance
