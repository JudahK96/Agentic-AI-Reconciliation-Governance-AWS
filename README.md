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
## Creating LAB Data
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


## Creating S3 Bucket/Uploading Data
Created two s3 Buckets `ai-recon-lab-data-jk-agentic-2026` & `ai-recon-lab-docs-jk-agentic-2026`
- Enabled Bucket versioning
- Enable Default Encryption SSE-S3 (will harden security and update to an SSE-KMS)

### 1. S3 Bucket `ai-recon-lab-data-jk-agentic-2026`
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

### 2. S3 Bucket `ai-recon-lab-docs-jk-agentic-2026`
  - Created Folders: `policies/`
  - In the `policies/`uploaded created polocy files `recon-policy.txt` `data-quality-rules.txt` `exception-handling-runbook.txt`
<img width="1893" height="714" alt="image" src="https://github.com/user-attachments/assets/478b7fb7-a55e-47aa-a118-a230a2120e86" />


## Created an Athena table
- Thsis Table is over the CVSs `source_system.csv` & `target_system.csv`
- Set Athena Query result location to `athena-results/` folder in S3
<img width="1897" height="495" alt="image" src="https://github.com/user-attachments/assets/4bfd2988-66e8-42ea-b4ef-9e5c6c460a41" />

| Database Creation - Source & Target System External Table | Verify Code Check |
|------------------------------|------------------------------|
|<img width="695" height="102" alt="image" src="https://github.com/user-attachments/assets/74508b45-e806-44f3-bb72-7413864858c8" /> <img width="488" height="292" alt="image" src="https://github.com/user-attachments/assets/f32f8c28-069a-4130-ad04-788ea26e2f67" /> <img width="476" height="291" alt="image" src="https://github.com/user-attachments/assets/5899f1a9-016d-42e7-90e1-b28717860189" /> |<img width="661" height="100" alt="image" src="https://github.com/user-attachments/assets/2f4ae8e0-6c74-4332-be2d-8f9fb700912f" /> <img width="1288" height="481" alt="image" src="https://github.com/user-attachments/assets/4f2ec9f8-2cf0-45f5-bc96-4786470c0366" /> <img width="1833" height="789" alt="image" src="https://github.com/user-attachments/assets/b72bc437-61c8-402f-9801-183f5e626909" />|

### Created Reconciliation Queries
These outputs become exception detection backbone
  - Saved the output files locally aswell

| `exceptions_missing_in_target.csv` | `exceptions_amount_mismatches.csv` | `exceptions_duplicates_in_target.csv` |
|-----------------------------------------|----------------------------------|----------------------------------|
|<img width="636" height="437" alt="image" src="https://github.com/user-attachments/assets/b7177026-f050-4a45-80da-b55f9772fe3b" />|<img width="628" height="475" alt="image" src="https://github.com/user-attachments/assets/ac5b06d1-d9da-4670-9b1d-7ab440692e08" />|<img width="630" height="397" alt="image" src="https://github.com/user-attachments/assets/e1a3aedd-68fb-46a2-9998-ebc8c1a0d0d6" />|

## Storing exceptions in DynamoDB
- Created DynamoDB Table: `recon_exceptions`
  - Partition Key: `exception_id`
    - Type: Sting
<img width="1893" height="340" alt="image" src="https://github.com/user-attachments/assets/9dcf831f-a3cc-464e-8384-42ca99b59138" />

***By default, DynamoDB can only efficiently answer questions like: “Give me the exception with ID = X”***
- That's not enough for a reconciliation workflow. At the moment I could only Query efficiently by `exception_id`, any other attributes required a scan
-  So I added a Global Secondary Index (GSI) `by_type` to make asking secondary questions cheaper

  ***The main table optimizes point lookups by exception ID, while the GSI enables operational and audit queries by exception type and time without scans***
  - All exceptions of a given type
  - Exceptions of a type within a time range
  - Sorted results by creation time

<img width="1851" height="421" alt="image" src="https://github.com/user-attachments/assets/0c5021a9-b177-4af2-98ab-e5ee4ca09b3b" />

***Now I can ask questions like this:***
- “Show me **all AMOUNT_MISMATCH** exceptions”
- “Show me **all MISSING_IN_TARGET** exceptions”
- “Show me **duplicates from today**”


## Created Knowledge Base for Policy + Runbooks
### Created `recon-kb` 
1. Synced with `ai-recon-lab-docs-jk-agentic-2026` S3 Bucket prefix `policies/` folder storing `recon-policy.txt`, `data-quality-rules.txt` & `exception-handling-runbook.txt` files
- Dedicated prefix `policies/` gives:
  - Auditability: In a real recon workflow, policy + procedure docs are part of the control environment. Keeping them in S3 mirrors that
  - Clear governance + separation: policies/runbooks live in one place, separate from raw recon data `incoming/source/` & `incoming/target/`
  - Simple Updates since the policy files can be added or versioned and Sync with the Knowledge Base
2.  I chose a vector stro for the KB as the `policies/` folder stored unstructured data. In the files they describe: ***match keys (trade_id, account_id), tolerances (amount thresholds), exception handling (missing records, late arrivals), escalation rules / SLA***
    - That kind of content is not best handled by structured store KBs (which are for database/table semantic querying)
      - In other words: **Structured KB** = “search inside tables” & **Vector store KB** = “search inside documents”
3. I went with OpenSearch Serverless because it works cleanly with Bedrock KBs and it’s a standard integration path
  - It stores my embeddings and has fast retrieval to return the top relevant chunks quickly.
  - It was less infrastructure work since I don’t need to size clusters, manage nodes, or think hard about scaling since it's a lab
4. I started with default chunking to keep the pipeline stable and reproducible, then planned to tune chunking only if retrieval quality tests showed consistent misses
  - Policies already read like sections headings, bullets, procedures; so default chunking usually captures those units well enough
  - It avoids over-tuning too early; custom chunking can accidentally split key definitions from their context, or create chunks that are too big and dilute relevance
  - My lab goal was for reliable retrieval, not chunk optimization research, although in hindsight I should have read the files ChatGPT created for my policies. They weere too short which made the default chunking too large as you will see in the testing
5. I used Amazon Nova Micro for this lab as I wanted very low cost text generation and didn't need multimodal inputs
  - Lowest-cost text generation model** on AWS
  - Text-only foundation model optimized for speed and cost
  - Great for tasks like summarization, classification, translation, simple chat, brainstorming, and lightweight reasoning
  - Very low per-token cost — around *$0.0000175 per 1,000 input tokens* and *$0.00007 per 1,000 output tokens* (batch mode) — roughly the cheapest in the Nova family

### Testing KB
- Upload a Snippet of the data I got back from DynamoDB/Athena
```
"trade_id","account_id","trade_date","source_amount","target_amount"
"T0005","ACCT1004","2025-12-03","450.0","475.0"
"T0018","ACCT1002","2025-12-09","310.0","295.0"
```

|recon_kb|More Results|
|-----------------------------------------|----------------------------------|
|<img width="2291" height="1136" alt="image" src="https://github.com/user-attachments/assets/ac07ae62-0807-428c-96b6-e212408ab9d0" />|<img width="920" height="986" alt="image" src="https://github.com/user-attachments/assets/3b265044-26c3-4e68-ad41-7796b9b03c7a" />|

## Agentic Triage - Step Functions + Lambda + Bedrock
### Created the Lambda `run_recon_and_write_exceptions`
  - Lambda Role: `lambda-recon-lab-role`
    - Permissions: `AmazonS3ReadOnlyAccess` `AmazonAthenaFullAccess` `AmazonDynamoDBFullAccess` `CloudWatchLogsFullAccess` `AmazonBedrockFullAccess`
    - Inline Policy
```
{
	"Version": "2012-10-17",
	"Statement": [
		{
			"Effect": "Allow",
			"Action": [
				"s3:PutObject",
				"s3:GetBucketLocation"
			],
			"Resource": [
				"arn:aws:s3:::recon-lab-data-jk-agentic-2026",
				"arn:aws:s3:::recon-lab-data-jk-agentic-2026/*"
			]
		}
	]
}
```
|Environment Variables|Lambda|
|-|-|
|<img width="309" height="187" alt="image" src="https://github.com/user-attachments/assets/79cd2467-a118-4359-a29f-ce6c8e968fe1" />|<img width="1226" height="872" alt="image" src="https://github.com/user-attachments/assets/c76cba06-feb7-4fa3-bee8-10578d6affac" />|

