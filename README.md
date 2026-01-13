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
<details>
<summary><strong>S3 IAM policy (click to expand)</strong></summary>

<pre><code class="language-json">
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
</code></pre>

</details>

<details>
<summary><strong> lambda-recon-lab-role code (click to expand)</strong></summary>

<pre><code class="language-python">
import os
import json
import time
import uuid
import logging
from datetime import datetime, timezone, timedelta

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

athena = boto3.client("athena")
ddb = boto3.resource("dynamodb")


def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None or str(v).strip() == "":
        raise ValueError(f"Missing required environment variable: {name}")
    return v.strip()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _ttl_epoch_days(days: int) -> int:
    # DynamoDB TTL expects epoch seconds (int)
    expire_at = datetime.now(timezone.utc) + timedelta(days=days)
    return int(expire_at.timestamp())


def _start_athena_query(sql: str, database: str, output_s3: str) -> str:
    resp = athena.start_query_execution(
        QueryString=sql,
        QueryExecutionContext={"Database": database},
        ResultConfiguration={"OutputLocation": output_s3},
    )
    return resp["QueryExecutionId"]


def _wait_for_query(qid: str, max_poll_seconds: int, poll_interval_seconds: int) -> None:
    deadline = time.time() + max_poll_seconds
    while True:
        resp = athena.get_query_execution(QueryExecutionId=qid)
        state = resp["QueryExecution"]["Status"]["State"]
        if state in ("SUCCEEDED", "FAILED", "CANCELLED"):
            if state != "SUCCEEDED":
                reason = resp["QueryExecution"]["Status"].get("StateChangeReason", "Unknown")
                raise RuntimeError(f"Athena query {qid} ended with state={state}. Reason={reason}")
            return

        if time.time() > deadline:
            raise TimeoutError(f"Timed out waiting for Athena query {qid} after {max_poll_seconds}s")

        time.sleep(poll_interval_seconds)


def _get_all_results(qid: str) -> list[list[str]]:
    """
    Returns rows as a list of list-of-strings (already trimmed).
    The first row is the header row, matching Athena behavior.
    """
    rows: list[list[str]] = []
    next_token = None

    while True:
        kwargs = {"QueryExecutionId": qid, "MaxResults": 1000}
        if next_token:
            kwargs["NextToken"] = next_token

        resp = athena.get_query_results(**kwargs)
        for r in resp["ResultSet"]["Rows"]:
            # Each datum may have VarCharValue; missing values return {}
            rows.append([d.get("VarCharValue", "") for d in r.get("Data", [])])

        next_token = resp.get("NextToken")
        if not next_token:
            break

    return rows


def _rows_to_dicts(rows: list[list[str]]) -> list[dict]:
    """
    Converts Athena result rows into a list of dicts using the header row.
    Skips the header.
    """
    if not rows:
        return []
    header = rows[0]
    out = []
    for r in rows[1:]:
        item = {}
        for i, col in enumerate(header):
            if col == "":
                continue
            item[col] = r[i] if i < len(r) else ""
        out.append(item)
    return out


def _put_exception_items(
    table_name: str,
    exception_type: str,
    records: list[dict],
    run_id: str,
    ttl_days: int | None,
) -> int:
    table = ddb.Table(table_name)
    created_at = _utc_now_iso()

    ttl_epoch = _ttl_epoch_days(ttl_days) if ttl_days and ttl_days > 0 else None

    written = 0
    with table.batch_writer(overwrite_by_pkeys=["exception_id"]) as batch:
        for rec in records:
            exception_id = str(uuid.uuid4())
            trade_id = rec.get("trade_id") or rec.get("TRADE_ID") or rec.get("tradeid") or ""

            item = {
                "exception_id": exception_id,
                "exception_type": exception_type,
                "trade_id": trade_id,
                "status": "OPEN",
                "created_at": created_at,
                "run_id": run_id,
                "details_json": json.dumps(rec, ensure_ascii=False),
            }
            if ttl_epoch is not None:
                item["ttl_epoch"] = ttl_epoch

            batch.put_item(Item=item)
            written += 1

    return written


def lambda_handler(event, context):
    # ----- Load config -----
    database = _env("ATHENA_DATABASE")
    output_s3 = _env("ATHENA_OUTPUT_S3")
    source_table = _env("SOURCE_TABLE")
    target_table = _env("TARGET_TABLE")
    ddb_table = _env("DDB_TABLE")

    max_poll_seconds = int(os.environ.get("MAX_POLL_SECONDS", "90"))
    poll_interval_seconds = int(os.environ.get("POLL_INTERVAL_SECONDS", "2"))

    ttl_days_raw = os.environ.get("EXCEPTION_TTL_DAYS")
    ttl_days = int(ttl_days_raw) if ttl_days_raw and ttl_days_raw.strip().isdigit() else None

    # Correlation / run id (useful for Step Functions + logs)
    run_id = event.get("run_id") if isinstance(event, dict) else None
    if not run_id:
        run_id = context.aws_request_id if context else str(uuid.uuid4())

    logger.info(
        "Starting reconciliation run_id=%s database=%s source=%s target=%s",
        run_id, database, source_table, target_table
    )

    # ----- Define reconciliation SQL -----
    sql_missing_in_target = f"""
    SELECT s.trade_id, s.account_id, s.trade_date, CAST(s.amount AS varchar) AS source_amount
    FROM {database}.{source_table} s
    LEFT JOIN {database}.{target_table} t
      ON s.trade_id = t.trade_id
    WHERE t.trade_id IS NULL
    """

    sql_amount_mismatch = f"""
    SELECT s.trade_id,
           s.account_id,
           s.trade_date,
           CAST(s.amount AS varchar) AS source_amount,
           CAST(t.amount AS varchar) AS target_amount
    FROM {database}.{source_table} s
    JOIN {database}.{target_table} t
      ON s.trade_id = t.trade_id
    WHERE s.amount &lt;&gt; t.amount
    """

    sql_duplicates_in_target = f"""
    SELECT trade_id, CAST(COUNT(*) AS varchar) AS cnt
    FROM {database}.{target_table}
    GROUP BY trade_id
    HAVING COUNT(*) &gt; 1
    """

    queries = [
        ("MISSING_IN_TARGET", sql_missing_in_target),
        ("AMOUNT_MISMATCH", sql_amount_mismatch),
        ("DUPLICATE_IN_TARGET", sql_duplicates_in_target),
    ]

    summary = {
        "run_id": run_id,
        "written": {},
        "athena_query_ids": {},
        "database": database,
        "source_table": source_table,
        "target_table": target_table,
        "ddb_table": ddb_table,
        "timestamp_utc": _utc_now_iso(),
    }

    # ----- Execute queries + write exceptions -----
    for exception_type, sql in queries:
        try:
            logger.info("Starting Athena query for %s", exception_type)
            qid = _start_athena_query(sql, database=database, output_s3=output_s3)
            summary["athena_query_ids"][exception_type] = qid

            _wait_for_query(
                qid,
                max_poll_seconds=max_poll_seconds,
                poll_interval_seconds=poll_interval_seconds,
            )

            raw_rows = _get_all_results(qid)
            records = _rows_to_dicts(raw_rows)

            logger.info("Athena results %s rows=%d", exception_type, len(records))

            written = _put_exception_items(
                table_name=ddb_table,
                exception_type=exception_type,
                records=records,
                run_id=run_id,
                ttl_days=ttl_days,
            )
            summary["written"][exception_type] = written

        except Exception as e:
            logger.exception("Failed processing exception_type=%s error=%s", exception_type, str(e))
            summary["written"][exception_type] = 0
            summary.setdefault("errors", []).append(
                {"exception_type": exception_type, "error": str(e)}
            )

    logger.info("Reconciliation complete. Summary: %s", json.dumps(summary))
    return summary
</code></pre>

</details>


|Environment Variables|Lambda|
|-|-|
|<img width="309" height="187" alt="image" src="https://github.com/user-attachments/assets/79cd2467-a118-4359-a29f-ce6c8e968fe1" />|<img width="1226" height="872" alt="image" src="https://github.com/user-attachments/assets/c76cba06-feb7-4fa3-bee8-10578d6affac" />|
Purpose:
- Runs Athena reconciliation queries (missing, mismatched, duplicates)
- Writes normalized "exceptions" into DynamoDB
How it works:
1. Starts Athena queries
2. Polls until each query finishes
3. Reads results
4. Writes items to DynamoDB with consistent fields
- In General Config I increased the Increased Memory to 256MB & Timeout to 15sec, to stop the throttoling and memeory buffering issue that was syoping the Lambda from executing.

### Created the Lambda `ai_triage_exception`
<details>
<summary><strong>Lambda – ai_triage_exception code (click to expand)</strong></summary>

<pre><code class="language-python">
import os
import json
import logging
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ddb = boto3.resource("dynamodb")

# Bedrock Agent Runtime is what Knowledge Bases use
bedrock_kb = boto3.client("bedrock-agent-runtime")


def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None or str(v).strip() == "":
        raise ValueError(f"Missing required environment variable: {name}")
    return v.strip()


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_json_loads(s: str):
    try:
        return json.loads(s)
    except Exception:
        return None


def _get_exception_item(table_name: str, exception_id: str) -> dict:
    table = ddb.Table(table_name)
    resp = table.get_item(Key={"exception_id": exception_id})
    item = resp.get("Item")
    if not item:
        raise KeyError(f"Exception not found in DynamoDB: exception_id={exception_id}")
    return item


def _build_prompt(exception_item: dict) -> str:
    """
    Keep prompt very explicit so the model returns clean JSON.
    We also include a minimal "system-like" instruction in the user prompt
    because retrieve_and_generate doesn't support a true system role.
    """
    details = exception_item.get("details_json", "{}")
    parsed_details = _safe_json_loads(details) if isinstance(details, str) else details
    if parsed_details is None:
        parsed_details = {"raw_details_json": details}

    payload = {
        "exception_id": exception_item.get("exception_id", ""),
        "exception_type": exception_item.get("exception_type", ""),
        "trade_id": exception_item.get("trade_id", ""),
        "status": exception_item.get("status", ""),
        "run_id": exception_item.get("run_id", ""),
        "details": parsed_details,
    }

    desired_schema = {
        "severity": "LOW | MEDIUM | HIGH | CRITICAL",
        "summary": "1-3 sentences describing what happened and why it matters",
        "recommended_actions": [
            "Action 1",
            "Action 2"
        ],
        "root_cause_hypotheses": [
            "Hypothesis 1",
            "Hypothesis 2"
        ],
        "policy_citations": [
            {
                "title": "document title if known",
                "reason": "why this doc/rule applies"
            }
        ]
    }

    return (
        "You are a data governance and reconciliation assistant.\n"
        "Use ONLY the provided policy/runbook knowledge from retrieval results.\n"
        "If policy is missing, say so and provide best-practice guidance.\n\n"
        "TASK:\n"
        "1) Classify severity.\n"
        "2) Explain the exception.\n"
        "3) Propose concrete next actions for resolution.\n"
        "4) Provide root-cause hypotheses.\n"
        "5) Cite which policy/runbook guidance applies.\n\n"
        "IMPORTANT OUTPUT RULES:\n"
        "- Return STRICT JSON only. No markdown, no extra keys, no prose outside JSON.\n"
        f"- Use this exact JSON shape:\n{json.dumps(desired_schema, indent=2)}\n\n"
        f"EXCEPTION INPUT:\n{json.dumps(payload, indent=2)}\n"
    )


def _call_kb_retrieve_and_generate(knowledge_base_id: str, model_arn: str, prompt: str) -> dict:
    temperature = float(os.environ.get("TEMPERATURE", "0.2"))
    max_tokens = int(os.environ.get("MAX_TOKENS", "700"))
    top_p = float(os.environ.get("TOP_P", "0.9"))

    resp = bedrock_kb.retrieve_and_generate(
        input={"text": prompt},
        retrieveAndGenerateConfiguration={
            "type": "KNOWLEDGE_BASE",
            "knowledgeBaseConfiguration": {
                "knowledgeBaseId": knowledge_base_id,
                "modelArn": model_arn,
                "generationConfiguration": {
                    "inferenceConfig": {
                        "textInferenceConfig": {
                            "temperature": temperature,
                            "maxTokens": max_tokens,
                            "topP": top_p,
                        }
                    }
                },
            },
        },
    )
    return resp


def _extract_generation_text(resp: dict) -> str:
    out = resp.get("output", {})
    txt = out.get("text", "")
    return txt.strip() if isinstance(txt, str) else ""


def _extract_policy_citations(resp: dict) -> list[dict]:
    citations = resp.get("citations", []) or []
    simplified = []

    for c in citations:
        refs = c.get("retrievedReferences", []) or []
        for r in refs:
            loc = r.get("location", {}) or {}
            meta = r.get("metadata", {}) or {}

            title = meta.get("title") or meta.get("source") or meta.get("file_name") or "reference"
            uri = None

            if "s3Location" in loc:
                uri = loc["s3Location"].get("uri")
            elif "webLocation" in loc:
                uri = loc["webLocation"].get("url")

            simplified.append(
                {
                    "title": str(title),
                    "uri": uri,
                    "snippet": (r.get("content", {}) or {}).get("text", "")[:300],
                }
            )

    seen = set()
    unique = []
    for s in simplified:
        key = (s.get("title"), s.get("uri"))
        if key not in seen:
            seen.add(key)
            unique.append(s)
    return unique


def _update_exception_with_ai(
    table_name: str,
    exception_id: str,
    ai_payload: dict,
    citations: list[dict],
    model_arn: str,
) -> None:
    table = ddb.Table(table_name)
    now = _utc_now_iso()

    severity = ai_payload.get("severity", "UNKNOWN")
    summary = ai_payload.get("summary", "")
    recommended_actions = ai_payload.get("recommended_actions", [])
    root_causes = ai_payload.get("root_cause_hypotheses", [])
    policy_citations = ai_payload.get("policy_citations", [])

    table.update_item(
        Key={"exception_id": exception_id},
        UpdateExpression=(
            "SET ai_severity = :sev, "
            "ai_summary = :sum, "
            "ai_recommendation = :rec, "
            "ai_root_causes_json = :rc, "
            "ai_policy_citations_json = :pc, "
            "ai_kb_references_json = :kbrefs, "
            "last_triaged_at = :ts, "
            "triage_model = :model"
        ),
        ExpressionAttributeValues={
            ":sev": severity,
            ":sum": summary,
            ":rec": json.dumps(recommended_actions, ensure_ascii=False),
            ":rc": json.dumps(root_causes, ensure_ascii=False),
            ":pc": json.dumps(policy_citations, ensure_ascii=False),
            ":kbrefs": json.dumps(citations, ensure_ascii=False),
            ":ts": now,
            ":model": model_arn,
        },
    )


def lambda_handler(event, context):
    table_name = _env("DDB_TABLE")
    kb_id = _env("KNOWLEDGE_BASE_ID")
    model_arn = _env("MODEL_ARN")

    logger.info("Event received: %s", json.dumps(event))

    exception_id = None
    if isinstance(event, dict):
        exception_id = event.get("exception_id")

    if not exception_id:
        raise ValueError("Missing exception_id in event")

    exception_item = event if (isinstance(event, dict) and event.get("details_json")) else None
    if not exception_item:
        exception_item = _get_exception_item(table_name, exception_id)

    prompt = _build_prompt(exception_item)

    resp = _call_kb_retrieve_and_generate(
        knowledge_base_id=kb_id,
        model_arn=model_arn,
        prompt=prompt,
    )

    generated_text = _extract_generation_text(resp)
    citations = _extract_policy_citations(resp)

    ai_payload = _safe_json_loads(generated_text)
    if ai_payload is None:
        ai_payload = {
            "severity": "UNKNOWN",
            "summary": "Model did not return valid JSON. See raw output.",
            "recommended_actions": [],
            "root_cause_hypotheses": [],
            "policy_citations": [],
            "raw_output": generated_text[:4000],
        }

    _update_exception_with_ai(
        table_name=table_name,
        exception_id=exception_id,
        ai_payload=ai_payload,
        citations=citations,
        model_arn=model_arn,
    )

    result = {
        "exception_id": exception_id,
        "ai_severity": ai_payload.get("severity", "UNKNOWN"),
        "last_triaged_at": _utc_now_iso(),
        "kb_reference_count": len(citations),
    }

    logger.info("Triage complete: %s", json.dumps(result))
    return result
</code></pre>

</details>


|Environment Variables|Lambda|
|-|-|
|<img width="295" height="216" alt="image" src="https://github.com/user-attachments/assets/cb8505fd-6fb2-4775-a6d6-f23e11d6d912" />|<img width="1609" height="860" alt="image" src="https://github.com/user-attachments/assets/cfdb9a3f-11b0-42f1-83da-3f73fa2ab2b6" />|
- Purpose:
-  Separates reconciliation logic from AI reasoning, each function has isolated configuration and permissions
	-  The reconciliation Lambda is deterministic and SQL-driven, while the triage Lambda uses Bedrock with a Knowledge Base for explainability and policy grounding
- Also Enabled logging + tracing - Monitoring and operations tools/(X-Ray)

## Created Functions State Machine
This is an AWS Step Functions state machine that orchestrates a recon + AI triage workflow
| Steps | Flow |
|------|------|
| **1. RunReconciliation** | Calls the Lambda `run_recon_and_write_exceptions`, passing in the state input as the payload.<br><br>• Saves the Lambda result under `$.recon`<br>• Retries up to **3 times** on common Lambda/Task failures with exponential backoff |
| **2. HasExceptions (Choice)** | Checks whether at least one exception ID exists at `$.recon.Payload.exception_ids[0]`.<br><br>• If present → continue to triage<br>• If not → end successfully |
| **3. NoExceptions (Succeed)** | Ends the workflow immediately if no exceptions are detected |
| **4. TriageEachException (Map)** | Iterates over `$.recon.Payload.exception_ids` and runs triage in parallel (**MaxConcurrency = 5**).<br><br>For each item:<br>• `exception_id` = current item<br>• `run_id` = `$.recon.Payload.run_id`<br><br>Inside Map:<br>• **AITriage (Task – Lambda invoke)** calls `ai_triage_exception`<br>• Stores result at `$.triage` per item<br>• Retries up to **2 times** with backoff<br><br>All results stored at `$.triage_results` |
| **5. Done (Succeed)** | Workflow completes successfully after all exception triages finish |
| **Visual Flow** | <img width="662" height="817" alt="Step Functions workflow" src="https://github.com/user-attachments/assets/2a6bd135-b55e-4b6f-9685-4761fb885e37" /> |

## Trigger workflow on new uploads with EventBridge
- Create Event Bridge Rule
### EventBridge Rule - Step Functions Trigger
<details>
<summary><strong>EventBridge event pattern – S3 incoming/uploads code (click to expand)</strong></summary>

<pre><code class="language-json">
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["s3.amazonaws.com"],
    "eventName": ["PutObject", "CompleteMultipartUpload", "CopyObject"],
    "requestParameters": {
      "bucketName": ["recon-lab-data-jk-agentic-2026"],
      "key": [
        {
          "prefix": "incoming/"
        }
      ]
    }
  }
}
</code></pre>

</details>


|Target the Step Function recon-agentic-orchestrator|Role has `states:StartExecution` perms on state machine ARN|
|-|-|
|<img width="1459" height="808" alt="image" src="https://github.com/user-attachments/assets/70d11bfa-f243-4472-9962-f4d30eb82ff8" />|<img width="1458" height="847" alt="image" src="https://github.com/user-attachments/assets/4b01f871-5bfe-45e9-891e-b11dcc77dac7" />|

### Setting up CloudTrail
|recon-lab-cloudtrail|Data Events|
|-|-|
|<img width="1894" height="724" alt="image" src="https://github.com/user-attachments/assets/60b707fc-b7c2-4b3f-a239-10b7d2575440" />|<img width="1857" height="681" alt="image" src="https://github.com/user-attachments/assets/5e731f64-b295-43d1-8859-675457f34a15" />|
- Data event type - S3
- Object-level API activity - Write(Leave Read unchecked(Write triggers on uploads))
### Testing Event Bridge Trigger
- Upload a file to S3 Bucket folder `incoming/EventBridge-Test.csv`

|`incoming/EventBridge-Test.csv`|CloudTrial Event History|EventBridge rule invocations|Step Functions `recon-agentic-orchestrator` executed|
|-|-|-|-|
|<img width="1894" height="745" alt="image" src="https://github.com/user-attachments/assets/a842b5ea-997e-48ef-a422-ff271696b5be" />|<img width="1918" height="741" alt="image" src="https://github.com/user-attachments/assets/8880bcf5-8169-4dea-a189-7f4e87f047c6" />|<img width="1918" height="1078" alt="image" src="https://github.com/user-attachments/assets/fafb703a-fd43-4196-96b8-a246933b4a4b" />|<img width="1893" height="913" alt="image" src="https://github.com/user-attachments/assets/b46eb419-dc9a-480e-8b29-75453ee77594" />|

## Simple API/UI Integration (API Gateway + Lambda)
- Created `get_exceptions` Lambda
	- used previous role: `lambda-recon-lab-role`

<details>
<summary><strong>Lambda – get_exceptions code (click to expand)</strong></summary>

<pre><code class="language-python">
import json

def lambda_handler(event, context):
    # TODO implement
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
import os
import json
import logging
import boto3
from boto3.dynamodb.conditions import Key, Attr
from datetime import datetime, timezone

logger = logging.getLogger()
logger.setLevel(logging.INFO)

ddb = boto3.resource("dynamodb")


def _env(name: str, default: str | None = None) -> str:
    v = os.environ.get(name, default)
    if v is None or str(v).strip() == "":
        raise ValueError(f"Missing required environment variable: {name}")
    return v.strip()


def _to_int(s: str, default: int) -> int:
    try:
        return int(s)
    except Exception:
        return default


def _cors_headers():
    # Even if you enable CORS in API Gateway HTTP API, returning these headers
    # makes local tests and some tooling smoother.
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
        "Content-Type": "application/json",
    }


def lambda_handler(event, context):
    """
    Expects to be called by API Gateway HTTP API (proxy integration).
    Supports query params:
      - status=OPEN|RESOLVED|...
      - limit=1..200 (default 25)
      - exception_type=MISSING_IN_TARGET|AMOUNT_MISMATCH|DUPLICATE_IN_TARGET (optional)

    Returns: { items: [...], count: N }
    """
    table_name = _env("DDB_TABLE")
    table = ddb.Table(table_name)

    logger.info("Event: %s", json.dumps(event))

    # Handle preflight OPTIONS (usually API Gateway does this, but safe)
    if event.get("requestContext", {}).get("http", {}).get("method") == "OPTIONS":
        return {"statusCode": 204, "headers": _cors_headers(), "body": ""}

    params = event.get("queryStringParameters") or {}
    status = params.get("status")
    exception_type = params.get("exception_type")
    limit = _to_int(params.get("limit", "25"), 25)
    limit = max(1, min(limit, 200))  # clamp for safety

    # ---- Scan approach (simple, works without indexes) ----
    # For small lab datasets this is fine.
    filter_expr = None
    if status:
        filter_expr = Attr("status").eq(status)
    if exception_type:
        et_expr = Attr("exception_type").eq(exception_type)
        filter_expr = et_expr if filter_expr is None else (filter_expr & et_expr)

    scan_kwargs = {"Limit": limit}
    if filter_expr is not None:
        scan_kwargs["FilterExpression"] = filter_expr

    resp = table.scan(**scan_kwargs)
    items = resp.get("Items", [])

    # Sort newest first if created_at exists (best effort)
    def sort_key(x):
        return x.get("created_at", "")

    items.sort(key=sort_key, reverse=True)

    # Optionally, parse details_json from string into object for nicer UI
    for it in items:
        dj = it.get("details_json")
        if isinstance(dj, str):
            try:
                it["details"] = json.loads(dj)
            except Exception:
                it["details"] = {"raw_details_json": dj}

    body = {
        "count": len(items),
        "items": items,
        "next_token": resp.get("LastEvaluatedKey"),  # for pagination later
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    return {
        "statusCode": 200,
        "headers": _cors_headers(),
        "body": json.dumps(body, ensure_ascii=False),
    }
</code></pre>

</details>

- Environment Variable Configuration: add DynamoDB table as a value for the DDB_TABLE key
<img width="1623" height="709" alt="image" src="https://github.com/user-attachments/assets/fd89edd3-bd2b-4071-9e10-7783b37ef18c" />
### Test 
```
{
  "version": "2.0",
  "routeKey": "GET /exceptions",
  "rawPath": "/exceptions",
  "queryStringParameters": { "limit": "10" }
}
```
<img width="1617" height="1075" alt="image" src="https://github.com/user-attachments/assets/32b05e67-2c45-41f3-80fc-051cfbe16e95" />
Confirmed statusCode: 200 and a JSON body containing count and items were returned

### Created the API Gateway
- Build a HTTP API
	- integrate the `get_exceptions` Lambda
	- Configure routes:
    1. Add route:
        - Method: `GET`
        - Path: `/exceptions`
        - Integration: `get_exceptions`
    2. (Optional but useful for browsers) add an OPTIONS route:
        - Method: `OPTIONS`
        - Path: `/exceptions`
        	- HTTP API can handle CORS without this, but adding CORS in the API is cleaner
           <img width="551" height="296" alt="image" src="https://github.com/user-attachments/assets/bb7e27e6-72ec-48eb-9af6-fbf197126f6a" />
		   My UI calls an HTTP API. The API Gateway route GET /exceptions integrates with a Lambda called get_exceptions , which reads DynamoDB and returns JSON

|Turn on CORS|Test Endpoint `prod/exeption`|
|-|-|
|Angular UI can call it<img width="1639" height="482" alt="image" src="https://github.com/user-attachments/assets/abf26137-c2e2-460f-b5b3-a38aed6a2ef7" />|<img width="1275" height="1393" alt="image" src="https://github.com/user-attachments/assets/ee73b745-d8dd-4be4-8cdf-a16ce0bdb95f" />|

## Observability with CloudWatch + X-Ray
Each Lambda need AWS Tracing enabled
|`get_exceptions`|`run_recon_and_write_exceptions`|`ai_triage_exceptions`|
|-|-|-|
|<img width="1609" height="1079" alt="image" src="https://github.com/user-attachments/assets/89ce67ee-9021-45d6-ac6a-c8ca52425ec9" />|<img width="1606" height="1089" alt="image" src="https://github.com/user-attachments/assets/e7fad1bb-4bf1-4c93-9f0c-901885de5bee" />|<img width="1609" height="1092" alt="image" src="https://github.com/user-attachments/assets/10d149e6-7291-4bf1-8155-c22ae67b8097" />|



