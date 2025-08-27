# AWS S3 Lambda + Nintex Xtension — Setup and Information

This guide explains how to use our **AWS S3 Lambda API** together with a **Nintex Workflow (NW) Xtension** to upload, download, list, and manage files in Amazon S3.

**TL;DR**  
• Endpoint host: **&lt;your-function-id&gt;.lambda-url.&lt;region&gt;.on.aws** (Lambda Function URL)  
• Base path: **/**  
• Auth: **HTTP Basic** — **Username = AWS Access Key ID**, **Password = AWS Secret Access Key**  
• Default region: **us-east-2** (override per-call with region)  
• Max upload size: **50 MB** by default (configurable)  
• Buckets allowed: controlled by ALLOWED_BUCKETS env var (comma-separated)

## 1) Architecture Overview

Nintex Workflow → Xtension (Swagger) → Lambda Function URL → AWS SDK v3 → Amazon S3

- **Xtension** defines the actions visible in Nintex Workflow.  

- **Lambda** receives HTTPS requests, authenticates via Basic Auth (AWS key/secret), and calls **Amazon S3** using the AWS SDK for JavaScript v3 (When using the AWS SDK for JavaScript v3 client libraries (e.g., @aws-sdk/client-s3, @aws-sdk/client-dynamodb), the SDK automatically handles the SigV4 signing process for you.).  

- Responses are normalized JSON so you can map fields to Nintex Workflow variables easily.

## 2) Deploy & Configure the Lambda Function

### 2.1 Runtime & Dependencies

- Runtime: **Node.js 18.x+**
- Bundled AWS SDK v3 clients: @aws-sdk/client-s3, @aws-sdk/s3-request-presigner

### 2.2 Environment variables

| Name | Purpose | Default |
| --- | --- | --- |
| DEFAULT_REGION | Region used if a request doesn’t include region | us-east-2 |
| ALLOWED_BUCKETS | Comma-separated allowlist of bucket names. Empty = allow all | _(empty)_ |
| MAX_FILE_SIZE | Max upload size (bytes) validated for /amazon-s3-upload | 52428800 (50MB) |
| ENABLE_LOGGING | Set to true to log request metadata | false |
| ENCRYPTION_TYPE | S3 SSE option for writes | AES256 |
| PRESIGNED_URL_EXPIRY | Seconds for presigned URLs (if used) | 3600 |
| RATE_LIMIT_ENABLED | Enables in-memory per-key rate limiting | false |
| RATE_LIMIT_REQUESTS | Requests allowed in window | 100 |
| RATE_LIMIT_WINDOW | Window in ms | 60000 |

**Note:** If ALLOWED_BUCKETS is set, any request to other buckets returns a validation error. This is useful for tenant isolation.

### 2.3 Function URL

- Create a **Function URL** for the Lambda (Auth type: **NONE**).  

- The Lambda itself authenticates calls via the **Authorization** header (HTTP Basic) and then signs S3 requests with those credentials.

### 2.4 CORS

The Lambda responds with permissive CORS headers (Access-Control-Allow-Origin: \*). This covers Nintex Workflow calls. If you later use presigned URLs from a browser, configure **bucket CORS** appropriately (e.g., allow GET/PUT/HEAD and expose ETag).

## 3) Authentication

All requests require an Authorization header with **Basic** credentials:  
\- **Username:** AWS **Access Key ID**  
\- **Password:** AWS **Secret Access Key**

The Lambda validates the format and uses these credentials to create the S3 client for the call.

## 4) Supported Actions (exposed in the Xtension)

These are the 10 actions available in Nintex Workflow. Each action is a **POST** to the path shown.

1. **Amazon S3 Upload** — /amazon-s3-upload
2. **Create Bucket** — /create-bucket
3. **Create Folder** — /create-folder
4. **Create Object** — /create-object
5. **Delete File** — /delete-file
6. **Delete Folder** — /delete-folder
7. **Get Object** — /get-object
8. **List Buckets** — /list-buckets
9. **List Files** — /list-files
10. **List Folder Contents** — /list-folder-contents

The Lambda also supports additional endpoints (e.g., batch delete, copy object, presigned URL, object exists). These are **not** included in the default Xtension, but can be added later if desired.

## 5) Request & Response Cheatsheet

**Terminology**: In S3, a _file_ is an **object**. The **object key** (often called _file key_) is the full name within the bucket, e.g., invoices/2025/08/report.pdf.

### 5.1 Upload a file

**Path:** /amazon-s3-upload  
**Body:**

{  
"bucketName": "&lt;bucket&gt;",  
"fileName": "&lt;object-key&gt;",  
"fileContent": "&lt;base64-bytes&gt;",  
"contentType": "application/pdf",  
"metadata": {"docId": "123"},  
"tags": {"env": "prod"},  
"region": "us-east-2"  
}

**Notes** - fileContent must be **base64**. The Lambda validates size and blocks certain extensions (.exe, .bat, etc.). - The object is written with server-side encryption (AES256 by default).

**Success (200) excerpt:**

{  
"message": "File uploaded successfully",  
"fileUrl": "https://&lt;bucket&gt;.s3.&lt;region&gt;.amazonaws.com/&lt;object-key&gt;",  
"fileName": "&lt;object-key&gt;",  
"bucketName": "&lt;bucket&gt;",  
"fileSize": 12345,  
"etag": "\\"abc...\\"",  
"versionId": null,  
"uploadTimestamp": "2025-08-26T21:10:00.000Z"  
}

### 5.2 Create a bucket

**Path:** /create-bucket  
**Body:**

{  
"bucketName": "&lt;globally-unique-name&gt;",  
"region": "us-east-2"  
}

**Important** - S3 bucket names are **global**. If the name is already taken by any AWS account, S3 will return a 409 error.

### 5.3 Create a folder (prefix)

**Path:** /create-folder  
**Body:**

{  
"bucketName": "&lt;bucket&gt;",  
"folderName": "invoices/2025/"  
}

Creates a zero-byte object to represent the folder (invoices/2025/).

### 5.4 Create a small text object (no base64 required)

**Path:** /create-object  
**Body:**

{  
"bucketName": "&lt;bucket&gt;",  
"objectKey": "notes/info.txt",  
"content": "Hello, world!",  
"encoding": "utf8",  
"contentType": "text/plain"  
}

### 5.5 Delete a single file

**Path:** /delete-file  
**Body:**

{  
"bucketName": "&lt;bucket&gt;",  
"fileName": "invoices/2025/08/report.pdf"  
}

### 5.6 Delete a folder (and optionally its contents)

**Path:** /delete-folder  
**Body:**

{  
"bucketName": "&lt;bucket&gt;",  
"folderName": "invoices/2025/",  
"force": true  
}

- With force=false, deletion fails if the folder contains other objects.

### 5.7 Get object (content or presigned URL)

**Path:** /get-object  
**Body (content):**

{  
"bucketName": "&lt;bucket&gt;",  
"objectKey": "invoices/2025/08/report.pdf",  
"encoding": "base64"  
}

**Body (URL):**

{  
"bucketName": "&lt;bucket&gt;",  
"objectKey": "invoices/2025/08/report.pdf",  
"downloadUrl": true  
}

### 5.8 List buckets

**Path:** /list-buckets  
**Body:** {} (optional {"region":"us-east-2"})

### 5.9 List files (optionally by prefix)

**Path:** /list-files  
**Body:**

{  
"bucketName": "&lt;bucket&gt;",  
"prefix": "invoices/2025/",  
"maxKeys": 1000  
}

### 5.10 List folder contents (folders + files)

**Path:** /list-folder-contents  
**Body:**

{  
"bucketName": "&lt;bucket&gt;",  
"folderPath": "invoices/2025/",  
"includeSubfolders": false  
}

## 6) Setting up the Xtension in Nintex

1. **Import the Swagger** (provided).
    - host = **&lt;your-function-id&gt;.lambda-url.&lt;region&gt;.on.aws**  

    - basePath = **/**  

    - schemes = \["https"\]
2. Create a **Connection**: Auth type **Basic**.
    - **Username:** AWS Access Key ID  

    - **Password:** AWS Secret Access Key
3. Add actions to a workflow. For file uploads from a Form:
    - Use **Loop for each** over the file control collection.  

    - In **Amazon S3 Upload**:
        - **File Content (Base64)** = Loop for each → Current item  

        - **File Name/Key** = Loop for each → Current item file name  

    - Optionally prefix keys, e.g., uploads/{Instance ID}/{Current item file name}.

**Nintex Workflow Guardrail**: If you see **“Not allowed to execute the request for non permitted hosts.”** the action is bound to an Xtension whose host doesn’t match this Lambda URL. Re-add the action from the correct Xtension/connection.

## 7) IAM Permissions

Grant the Access Key used by Nintex Workflow the minimum required S3 permissions. Example (restrict to a specific bucket):

{  
"Version": "2012-10-17",  
"Statement": \[  
{ "Effect": "Allow", "Action": \["s3:ListAllMyBuckets"\], "Resource": "\*" },  
{ "Effect": "Allow", "Action": \["s3:ListBucket"\], "Resource": \["arn:aws:s3:::&lt;bucket&gt;"\] },  
{ "Effect": "Allow", "Action": \["s3:GetObject","s3:PutObject","s3:DeleteObject","s3:DeleteObjects","s3:CopyObject"\], "Resource": \["arn:aws:s3:::&lt;bucket&gt;/\*"\] }  
\]  
}

For cross-bucket copy: grant s3:GetObject on the **source** bucket and s3:PutObject on the **destination** bucket.

## 8) Validation & Limits

- **File name validation** blocks path traversal and disallowed extensions.  

- **Size validation** rejects payloads over MAX_FILE_SIZE.  

- **Allowlist** (ALLOWED_BUCKETS) rejects requests to any other bucket.  

- **Rate limit** (optional) enforces RATE_LIMIT_REQUESTS / RATE_LIMIT_WINDOW by Access Key.

## 9) Error Handling

The API normalizes common failures:

| Scenario | Error code | Message |
| --- | --- | --- |
| Wrong/missing Basic Auth | AUTHENTICATION_ERROR | Missing or invalid Authorization header |
| Invalid bucket per allowlist | VALIDATION_ERROR | Access to bucket &lt;name&gt; is not allowed |
| Key not found | OBJECT_NOT_FOUND | Object not found |
| Bucket not found | BUCKET_NOT_FOUND | Bucket not found |
| Insufficient IAM permissions | ACCESS_DENIED | Access denied – insufficient permissions |
| Name taken globally | BUCKET_EXISTS | Bucket already exists |
| File too large | FILE_TOO_LARGE | File size exceeds maximum allowed |
| Too many requests | RATE_LIMITED | Too many requests – please slow down |

Tip: If you just deleted a bucket, its name may not be reusable immediately. S3 bucket names are **global**.

## 10) Frequently Asked Questions

**Q: What’s a “file key”?**  
A: The full object name within the bucket, e.g., invoices/2025/08/report.pdf.

**Q: Are “files” and “objects” different?**  
A: In S3, a “file” **is** an **object**. “Folders” are just **prefixes**.

**Q: Can we return a direct download link?**  
A: Yes. Call **Get Object** with {"downloadUrl": true} to receive a presigned URL.

**Q: Upload fails but other actions work in Nintex Workflow. Why?**  
A: The Upload card is likely bound to a different Xtension/connection (host mismatch). Re-add it from the correct Xtension.

**Q: Do we need CORS?**  
A: Nintex Workflow → Lambda does not require bucket CORS. If browsers use presigned URLs directly to S3, configure bucket CORS to allow your origin.
