# PII Redaction Gateway — Detailed Flowcharts

## 1. Overall System Flow

```mermaid
sequenceDiagram
    participant Z as Zendesk
    participant AG as API Gateway
    participant L as Lambda
    participant RD as Regex Detector
    participant LD as LLM Detector
    participant R as Redactor
    participant ZA as Zendesk API
    participant S3 as S3 Audit
    participant CW as CloudWatch

    Z->>AG: POST /webhook (ticket solved)
    AG->>L: Invoke Lambda
    L->>L: Verify authentication
    alt Auth failed
        L-->>AG: 401 Unauthorized
    end
    L->>L: Parse payload
    L->>L: Check status = "solved"
    alt Not solved
        L-->>AG: 200 Skipped (not_solved)
    end
    L->>L: Check "pii-redacted" tag
    alt Already redacted
        L-->>AG: 200 Skipped (already_redacted)
    end
    L->>ZA: Fetch all ticket comments
    ZA-->>L: Comments list
    L->>RD: Detect PII (regex patterns)
    RD-->>L: Regex entities
    L->>LD: Detect PII (LLM contextual)
    LD-->>L: LLM entities
    L->>L: Merge & deduplicate
    L->>R: Apply redaction
    R-->>L: Redacted text
    alt PII found
        L->>ZA: Update ticket + add tag
        ZA-->>L: 200 OK
    end
    L->>S3: Write audit log (metadata only)
    L->>CW: Structured logs
    L-->>AG: 200 Processed
    AG-->>Z: Response
```

## 2. Regex Detection Pipeline

```mermaid
graph TD
    A[Input Text] --> B[Regex Detector]
    B --> C{For each pattern}
    C --> D[SSN Pattern<br/>Prefix Validation]
    C --> E[Credit Card Pattern<br/>Luhn Algorithm]
    C --> F[Email Pattern]
    C --> G[Phone Pattern<br/>Digit Count Check]
    C --> H[Password Pattern<br/>Keyword Proximity]
    C --> I[PHI Patterns<br/>MRN / DOB / ICD-10]
    C --> J[Address Pattern<br/>Street + ZIP]

    D --> K{Validator<br/>Passes?}
    E --> K
    F --> K
    G --> K
    H --> K
    I --> K
    J --> K

    K -->|Yes| L[Create PIIEntity<br/>type, start, end, confidence]
    K -->|No| M[Discard Match]

    L --> N[Deduplicate<br/>Overlapping Entities]
    N --> O[Return Entity List]
```

## 3. LLM Detection Pipeline

```mermaid
graph TD
    A[Input Text] --> B{Text Length<br/>> 12000 chars?}
    B -->|Yes| C[Chunk Text<br/>at Sentence Boundaries]
    B -->|No| D[Single Chunk]

    C --> E[Process Each Chunk]
    D --> E

    E --> F[Try Primary Provider]
    F --> G{Success?}
    G -->|Yes| H[Parse JSON Response]
    G -->|No| I[Try Fallback Provider]

    I --> J{Success?}
    J -->|Yes| H
    J -->|No| K[Try Third Provider]

    K --> L{Success?}
    L -->|Yes| H
    L -->|No| M[Return Empty<br/>Log Warning]

    H --> N{Confidence<br/>>= Threshold?}
    N -->|Yes| O[Map to PIIEntity<br/>Find Text Offsets]
    N -->|No| P[Filter Out]

    O --> Q[Normalize Type Names]
    Q --> R[Return Entity List]
```

## 4. Entity Merge Algorithm

```mermaid
graph TD
    A[Regex Entities] --> C[Combine Lists]
    B[LLM Entities] --> C

    C --> D[Sort by Start Position<br/>then by Confidence DESC]
    D --> E[Initialize Result<br/>with First Entity]

    E --> F{Next Entity}
    F --> G{Overlaps with<br/>Last in Result?}

    G -->|Yes| H[Merge:<br/>Expand Span<br/>Keep Higher Confidence<br/>Keep Better Type]
    G -->|No| I[Append to Result]

    H --> F
    I --> F

    F -->|No More| J[Return Merged List]
```

## 5. Redaction Process

```mermaid
graph TD
    A[Original Text +<br/>Merged Entities] --> B[Sort Entities<br/>by Start Position]
    B --> C[Merge Overlapping<br/>Entities]
    C --> D[Reverse Order<br/>Process End to Start]

    D --> E{For Each Entity}
    E --> F{Redaction Style?}

    F -->|Bracket| G["Replace with<br/>[REDACTED-TYPE]"]
    F -->|Mask| H[Replace with<br/>****]

    G --> I[Update Text]
    H --> I

    I --> E
    E -->|Done| J[Return RedactionResult<br/>redacted_text + metadata]
```

## 6. Audit Log Flow

```mermaid
graph TD
    A[Redaction Complete] --> B[Build Audit Record]
    B --> C[ticket_id + timestamp +<br/>request_id]
    B --> D[For Each Entity:<br/>pii_type, field,<br/>detection_method, confidence]
    B --> E[total_redactions +<br/>llm_provider + processing_ms]

    C --> F[Audit Record JSON]
    D --> F
    E --> F

    F --> G[Generate S3 Key<br/>audit/YYYY/MM/DD/<br/>ticket_timestamp_requestid.json]
    G --> H[S3 PutObject<br/>AES-256 Encryption]

    H --> I{Success?}
    I -->|Yes| J[Log: Audit Written]
    I -->|No| K[Log Error<br/>Pipeline Continues]

    style D fill:#ff9,stroke:#333
    style F fill:#9f9,stroke:#333
```

## 7. S3 Audit Lifecycle

```mermaid
graph LR
    A[New Audit Log<br/>S3 Standard] -->|30 days| B[S3 Glacier<br/>Archival Storage]
    B -->|90 days from creation| C[Expired<br/>Auto-Deleted]

    style A fill:#4da6ff,color:#fff
    style B fill:#6699cc,color:#fff
    style C fill:#cc6666,color:#fff
```
