# go-sql-engine

A lightweight SQL security analysis engine that parses SQL statements with a full AST and detects dangerous or suspicious patterns via a JSON-driven rule set.

## Features

- **AST-based parsing** — uses [xwb1989/sqlparser](https://github.com/xwb1989/sqlparser) for accurate structural analysis rather than fragile regex matching
- **6 built-in detection rules** (R001–R006) covering data destruction, data exposure, and injection patterns
- **Bilingual responses** — rule names and descriptions in both Chinese (`zh`) and English (`en`)
- **JSON rule engine** — rules are defined in `rules.json` and embedded at compile time; easy to extend without changing Go code
- **Structured JSON API** — returns parsed statement metadata alongside any detected risks

## Detection Rules

| ID   | Severity | Category           | Description |
|------|----------|--------------------|-------------|
| R001 | high     | dangerous_operation | DELETE / UPDATE without WHERE clause — may cause massive data loss or corruption |
| R002 | high     | dangerous_operation | High-risk DDL: DROP / TRUNCATE — immediately destroys table structure or all data, typically irreversible |
| R003 | medium   | data_exposure       | SELECT * full-column query — may unintentionally expose sensitive fields (e.g. passwords, phone numbers) |
| R004 | medium   | data_exposure       | Large LIMIT value (>10,000) — suggests bulk data export, potential data exfiltration risk |
| R005 | high     | injection           | UNION-based injection pattern — common SQL injection technique to extract data from additional tables |
| R006 | medium   | injection           | Comment-based injection pattern — SQL comment characters (`--` or `/**/`) used to truncate original SQL logic |

## API

### `POST /check`

Analyze a SQL statement for security risks.

**Request**

```json
{
  "sql": "SELECT * FROM users",
  "locale": "en"
}
```

- `sql` — the SQL statement to analyze (max 5000 chars)
- `locale` — `"zh"` (default) or `"en"`

**Response — with risks**

```json
{
  "success": true,
  "parsedInfo": {
    "statementType": "SELECT",
    "tables": ["users"],
    "hasWhere": false,
    "hasLimit": false,
    "isSelectStar": true,
    "hasUnion": false
  },
  "risks": [
    {
      "ruleId": "R003",
      "name": "SELECT * full-column query",
      "severity": "medium",
      "description": "Querying all columns may unintentionally expose sensitive fields (e.g. passwords, phone numbers). Specify only the columns you need."
    }
  ]
}
```

**Response — clean SQL**

```json
{
  "success": true,
  "parsedInfo": {
    "statementType": "SELECT",
    "tables": ["orders"],
    "hasWhere": true,
    "hasLimit": true,
    "limitValue": 20,
    "isSelectStar": false,
    "hasUnion": false
  },
  "risks": []
}
```

**Response — parse error**

```json
{
  "success": false,
  "risks": [],
  "error": "SQL parse failed — please check your syntax"
}
```

### `GET /health`

Returns `200 OK` with body `ok`. Used for container health checks.

## Quick Start

### go run

```bash
git clone https://github.com/bingcs/go-sql-engine.git
cd go-sql-engine
go run .
# Listening on :8081
```

### make

```bash
make run        # go run .
make build      # builds to build/sql-engine
make build-linux  # cross-compile linux/amd64 + darwin/arm64
make vet        # go vet ./...
```

### Docker (optional)

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -o sql-engine .

FROM alpine:3.19
COPY --from=builder /app/sql-engine /usr/local/bin/
EXPOSE 8081
CMD ["sql-engine"]
```

```bash
docker build -t sql-engine .
docker run -p 8081:8081 sql-engine
```

## Usage on bingcs.com

This engine powers the interactive SQL Security Detector tool on [bingcs.com](https://bingcs.com). You can try it live in the browser without any setup.

Read the full write-up: [SQL Security Detector — How It Works](https://bingcs.com/blog/2026-03-28-sql-security-detector)

## Technical Implementation

- **Parser**: [xwb1989/sqlparser](https://github.com/xwb1989/sqlparser) — a Go port of the Vitess SQL parser supporting MySQL dialect
- **Embedded rules**: `rules.json` is compiled into the binary via Go's `//go:embed` directive — no external config files needed at runtime
- **AST traversal**: `extractTables` walks `Select`, `Union`, `Delete`, `Update`, and `DDL` nodes to extract referenced table names
- **Comment detection**: R006 runs a regex check on the *raw* SQL string before parsing, because the parser silently strips comments

## Future Plans

- Support for additional SQL dialects (PostgreSQL, SQLite)
- Hot-reload of rules without binary rebuild
- Rule severity overrides via environment variables
- Additional rules: privilege escalation (`GRANT`/`REVOKE`), stored procedure calls, subquery depth limits
- OpenTelemetry tracing support
