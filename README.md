# 🔐 Tamper-Evident Logging System

A Python-based tamper-evident logging system that ensures the integrity of logs by chaining each entry using cryptographic hashing (SHA-256 or optional HMAC-SHA-256). The system is designed to detect any unauthorized modification, deletion, or insertion of log entries by maintaining a secure hash chain similar to blockchain principles.

This tool provides a complete pipeline for ingesting logs from multiple formats, normalizing them into structured JSON, and securely chaining them into an append-only log file. It is useful for cybersecurity auditing, forensic analysis, secure logging systems, and demonstrating integrity verification mechanisms.

The system works in two main stages. First, it converts raw logs from different formats such as .txt, .csv, or .json into a normalized NDJSON (newline-delimited JSON) format. Each line in this intermediate file contains a clean and structured event and associated data. Second, the normalized data is imported into the tamper-evident log where each entry is cryptographically linked to the previous one using a hash. This ensures that any modification to even a single entry breaks the entire chain and can be detected.

Each log entry contains a timestamp, event type, data payload, previous hash, and current hash. The first entry starts with a genesis hash, and every subsequent entry depends on the integrity of the previous one. Optionally, an HMAC-based secret key can be used to strengthen the integrity guarantees and prevent unauthorized recomputation of hashes.

The system supports parsing real-world log formats automatically. For plain text logs, it detects common patterns such as HTTP access logs, syslog entries, ISO timestamp logs, and Windows-style logs. CSV files are converted using headers, with automatic type conversion for numeric fields. JSON files are supported both as arrays and newline-delimited formats. If a line cannot be parsed, it is safely stored as raw data without breaking the pipeline.

To install and run the project, no external dependencies are required since it uses only Python standard libraries. Simply run the script using Python 3.

Basic usage starts with converting a raw log file into normalized JSON:
python tamper_evident_log.py convert server.log.txt

This creates a normalized file (e.g., server.log_normalized.json) where each line is a structured JSON record. You can then import this file into the tamper-evident log:
python tamper_evident_log.py import server.log_normalized.json

For convenience, both steps can be executed in a single command:
python tamper_evident_log.py ingest server.log.txt

This will automatically convert and chain all entries into the log file (default: tamper_evident.log).

You can also manually add entries:
python tamper_evident_log.py add USER_LOGIN '{"user":"alice"}'

To verify the integrity of the log chain:
python tamper_evident_log.py verify

For detailed verification output:
python tamper_evident_log.py verify --verbose

To display all stored log entries:
python tamper_evident_log.py show

A tampering simulation feature is included for demonstration purposes:
python tamper_evident_log.py tamper 2 '{"user":"mallory"}'

After tampering, running verification will detect inconsistencies and highlight the first corrupted entry along with all affected entries in the chain.

The system also supports HMAC-based hashing for stronger security. This prevents attackers from recomputing hashes even if they modify the log:
python tamper_evident_log.py ingest logs.json --secret mykey
python tamper_evident_log.py verify --secret mykey

All logs are stored in a file called tamper_evident.log by default. Each entry includes its own hash and the hash of the previous entry, forming a continuous chain. If any entry is modified, the verification process will detect a mismatch and report the exact location where tampering occurred.

Example log entry:
{"timestamp":"2026-04-08T12:00:00Z","event":"USER_LOGIN","data":{"user":"alice"},"prev_hash":"000...","hash":"abc123..."}

Example verification result:

* Chain intact → all entries are valid
* Tampered → system identifies first corrupted entry and marks subsequent entries as affected

This project is useful for demonstrating secure logging concepts such as integrity verification, log chaining, forensic analysis, and attack detection. It can be extended to integrate with SIEM systems, monitoring dashboards, or cloud-based logging pipelines.

This tool is intended for educational purposes, cybersecurity experimentation, and demonstrating tamper-evident mechanisms. It should not be used as a replacement for production-grade logging systems without further enhancements such as encryption, access control, and distributed storage.

Author: Taher Musaji

If you find this project useful, consider using it in your cybersecurity portfolio or extending it with features like real-time monitoring, alerting systems, or visualization dashboards.
