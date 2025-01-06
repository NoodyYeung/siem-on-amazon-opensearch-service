# Lambda Function Overview

This section provides an overview of the Lambda function `hkg-hkma-sys-log-nonprd-vpc01-pa-firewall-rawlog-transformer` within the "hkg-hkma-sys-log-nonprd" landing zone.

## Functionality

The Lambda function is designed to process log files uploaded to the S3 bucket `hkg-hkma-sys-log-nonprd-syslog-bucket-558454069898`. Upon detecting a new file upload, the function is triggered to parse and transform the log data. The primary objective is to split multiple log types within each row record into individual log entries, categorized by specific log types. The categories include SYSTEM, THREAT_URL, THREAT_OTHERSE, TRAFFIC, DECRYPTION, CONFIG, and AUTHENTICATION.

## Workflow

1. **Event Trigger:**
   - The Lambda function is invoked by an S3 event whenever a new file is uploaded to the `hkg-hkma-sys-log-nonprd-syslog-bucket-558454069898` bucket.

2. **Log File Retrieval:**
   - The function retrieves the uploaded log file from the S3 bucket.
   - It reads the content of the file and processes each log entry.

3. **Log Processing:**
   - The function splits the log data into individual log entries based on predefined categories.
   - Each log entry is categorized into one of the following types: SYSTEM, THREAT_URL, THREAT_OTHERSE, TRAFFIC, DECRYPTION, CONFIG, and AUTHENTICATION.

4. **Data Transformation:**
   - The function transforms the log entries into a structured format suitable for further analysis.
   - Each log entry is grouped by its respective category.

5. **Data Storage:**
   - The processed and categorized log entries are stored in the destination S3 bucket `hkg-hkma-sys-log-nonprd-pa-firewall-bucket-558454069898`.

## Log Categories

- **SYSTEM:** Logs related to system events.
- **THREAT_URL:** Logs related to URL-based threats.
- **THREAT_OTHERSE:** Logs related to other types of threats.
- **TRAFFIC:** Logs related to network traffic.
- **DECRYPTION:** Logs related to decryption events.
- **CONFIG:** Logs related to configuration changes.
- **AUTHENTICATION:** Logs related to authentication events.

The Lambda function ensures that each log entry is accurately categorized and stored, facilitating efficient log analysis and monitoring.