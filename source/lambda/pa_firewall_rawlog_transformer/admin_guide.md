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

### Adding a New Data Type for Loading Data from S3 to OpenSearch

This section guides the administrator through the steps to add a new data type for loading data from S3 to OpenSearch.

#### Configuration in `aws.ini`
The `aws.ini` file is used in the `es_loader` Lambda function to configure the ingestion of data from S3 into OpenSearch. To define a new data type, update the `aws.ini` file by adding a new section. The example below demonstrates how to configure a data type named `pa_firewall_system`:

```ini
[pa_firewall_system]
index_name = log-aws-pa-firewall-system
s3_key = PA_SYSTEM
file_format = csv
timestamp_key = generated_time
csv_delimiter = ,
timestamp_format = %Y/%m/%d %H:%M:%S

ecs = 
    type
    content_threat_type
    event_id
    object
    module
    severity
    description
    sequence_number

# Mapping CSV Columns to ECS Fields
receive_time = receive_time
identifiers.serial = serial_number
type = type
content_threat_type = content_threat_type
future_use_1 = future_use_1
generated_time = generated_time
```

##### Explanation of Configuration Fields:
1. **`index_name`**: Defines the index name in OpenSearch (e.g., `log-aws-pa-firewall-system`).
2. **`s3_key`**: Specifies the folder in the S3 bucket where the data is stored (e.g., `PA_SYSTEM`).
3. **`file_format`**: The format of the file in S3, which can be `csv`, `json`, `text`, or `multiline`.
4. **`timestamp_key`**: Specifies the key to be used as the timestamp (e.g., `generated_time`).
5. **`csv_delimiter`**: Defines the delimiter used in CSV files (e.g., `,`).
6. **`timestamp_format`**: The format of the timestamp in the file (e.g., `%Y/%m/%d %H:%M:%S`).

##### ECS Fields:
The `ecs` section defines the schema in OpenSearch. Each entry represents a field that will be indexed. For example, the `type`, `content_threat_type`, and `event_id` fields are included in the OpenSearch schema.

##### Mapping CSV Columns to ECS Fields:
The mapping section aligns the CSV columns to the ECS fields defined in OpenSearch. For example:
- `receive_time` (CSV column) maps to `receive_time` (ECS field).
- `identifiers.serial` (ECS field) maps to `serial_number` (CSV column).

#### Example: `pa_firewall_decryption`
Here is a complete example of a data type configuration for `pa_firewall_decryption`:

```ini
[pa_firewall_decryption]
index_name = log-aws-pa-firewall-decryption
s3_key = PA_DECRYPTION
file_format = csv
timestamp_key = generated_time
csv_delimiter = ,
timestamp_format = %Y/%m/%d %H:%M:%S

ecs = 
    receive_time
    serial_number
    type
    threat_content_type
    config_version
    generate_time
    source.address
    destination.address
    nat.source.ip
    nat.destination.ip
    rule
    user.src.username
    user.dst.username
    application.name
    virtual_system
    source.zone
    destination.zone
    network.inbound.interface
    network.outbound.interface
    log.action
    time_logged
    session.id
    session.repeat_count

# Mapping CSV Columns to ECS Fields
receive_time = receive_time
serial_number = serial_number
type = type
threat_content_type = threat_content_type
config_version = config_version
generate_time = generate_time
source.address = source_address
destination.address = destination_address
nat.source.ip = nat_source_ip
nat.destination.ip = nat_destination_ip
rule = rule
user.src.username = source_user
user.dst.username = destination_user
application.name = application
```

#### Setting the Index Template for OpenSearch
To ensure the data ingested into OpenSearch conforms to specific types, set up an index template. The index template defines the settings and mappings for the data. Below is an example of setting an index template for `log-aws-pa-firewall-threat-data`:

```json
PUT _component_template/component_template_log-aws-pa-firewall-threat-data
{
  "template": {
    "settings": {
      "index.refresh_interval": "2s",
      "index.mapping.ignore_malformed": true,
      "index.max_docvalue_fields_search": 200,
      "index.number_of_shards": 3
    },
    "mappings": {
      "properties": {
        "receive_time": {
          "type": "keyword"
        },
        "serial_number": {
          "type": "keyword"
        },
        "type": {
          "type": "keyword"
        },
        "threat_content_type": {
          "type": "keyword"
        },
        "future_use_1": {
          "type": "keyword"
        },
        "generated_time": {
          "type": "date",
          "format": "yyyy/MM/dd HH:mm:ss"
        },
        "source": {
          "properties": {
            "address": {
              "type": "keyword"
            },
            "port": {
              "type": "integer"
            },
            "ip": {
              "type": "ip"
            }
          }
        }
      }
    }
  }
}

PUT _index_template/log-aws-pa-firewall-threat-data
{
  "index_patterns": ["log-aws-pa-firewall-threat-data-*"],
  "priority": 2,
  "composed_of": [
    "component_template_log",
    "component_template_log-aws",
    "component_template_log-aws-pa-firewall-threat-data"
  ],
  "_meta": {"description": "Provided by AWS. Do not edit"},
  "version": 2
}
```

##### Explanation of Index Template:
1. **Component Template**: The `component_template_log-aws-pa-firewall-threat-data` defines the settings and mappings for the data.
   - **Settings**: Includes properties such as `index.refresh_interval` and `index.mapping.ignore_malformed`.
   - **Mappings**: Specifies the data types for fields (e.g., `keyword`, `date`, `integer`).
2. **Index Template**: The `log-aws-pa-firewall-threat-data` template applies these settings and mappings to indices matching the pattern `log-aws-pa-firewall-threat-data-*`.

#### Creating Index Patterns for OpenSearch Dashboards
After setting the index template in OpenSearch, the user must create index patterns in OpenSearch Dashboards to enable the dashboard to use the index. This can be managed through the OpenSearch Dashboards interface at:

```
{host_name}/_dashboards/app/management/opensearch-dashboards/indexPatterns
```

##### Steps to Create Index Patterns:
1. Navigate to the above URL in your browser.
2. Click on **Create Index Pattern**.
3. Enter the index pattern (e.g., `log-aws-pa-firewall-threat-data-*`).
4. Specify the **Time Field** (e.g., `generated_time`) if applicable.
5. Save the index pattern.

Once the index pattern is created, it can be used to build visualizations and dashboards in OpenSearch Dashboards.

#### Important Notes:
- Ensure the index template is created before ingesting data.
- Modify the `settings` and `mappings` as needed for specific use cases.
- Use descriptive names for component templates to maintain clarity.
- Index patterns are essential for visualizations and must be set up correctly for seamless dashboard integration.

This process ensures that data ingested into OpenSearch is correctly structured, searchable, and available for visualization.

