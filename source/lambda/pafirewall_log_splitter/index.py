import json
import logging
import os
import re
import sys
import time
import urllib.parse
import warnings
from functools import lru_cache, wraps
import csv
import pandas as pd
import io

import boto3

logging.basicConfig(level=logging.INFO)

BUCKET_DESTINATION = os.environ["BUCKET_DESTINATION"]


LOG_PATHS_PREFIXS = {
    "BUCKET_SYSTEM": "PA_SYSTEM",
    "BUCKET_THREAT_URL": "PA_THREAT_URL",
    "BUCKET_THREAT_DATA": "PA_THREAT_DATA",
    "BUCKET_THREAT_OTHERS": "PA_THREAT_OTHERST",
    "BUCKET_TRAFFIC": "PA_TRAFFIC",
    "BUCKET_DECRYPTION": "PA_DECRYPTION",
    "BUCKET_CONFIG": "PA_CONFIG",
    "BUCKET_AUTHENTICATION": "PA_AUTHENTICATION"
}


def lambda_handler(event, context):
    # Log the received event
    print("[INFO] Received event: %s" % json.dumps(event))

    # Process each record in the event
    for record in event['Records']:
        # Get the S3 bucket and object key from the event
        bucket = record['s3']['bucket']['name']
        key = urllib.parse.unquote_plus(record['s3']['object']['key'])
        # The key example is hkg-hkg-hkma-sys-net-nonprd-kinesis-firehose-cloudwatch01-3-2024-10-17-14-32-34-082a082a-cb38-47ff-95f7-76d0b5ce3259
        name_prefix = key.split("/")[-1].split('-kinesis')[0]
        uuid = key.split('-')[-5:]
        uuid = '-'.join(uuid)
        
        try:
            # Get the log file from S3
            s3_client = boto3.client('s3')
            response = s3_client.get_object(Bucket=bucket, Key=key)
            content = response['Body'].read().decode('utf-8')
            decoder = json.JSONDecoder()
            pos = 0
            groups = {}
            while pos < len(content):
                obj, pos = decoder.raw_decode(content, pos)
                # Process the log data
                _groups = process_log_data(json.dumps(obj))

                # Upload the processed log data to S3
                # The path formatting is: {bucket_path}/{year}/{month}/{day}/{hour}/{NAME_PREFIX}-{log_type}-{year}-{month}-{day}-{hour}-{minute}-{second}-{uuid}.csv
                for key, val in _groups.items():
                    if key not in groups:
                        groups[key] = []
                    groups[key].extend(val)
            
            print("groups" ,groups)
            for bucket_name, prefix in LOG_PATHS_PREFIXS.items():
                if groups.get(bucket_name):
                    dfs = groups[bucket_name]
                    # Get the current time
                    current_time = time.gmtime()
                    year = current_time.tm_year
                    month = current_time.tm_mon
                    day = current_time.tm_mday
                    hour = current_time.tm_hour

                    # Create the path for the processed log data
                    s3_path = f"{prefix}/{year}/{month}/{day}/{hour}/{name_prefix}-{bucket_name}-{year}-{month}-{day}-{hour}-{uuid}.csv"
                    tmp_path = f"/tmp/{name_prefix}-{bucket_name}-{year}-{month}-{day}-{hour}-{uuid}.csv"
                    
                    # Concat the DataFrames
                    if (len(dfs) == 0):
                        continue
                    for i in dfs: 
                        print("type of i ", type(i))
                    df = pd.concat(dfs)
                    # Write the DataFrame to a temporary CSV file
                    df.to_csv(tmp_path, index=False)
                    # Upload the CSV file to S3
                    s3_client.upload_file(tmp_path, BUCKET_DESTINATION, s3_path)
                    
                    print("[INFO] Uploaded processed log data to S3: %s" % s3_path)
                    
        except json.JSONDecodeError as e:
            print("[ERROR] JSON decoding error: %s" % e)
        except Exception as e:
            print("[ERROR] Error processing log file from S3: %s" % e)
            raise e

def process_log_data(log_data):
    # Split the log data into individual log entries
    log_entries = log_data.split('\n')
    groups = {
        "BUCKET_SYSTEM": [],
        "BUCKET_THREAT_URL": [],
        "BUCKET_THREAT_DATA": [],
        "BUCKET_THREAT_OTHERS": [],
        "BUCKET_TRAFFIC": [],
        "BUCKET_DECRYPTION": [],
        "BUCKET_CONFIG": [],
        "BUCKET_AUTHENTICATION": []
    }
    for entry in log_entries:
        if entry:
            try:
                print("Entry:" , entry)
                log_json = json.loads(entry)
                for log_event in log_json.get('logEvents', []):
                    message = log_event.get('message', '')
                    if 'SYSTEM' in message:
                        df = process_system_log(message)
                        print("[INFO] Processed system log DataFrame: %s" % df)
                        groups["BUCKET_SYSTEM"].append(df)
                        
                    elif 'TRAFFIC' in message:
                        df = process_traffic_log(message)
                        print("[INFO] Processed traffic log DataFrame: %s" % df)
                        groups["BUCKET_TRAFFIC"].append(df)
                    elif 'THREAT' in message:
                        # Check if subtype is 'url'
                        if ',url,' in message.lower():
                            df = process_url_filtering_log(message)
                            print("[INFO] Processed URL filtering log DataFrame: %s" % df)
                            groups["BUCKET_THREAT_URL"].append(df)
                        elif ',data,' in message.lower() or ',dlp,' in message.lower() or ',file,' in message.lower():
                            # Handle data filtering logs
                            df = process_data_filtering_log(message)
                            print("[INFO] Processed data filtering log DataFrame: %s" % df)
                            groups["BUCKET_THREAT_DATA"].append(df)
                        else:
                            df = process_threat_log(message)
                            print("[INFO] Processed threat log DataFrame: %s" % df)
                            groups["BUCKET_THREAT_OTHERS"].append(df)
                    elif 'DECRYPTION' in message:
                        df = process_decryption_log(message)
                        print("[INFO] Processed decryption log DataFrame: %s" % df)
                        groups["BUCKET_DECRYPTION"].append(df)
                    elif "CONFIG" in message:
                        df = process_config_log(message)
                        print("[INFO] Processed config log DataFrame: %s" % df)
                        groups["BUCKET_CONFIG"].append(df)
                    elif 'AUTHENTICATION' in message:
                        df = process_authentication_log(message)
                        print("[INFO] Processed authentication log DataFrame: %s" % df)
                        groups["BUCKET_AUTHENTICATION"].append(df)
                    else:
                        logging.warning("Unknown log type: %s", message)
            except json.JSONDecodeError as e:
                print("[ERROR] Error decoding JSON: %s" % e)


                
    return groups


def process_system_log(message):
    """
    Processes system log CSV data and returns a pandas DataFrame with appropriately mapped ECS fields.
    
    Parameters:
    - message (str): A string containing CSV-formatted system log data.
    
    Returns:
    - pd.DataFrame: A DataFrame containing the processed system log data.
    """
    
    # Define the new columns list with snake_case naming and FUTURE_USE fields appropriately renamed
    columns = [
        "receive_time",
        "serial_number",
        "type",
        "content_threat_type",
        "future_use_1",
        "generated_time",
        "virtual_system",
        "event_id",
        "object",
        "future_use_2",
        "future_use_3",
        "module",
        "severity",
        "description",
        "sequence_number",
        "action_flags",
        "device_group_hierarchy_level_1",
        "device_group_hierarchy_level_2",
        "device_group_hierarchy_level_3",
        "device_group_hierarchy_level_4",
        "virtual_system_name",
        "device_name",
        "future_use_4",
        "future_use_5",
        "high_resolution_timestamp"
    ]
    
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), delimiter=',', quotechar='"')
    
    # Initialize a list to hold all system logs
    system_logs = []
    
    for fields in csv_reader:
        # Skip empty lines
        if not fields or all(field.strip() == "" for field in fields):
            continue
        
        # Build the system_log dictionary by mapping ECS fields to CSV fields
        system_log = {
            "receive_time": fields[0].strip(),
            "serial_number": fields[1].strip(),
            "type": fields[2].strip(),
            "content_threat_type": fields[3].strip(),
            "future_use_1": fields[4].strip(),
            "generated_time": fields[5].strip(),
            "virtual_system": fields[6].strip(),
            "event_id": fields[7].strip(),
            "object": fields[8].strip(),
            "future_use_2": fields[9].strip(),
            "future_use_3": fields[10].strip(),
            "module": fields[11].strip(),
            "severity": fields[12].strip(),
            "description": fields[13].strip(),
            "sequence_number": fields[14].strip(),
            "action_flags": fields[15].strip(),
            "device_group_hierarchy_level_1": fields[16].strip(),
            "device_group_hierarchy_level_2": fields[17].strip(),
            "device_group_hierarchy_level_3": fields[18].strip(),
            "device_group_hierarchy_level_4": fields[19].strip(),
            "virtual_system_name": fields[20].strip(),
            "device_name": fields[21].strip(),
            "future_use_4": fields[22].strip(),
            "future_use_5": fields[23].strip(),
            "high_resolution_timestamp": fields[24].strip()
        }
        
        system_logs.append(system_log)
    
    # Create a DataFrame from the list of system logs
    df = pd.DataFrame(system_logs, columns=columns)
    
    return df


def process_traffic_log(message):
    # Define the new columns list with snake_case naming and FUTURE_USE fields appropriately renamed
    columns = [
        "receive_time",
        "serial_number",
        "type",
        "threat_content_type",
        "future_use_1",
        "generated_time",
        "source_address",
        "destination_address",
        "nat_source_ip",
        "nat_destination_ip",
        "rule_name",
        "source_user",
        "destination_user",
        "application",
        "virtual_system",
        "source_zone",
        "destination_zone",
        "inbound_interface",
        "outbound_interface",
        "log_action",
        "future_use_2",
        "session_id",
        "repeat_count",
        "source_port",
        "destination_port",
        "nat_source_port",
        "nat_destination_port",
        "flags",
        "protocol",
        "action",
        "bytes",
        "bytes_sent",
        "bytes_received",
        "packets",
        "start_time",
        "elapsed_time",
        "category",
        "future_use_3",
        "sequence_number",
        "action_flags",
        "source_country",
        "destination_country",
        "future_use_4",
        "packets_sent",
        "packets_received",
        "session_end_reason",
        "device_group_hierarchy_level_1",
        "device_group_hierarchy_level_2",
        "device_group_hierarchy_level_3",
        "device_group_hierarchy_level_4",
        "virtual_system_name",
        "device_name",
        "action_source",
        "source_vm_uuid",
        "destination_vm_uuid",
        "tunnel_id_imsi",
        "monitor_tag_imei",
        "parent_session_id",
        "parent_start_time",
        "tunnel_type",
        "sctp_association_id",
        "sctp_chunks",
        "sctp_chunks_sent",
        "sctp_chunks_received",
        "rule_uuid",
        "http2_connection",
        "app_flap_count",
        "policy_id",
        "link_switches",
        "sd_wan_cluster",
        "sd_wan_device_type",
        "sd_wan_cluster_type",
        "sd_wan_site",
        "dynamic_user_group_name",
        "xff_address",
        "source_device_category",
        "source_device_profile",
        "source_device_model",
        "source_device_vendor",
        "source_device_os_family",
        "source_device_os_version",
        "source_hostname",
        "source_mac_address",
        "destination_device_category",
        "destination_device_profile",
        "destination_device_model",
        "destination_device_vendor",
        "destination_device_os_family",
        "destination_device_os_version",
        "destination_hostname",
        "destination_mac_address",
        "container_id",
        "pod_namespace",
        "pod_name",
        "source_external_dynamic_list",
        "destination_external_dynamic_list",
        "host_id",
        "serial_number_2",  # Renamed to avoid duplication
        "source_dynamic_address_group",
        "destination_dynamic_address_group",
        "session_owner",
        "high_resolution_timestamp",
        "a_slice_service_type",
        "a_slice_differentiator",
        "application_subcategory",
        "application_category",
        "application_technology",
        "application_risk",
        "application_characteristic",
        "application_container",
        "tunneled_application",
        "application_saas",
        "application_sanctioned_state",
        "offloaded"
    ]
    
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), lineterminator='')
    
    # Initialize a list to hold all traffic logs
    traffic_logs = []
    
    for fields in csv_reader:
        # Ensure that the number of fields matches the expected count
        
        traffic_log = {
            "receive_time": fields[0].strip(),
            "serial_number": fields[1].strip(),
            "type": fields[2].strip(),
            "threat_content_type": fields[3].strip(),
            "future_use_1": fields[4].strip(),
            "generated_time": fields[5].strip(),
            "source_address": fields[6].strip(),
            "destination_address": fields[7].strip(),
            "nat_source_ip": fields[8].strip(),
            "nat_destination_ip": fields[9].strip(),
            "rule_name": fields[10].strip(),
            "source_user": fields[11].strip(),
            "destination_user": fields[12].strip(),
            "application": fields[13].strip(),
            "virtual_system": fields[14].strip(),
            "source_zone": fields[15].strip(),
            "destination_zone": fields[16].strip(),
            "inbound_interface": fields[17].strip(),
            "outbound_interface": fields[18].strip(),
            "log_action": fields[19].strip(),
            "future_use_2": fields[20].strip(),
            "session_id": fields[21].strip(),
            "repeat_count": fields[22].strip(),
            "source_port": fields[23].strip(),
            "destination_port": fields[24].strip(),
            "nat_source_port": fields[25].strip(),
            "nat_destination_port": fields[26].strip(),
            "flags": fields[27].strip(),
            "protocol": fields[28].strip(),
            "action": fields[29].strip(),
            "bytes": fields[30].strip(),
            "bytes_sent": fields[31].strip(),
            "bytes_received": fields[32].strip(),
            "packets": fields[33].strip(),
            "start_time": fields[34].strip(),
            "elapsed_time": fields[35].strip(),
            "category": fields[36].strip(),
            "future_use_3": fields[37].strip(),
            "sequence_number": fields[38].strip(),
            "action_flags": fields[39].strip(),
            "source_country": fields[40].strip(),
            "destination_country": fields[41].strip(),
            "future_use_4": fields[42].strip(),
            "packets_sent": fields[43].strip(),
            "packets_received": fields[44].strip(),
            "session_end_reason": fields[45].strip(),
            "device_group_hierarchy_level_1": fields[46].strip(),
            "device_group_hierarchy_level_2": fields[47].strip(),
            "device_group_hierarchy_level_3": fields[48].strip(),
            "device_group_hierarchy_level_4": fields[49].strip(),
            "virtual_system_name": fields[50].strip(),
            "device_name": fields[51].strip(),
            "action_source": fields[52].strip(),
            "source_vm_uuid": fields[53].strip(),
            "destination_vm_uuid": fields[54].strip(),
            "tunnel_id_imsi": fields[55].strip(),
            "monitor_tag_imei": fields[56].strip(),
            "parent_session_id": fields[57].strip(),
            "parent_start_time": fields[58].strip(),
            "tunnel_type": fields[59].strip(),
            "sctp_association_id": fields[60].strip(),
            "sctp_chunks": fields[61].strip(),
            "sctp_chunks_sent": fields[62].strip(),
            "sctp_chunks_received": fields[63].strip(),
            "rule_uuid": fields[64].strip(),
            "http2_connection": fields[65].strip(),
            "app_flap_count": fields[66].strip(),
            "policy_id": fields[67].strip(),
            "link_switches": fields[68].strip(),
            "sd_wan_cluster": fields[69].strip(),
            "sd_wan_device_type": fields[70].strip(),
            "sd_wan_cluster_type": fields[71].strip(),
            "sd_wan_site": fields[72].strip(),
            "dynamic_user_group_name": fields[73].strip(),
            "xff_address": fields[74].strip(),
            "source_device_category": fields[75].strip(),
            "source_device_profile": fields[76].strip(),
            "source_device_model": fields[77].strip(),
            "source_device_vendor": fields[78].strip(),
            "source_device_os_family": fields[79].strip(),
            "source_device_os_version": fields[80].strip(),
            "source_hostname": fields[81].strip(),
            "source_mac_address": fields[82].strip(),
            "destination_device_category": fields[83].strip(),
            "destination_device_profile": fields[84].strip(),
            "destination_device_model": fields[85].strip(),
            "destination_device_vendor": fields[86].strip(),
            "destination_device_os_family": fields[87].strip(),
            "destination_device_os_version": fields[88].strip(),
            "destination_hostname": fields[89].strip(),
            "destination_mac_address": fields[90].strip(),
            "container_id": fields[91].strip(),
            "pod_namespace": fields[92].strip(),
            "pod_name": fields[93].strip(),
            "source_external_dynamic_list": fields[94].strip(),
            "destination_external_dynamic_list": fields[95].strip(),
            "host_id": fields[96].strip(),
            "serial_number_2": fields[97].strip(),  # Renamed to avoid duplication
            "source_dynamic_address_group": fields[98].strip(),
            "destination_dynamic_address_group": fields[99].strip(),
            "session_owner": fields[100].strip(),
            "high_resolution_timestamp": fields[101].strip(),
            "a_slice_service_type": fields[102].strip(),
            "a_slice_differentiator": fields[103].strip(),
            "application_subcategory": fields[104].strip(),
            "application_category": fields[105].strip(),
            "application_technology": fields[106].strip(),
            "application_risk": fields[107].strip(),
            "application_characteristic": fields[108].strip(),
            "application_container": fields[109].strip(),
            "tunneled_application": fields[110].strip() if len(fields) > 110 else "",
            "application_saas": fields[111].strip() if len(fields) > 111 else "",
            "application_sanctioned_state": fields[112].strip() if len(fields) > 112 else "",
            "offloaded": fields[113].strip() if len(fields) > 113 else ""
        }
        traffic_logs.append(traffic_log)
    
    # Create a DataFrame from the list of traffic logs
    df = pd.DataFrame(traffic_logs, columns=columns)
    return df


def process_threat_log(message):
    """
    Processes threat log CSV data and returns a pandas DataFrame with appropriately mapped fields.
    
    Parameters:
    - message (str): A string containing CSV-formatted threat log data.
    
    Returns:
    - pd.DataFrame: A DataFrame containing the processed threat log data.
    """
    
    # Define the new columns list with snake_case naming and FUTURE_USE fields appropriately renamed
    columns = [
        "receive_time",
        "serial_number",
        "type",
        "threat_content_type",
        "future_use_1",
        "generated_time",
        "source_address",
        "destination_address",
        "nat_source_ip",
        "nat_destination_ip",
        "rule_name",
        "source_user",
        "destination_user",
        "application",
        "virtual_system",
        "source_zone",
        "destination_zone",
        "inbound_interface",
        "outbound_interface",
        "log_action",
        "future_use_2",
        "session_id",
        "repeat_count",
        "source_port",
        "destination_port",
        "nat_source_port",
        "nat_destination_port",
        "flags",
        "ip_protocol",
        "action",
        "url_filename",
        "threat_id",
        "category",
        "severity",
        "direction",
        "sequence_number",
        "action_flags",
        "source_location",
        "destination_location",
        "future_use_3",
        "content_type",
        "pcap_id",
        "file_digest",
        "cloud",
        "url_index",
        "user_agent",
        "file_type",
        "x_forwarded_for",
        "referer",
        "sender",
        "subject",
        "recipient",
        "report_id",
        "device_group_hierarchy_level_1",
        "device_group_hierarchy_level_2",
        "device_group_hierarchy_level_3",
        "device_group_hierarchy_level_4",
        "virtual_system_name",
        "device_name",
        "future_use_4",
        "source_vm_uuid",
        "destination_vm_uuid",
        "http_method",
        "tunnel_id_imsi",
        "monitor_tag_imei",
        "parent_session_id",
        "parent_start_time",
        "tunnel_type",
        "threat_category",
        "content_version",
        "future_use_5",
        "sctp_association_id",
        "payload_protocol_id",
        "http_headers",
        "url_category_list",
        "rule_uuid",
        "http2_connection",
        "dynamic_user_group_name",
        "xff_address",
        "source_device_category",
        "source_device_profile",
        "source_device_model",
        "source_device_vendor",
        "source_device_os_family",
        "source_device_os_version",
        "source_hostname",
        "source_mac_address",
        "destination_device_category",
        "destination_device_profile",
        "destination_device_model",
        "destination_device_vendor",
        "destination_device_os_family",
        "destination_device_os_version",
        "destination_hostname",
        "destination_mac_address",
        "container_id",
        "pod_namespace",
        "pod_name",
        "source_external_dynamic_list",
        "destination_external_dynamic_list",
        "host_id",
        "serial_number_duplicate",  # Assuming "serialnumber" appears twice; adjust as needed
        "domain_edl",
        "source_dynamic_address_group",
        "destination_dynamic_address_group",
        "partial_hash",
        "high_resolution_timestamp",
        "reason",
        "justification",
        "slice_service_type",
        "application_subcategory",
        "application_category",
        "application_technology",
        "application_risk",
        "application_characteristic",
        "application_container",
        "tunneled_application",
        "application_saas",
        "application_sanctioned_state"
    ]
    
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), delimiter=',', quotechar='"')
    
    # Initialize a list to hold all threat logs
    threat_logs = []
    
    for fields in csv_reader:
        
        # Build the threat_log dictionary by mapping ECS fields to CSV fields
        threat_log = {
            "receive_time": fields[0].strip(),
            "serial_number": fields[1].strip(),
            "type": fields[2].strip(),
            "threat_content_type": fields[3].strip(),
            "future_use_1": fields[4].strip(),
            "generated_time": fields[5].strip(),
            "source_address": fields[6].strip(),
            "destination_address": fields[7].strip(),
            "nat_source_ip": fields[8].strip(),
            "nat_destination_ip": fields[9].strip(),
            "rule_name": fields[10].strip(),
            "source_user": fields[11].strip(),
            "destination_user": fields[12].strip(),
            "application": fields[13].strip(),
            "virtual_system": fields[14].strip(),
            "source_zone": fields[15].strip(),
            "destination_zone": fields[16].strip(),
            "inbound_interface": fields[17].strip(),
            "outbound_interface": fields[18].strip(),
            "log_action": fields[19].strip(),
            "future_use_2": fields[20].strip(),
            "session_id": fields[21].strip(),
            "repeat_count": fields[22].strip(),
            "source_port": fields[23].strip(),
            "destination_port": fields[24].strip(),
            "nat_source_port": fields[25].strip(),
            "nat_destination_port": fields[26].strip(),
            "flags": fields[27].strip(),
            "ip_protocol": fields[28].strip(),
            "action": fields[29].strip(),
            "url_filename": fields[30].strip(),
            "threat_id": fields[31].strip(),
            "category": fields[32].strip(),
            "severity": fields[33].strip(),
            "direction": fields[34].strip(),
            "sequence_number": fields[35].strip(),
            "action_flags": fields[36].strip(),
            "source_location": fields[37].strip(),
            "destination_location": fields[38].strip(),
            "future_use_3": fields[39].strip(),
            "content_type": fields[40].strip(),
            "pcap_id": fields[41].strip(),
            "file_digest": fields[42].strip(),
            "cloud": fields[43].strip(),
            "url_index": fields[44].strip(),
            "user_agent": fields[45].strip(),
            "file_type": fields[46].strip(),
            "x_forwarded_for": fields[47].strip(),
            "referer": fields[48].strip(),
            "sender": fields[49].strip(),
            "subject": fields[50].strip(),
            "recipient": fields[51].strip(),
            "report_id": fields[52].strip(),
            "device_group_hierarchy_level_1": fields[53].strip(),
            "device_group_hierarchy_level_2": fields[54].strip(),
            "device_group_hierarchy_level_3": fields[55].strip(),
            "device_group_hierarchy_level_4": fields[56].strip(),
            "virtual_system_name": fields[57].strip(),
            "device_name": fields[58].strip(),
            "future_use_4": fields[59].strip(),
            "source_vm_uuid": fields[60].strip(),
            "destination_vm_uuid": fields[61].strip(),
            "http_method": fields[62].strip(),
            "tunnel_id_imsi": fields[63].strip(),
            "monitor_tag_imei": fields[64].strip(),
            "parent_session_id": fields[65].strip(),
            "parent_start_time": fields[66].strip(),
            "tunnel_type": fields[67].strip(),
            "threat_category": fields[68].strip(),
            "content_version": fields[69].strip(),
            "future_use_5": fields[70].strip(),
            "sctp_association_id": fields[71].strip(),
            "payload_protocol_id": fields[72].strip(),
            "http_headers": fields[73].strip(),
            "url_category_list": fields[74].strip(),
            "rule_uuid": fields[75].strip(),
            "http2_connection": fields[76].strip(),
            "dynamic_user_group_name": fields[77].strip(),
            "xff_address": fields[78].strip(),
            "source_device_category": fields[79].strip(),
            "source_device_profile": fields[80].strip(),
            "source_device_model": fields[81].strip(),
            "source_device_vendor": fields[82].strip(),
            "source_device_os_family": fields[83].strip(),
            "source_device_os_version": fields[84].strip(),
            "source_hostname": fields[85].strip(),
            "source_mac_address": fields[86].strip(),
            "destination_device_category": fields[87].strip(),
            "destination_device_profile": fields[88].strip(),
            "destination_device_model": fields[89].strip(),
            "destination_device_vendor": fields[90].strip(),
            "destination_device_os_family": fields[91].strip(),
            "destination_device_os_version": fields[92].strip(),
            "destination_hostname": fields[93].strip(),
            "destination_mac_address": fields[94].strip(),
            "container_id": fields[95].strip(),
            "pod_namespace": fields[96].strip(),
            "pod_name": fields[97].strip(),
            "source_external_dynamic_list": fields[98].strip(),
            "destination_external_dynamic_list": fields[99].strip(),
            "host_id": fields[100].strip(),
            "serial_number_duplicate": fields[101].strip(),  # Adjust if "serialnumber" appears twice
            "domain_edl": fields[102].strip(),
            "source_dynamic_address_group": fields[103].strip(),
            "destination_dynamic_address_group": fields[104].strip(),
            "partial_hash": fields[105].strip(),
            "high_resolution_timestamp": fields[106].strip(),
            "reason": fields[107].strip(),
            "justification": fields[108].strip(),
            "slice_service_type": fields[109].strip(),
            "application_subcategory": fields[110].strip(),
            "application_category": fields[111].strip(),
            "application_technology": fields[112].strip(),
            "application_risk": fields[113].strip(),
            "application_characteristic": fields[114].strip(),
            "application_container": fields[115].strip(),
            "tunneled_application": fields[116].strip(),
            "application_saas": fields[117].strip(),
            "application_sanctioned_state": fields[118].strip()
        }
        
        threat_logs.append(threat_log)
    
    # Define the DataFrame columns to ensure correct ordering
    df = pd.DataFrame(threat_logs, columns=columns)
    return df



def process_url_filtering_log(message):
    """
    Processes URL filtering log CSV data and returns a pandas DataFrame with appropriately mapped fields.
    
    Parameters:
    - message (str): A string containing CSV-formatted URL filtering log data.
    
    Returns:
    - pd.DataFrame: A DataFrame containing the processed URL filtering log data.
    """
    
    # Define the new columns list with correct mapping (no initial FUTURE_USE)
    columns = [
        "receive_time",
        "serial_number",
        "type",
        "threat_content_type",
        "future_use_1",
        "generated_time",
        "source_address",
        "destination_address",
        "nat_source_ip",
        "nat_destination_ip",
        "rule_name",
        "source_user",
        "destination_user",
        "application",
        "virtual_system",
        "source_zone",
        "destination_zone",
        "inbound_interface",
        "outbound_interface",
        "log_action",
        "future_use_2",
        "session_id",
        "repeat_count",
        "source_port",
        "destination_port",
        "nat_source_port",
        "nat_destination_port",
        "flags",
        "ip_protocol",
        "action",
        "url_filename",
        "threat_id",
        "category",
        "severity",
        "direction",
        "sequence_number",
        "action_flags",
        "source_country",
        "destination_country",
        "future_use_3",
        "content_type",
        "pcap_id",
        "file_digest",
        "cloud",
        "url_index",
        "user_agent",
        "file_type",
        "x_forwarded_for",
        "referer",
        "sender",
        "subject",
        "recipient",
        "report_id",
        "device_group_hierarchy_level_1",
        "device_group_hierarchy_level_2",
        "device_group_hierarchy_level_3",
        "device_group_hierarchy_level_4",
        "virtual_system_name",
        "device_name",
        "future_use_4",
        "source_vm_uuid",
        "destination_vm_uuid",
        "http_method",
        "tunnel_id_imsi",
        "monitor_tag_imei",
        "parent_session_id",
        "parent_start_time",
        "tunnel_type",
        "threat_category",
        "content_version",
        "future_use_5",
        "sctp_association_id",
        "payload_protocol_id",
        "http_headers",
        "url_category_list",
        "rule_uuid",
        "http2_connection",
        "dynamic_user_group_name",
        "xff_address",
        "source_device_category",
        "source_device_profile",
        "source_device_model",
        "source_device_vendor",
        "source_device_os_family",
        "source_device_os_version",
        "source_hostname",
        "source_mac_address",
        "destination_device_category",
        "destination_device_profile",
        "destination_device_model",
        "destination_device_vendor",
        "destination_device_os_family",
        "destination_device_os_version",
        "destination_hostname",
        "destination_mac_address",
        "container_id",
        "pod_namespace",
        "pod_name",
        "source_external_dynamic_list",
        "destination_external_dynamic_list",
        "host_id",
        "serial_number_duplicate",
        "domain_edl",
        "source_dynamic_address_group",
        "destination_dynamic_address_group",
        "partial_hash",
        "high_resolution_timestamp",
        "reason",
        "justification",
        "slice_service_type",
        "application_subcategory",
        "application_category",
        "application_technology",
        "application_risk",
        "application_characteristic",
        "application_container",
        "tunneled_application",
        "application_saas",
        "application_sanctioned_state"
    ]
    
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), delimiter=',', quotechar='"')
    
    # Initialize a list to hold all URL filtering logs
    url_filtering_logs = []
    
    for fields in csv_reader:        
        # Build the url_filtering_log dictionary by mapping ECS fields to CSV fields
        url_filtering_log = {columns[i]: fields[i].strip() for i in range(len(fields))}
        url_filtering_logs.append(url_filtering_log)
    
    # Define the DataFrame columns to ensure correct ordering
    df = pd.DataFrame(url_filtering_logs, columns=columns)
    
    return df




def process_data_filtering_log(message):
    """
    Processes data filtering log CSV data and returns a pandas DataFrame with appropriately mapped fields.
    
    Parameters:
    - message (str): A string containing CSV-formatted data filtering log data.
    
    Returns:
    - pd.DataFrame: A DataFrame containing the processed data filtering log data.
    """
    
    # Define the new columns list based on the provided structure
    columns = [
        "receive_time",
        "serial_number",
        "type",
        "threat_content_type",
        "future_use_1",
        "generated_time",
        "source_address",
        "destination_address",
        "nat_source_ip",
        "nat_destination_ip",
        "rule_name",
        "source_user",
        "destination_user",
        "application",
        "virtual_system",
        "source_zone",
        "destination_zone",
        "inbound_interface",
        "outbound_interface",
        "log_action",
        "future_use_2",
        "session_id",
        "repeat_count",
        "source_port",
        "destination_port",
        "nat_source_port",
        "nat_destination_port",
        "flags",
        "ip_protocol",
        "action",
        "url_filename",
        "threat_id",
        "category",
        "severity",
        "direction",
        "sequence_number",
        "action_flags",
        "source_country",
        "destination_country",
        "future_use_3",
        "content_type",
        "pcap_id",
        "file_digest",
        "cloud",
        "url_index",
        "user_agent",
        "file_type",
        "x_forwarded_for",
        "referer",
        "sender",
        "subject",
        "recipient",
        "report_id",
        "device_group_hierarchy_level_1",
        "device_group_hierarchy_level_2",
        "device_group_hierarchy_level_3",
        "device_group_hierarchy_level_4",
        "virtual_system_name",
        "device_name",
        "future_use_4",
        "source_vm_uuid",
        "destination_vm_uuid",
        "http_method",
        "tunnel_id_imsi",
        "monitor_tag_imei",
        "parent_session_id",
        "parent_start_time",
        "tunnel_type",
        "threat_category",
        "content_version",
        "future_use_5",
        "sctp_association_id",
        "payload_protocol_id",
        "http_headers",
        "url_category_list",
        "rule_uuid",
        "http2_connection",
        "dynamic_user_group_name",
        "xff_address",
        "source_device_category",
        "source_device_profile",
        "source_device_model",
        "source_device_vendor",
        "source_device_os_family",
        "source_device_os_version",
        "source_hostname",
        "source_mac_address",
        "destination_device_category",
        "destination_device_profile",
        "destination_device_model",
        "destination_device_vendor",
        "destination_device_os_family",
        "destination_device_os_version",
        "destination_hostname",
        "destination_mac_address",
        "container_id",
        "pod_namespace",
        "pod_name",
        "source_external_dynamic_list",
        "destination_external_dynamic_list",
        "host_id",
        "serial_number_duplicate",
        "domain_edl",
        "source_dynamic_address_group",
        "destination_dynamic_address_group",
        "partial_hash",
        "high_resolution_timestamp",
        "reason",
        "justification",
        "slice_service_type",
        "application_subcategory",
        "application_category",
        "application_technology",
        "application_risk",
        "application_characteristic",
        "application_container",
        "tunneled_application",
        "application_saas",
        "application_sanctioned_state"
    ]
    
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), delimiter=',', quotechar='"')
    
    # Initialize a list to hold all data filtering logs
    data_filtering_logs = []
    
    for fields in csv_reader:
        # Skip empty lines
        if not fields or all(field.strip() == "" for field in fields):
            continue
        
        # Build the data_filtering_log dictionary by mapping ECS fields to CSV fields
        data_filtering_log = {columns[i]: fields[i].strip() for i in range(len(fields))}
        data_filtering_logs.append(data_filtering_log)
    
    # Define the DataFrame columns to ensure correct ordering
    df = pd.DataFrame(data_filtering_logs, columns=columns)
    
    return df



def process_decryption_log(message):
    """
    Processes decryption log CSV data and returns a pandas DataFrame with appropriately mapped fields.
    
    Parameters:
    - message (str): A string containing CSV-formatted decryption log data.
    
    Returns:
    - pd.DataFrame: A DataFrame containing the processed decryption log data.
    """
    
    # Define the updated columns based on the provided structure
    columns = [
        "receive_time",
        "serial_number",
        "type",
        "threat_content_type",
        "config_version",
        "generate_time",
        "source_address",
        "destination_address",
        "nat_source_ip",
        "nat_destination_ip",
        "rule",
        "source_user",
        "destination_user",
        "application",
        "virtual_system",
        "source_zone",
        "destination_zone",
        "inbound_interface",
        "outbound_interface",
        "log_action",
        "time_logged",
        "session_id",
        "repeat_count",
        "source_port",
        "destination_port",
        "nat_source_port",
        "nat_destination_port",
        "flags",
        "ip_protocol",
        "action",
        "tunnel",
        "future_use_1",
        "future_use_2",
        "source_vm_uuid",
        "destination_vm_uuid",
        "uuid_for_rule",
        "stage_client_to_firewall",
        "stage_firewall_to_server",
        "tls_version",
        "key_exchange_algorithm",
        "encryption_algorithm",
        "hash_algorithm",
        "policy_name",
        "elliptic_curve",
        "error_index",
        "root_status",
        "chain_status",
        "proxy_type",
        "certificate_serial_number",
        "fingerprint",
        "certificate_start_date",
        "certificate_end_date",
        "certificate_version",
        "certificate_size",
        "common_name_length",
        "issuer_common_name_length",
        "root_common_name_length",
        "sni_length",
        "certificate_flags",
        "subject_common_name",
        "issuer_subject_common_name",
        "root_subject_common_name",
        "server_name_indication",
        "error",
        "container_id",
        "pod_namespace",
        "pod_name",
        "source_external_dynamic_list",
        "destination_external_dynamic_list",
        "source_dynamic_address_group",
        "destination_dynamic_address_group",
        "high_res_timestamp",
        "source_device_category",
        "source_device_profile",
        "source_device_model",
        "source_device_vendor",
        "source_device_os_family",
        "source_device_os_version",
        "source_hostname",
        "source_mac_address",
        "destination_device_category",
        "destination_device_profile",
        "destination_device_model",
        "destination_device_vendor",
        "destination_device_os_family",
        "destination_device_os_version",
        "destination_hostname",
        "destination_mac_address",
        "sequence_number",
        "action_flags",
        "device_group_hierarchy_level_1",
        "device_group_hierarchy_level_2",
        "device_group_hierarchy_level_3",
        "device_group_hierarchy_level_4",
        "virtual_system_name",
        "device_name",
        "virtual_system_id",
        "application_subcategory",
        "application_category",
        "application_technology",
        "application_risk",
        "application_characteristic",
        "application_container",
        "application_saas",
        "application_sanctioned_state"
    ]
    
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), delimiter=',', quotechar='"')
    
    # Initialize a list to hold all decryption logs
    decryption_logs = []
    
    for fields in csv_reader:
        # Skip empty lines
        if not fields or all(field.strip() == "" for field in fields):
            continue
        
        # Build the decryption_log dictionary by mapping ECS fields to CSV fields
        decryption_log = {columns[i]: fields[i].strip() for i in range(len(fields))}
        decryption_logs.append(decryption_log)
    
    # Define the DataFrame columns to ensure correct ordering
    df = pd.DataFrame(decryption_logs, columns=columns)
    
    return df


def process_config_log(message):
    """
    Processes configuration log CSV data and returns a pandas DataFrame with appropriately mapped fields.
    
    Parameters:
    - message (str): A string containing CSV-formatted configuration log data.
    
    Returns:
    - pd.DataFrame: A DataFrame containing the processed configuration log data.
    """
    
    # Define the updated columns based on the provided structure
    columns = [
        "receive_time",
        "serial_number",
        "type",
        "subtype",
        "future_use_1",
        "generated_time",
        "host",
        "virtual_system",
        "command",
        "admin",
        "client",
        "result",
        "configuration_path",
        "before_change_detail",
        "after_change_detail",
        "sequence_number",
        "action_flags",
        "device_group_hierarchy_level_1",
        "device_group_hierarchy_level_2",
        "device_group_hierarchy_level_3",
        "device_group_hierarchy_level_4",
        "virtual_system_name",
        "device_name",
        "device_group",
        "audit_comment",
        "future_use_2",
        "high_resolution_timestamp"
    ]
    
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), delimiter=',', quotechar='"')
    
    # Initialize a list to hold all configuration logs
    config_logs = []
    
    for fields in csv_reader:
        # Skip empty lines
        if not fields or all(field.strip() == "" for field in fields):
            continue

        
        # Build the config_log dictionary by mapping ECS fields to CSV fields
        config_log = {columns[i]: fields[i].strip() for i in range(len(fields))}
        config_logs.append(config_log)
    
    # Create a DataFrame from the list of configuration logs
    df = pd.DataFrame(config_logs, columns=columns)
    
    return df



def process_authentication_log(message):
    """
    Processes authentication log CSV data and returns a pandas DataFrame with appropriately mapped fields.
    
    Parameters:
    - message (str): A string containing CSV-formatted authentication log data.
    
    Returns:
    - pd.DataFrame: A DataFrame containing the processed authentication log data.
    """
    
    # Define the updated columns based on the provided structure
    columns = [
        "receive_time",
        "serial_number",
        "type",
        "threat_content_type",
        "future_use_1",
        "generated_time",
        "virtual_system",
        "source_ip",
        "user",
        "normalize_user",
        "object",
        "authentication_policy",
        "repeat_count",
        "authentication_id",
        "vendor",
        "log_action",
        "server_profile",
        "description",
        "client_type",
        "event_type",
        "factor_number",
        "sequence_number",
        "action_flags",
        "device_group_hierarchy_1",
        "device_group_hierarchy_2",
        "device_group_hierarchy_3",
        "device_group_hierarchy_4",
        "virtual_system_name",
        "device_name",
        "virtual_system_id",
        "authentication_protocol",
        "uuid_for_rule",
        "high_resolution_timestamp",
        "source_device_category",
        "source_device_profile",
        "source_device_model",
        "source_device_vendor",
        "source_device_os_family",
        "source_device_os_version",
        "source_hostname",
        "source_mac_address",
        "region",
        "future_use_2",
        "user_agent",
        "session_id"
    ]
    
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), delimiter=',', quotechar='"')
    
    # Initialize a list to hold all authentication logs
    authentication_logs = []
    
    for fields in csv_reader:
        # Skip empty lines
        if not fields or all(field.strip() == "" for field in fields):
            continue
        
        # Build the authentication_log dictionary by mapping ECS fields to CSV fields
        authentication_log = {columns[i]: fields[i].strip() for i in range(len(fields))}
        authentication_logs.append(authentication_log)
    
    # Create a DataFrame from the list of authentication logs
    df = pd.DataFrame(authentication_logs, columns=columns)
    
    return df
