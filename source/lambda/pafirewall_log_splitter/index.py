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
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), lineterminator='')
    columns = ["receive_time", "serial", "type", "subtype", "time_generated", "vsys", "eventid", "object", "module", "severity", "opaque", "seqno", "actionflags", "dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4", "vsys_name", "device_name", "high_res_timestamp"]
    for fields in csv_reader:
        system_log = {
            "receive_time": fields[0].strip(),
            "serial": fields[1].strip(),
            "type": fields[2].strip(),
            "subtype": fields[3].strip(),
            "time_generated": fields[4].strip(),
            "vsys": fields[5].strip(),
            "eventid": fields[6].strip(),
            "object": fields[7].strip(),
            "module": fields[8].strip(),
            "severity": fields[9].strip(),
            "opaque": fields[10].strip(),
            "seqno": fields[11].strip(),
            "actionflags": fields[12].strip(),
            "dg_hier_level_1": fields[13].strip(),
            "dg_hier_level_2": fields[14].strip(),
            "dg_hier_level_3": fields[15].strip(),
            "dg_hier_level_4": fields[16].strip(),
            "vsys_name": fields[17].strip(),
            "device_name": fields[18].strip(),
            "high_res_timestamp": fields[19].strip()
        }
        df = pd.DataFrame([system_log], columns=columns)
        return df
import csv
import io
import pandas as pd

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
        if len(fields) < 110:
            # Handle missing fields by padding with empty strings
            fields += [''] * (110 - len(fields))
        elif len(fields) > 110:
            # If there are extra fields, trim them
            fields = fields[:110]
        
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
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), lineterminator='')
    columns = ["receive_time", "serial", "type", "subtype", "time_generated", "src", "dst", "natsrc", "natdst", "rule", "srcuser", "dstuser", "app", "vsys", "from", "to", "inbound_if", "outbound_if", "logset", "sessionid", "repeatcnt", "sport", "dport", "natsport", "natdport", "flags", "proto", "action", "misc", "threatid", "category", "severity", "direction", "seqno", "actionflags", "srcloc", "dstloc", "contenttype", "pcap_id", "filedigest", "cloud", "url_idx", "user_agent", "filetype", "xff", "referer", "sender", "subject", "recipient", "reportid", "dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4", "vsys_name", "device_name", "src_uuid", "dst_uuid", "http_method", "tunnel_id/imsi", "monitortag/imei", "parent_session_id", "parent_start_time", "tunnel", "thr_category", "contentver", "assoc_id", "ppid", "http_headers", "url_category_list", "rule_uuid", "http2_connection", "dynusergroup_name", "xff_ip", "src_category", "src_profile", "src_model", "src_vendor", "src_osfamily", "src_osversion", "src_host", "src_mac", "dst_category", "dst_profile", "dst_model", "dst_vendor", "dst_osfamily", "dst_osversion", "dst_host", "dst_mac", "container_id", "pod_namespace", "pod_name", "src_edl", "dst_edl", "hostid", "serialnumber", "domain_edl", "src_dag", "dst_dag", "partial_hash", "high_res_timestamp", "reason", "justification", "nssai_sst", "subcategory_of_app", "category_of_app", "technology_of_app", "risk_of_app", "characteristic_of_app", "container_of_app", "tunneled_app", "is_saas_of_app", "sanctioned_state_of_app"]
    for fields in csv_reader:
        threat_log = {
            "receive_time": fields[0].strip(),
            "serial": fields[1].strip(),
            "type": fields[2].strip(),
            "subtype": fields[3].strip(),
            "time_generated": fields[4].strip(),
            "src": fields[5].strip(),
            "dst": fields[6].strip(),
            "natsrc": fields[7].strip(),
            "natdst": fields[8].strip(),
            "rule": fields[9].strip(),
            "srcuser": fields[10].strip(),
            "dstuser": fields[11].strip(),
            "app": fields[12].strip(),
            "vsys": fields[13].strip(),
            "from": fields[14].strip(),
            "to": fields[15].strip(),
            "inbound_if": fields[16].strip(),
            "outbound_if": fields[17].strip(),
            "logset": fields[18].strip(),
            "sessionid": fields[19].strip(),
            "repeatcnt": fields[20].strip(),
            "sport": fields[21].strip(),
            "dport": fields[22].strip(),
            "natsport": fields[23].strip(),
            "natdport": fields[24].strip(),
            "flags": fields[25].strip(),
            "proto": fields[26].strip(),
            "action": fields[27].strip(),
            "misc": fields[28].strip(),
            "threatid": fields[29].strip(),
            "category": fields[30].strip(),
            "severity": fields[31].strip(),
            "direction": fields[32].strip(),
            "seqno": fields[33].strip(),
            "actionflags": fields[34].strip(),
            "srcloc": fields[35].strip(),
            "dstloc": fields[36].strip(),
            "contenttype": fields[37].strip(),
            "pcap_id": fields[38].strip(),
            "filedigest": fields[39].strip(),
            "cloud": fields[40].strip(),
            "url_idx": fields[41].strip(),
            "user_agent": fields[42].strip(),
            "filetype": fields[43].strip(),
            "xff": fields[44].strip(),
            "referer": fields[45].strip(),
            "sender": fields[46].strip(),
            "subject": fields[47].strip(),
            "recipient": fields[48].strip(),
            "reportid": fields[49].strip(),
            "dg_hier_level_1": fields[50].strip(),
            "dg_hier_level_2": fields[51].strip(),
            "dg_hier_level_3": fields[52].strip(),
            "dg_hier_level_4": fields[53].strip(),
            "vsys_name": fields[54].strip(),
            "device_name": fields[55].strip(),
            "src_uuid": fields[56].strip(),
            "dst_uuid": fields[57].strip(),
            "http_method": fields[58].strip(),
            "tunnel_id/imsi": fields[59].strip(),
            "monitortag/imei": fields[60].strip(),
            "parent_session_id": fields[61].strip(),
            "parent_start_time": fields[62].strip(),
            "tunnel": fields[63].strip(),
            "thr_category": fields[64].strip(),
            "contentver": fields[65].strip(),
            "assoc_id": fields[66].strip(),
            "ppid": fields[67].strip(),
            "http_headers": fields[68].strip(),
            "url_category_list": fields[69].strip(),
            "rule_uuid": fields[70].strip(),
            "http2_connection": fields[71].strip(),
            "dynusergroup_name": fields[72].strip(),
            "xff_ip": fields[73].strip(),
            "src_category": fields[74].strip(),
            "src_profile": fields[75].strip(),
            "src_model": fields[76].strip(),
            "src_vendor": fields[77].strip(),
            "src_osfamily": fields[78].strip(),
            "src_osversion": fields[79].strip(),
            "src_host": fields[80].strip(),
            "src_mac": fields[81].strip(),
            "dst_category": fields[82].strip(),
            "dst_profile": fields[83].strip(),
            "dst_model": fields[84].strip(),
            "dst_vendor": fields[85].strip(),
            "dst_osfamily": fields[86].strip(),
            "dst_osversion": fields[87].strip(),
            "dst_host": fields[88].strip(),
            "dst_mac": fields[89].strip(),
            "container_id": fields[90].strip(),
            "pod_namespace": fields[91].strip(),
            "pod_name": fields[92].strip(),
            "src_edl": fields[93].strip(),
            "dst_edl": fields[94].strip(),
            "hostid": fields[95].strip(),
            "serialnumber": fields[96].strip(),
            "domain_edl": fields[97].strip(),
            "src_dag": fields[98].strip(),
            "dst_dag": fields[99].strip(),
            "partial_hash": fields[100].strip(),
            "high_res_timestamp": fields[101].strip(),
            "reason": fields[102].strip(),
            "justification": fields[103].strip(),
            "nssai_sst": fields[104].strip(),
            "subcategory_of_app": fields[105].strip(),
            "category_of_app": fields[106].strip(),
            "technology_of_app": fields[107].strip(),
            "risk_of_app": fields[108].strip(),
            "characteristic_of_app": fields[109].strip(),
            "container_of_app": fields[110].strip(),
            "tunneled_app": fields[111].strip(),
            "is_saas_of_app": fields[112].strip(),
            "sanctioned_state_of_app": fields[113].strip()
        }
        df = pd.DataFrame([threat_log], columns=columns)
        return df

def process_url_filtering_log(message):
    csv_reader = csv.reader(io.StringIO(message), lineterminator='')
    columns = [
        "FUTURE_USE", "receive_time", "serial", "type", "subtype", "FUTURE_USE",
        "time_generated", "src", "dst", "natsrc", "natdst", "rule", "srcuser",
        "dstuser", "app", "vsys", "from", "to", "inbound_if", "outbound_if",
        "log_action", "FUTURE_USE", "sessionid", "repeatcnt", "sport", "dport",
        "natsport", "natdport", "flags", "proto", "action", "misc", "threatid",
        "category", "severity", "direction", "seqno", "actionflags", "srcloc",
        "dstloc", "contenttype", "pcap_id", "filedigest", "cloud", "url_idx",
        "user_agent", "filetype", "xff_ip", "referer", "sender", "subject",
        "recipient", "reportid", "dg_hier_level_1", "dg_hier_level_2",
        "dg_hier_level_3", "dg_hier_level_4", "vsys_name", "device_name",
        "FUTURE_USE", "src_uuid", "dst_uuid", "http_method",
        "tunnelid/imsi", "monitortag/imei", "parent_session_id",
        "parent_start_time", "tunnel", "thr_category", "contentver",
        "FUTURE_USE", "assoc_id", "ppid", "http_headers", "url_category_list",
        "rule_uuid", "http2_connection", "dynusergroup_name", "xff_ip",
        "src_category", "src_profile", "src_model", "src_vendor",
        "src_osfamily", "src_osversion", "src_host", "src_mac",
        "dst_category", "dst_profile", "dst_model", "dst_vendor",
        "dst_osfamily", "dst_osversion", "dst_host", "dst_mac",
        "container_id", "pod_namespace", "pod_name", "src_edl", "dst_edl",
        "hostid", "serialnumber", "domain_edl", "src_dag", "dst_dag",
        "partial_hash", "high_res_timestamp", "reason", "justification",
        "nssai_sst", "subcategory_of_app", "category_of_app",
        "technology_of_app", "risk_of_app", "characteristic_of_app",
        "container_of_app", "tunneled_app", "is_saas_of_app",
        "sanctioned_state_of_app"
    ]
    for fields in csv_reader:
        url_filtering_log = {
            "FUTURE_USE": fields[0].strip(),
            "receive_time": fields[1].strip(),
            "serial": fields[2].strip(),
            "type": fields[3].strip(),
            "subtype": fields[4].strip(),
            "FUTURE_USE": fields[5].strip(),
            "time_generated": fields[6].strip(),
            "src": fields[7].strip(),
            "dst": fields[8].strip(),
            "natsrc": fields[9].strip(),
            "natdst": fields[10].strip(),
            "rule": fields[11].strip(),
            "srcuser": fields[12].strip(),
            "dstuser": fields[13].strip(),
            "app": fields[14].strip(),
            "vsys": fields[15].strip(),
            "from": fields[16].strip(),
            "to": fields[17].strip(),
            "inbound_if": fields[18].strip(),
            "outbound_if": fields[19].strip(),
            "log_action": fields[20].strip(),
            "FUTURE_USE": fields[21].strip(),
            "sessionid": fields[22].strip(),
            "repeatcnt": fields[23].strip(),
            "sport": fields[24].strip(),
            "dport": fields[25].strip(),
            "natsport": fields[26].strip(),
            "natdport": fields[27].strip(),
            "flags": fields[28].strip(),
            "proto": fields[29].strip(),
            "action": fields[30].strip(),
            "misc": fields[31].strip(),
            "threatid": fields[32].strip(),
            "category": fields[33].strip(),
            "severity": fields[34].strip(),
            "direction": fields[35].strip(),
            "seqno": fields[36].strip(),
            "actionflags": fields[37].strip(),
            "srcloc": fields[38].strip(),
            "dstloc": fields[39].strip(),
            "contenttype": fields[40].strip(),
            "pcap_id": fields[41].strip(),
            "filedigest": fields[42].strip(),
            "cloud": fields[43].strip(),
            "url_idx": fields[44].strip(),
            "user_agent": fields[45].strip(),
            "filetype": fields[46].strip(),
            "xff_ip": fields[47].strip(),
            "referer": fields[48].strip(),
            "sender": fields[49].strip(),
            "subject": fields[50].strip(),
            "recipient": fields[51].strip(),
            "reportid": fields[52].strip(),
            "dg_hier_level_1": fields[53].strip(),
            "dg_hier_level_2": fields[54].strip(),
            "dg_hier_level_3": fields[55].strip(),
            "dg_hier_level_4": fields[56].strip(),
            "vsys_name": fields[57].strip(),
            "device_name": fields[58].strip(),
            "FUTURE_USE": fields[59].strip(),
            "src_uuid": fields[60].strip(),
            "dst_uuid": fields[61].strip(),
            "http_method": fields[62].strip(),
            "tunnelid/imsi": fields[63].strip(),
            "monitortag/imei": fields[64].strip(),
            "parent_session_id": fields[65].strip(),
            "parent_start_time": fields[66].strip(),
            "tunnel": fields[67].strip(),
            "thr_category": fields[68].strip(),
            "contentver": fields[69].strip(),
            "FUTURE_USE": fields[70].strip(),
            "assoc_id": fields[71].strip(),
            "ppid": fields[72].strip(),
            "http_headers": fields[73].strip(),
            "url_category_list": fields[74].strip(),
            "rule_uuid": fields[75].strip(),
            "http2_connection": fields[76].strip(),
            "dynusergroup_name": fields[77].strip(),
            "xff_ip": fields[78].strip(),
            "src_category": fields[79].strip(),
            "src_profile": fields[80].strip(),
            "src_model": fields[81].strip(),
            "src_vendor": fields[82].strip(),
            "src_osfamily": fields[83].strip(),
            "src_osversion": fields[84].strip(),
            "src_host": fields[85].strip(),
            "src_mac": fields[86].strip(),
            "dst_category": fields[87].strip(),
            "dst_profile": fields[88].strip(),
            "dst_model": fields[89].strip(),
            "dst_vendor": fields[90].strip(),
            "dst_osfamily": fields[91].strip(),
            "dst_osversion": fields[92].strip(),
            "dst_host": fields[93].strip(),
            "dst_mac": fields[94].strip(),
            "container_id": fields[95].strip(),
            "pod_namespace": fields[96].strip(),
            "pod_name": fields[97].strip(),
            "src_edl": fields[98].strip(),
            "dst_edl": fields[99].strip(),
            "hostid": fields[100].strip(),
            "serialnumber": fields[101].strip(),
            "domain_edl": fields[102].strip(),
            "src_dag": fields[103].strip(),
            "dst_dag": fields[104].strip(),
            "partial_hash": fields[105].strip(),
            "high_res_timestamp": fields[106].strip(),
            "reason": fields[107].strip(),
            "justification": fields[108].strip(),
            "nssai_sst": fields[109].strip(),
            "subcategory_of_app": fields[110].strip(),
            "category_of_app": fields[111].strip(),
            "technology_of_app": fields[112].strip(),
            "risk_of_app": fields[113].strip(),
            "characteristic_of_app": fields[114].strip(),
            "container_of_app": fields[115].strip(),
            "tunneled_app": fields[116].strip(),
            "is_saas_of_app": fields[117].strip(),
            "sanctioned_state_of_app": fields[118].strip()
        }
        df = pd.DataFrame([url_filtering_log], columns=columns)
        return df

def process_data_filtering_log(message):
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), lineterminator='')
    columns = [
        "receive_time", "serial", "type", "subtype", "time_generated", "src", "dst",
        "natsrc", "natdst", "rule", "srcuser", "dstuser", "app", "vsys", "from", "to",
        "inbound_if", "outbound_if", "logset", "sessionid", "repeatcnt", "sport",
        "dport", "natsport", "natdport", "flags", "proto", "action", "misc",
        "threatid", "category", "severity", "direction", "seqno", "actionflags",
        "srcloc", "dstloc", "contenttype", "pcap_id", "filedigest", "cloud",
        "url_idx", "user_agent", "filetype", "xff_ip", "referer", "sender",
        "subject", "recipient", "reportid", "dg_hier_level_1", "dg_hier_level_2",
        "dg_hier_level_3", "dg_hier_level_4", "vsys_name", "device_name",
        "src_uuid", "dst_uuid", "http_method", "tunnel_id/imsi",
        "monitortag/imei", "parent_session_id", "parent_start_time", "tunnel",
        "thr_category", "contentver", "assoc_id", "ppid", "http_headers",
        "url_category_list", "rule_uuid", "http2_connection", "dynusergroup_name",
        "xff_ip", "src_category", "src_profile", "src_model", "src_vendor",
        "src_osfamily", "src_osversion", "src_host", "src_mac", "dst_category",
        "dst_profile", "dst_model", "dst_vendor", "dst_osfamily", "dst_osversion",
        "dst_host", "dst_mac", "container_id", "pod_namespace", "pod_name",
        "src_edl", "dst_edl", "hostid", "serialnumber", "domain_edl", "src_dag",
        "dst_dag", "partial_hash", "high_res_timestamp", "reason",
        "justification", "nssai_sst", "subcategory_of_app", "category_of_app",
        "technology_of_app", "risk_of_app", "characteristic_of_app",
        "container_of_app", "tunneled_app", "is_saas_of_app",
        "sanctioned_state_of_app"
    ]
    for fields in csv_reader:
        data_filtering_log = {
            "receive_time": fields[0].strip(),
            "serial": fields[1].strip(),
            "type": fields[2].strip(),
            "subtype": fields[3].strip(),
            "time_generated": fields[4].strip(),
            "src": fields[5].strip(),
            "dst": fields[6].strip(),
            "natsrc": fields[7].strip(),
            "natdst": fields[8].strip(),
            "rule": fields[9].strip(),
            "srcuser": fields[10].strip(),
            "dstuser": fields[11].strip(),
            "app": fields[12].strip(),
            "vsys": fields[13].strip(),
            "from": fields[14].strip(),
            "to": fields[15].strip(),
            "inbound_if": fields[16].strip(),
            "outbound_if": fields[17].strip(),
            "logset": fields[18].strip(),
            "sessionid": fields[19].strip(),
            "repeatcnt": fields[20].strip(),
            "sport": fields[21].strip(),
            "dport": fields[22].strip(),
            "natsport": fields[23].strip(),
            "natdport": fields[24].strip(),
            "flags": fields[25].strip(),
            "proto": fields[26].strip(),
            "action": fields[27].strip(),
            "misc": fields[28].strip(),
            "threatid": fields[29].strip(),
            "category": fields[30].strip(),
            "severity": fields[31].strip(),
            "direction": fields[32].strip(),
            "seqno": fields[33].strip(),
            "actionflags": fields[34].strip(),
            "srcloc": fields[35].strip(),
            "dstloc": fields[36].strip(),
            "contenttype": fields[37].strip(),
            "pcap_id": fields[38].strip(),
            "filedigest": fields[39].strip(),
            "cloud": fields[40].strip(),
            "url_idx": fields[41].strip(),
            "user_agent": fields[42].strip(),
            "filetype": fields[43].strip(),
            "xff_ip": fields[44].strip(),
            "referer": fields[45].strip(),
            "sender": fields[46].strip(),
            "subject": fields[47].strip(),
            "recipient": fields[48].strip(),
            "reportid": fields[49].strip(),
            "dg_hier_level_1": fields[50].strip(),
            "dg_hier_level_2": fields[51].strip(),
            "dg_hier_level_3": fields[52].strip(),
            "dg_hier_level_4": fields[53].strip(),
            "vsys_name": fields[54].strip(),
            "device_name": fields[55].strip(),
            "src_uuid": fields[56].strip(),
            "dst_uuid": fields[57].strip(),
            "http_method": fields[58].strip(),
            "tunnel_id/imsi": fields[59].strip(),
            "monitortag/imei": fields[60].strip(),
            "parent_session_id": fields[61].strip(),
            "parent_start_time": fields[62].strip(),
            "tunnel": fields[63].strip(),
            "thr_category": fields[64].strip(),
            "contentver": fields[65].strip(),
            "assoc_id": fields[66].strip(),
            "ppid": fields[67].strip(),
            "http_headers": fields[68].strip(),
            "url_category_list": fields[69].strip(),
            "rule_uuid": fields[70].strip(),
            "http2_connection": fields[71].strip(),
            "dynusergroup_name": fields[72].strip(),
            "xff_ip": fields[73].strip(),
            "src_category": fields[74].strip(),
            "src_profile": fields[75].strip(),
            "src_model": fields[76].strip(),
            "src_vendor": fields[77].strip(),
            "src_osfamily": fields[78].strip(),
            "src_osversion": fields[79].strip(),
            "src_host": fields[80].strip(),
            "src_mac": fields[81].strip(),
            "dst_category": fields[82].strip(),
            "dst_profile": fields[83].strip(),
            "dst_model": fields[84].strip(),
            "dst_vendor": fields[85].strip(),
            "dst_osfamily": fields[86].strip(),
            "dst_osversion": fields[87].strip(),
            "dst_host": fields[88].strip(),
            "dst_mac": fields[89].strip(),
            "container_id": fields[90].strip(),
            "pod_namespace": fields[91].strip(),
            "pod_name": fields[92].strip(),
            "src_edl": fields[93].strip(),
            "dst_edl": fields[94].strip(),
            "hostid": fields[95].strip(),
            "serialnumber": fields[96].strip(),
            "domain_edl": fields[97].strip(),
            "src_dag": fields[98].strip(),
            "dst_dag": fields[99].strip(),
            "partial_hash": fields[100].strip(),
            "high_res_timestamp": fields[101].strip(),
            "reason": fields[102].strip(),
            "justification": fields[103].strip(),
            "nssai_sst": fields[104].strip(),
            "subcategory_of_app": fields[105].strip(),
            "category_of_app": fields[106].strip(),
            "technology_of_app": fields[107].strip(),
            "risk_of_app": fields[108].strip(),
            "characteristic_of_app": fields[109].strip(),
            "container_of_app": fields[110].strip(),
            "tunneled_app": fields[111].strip(),
            "is_saas_of_app": fields[112].strip(),
            "sanctioned_state_of_app": fields[113].strip()
        }
        df = pd.DataFrame([data_filtering_log], columns=columns)
        return df

def process_decryption_log(message):
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), lineterminator='')
    columns = [
        "receive_time", "serial", "type", "subtype", "config_ver", "time_generated",
        "src", "dst", "natsrc", "natdst", "rule", "srcuser", "dstuser", "app",
        "vsys", "from", "to", "inbound_if", "outbound_if", "logset", "time_logged",
        "sessionid", "repeatcnt", "sport", "dport", "natsport", "natdport", "flags",
        "proto", "action", "tunnel", "FUTURE_USE1", "FUTURE_USE2",
        "src_uuid", "dst_uuid", "rule_uuid", "hs_stage_c2f", "hs_stage_f2s",
        "tls_version", "tls_keyxchg", "tls_enc", "tls_auth", "policy_name",
        "ec_curve", "err_index", "root_status", "chain_status", "proxy_type",
        "cert_serial", "fingerprint", "notbefore", "notafter", "cert_ver",
        "cert_size", "cn_len", "issuer_len", "rootcn_len", "sni_len",
        "cert_flags", "cn", "issuer_cn", "root_cn", "sni", "error",
        "container_id", "pod_namespace", "pod_name", "src_edl", "dst_edl",
        "src_dag", "dst_dag", "high_res_timestamp", "src_category",
        "src_profile", "src_model", "src_vendor", "src_osfamily",
        "src_osversion", "src_host", "src_mac", "dst_category", "dst_profile",
        "dst_model", "dst_vendor", "dst_osfamily", "dst_osversion", "dst_host",
        "dst_mac", "seqno", "actionflags", "dg_hier_level_1", "dg_hier_level_2",
        "dg_hier_level_3", "dg_hier_level_4", "vsys_name", "device_name",
        "subcategory_of_app", "category_of_app", "technology_of_app",
        "risk_of_app", "characteristic_of_app", "container_of_app",
        "is_saas_of_app", "sanctioned_state_of_app"
    ]
    for fields in csv_reader:
        decryption_log = {
            "receive_time": fields[0].strip(),
            "serial": fields[1].strip(),
            "type": fields[2].strip(),
            "subtype": fields[3].strip(),
            "config_ver": fields[4].strip(),
            "time_generated": fields[5].strip(),
            "src": fields[6].strip(),
            "dst": fields[7].strip(),
            "natsrc": fields[8].strip(),
            "natdst": fields[9].strip(),
            "rule": fields[10].strip(),
            "srcuser": fields[11].strip(),
            "dstuser": fields[12].strip(),
            "app": fields[13].strip(),
            "vsys": fields[14].strip(),
            "from": fields[15].strip(),
            "to": fields[16].strip(),
            "inbound_if": fields[17].strip(),
            "outbound_if": fields[18].strip(),
            "logset": fields[19].strip(),
            "time_logged": fields[20].strip(),
            "sessionid": fields[21].strip(),
            "repeatcnt": fields[22].strip(),
            "sport": fields[23].strip(),
            "dport": fields[24].strip(),
            "natsport": fields[25].strip(),
            "natdport": fields[26].strip(),
            "flags": fields[27].strip(),
            "proto": fields[28].strip(),
            "action": fields[29].strip(),
            "tunnel": fields[30].strip(),
            "FUTURE_USE1": fields[31].strip(),
            "FUTURE_USE2": fields[32].strip(),
            "src_uuid": fields[33].strip(),
            "dst_uuid": fields[34].strip(),
            "rule_uuid": fields[35].strip(),
            "hs_stage_c2f": fields[36].strip(),
            "hs_stage_f2s": fields[37].strip(),
            "tls_version": fields[38].strip(),
            "tls_keyxchg": fields[39].strip(),
            "tls_enc": fields[40].strip(),
            "tls_auth": fields[41].strip(),
            "policy_name": fields[42].strip(),
            "ec_curve": fields[43].strip(),
            "err_index": fields[44].strip(),
            "root_status": fields[45].strip(),
            "chain_status": fields[46].strip(),
            "proxy_type": fields[47].strip(),
            "cert_serial": fields[48].strip(),
            "fingerprint": fields[49].strip(),
            "notbefore": fields[50].strip(),
            "notafter": fields[51].strip(),
            "cert_ver": fields[52].strip(),
            "cert_size": fields[53].strip(),
            "cn_len": fields[54].strip(),
            "issuer_len": fields[55].strip(),
            "rootcn_len": fields[56].strip(),
            "sni_len": fields[57].strip(),
            "cert_flags": fields[58].strip(),
            "cn": fields[59].strip(),
            "issuer_cn": fields[60].strip(),
            "root_cn": fields[61].strip(),
            "sni": fields[62].strip(),
            "error": fields[63].strip(),
            "container_id": fields[64].strip(),
            "pod_namespace": fields[65].strip(),
            "pod_name": fields[66].strip(),
            "src_edl": fields[67].strip(),
            "dst_edl": fields[68].strip(),
            "src_dag": fields[69].strip(),
            "dst_dag": fields[70].strip(),
            "high_res_timestamp": fields[71].strip(),
            "src_category": fields[72].strip(),
            "src_profile": fields[73].strip(),
            "src_model": fields[74].strip(),
            "src_vendor": fields[75].strip(),
            "src_osfamily": fields[76].strip(),
            "src_osversion": fields[77].strip(),
            "src_host": fields[78].strip(),
            "src_mac": fields[79].strip(),
            "dst_category": fields[80].strip(),
            "dst_profile": fields[81].strip(),
            "dst_model": fields[82].strip(),
            "dst_vendor": fields[83].strip(),
            "dst_osfamily": fields[84].strip(),
            "dst_osversion": fields[85].strip(),
            "dst_host": fields[86].strip(),
            "dst_mac": fields[87].strip(),
            "seqno": fields[88].strip(),
            "actionflags": fields[89].strip(),
            "dg_hier_level_1": fields[90].strip(),
            "dg_hier_level_2": fields[91].strip(),
            "dg_hier_level_3": fields[92].strip(),
            "dg_hier_level_4": fields[93].strip(),
            "vsys_name": fields[94].strip(),
            "device_name": fields[95].strip(),
            "subcategory_of_app": fields[96].strip(),
            "category_of_app": fields[97].strip(),
            "technology_of_app": fields[98].strip(),
            "risk_of_app": fields[99].strip(),
            "characteristic_of_app": fields[100].strip(),
            "container_of_app": fields[101].strip(),
            "is_saas_of_app": fields[102].strip(),
            "sanctioned_state_of_app": fields[103].strip()
        }
        df = pd.DataFrame([decryption_log], columns=columns)
        return df

def process_config_log(message):
    csv_reader = csv.reader(io.StringIO(message), lineterminator='')
    columns = [
        "receive_time", "serial", "type", "subtype", "generated_time", "host",
        "vsys", "cmd", "admin", "client", "result", "path",
        "before_change_detail", "after_change_detail", "seqno", "actionflags",
        "dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4",
        "vsys_name", "device_name", "dg_id", "comment", "high_res_timestamp"
    ]
    for fields in csv_reader:
        config_log = {
            "receive_time": fields[0].strip(),
            "serial": fields[1].strip(),
            "type": fields[2].strip(),
            "subtype": fields[3].strip(),
            "generated_time": fields[6].strip(),
            "host": fields[7].strip(),
            "vsys": fields[8].strip(),
            "cmd": fields[9].strip(),
            "admin": fields[10].strip(),
            "client": fields[11].strip(),
            "result": fields[12].strip(),
            "path": fields[13].strip(),
            "before_change_detail": fields[14].strip(),
            "after_change_detail": fields[15].strip(),
            "seqno": fields[16].strip(),
            "actionflags": fields[17].strip(),
            "dg_hier_level_1": fields[18].strip(),
            "dg_hier_level_2": fields[19].strip(),
            "dg_hier_level_3": fields[20].strip(),
            "dg_hier_level_4": fields[21].strip(),
            "vsys_name": fields[22].strip(),
            "device_name": fields[23].strip(),
            "dg_id": fields[24].strip(),
            "comment": fields[25].strip(),
            "high_res_timestamp": fields[26].strip()
        }
        df = pd.DataFrame([config_log], columns=columns)
        return df

def process_authentication_log(message):
    # Use csv.reader to parse the CSV data within the message
    csv_reader = csv.reader(io.StringIO(message), lineterminator='')
    columns = [
        "receive_time", "serial", "type", "subtype", "authpolicy", "FUTURE_USE",
        "time_generated", "vsys", "ip", "user", "normalize_user", "object",
        "authpolicy", "repeatcnt", "authid", "vendor", "logset", "serverprofile",
        "desc", "clienttype", "event", "factorno", "seqno", "actionflags",
        "dg_hier_level_1", "dg_hier_level_2", "dg_hier_level_3", "dg_hier_level_4",
        "vsys_name", "device_name", "vsys_id", "authproto", "rule_uuid",
        "high_res_timestamp", "src_category", "src_profile", "src_model",
        "src_vendor", "src_osfamily", "src_osversion", "src_host", "src_mac",
        "region", "user_agent", "sessionid"
    ]
    for fields in csv_reader:
        authentication_log = {
            "receive_time": fields[0].strip(),
            "serial": fields[1].strip(),
            "type": fields[2].strip(),
            "subtype": fields[3].strip(),
            "authpolicy": fields[4].strip(),
            "FUTURE_USE": fields[5].strip(),
            "time_generated": fields[6].strip(),
            "vsys": fields[7].strip(),
            "ip": fields[8].strip(),
            "user": fields[9].strip(),
            "normalize_user": fields[10].strip(),
            "object": fields[11].strip(),
            "authpolicy": fields[12].strip(),
            "repeatcnt": fields[13].strip(),
            "authid": fields[14].strip(),
            "vendor": fields[15].strip(),
            "logset": fields[16].strip(),
            "serverprofile": fields[17].strip(),
            "desc": fields[18].strip(),
            "clienttype": fields[19].strip(),
            "event": fields[20].strip(),
            "factorno": fields[21].strip(),
            "seqno": fields[22].strip(),
            "actionflags": fields[23].strip(),
            "dg_hier_level_1": fields[24].strip(),
            "dg_hier_level_2": fields[25].strip(),
            "dg_hier_level_3": fields[26].strip(),
            "dg_hier_level_4": fields[27].strip(),
            "vsys_name": fields[28].strip(),
            "device_name": fields[29].strip(),
            "vsys_id": fields[30].strip(),
            "authproto": fields[31].strip(),
            "rule_uuid": fields[32].strip(),
            "high_res_timestamp": fields[33].strip(),
            "src_category": fields[34].strip(),
            "src_profile": fields[35].strip(),
            "src_model": fields[36].strip(),
            "src_vendor": fields[37].strip(),
            "src_osfamily": fields[38].strip(),
            "src_osversion": fields[39].strip(),
            "src_host": fields[40].strip(),
            "src_mac": fields[41].strip(),
            "region": fields[42].strip(),
            "user_agent": fields[43].strip(),
            "sessionid": fields[44].strip()
        }
        df = pd.DataFrame([authentication_log], columns=columns)
        return df
