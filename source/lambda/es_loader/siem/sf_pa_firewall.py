import re
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def merge_dicts(original, new):
    """
    Merge two dictionaries recursively. If there are overlapping keys,
    values from the 'new' dictionary will overwrite those from 'original'.
    """
    for key, value in new.items():
        if isinstance(value, dict) and key in original and isinstance(original[key], dict):
            merge_dicts(original[key], value)
        else:
            original[key] = value
    return original

RE_PA_TYPE = re.compile(
    r"(?P<ThreatPurpose>\w+):(?P<ResourceTypeAffected>\w+)/"
    r"(?P<ThreatFamilyName>[\w\&]+)(?:\.(?P<DetectionMechanism>\w+))?"
    r"(?:\!(?P<Artifact>\w+))?"
)

def transform(logdata):
    """
    Transform a PA Firewall log entry to conform to ECS and enhance it with additional fields.

    Args:
        logdata (dict): The original log data parsed from PA Firewall logs.

    Returns:
        dict: The transformed log data.
    """
    logger.debug("Original logdata: %s", logdata)

    # 1. Clean and prepare rule name
    if 'rule_name' in logdata and isinstance(logdata['rule_name'], str):
        original_rule_name = logdata['rule_name']
        logdata['rule_name'] = logdata['rule_name'].strip().rstrip('.')
        logger.debug("Cleaned rule_name from '%s' to '%s'", original_rule_name, logdata['rule_name'])

    # 2. Assign severity label based on 'threat_level'
    threat_level = logdata.get('threat_level', 0)
    try:
        threat_level = float(threat_level)
    except (ValueError, TypeError):
        threat_level = 0  # Default to 0 if conversion fails
        logger.warning("Invalid threat_level '%s', defaulting to 0", logdata.get('threat_level'))

    if threat_level <= 3.9:
        label = "low"
    elif threat_level <= 6.9:
        label = "medium"
    elif threat_level <= 8.9:
        label = "high"
    else:
        label = "critical"

    logger.debug("Assigned severity label '%s' for threat_level %s", label, threat_level)

    # 3. Parse the 'type' field using regex
    type_field = logdata.get('type', '')
    m = RE_PA_TYPE.match(type_field)
    if m:
        gd = {
            'severitylabel': label,
            'ThreatPurpose': m.group('ThreatPurpose'),
            'ResourceTypeAffected': m.group('ResourceTypeAffected'),
            'ThreatFamilyName': m.group('ThreatFamilyName'),
            'DetectionMechanism': m.group('DetectionMechanism') or '',
            'Artifact': m.group('Artifact') or ''
        }
        logger.debug("Parsed type_field '%s' into gd: %s", type_field, gd)
    else:
        gd = {
            'severitylabel': label,
            'ThreatPurpose': '',
            'ResourceTypeAffected': '',
            'ThreatFamilyName': type_field,  # Assign the whole 'type' if pattern doesn't match
            'DetectionMechanism': '',
            'Artifact': ''
        }
        logger.warning("Type field '%s' did not match regex. Assigned gd: %s", type_field, gd)

    # 4. Determine action type and network direction
    action_type = logdata.get('action', '').upper()
    if action_type == 'ALLOW':
        direction = "INBOUND"  # Assuming ALLOW actions are inbound; adjust as necessary
    elif action_type == 'DENY':
        direction = "OUTBOUND"  # Assuming DENY actions are outbound; adjust as necessary
    else:
        direction = "UNKNOWN"

    logger.debug("Determined action_type '%s' leads to direction '%s'", action_type, direction)

    # Override direction based on ThreatFamilyName if necessary
    if gd['ThreatFamilyName'] in ('SuspiciousFile', 'MaliciousFile'):
        logger.debug("ThreatFamilyName '%s' overrides direction to None", gd['ThreatFamilyName'])
        direction = None

    # 5. Add network direction to the log data
    if direction:
        gd['network'] = {'direction': direction.lower()}
        logger.debug("Added network.direction: %s", gd['network'])

    # 6. Merge the new fields into the original log data
    logdata = merge_dicts(logdata, gd)
    logger.debug("Merged logdata with gd: %s", gd)

    # 7. Adjust source and destination based on direction
    if direction == "OUTBOUND":
        original_source = logdata.get('source')
        original_destination = logdata.get('destination')
        logdata['source'], logdata['destination'] = logdata.get('destination'), logdata.get('source')
        logger.debug("Swapped source and destination for OUTBOUND direction")
        if not logdata.get('source'):
            logdata.pop('source', None)
            logger.debug("Removed empty source field after swapping")
        if not logdata.get('destination'):
            logdata.pop('destination', None)
            logger.debug("Removed empty destination field after swapping")

    # 8. Assign event category based on ThreatPurpose and ThreatFamilyName
    threat_purpose = logdata.get('ThreatPurpose', '')
    threat_family = logdata.get('ThreatFamilyName', '')

    if threat_purpose in ('Backdoor', 'CryptoCurrency', 'Trojan') or threat_family in ('SuspiciousFile', 'MaliciousFile'):
        event_category = 'malware'
    else:
        event_category = 'network_traffic'

    logger.debug("Assigned event category '%s' based on ThreatPurpose '%s' and ThreatFamilyName '%s'", 
                 event_category, threat_purpose, threat_family)

    # Assign the event category
    if 'event' not in logdata or not isinstance(logdata['event'], dict):
        logdata['event'] = {}
        logger.debug("Initialized 'event' field as empty dict")
    logdata['event']['category'] = event_category
    logger.debug("Set event.category to '%s'", event_category)

    logger.info("Transformation complete for logdata: %s", logdata)

    return logdata
