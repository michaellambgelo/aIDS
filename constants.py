# error messages
ERROR_GENERAL = 'An error occurred'
ERROR_CONFIG_EXAMPLES = 'View an example configuration in the README'
ERROR_INVALID_JSON = 'The config file has a JSON format error. ' + ERROR_CONFIG_EXAMPLES + ' and try again.' 

# alert messages
ALERT_MATCHED_BLACKLISTED_IP = 'A packet containing a source or destination to a blacklisted IP was detected and logged'
ALERT_IP_LOG_MESSAGE = '[BLIP]'
ALERT_MATCHED_BLACKLISTED_DNS = 'A packet containing a request to a blacklisted DNS was detected and logged'
ALERT_DNS_LOG_MESSAGE = '[BDNS]'
ALERT_MATCHED_BLACKLISTED_STRING_IN_URL = 'A packet containing a URL request with a blacklisted string was detected and logged'
ALERT_STRING_LOG_MESSAGE = '[BURL]'
ALERT_MATCHED_PAYLOAD_SIGNATURE = 'A packet containing a user-defined signature was detected and logged'
ALERT_SIGNATURE_LOG_MESSAGE = '[PSIG]'
ALERT_PORT_SCANNING_MESSAGE = 'A port scan was detected from IP: '
ALERT_PORT_SCAN_LOG_MESSAGE = '[PSCN]'

# timer; the number of seconds to suppress alerts to the console
SUPPRESS_ALERT_TIME_CONSTANT = 300

'''
port scan parameters
'''
PORT_SCAN_UNIQUE_PORTS_CONSANT = 10		 # must be an integer
PORT_SCAN_TIME_CONSTRAINT_CONSTANT = 0.5 # e.g., 0.5 is half a second