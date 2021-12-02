#########################
# Runtime Configuration #
#########################
from flask import Flask, jsonify, make_response
# TODO Future Implementation : Aggregation  for trending --> Discuss with ENG
runtime = Flask(__name__)
runtime.config['unit_of_measure'] = 20  # units Seconds(Time interval to capture metrics - internal to DEH Client)
runtime.config['timestamp'] = 28800  # Unit Seconds (Time interval over which metrics will be sent to DEH)
runtime.config['no_of_records_per_timestamp'] = 100
# Number of records sent for each container for the interval timestamp
runtime.config['sort_by'] = {"cpu": {"cpu_percent": -1},
                             "memory": {"mem_percent": -1}}  # Sorting Order default Descending
runtime.config['db_keep_non_uid_records'] = False
