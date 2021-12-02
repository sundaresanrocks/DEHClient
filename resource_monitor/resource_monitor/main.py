import os
import logging
import os
path = './resource_monitor'
os.environ['PATH'] += ':'+path

from app import app
#import metric_handler
#import event_handler as alarm
import metric_updater as updater

# set logger
logger = logging.getLogger('DEHClientEnabler')
logger.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
channel = logging.StreamHandler()
channel.setFormatter(formatter)
logger.addHandler(channel)

# start alarm handler

# Client Certificate Details
CERT_BASE = app.config['tls_cert_path']
docker_ca_cert = None
docker_client_cert = None
docker_client_key = None

if app.config['secure_connection'].lower().strip() == "true":
    print("DEH Client - Attempting to establish communication with Docker Host over secured channel.")
    logger.info("DEH Client - Attempting to establish communication with Docker Host over secured channel.")
    try:
        docker_ca_cert = CERT_BASE + '/ca.pem'
        docker_client_cert = CERT_BASE + '/cert.pem'
        docker_client_key = CERT_BASE + '/key.pem'
    except Exception as ERROR:
        print("Exception encountered in main.py, possibly TLS certificates path wrong. Please check{}. ".format(ERROR))
        logger.error("Exception encountered in main.py, possibly TLS certificates path wrong. Please check{}. "
                     .format(ERROR))

elif app.config['secure_connection'].lower().strip() == "false":
    print("Warning DEH Client - Attempting to establish open communication with Docker Host i.e. unsecured. ")
    logger.info("Warning DEH Client - Attempting to establish open communication with Docker Host i.e. unsecured. ")
    docker_ca_cert = None
    docker_client_cert = None
    docker_client_key = None

https_url = app.config['docker_host']
container_name = None
#client = ContainerRegistry(client = ContainerRegistry(docker_ca_cert, docker_client_cert, docker_client_key, https_url, container_name))

# start alarm handler
host = 'localhost'#os.environ.get('RABBITMQ_HOST', 'rabbitmq')
port = '5672'#os.environ.get('RABBITMQ_PORT', '5672')
user = 'guest'#os.environ.get('RABBITMQ_USER', 'guest')
password = 'guest'#os.environ.get('RABBITMQ_PASSWORD', 'guest')
# alarm.AlarmHandler(host, port, user, password, docker_ca_cert, docker_client_cert, docker_client_key, https_url,
#                    container_name)

metrics_updater_client = updater.MetricsUpdater()
metrics_updater_client.thread_start()

# start metric handler
# metric_handler.MetricHandler(docker_ca_cert, docker_client_cert, docker_client_key, https_url, container_name)

if __name__ == '__main__':
    # start rest server
    app.run(host='0.0.0.0', port=app.config['deh_client_port'], threaded=False, debug=False)


