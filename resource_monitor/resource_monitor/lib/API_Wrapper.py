import pytz
import requests
import logging
import os
import json
import inspect
from app import app
import lib.API as API
import sys
import sys
import mongodb_wrapper
# To Suppress InsecureRequestWarning: Unverified HTTPS request
import urllib3
import traceback
import calendar, time
from datetime import datetime
from time import mktime
from dateutil import tz
import calendar, time
from datetime import datetime, timezone, timedelta
from time import mktime
from dateutil import tz

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LOG_LEVEL = logging.DEBUG  # DEBUG, INFO, WARNING, ERROR, CRITICAL
common_formatter = logging.Formatter('%(asctime)s [%(levelname)-7s][ln-%(lineno)-3d]: %(message)s',
                                     datefmt='%Y-%m-%d %I:%M:%S')

# root_path is parent folder of Scripts folder (one level up)
root_path = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def setup_logger(log_file, level=logging.INFO, name='', formatter=common_formatter):
    """Function setup as many loggers as you want."""
    handler = logging.FileHandler(log_file, mode='w')  # default mode is append
    # Or use a rotating file handler
    # handler = RotatingFileHandler(log_file,maxBytes=1023, backupCount=5)
    handler.setFormatter(formatter)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    logger.addHandler(handler)
    return logger


# default debug logger
debug_log_filename = '../debug.log'
log = setup_logger(debug_log_filename, LOG_LEVEL, 'log')

api_formatter = logging.Formatter('%(asctime)s: %(message)s', datefmt='%Y-%m-%d %I:%M:%S')
api_outputs_filename = '../api_outputs.log'
log_api = setup_logger(api_outputs_filename, LOG_LEVEL, 'log_api', formatter=api_formatter)


def pretty_print_request(request):
    """
    Pay attention at the formatting used in this function because it is programmed to be pretty printed and may differ from the actual request.
    """
    log_api.info('{}\n{}\n\n{}\n\n{}\n'.format(
        '-----------Request----------->',
        request.method + ' ' + request.url,
        '\n'.join('{}: {}'.format(k, v) for k, v in request.headers.items()),
        request.body)
    )


# pretty print Restful response to API log
# argument is response object
def pretty_print_response(response):
    log_api.info('{}\n{}\n\n{}\n\n{}\n'.format(
        '<-----------Response-----------',
        'Status code:' + str(response.status_code),
        '\n'.join('{}: {}'.format(k, v) for k, v in response.headers.items()),
        response.text
    ))


# argument is response object
# display body in json format explicitly with expected indent. Actually most of the time it is not very necessary because body is formatted in pretty print way.
def pretty_print_response_json(response):
    """ pretty print response in json format.
        If failing to parse body in json format, print in text.
    """
    try:
        resp_data = response.json()
        resp_body = json.dumps(resp_data, indent=3)
    # if .json() fails, ValueError is raised.
    except ValueError:
        resp_body = response.text
    log_api.info('{}\n{}\n\n{}\n\n{}\n'.format(
        '<-----------Response-----------',
        'Status code:' + str(response.status_code),
        '\n'.join('{}: {}'.format(k, v) for k, v in response.headers.items()),
        resp_body
    ))


#########################################################################################
def parse_prefix(line, fmt):
    try:
        t = time.strptime(line, fmt)
    except ValueError as v:
        # To handle ValueError: unconverted data remains: Z
        if len(v.args) > 0 and v.args[0].startswith('unconverted data remains: '):
            line = line[:-(len(v.args[0]) - 26)]
            t = time.strptime(line, fmt)
        else:
            raise
    return datetime.fromtimestamp(mktime(t))


def convert_gmt_to_other_timezone_datetime_obj(datetime_obj, time_zone='CET'):
    # datetime_str = "2021-04-02T12:32:34.467Z"
    to_zone = tz.gettz(time_zone)
    datetime_obj = datetime_obj.astimezone(to_zone)
    return datetime_obj


def cached_token(jsonfile):
    def has_valid_token(data):
        return 'token' in data

    def get_token_info_from_file(get="token"):
        with open(jsonfile) as f:
            data = json.load(f)
            # if has_valid_token(data):
            return data

    def save_token_to_file(token, generated_date, expiry_date):
        with open(jsonfile, 'w') as f:
            json.dump({'token': token, 'generated_date': generated_date, 'expiry_date': expiry_date}, f)

    def decorator(fn):
        def wrapped(*args, **kwargs):
            if os.path.exists(jsonfile):
                token_info = get_token_info_from_file()
                token = token_info.get('token')
                expiry_date = token_info.get('expiry_date')
                date_format = '%Y-%m-%dT%H:%M:%S.%f'
                expiry_date_datetime_obj = parse_prefix(expiry_date, date_format)
                cet_expiry_date_datetime_obj = convert_gmt_to_other_timezone_datetime_obj(expiry_date_datetime_obj,
                                                                                          time_zone="CET")
                local_datetime_obj = datetime.now()
                local_datetime_str = local_datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%f')
                utc_now_datetime_obj = parse_prefix(local_datetime_str, date_format)
                print("local_datetime_str: {}".format(local_datetime_str))
                print("cet_expiry_date_datetime_obj: {}".format(cet_expiry_date_datetime_obj.replace(tzinfo=None)))
                print("utc_now_datetime_obj {}".format(utc_now_datetime_obj.replace(tzinfo=None)))
                token_expired = (cet_expiry_date_datetime_obj.replace(tzinfo=None) <=
                                 utc_now_datetime_obj.replace(tzinfo=None))
                if not token_expired:
                    print("ACS Token Still Valid / Not-Expired.")
                    return f'{token} (cached!!)'
                else:
                    print("ACS Token Expired, attempting to generate new Token.")
            token, generated_data, expiry_date = fn(*args, **kwargs)
            save_token_to_file(token, generated_data, expiry_date)
            # return token, generated_data, expiry_date
            return token

        return wrapped

    return decorator


#########################################################################################


class DEHAPIWrapper:
    """
    Test Restful HTTP API examples.
    """
    acs_token = None
    acs_token_status_code = None
    acs_token_response = None
    acs_token_expiry_date = None

    capability_token_status_code = None
    capability_token_response = None
    capability_token_expiry_date = None

    def __init__(self, url=None, method=None, payload=None, headers=None):
        self.url = url
        self.method = method
        self.payload = payload
        self.headers = headers
        self.__logger = logging.getLogger('DEHClientEnabler.APIWrapper')
        self.mongo_client = mongodb_wrapper.MongoAPI(hostname=app.config["mongo_host"],
                                                     port=app.config["mongo_port"],
                                                     database=app.config["mongo_db"],
                                                     collection=app.config["mongo_collection_metrics"])

    def get(self, url, auth=None, params=None, verify=False, headers=None):
        """
        common request get function with below features, which you only need to take care of url:
            - print request and response in API log file
            - Take care of request exception and non-200 response codes and return None, so you only need to care normal json response.
            - arguments are the same as requests.get

        verify: False - Disable SSL certificate verification
        """
        try:
            s = requests.Session()
            if auth == None:
                if params is not None:
                    resp = s.get(url, params=params, verify=verify, headers=headers)
                else:
                    resp = s.get(url, verify=verify, headers=headers)
            else:
                resp = requests.get(url, auth=auth, verify=verify, headers=headers)
                if params is not None:
                    resp = requests.get(url, auth=auth, verify=verify, headers=headers)
                else:
                    resp = requests.get(url, auth=auth, params=params, verify=verify, headers=headers)
        except Exception as ex:
            return None

        # pretty request and response into API log file
        pretty_print_request(resp.request)
        pretty_print_response_json(resp)

        # This return caller function's name, not this function post.
        caller_func_name = inspect.stack()[1][3]
        if resp.status_code != 200:
            log.error('%s failed with response code %s.' % (caller_func_name, resp.status_code))
        return resp.status_code, resp.json()

    def post(self, url, data, headers={}, verify=False, amend_headers=False):
        """
        common request post function with below features, which you only need to take care of url and body data:
            - append common headers
            - print request and response in API log file
            - Take care of request exception and non-200 response codes and return None, so you only need to care normal json response.
            - arguments are the same as requests.post, except amend_headers.

        verify: False - Disable SSL certificate verification
        """

        # append common headers if none
        headers_new = headers
        if amend_headers:
            if 'Content-Type' not in headers_new:
                headers_new['Content-Type'] = r'application/json'
            if 'User-Agent' not in headers_new:
                headers_new['User-Agent'] = 'Python Requests'

        # send post request
        resp = requests.post(url, data=data, headers=headers_new, verify=verify)

        # pretty request and response into API log file
        # Note: request print is common instead of checking if it is JSON body.
        # So pass pretty formatted json string as argument to the request for pretty logging.
        pretty_print_request(resp.request)
        pretty_print_response_json(resp)

        # This return caller function's name, not this function post.
        caller_func_name = inspect.stack()[1][3]
        if resp.status_code != 200:
            log.error('%s failed with response code %s.' % (caller_func_name, resp.status_code))
        return resp.status_code, resp.json()

    """ DEH Enabler Hub Wrapper"""

    def deh_enabler_hub_resource_search_by_uid(self, parameter):
        """
        Get DEH RRM registered resource by uid,
        parameter can be {"uid":<value>>}
        """
        # Step 1 : Get Authentication Token
        # Step 2 : Get Capability Token
        # Step 3 : Save DEH Resource
        deh_resource_search_url = app.config['DEH_RRM_Proxy_URL']
        headers = {"Content-Type": "application/json"}
        headers = headers
        # Step 1 Attributes:
        asc_token_url = app.config['ACS_Token_Request_Url']
        asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'],
                             "password": app.config['DEH_ACCOUNT_PASS']}

        # Step 2 Attributes:
        capability_token_url = app.config['Capability_Token_Url']
        capability_token_payload = app.config['Request_Capability_Token_Format']
        '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
            "de": "$ProxyURL", "re": "$Resource"}'''
        capability_token_proxy_url = app.config['DEH_RRM_Proxy_URL']

        # Step 3 Attributes
        capability_token_request_resource = app.config['DEHEnablerHub_Resource']
        capability_token_request_resource += '/' + str(parameter['uid'])
        self.__logger.info("capability_token_request_resource: " + capability_token_request_resource)
        deh_resource_search_url = deh_resource_search_url + capability_token_request_resource
        self.__logger.info("deh_resource_search_url: " + deh_resource_search_url)
        headers = {"Content-Type": "application/json"}
        status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, headers)
        if status_code in (200, 201):
            auth_token = response.headers['X-Subject-Token']
            capability_token_payload['token'] = auth_token
            capability_token_payload['ac'] = "GET"
            capability_token_payload['de'] = capability_token_proxy_url
            capability_token_payload['re'] = capability_token_request_resource
            status_code, response = self.request_capability_token(capability_token_url,
                                                                  capability_token_payload,
                                                                  headers)
            if status_code == 200:
                # Adding the entire capacity token request's response as x-auth-token header for saving resource
                headers = app.config['DEH_RRM_Request_Header']
                capability_token_response = response
                headers['x-auth-token'] = capability_token_response.text
                # As per new RRM change, x-subject-token needs to be included in all RRM API request
                headers['x-subject-token'] = auth_token
                client = API.APIWrapper(url=deh_resource_search_url, headers=headers)
                status_code, response = client.get(verify=False)
                self.__logger.info(response.json())
                if status_code == 200 and response.json()["data"] is not None:
                    self.__logger.info("Step 3 : DEH RRM, resource search result returned success, "
                                       "Resource matching UID {}.".format(parameter['uid']))
                    self.__logger.info(response.json())

                if status_code == 200 and response.json()["data"] is None:
                    self.__logger.info("Step 3 : DEH RRM, resource search result returned success, "
                                       "but no resource found/ registered with UID {}.".format(parameter['uid']))
                elif status_code != 200:
                    self.__logger.error("Step 3 : DEH RRM, resource search result returned failed with response code {}"
                                        .format(status_code))
                    self.__logger.error(response.json())
            else:
                self.__logger.error("Step 2 : Failed to Get Capability Token with response code {}".format(status_code))
                self.__logger.error(response.json())
        else:
            self.__logger.error("Step 1 : Failed to Get Authentication Token with response code {}".format(status_code))
        return status_code, response

    def deh_enabler_hub_resource_search(self, url=None, payload=None, headers=None, method=None):
        """
        Search DEH Resources by filters (name)
        #TODO:Make this method more dynamic, ie accept search by multiple parameters ?p1=v1&p2=v2
        # Step 1 : Get Authentication Token
        # Step 2 : Get Capability Token
        # Step 3 : Save DEH Resource
        """
        if url is None:
            url = app.config['DEH_RRM_Proxy_URL']
        if headers is None:
            headers = {"Content-Type": "application/json"}
        headers = headers
        # Step 1 Attributes:
        asc_token_url = app.config['ACS_Token_Request_Url']
        asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}

        # Step 2 Attributes:
        capability_token_url = app.config['Capability_Token_Url']
        capability_token_payload = app.config['Request_Capability_Token_Format']
        '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
            "de": "$ProxyURL", "re": "$Resource"}'''
        capability_token_proxy_url = app.config['DEH_RRM_Proxy_URL']

        # Step 3 Attributes
        deh_resource_search_url = url
        capability_token_request_resource = app.config['DEH_RRM_Search_Resource']
        if method:
            for key in payload:
                capability_token_request_resource = method + "?" + key + "=" + payload[key]
            deh_resource_search_url = deh_resource_search_url + capability_token_request_resource
        headers = {"Content-Type": "application/json"}
        # Generate ACS token
        status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, headers)
        if status_code in (200, 201):
            log.info("Successfully generated ACS token, proceeding to generate capability token.")
            auth_token = response.headers['X-Subject-Token']
            capability_token_payload['token'] = auth_token
            capability_token_payload['ac'] = "GET"
            capability_token_payload['de'] = capability_token_proxy_url
            capability_token_payload['re'] = capability_token_request_resource
            status_code, response = self.request_capability_token(capability_token_url,
                                                                  capability_token_payload,
                                                                  headers)
            if status_code == 200:
                # Adding the entire capacity token request's response as x-auth-token header for saving resource
                headers = app.config['DEH_RRM_Request_Header']
                capability_token_response = response
                headers['x-auth-token'] = capability_token_response.text
                # As per new RRM change, x-subject-token needs to be included in all RRM API request
                headers['x-subject-token'] = auth_token
                client = API.APIWrapper(url=deh_resource_search_url, headers=headers)
                status_code, response = client.get(verify=False)
                if status_code == 200:
                    self.__logger.info("Successfully fetched all resource registration details from DEH RRM.")
                    self.__logger.info(response.json())
                else:
                    self.__logger.error("Failed to List DEH with response code {}".format(status_code))
                    self.__logger.error(response.json())
            else:
                self.__logger.error("Failed to Get Capability Token with response code {}".format(status_code))
        else:
            self.__logger.error("Failed to Get Authentication Token with response code {}".format(status_code))
        print("PayLoad for deh_enabler_hub_resource_search: ", payload)
        print("Response for deh_enabler_hub_resource_search: ", response.json())
        return status_code, response

    def validate_acs_token_re_usability(self):
        """ Implemented to validate if the acs token for POST metrics call can be reused. """
        status_code, response = None, None
        acs_token_expired = True
        self.__logger.info("Step 1 : Attempting to generate new ACS token. "
                           "Flow is to Reuse previously generated token if any generated & not expiated.")
        if DEHAPIWrapper.acs_token_status_code is not None and \
                DEHAPIWrapper.acs_token_response is not None:
            self.__logger.info("ACS token exists, validating if the token is not expired. ")
            token_info = DEHAPIWrapper.acs_token_response.json()['token']
            expiry_date = token_info['expires_at']
            date_format = '%Y-%m-%dT%H:%M:%S.%f'
            expiry_date_datetime_obj = parse_prefix(expiry_date, date_format)
            utc_expiry_date_datetime_obj = convert_gmt_to_other_timezone_datetime_obj(expiry_date_datetime_obj,
                                                                                      time_zone="UTC")
            utc_expiry_date_datetime_obj = utc_expiry_date_datetime_obj.replace(second=0) - timedelta(minutes=10)
            local_datetime_obj = datetime.utcnow()
            # local_datetime_obj = datetime.fromtimestamp(utc_expiry_date_datetime_obj, cet)
            local_datetime_str = local_datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%f')
            utc_now_datetime_obj = parse_prefix(local_datetime_str, date_format)
            self.__logger.info("utc_expiry_date_datetime_obj    :   {}.".format(utc_expiry_date_datetime_obj))
            self.__logger.info("utc_now_datetime_obj            :   {}.".format(utc_now_datetime_obj))
            token_expired = (utc_expiry_date_datetime_obj.replace(tzinfo=None) <=
                             utc_now_datetime_obj.replace(tzinfo=None))
            if not token_expired:
                acs_token_expired = False
                self.__logger.info("Previous generated ACS token still valid / not-expired attempting to reuse. ")
                status_code, response = DEHAPIWrapper.acs_token_status_code, DEHAPIWrapper.acs_token_response
            else:
                acs_token_expired = True
                self.__logger.info("previously generated ACS token is expired. Attempting to generate new token.")
                status_code, response = None, None

        return status_code, response, acs_token_expired

    def validate_capability_token_re_usability(self):
        """ Implemented to validate if the capacity token for POST metrics call can be reused. """
        status_code, response = None, None
        capability_token_expired = True
        self.__logger.info("Step 2 : Attempting to generate new capability token. "
                           "Flow is to Reuse previously generated token if any generated & not expiated.")
        if DEHAPIWrapper.capability_token_status_code is not None and \
                DEHAPIWrapper.capability_token_response is not None:
            self.__logger.info("Capacity token exists, validating if the token is not expired. ")
            date_format = '%Y-%m-%dT%H:%M:%S.%f'
            expiry_date_epoch = DEHAPIWrapper.capability_token_response.json().get(["na"])
            dt = datetime.fromtimestamp(expiry_date_epoch, pytz.timezone('UTC'))
            expiry_date_str = dt.strftime(date_format)
            utc_expiry_date_datetime_obj = datetime.strptime(expiry_date_str, date_format)  # 2021-09-28 15:58:47
            utc_expiry_date_datetime_obj = utc_expiry_date_datetime_obj.replace(second=0) - timedelta(minutes=165)
            local_datetime_obj = datetime.utcnow()
            local_datetime_str = local_datetime_obj.strftime(date_format)
            utc_now_datetime_obj = parse_prefix(local_datetime_str, date_format)
            self.__logger.info("utc_expiry_date_datetime_obj    :   {}.".format(utc_expiry_date_datetime_obj))
            self.__logger.info("utc_now_datetime_obj            :   {}.".format(utc_now_datetime_obj))
            # utc_now_datetime_str = utc_now_datetime_obj.strftime(date_format)
            token_expired = (utc_expiry_date_datetime_obj <=
                             utc_now_datetime_obj)
            if not token_expired:
                capability_token_expired = False
                self.__logger.info("Capability Token Still Valid / Not-Expired, attempting to reuse.")
                status_code, response = DEHAPIWrapper.capability_token_status_code, \
                                        DEHAPIWrapper.capability_token_response
            else:
                capability_token_expired = True
                self.__logger.info("Capability Token Expired, attempting to generate new Token.")
                status_code, response = None, None
        return status_code, response, capability_token_expired

    # def request_acs_token(self, url, payload, headers, method=None):
    #     """ Method to Get Authentication Token"""
    #     subject_token = None
    #     self.__logger.info("Step 1 : Attempting to generate new ACS token. "
    #                        "Flow is to, Reuse previously generated token if any & not expiated.")
    #     if DEHAPIWrapper.acs_token_status_code is not None and \
    #             DEHAPIWrapper.acs_token_response is not None:
    #         self.__logger.info("Validating ACS token reuse criteria.")
    #         token_info = DEHAPIWrapper.acs_token_response.json()['token']
    #         local_datetime_obj = datetime.now()
    #         local_datetime_str = local_datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%f')
    #         # expiry_date = token_info['expires_at']
    #         status_code = DEHAPIWrapper.acs_token_response.status_code
    #         response = token_info.get('response')
    #         # acs_token_expiry_date = token_info.get('expires_at')
    #         date_format = '%Y-%m-%dT%H:%M:%S.%f'
    #         expiry_date_datetime_obj = parse_prefix(DEHAPIWrapper.acs_token_expiry_date, date_format)
    #         cet_expiry_date_datetime_obj = convert_gmt_to_other_timezone_datetime_obj(expiry_date_datetime_obj,
    #                                                                                   time_zone="CET")
    #         local_datetime_obj = datetime.now()
    #         local_datetime_str = local_datetime_obj.strftime('%Y-%m-%dT%H:%M:%S.%f')
    #         utc_now_datetime_obj = parse_prefix(local_datetime_str, date_format)
    #         token_expired = (cet_expiry_date_datetime_obj.replace(tzinfo=None) <=
    #                          utc_now_datetime_obj.replace(tzinfo=None))
    #         if not token_expired:
    #             self.__logger.info("GET ACS token success. "
    #                                "Previous generated token still valid / not-expired so reusing.")
    #             # return f'{token} (cached!!)'
    #             status_code, response = DEHAPIWrapper.acs_token_status_code, DEHAPIWrapper.acs_token_response
    #             return status_code, response
    #     else:
    #         self.__logger.info("Attempting to generate new ACS token as, "
    #                            "no previously generated token exists or expiated.")
    #         if method:
    #             url = url + "/" + method + "/"
    #         client = API.APIWrapper(url=url, payload=json.dumps(payload), headers=headers)
    #         status_code, response = client.post(verify=False)
    #         # Status code 201 --> Created
    #         if status_code in (200, 201):
    #             self.__logger.info("GET ACS token success, generated new token as, "
    #                                "no previously generated token exists or expiated. ")
    #             token_info = response.json()['token']
    #             expiry_date = token_info.get('expires_at')
    #             DEHAPIWrapper.acs_token_status_code, DEHAPIWrapper.acs_token_response, \
    #             DEHAPIWrapper.acs_token_expiry_date = status_code, response, expiry_date
    #         else:
    #             self.__logger.error("Failed to Get Authentication Token with response code "
    #                                 "{}".format(status_code))
    #     self.__logger.info("status_code : {} , acs_token_response : {} ."
    #                        .format(DEHAPIWrapper.acs_token_status_code,
    #                                DEHAPIWrapper.acs_token_response))
    #     return status_code, response

    def request_acs_token(self, url, payload, headers, method=None):
        """ Method to Get Authentication Token"""
        subject_token = None
        if method:
            url = url + "/" + method + "/"
        client = API.APIWrapper(url=url, payload=json.dumps(payload), headers=headers)
        status_code, response, acs_token_expired = self.validate_acs_token_re_usability()
        if response is None or acs_token_expired == True:
            status_code, response = client.post(verify=False)
            DEHAPIWrapper.acs_token_status_code, \
            DEHAPIWrapper.acs_token_response = status_code, response
        # Status code 201 --> Created
        if status_code in (200, 201):
            if acs_token_expired:
                self.__logger.info("Step 1 : GET ACS token success, no existing token or expired, generated new one. ")
            else:
                self.__logger.info("Step 1 : GET ACS token success, reusing already generated token. ")
        else:
            self.__logger.error("Failed to Get Authentication Token with response code "
                                "{}".format(status_code))
        return status_code, response

    def request_capability_token(self, url, payload, headers, method=None):
        """ Method to Get the Capability token from ACS Capability Manger.
        using x-subject-token received in header from method request_acs_token (Get Authentication Token) """
        subject_token = None
        if method:
            url = url + "/" + method + "/"
        client = API.APIWrapper(url=url, payload=json.dumps(payload), headers=headers)
        status_code, response = client.post(verify=False)
        if status_code == 200:
            capability_token = response.text
            self.__logger.info("Step 2 : GET Capability Token success")
        else:
            self.__logger.error("Failed to Get Capability Token with response code {}".format(status_code))
        return status_code, response

    def save_deh_resource(self, resource_data, request_type="POST"):
        """
        # Step 1 : Get Authentication Token
        # Step 2 : Get Capability Token
        # Step 3 : Save DEH Resource
        """
        header = {"content-type": "application/json"}

        # Step 1 Attributes:
        asc_token_url = app.config['ACS_Token_Request_Url']
        asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}

        # Step 2 Attributes:
        capability_token_url = app.config['Capability_Token_Url']
        capability_token_payload = app.config['Request_Capability_Token_Format']
        '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
            "de": "$ProxyURL", "re": "$Resource"}'''
        capability_token_proxy_url = app.config['DEH_RRM_Proxy_URL']
        capability_token_request_resource = app.config['DEH_Save_Resource_Url']

        # Step 3 Attributes
        deh_save_resource_url = app.config['DEH_RRM_Proxy_URL'] + capability_token_request_resource
        deh_save_resource_payload = resource_data

        status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, header)
        if status_code in (200, 201):
            auth_token = response.headers['X-Subject-Token']
            capability_token_payload['token'] = auth_token
            if request_type:
                if request_type.upper() == "POST":
                    capability_token_payload['re'] = capability_token_request_resource
                    capability_token_payload['ac'] = request_type.upper()
                elif request_type.upper() == "PUT":
                    """#TODO: Right now PUT updates over criteria uid, future make available for others"""
                    capability_token_request_resource += "/" + resource_data['uid']
                    capability_token_payload['re'] = capability_token_request_resource
                    capability_token_payload['ac'] = request_type.upper()
                    deh_save_resource_url = app.config['DEH_RRM_Proxy_URL'] + capability_token_request_resource
                    # Remove ir-relevant keys from resource data, in case of PUT request
                    keys_to_remove = ["uid", "createAt", "lastUpdate", "downloadsHistory", "billingInformation",
                                      "rating", "attachment"]
                    for key in keys_to_remove:
                        try:
                            del deh_save_resource_payload[key]
                        except KeyError:
                            continue
                    # Hardcoded the value of  localisation as its creating problems while put
                    deh_save_resource_payload["localisation"] = [
                        {
                            "type": "Point",
                            "coordinates": [
                                0,
                                0
                            ]
                        }
                    ]
            capability_token_payload['de'] = capability_token_proxy_url
            status_code, response = self.request_capability_token(capability_token_url, capability_token_payload,
                                                                  header)
            if status_code == 200:
                # Adding the entire capacity token request's response as x-auth-token header for saving resource
                header = app.config['DEH_RRM_Request_Header']
                capability_token_response = response
                header['x-auth-token'] = capability_token_response.text
                # As per new RRM change, x-subject-token needs to be included in all RRM API request
                header['x-subject-token'] = auth_token
                payload = deh_save_resource_payload
                client = API.APIWrapper(url=deh_save_resource_url, payload=json.dumps(payload), headers=header)
                if request_type.upper() == "POST":
                    status_code, response = client.post(verify=False)
                elif request_type.upper() == "PUT":
                    """#TODO: Use common lib for PUT"""
                    status_code, response = client.put(verify=False)
                    response = requests.request("PUT", deh_save_resource_url, data=json.dumps(payload), headers=header)
                    status_code = response.status_code
                if status_code == 200:
                    self.__logger.info("Successfully registered/ save resource with DEH RRM")
                    self.__logger.info(response.json())
                else:
                    self.__logger.error("Failed to register/save DEH resource : {}".format(resource_data['name']))
                    self.__logger.error("Failed to register/save DEH resource response code {}".format(status_code))
                    self.__logger.error(response)
            else:
                self.__logger.error("Failed to Get Capability Token with response code {}".format(status_code))
        else:
            self.__logger.error("Failed to Get Authentication Token with response code {}".format(status_code))
        return status_code, response

    """ DEH RRM Metrics APIs"""

    def post_deh_metrics(self, resource_data, request_type="POST"):
        """
        # Step 1 : Get Authentication Token
        # Step 2 : Get Capability Token
        # Step 3 : Post Metrics Data to DEH
        """
        # Read Metric Data from MongoDB
        try:
            resource_list = [data["_id"] for data in resource_data]
            payload = resource_data

            header = {"content-type": "application/json"}

            # Step 1 Attributes:
            asc_token_url = app.config['ACS_Token_Request_Url']
            asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}

            # Step 2 Attributes:
            capability_token_url = app.config['Capability_Token_Url']
            capability_token_payload = app.config['Request_Capability_Token_Format']
            '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
                "de": "$ProxyURL", "re": "$Resource"}'''
            capability_token_proxy_url = app.config['DEH_RRM_Proxy_URL']
            capability_token_request_resource = app.config['DEH_RRM_Metrics']

            # Step 3 Attributes
            deh_metrics_url = app.config['DEH_RRM_Proxy_URL'] + capability_token_request_resource
            status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, header)
            if status_code in (200, 201):
                auth_token = response.headers['X-Subject-Token']
                capability_token_payload['token'] = auth_token
                if request_type:
                    if request_type.upper() == "POST":
                        capability_token_payload['re'] = capability_token_request_resource
                        capability_token_payload['ac'] = request_type.upper()
                capability_token_payload['de'] = capability_token_proxy_url

                status_code, response = self.request_capability_token(capability_token_url,
                                                                      capability_token_payload,
                                                                      header)

                if status_code == 200:
                    self.__logger.info("Step 2 : GET capability token success. ")

                    # Adding the entire capacity token request's response as x-auth-token header for saving resource
                    header = app.config['DEH_RRM_Request_Header']
                    capability_token_response = response
                    header['x-auth-token'] = capability_token_response.text
                    # As per new RRM change, x-subject-token needs to be included in all RRM API request
                    header['x-subject-token'] = auth_token
                    header['Accept'] = "application/json"
                    # client = API.APIWrapper(url=deh_metrics_url, payload=json.dumps(payload), headers=header)
                    if request_type.upper() == "POST":
                        # status_code, response = client.post(verify=False)
                        response = requests.request("POST", deh_metrics_url, data=json.dumps(payload), headers=header)
                        if status_code == 200 and response.json()['success'] == True:
                            self.__logger.info("Successfully Post metrics data with DEH RRM for container id : {} "
                                               .format(resource_list))
                            self.__logger.info(response.json())
                        else:
                            self.__logger.error("Failed to Post metrics data for container id {} "
                                                "to DEH RRM for with exception : {}".format(resource_list,
                                                                                            response.json()))
                            self.__logger.error("Failed to Post metrics data to DEH RRM response code {}".
                                                format(status_code))
                            # To handle exception "TypeError: list indices must be integers or slices, not str"
                            try:
                                self.__logger.error("Failed to Post metrics data to DEH RRM for uid : {}".
                                                    format(resource_list))

                            except TypeError as error:
                                self.__logger.error("Failed to Post metrics data to DEH RRM for "
                                                    "Container id : {} with error : {}.".format(resource_list,
                                                                                                error))
                            except Exception as error:
                                self.__logger.error("Failed to Post metrics data to DEH RRM for Container id : {} "
                                                    "with exception : {}".format(resource_list, error))

                    else:
                        self.__logger.error("Invalid request_type selected for method post_deh_metrics.")
                else:
                    self.__logger.error("Failed to Get Capability Token with response code {}".format(status_code))
            else:
                self.__logger.error("Failed to Get Authentication Token with response code {}".format(status_code))

            return response.status_code, response

        except KeyError as error:
            self.__logger.error("Exception encountered posting metrics data to RRM with error: {}. Possibly "
                                "missing keyword in the resource data. ".format(error))
        except Exception as error:
            self.__logger.error("Exception encountered posting metrics data to RRM with error: {}.".format(error))

    def initiate_post_deh_metrics_request(self, record):
        if record:
            try:
                self.__logger.info("Attempting to update metrics to RRM for container id : {} . "
                                   .format([data["_id"] for data in record]))
                status_code, response = self.post_deh_metrics(record, request_type="POST")
                if status_code == 200 and response.json()["success"] is True:
                    # Once metrics is successfully posted clear mongoDB metrics collection for the specific container
                    # If failed post, the record/s will be retained till next successful attempt
                    #   TODO : Future implementation, retain historic data
                    self.__logger.info("Successfully posted metrics to RRM with response {} .".format(response.json()))
                    for document in record:
                        self.__logger.info("Deleting record for container ID {} "
                                           "from internal DB after metrics result successfully posted to RRM."
                                           .format(document['_id']))
                        remove_document = self.mongo_client.delete_one({"_id": document['_id']})
                else:
                    self.__logger.error(
                        "Failed to post metrics to RRM with response status code {}".format(status_code))
                    self.__logger.error("Failed to post metrics to RRM with response {}, "
                                        "will be reattempted later".format(response.json()))
            except Exception as error:
                self.__logger.warning("Exception encountered Possibly missing keyword.")
                self.__logger.warning("ERROR : {}".format(traceback.print_exc()))
        else:
            self.__logger.warning("No metrics records found in local DB to be post to RRM. ")

    """ DEH BSE API Wrapper"""

    def deh_bse_get_running_services(self):
        """ BSE endpoint that returns a list of the running services """
        header = app.config['DEH_RRM_Request_Header']
        # Step 1 Attributes:
        asc_token_url = app.config['DEH_BSE_ACS_Token_Request_Url']
        asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}
        # Step 2 Attributes:
        capability_token_url = app.config['DEH_BSE_Capability_Token_Url']
        capability_token_payload = app.config['Request_Capability_Token_Format']
        '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
            "de": "$ProxyURL", "re": "$Resource"}'''
        capability_token_proxy_url = app.config['DEH_BSE_Proxy_URL']
        # Condition to switch if the request is to get all services or get service by name
        if self.payload is None:
            self.__logger.info("GET BSE get all running services")
            bse_get_running_services_url = self.url + self.method
            capability_token_request_services = app.config['DEH_BSE_GET_SERVICES']
        elif self.payload is not None:
            if 'service_name' in self.payload:
                self.__logger.info("Get BSE service by name is enabled")
                bse_get_running_services_url = self.url + self.method + "/" + self.payload['service_name']
                # For search by service name, capacity token request format:
                '''{"token": "3d0782f4-3d57-4bed-b8a1-324a8d3aebb4","ac": "GET", 
                "de": "https://vm1.test.h2020-demeter-cloud.eu:443", "re": "/api/BSE/service/<<service name>>"}'''
                capability_token_request_services = self.method + "/" + self.payload['service_name']
            if 'deh_id' in self.payload:
                self.__logger.info("Get BSE service by deh_id is enabled")
                bse_get_running_services_url = self.url + self.method + "/" + self.payload['deh_id']
                # For search by service name, capacity token request format:
                '''{"token": "3d0782f4-3d57-4bed-b8a1-324a8d3aebb4","ac": "GET", 
                "de": "https://vm1.test.h2020-demeter-cloud.eu:443", "re": "/api/BSE/service/<<service name>>"}'''
                capability_token_request_services = self.method + "/" + self.payload['deh_id']
        self.__logger.info("BSE list services : " + bse_get_running_services_url)
        self.__logger.info("BSE capability token request : " + capability_token_request_services)
        status_code = None
        response = None
        status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, header)
        if status_code in (200, 201):
            auth_token = response.headers['X-Subject-Token']
            capability_token_payload['token'] = auth_token
            capability_token_payload['ac'] = "GET"
            capability_token_payload['de'] = capability_token_proxy_url
            capability_token_payload['re'] = capability_token_request_services
            status_code, response = self.request_capability_token(capability_token_url,
                                                                  capability_token_payload,
                                                                  header)
            if status_code == 200:
                # Adding the entire capacity token request's response as x-auth-token header for saving resource
                capability_token_response = response
                header['x-auth-token'] = capability_token_response.text
                client = API.APIWrapper(url=bse_get_running_services_url, headers=header)
                status_code, response = client.get(verify=False)
                if status_code == 200:
                    self.__logger.info("Step 3 : Successfully authorized, BSE list of running resources")
                    self.__logger.info(response.json())
                else:
                    self.__logger.error("Failed to get services list response code {}".format(status_code))
            else:
                self.__logger.error("Failed to Get Capability Token with response code {}".format(status_code))
        else:
            self.__logger.error("Failed to Get Authentication Token with response code {}".format(status_code))
        return status_code, response

    def deh_bse_get_bse_register_service_payload(self, parameter):
        if 'id' in parameter:
            service_name = parameter['id']
        elif 'name' in parameter:
            service_name = parameter['name']

        return

    def deh_bse_get_service_by_parameter(self, parameter):
        """TODO : Not used ,in-corporate ed search by name functionality in method deh_bse_get_running_services"""
        """ BSE endpoint that returns a list of the running services """
        header = app.config['DEH_BSE_Request_Header']

        # Step 1 Attributes:
        asc_token_url = app.config['DEH_BSE_ACS_Token_Request_Url']
        asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}

        # Step 2 Attributes:
        capability_token_url = app.config['DEH_BSE_Capability_Token_Url']
        capability_token_payload = app.config['Request_Capability_Token_Format']
        '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
            "de": "$ProxyURL", "re": "$Resource"}'''
        capability_token_proxy_url = app.config['DEH_BSE_Proxy_URL']
        capability_token_request_services = app.config['DEH_BSE_GET_SERVICE']

        status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, header)
        if status_code in (200, 201):
            auth_token = response.headers['X-Subject-Token']
            capability_token_payload['token'] = auth_token
            capability_token_payload['ac'] = "GET"
            capability_token_payload['de'] = capability_token_proxy_url
            capability_token_payload['re'] = capability_token_request_services
            status_code, response = self.request_capability_token(capability_token_url,
                                                                  capability_token_payload,
                                                                  header)
            if status_code == 200:
                # Adding the entire capacity token request's response as x-auth-token header for saving resource
                capability_token_response = response
                header['x-auth-token'] = capability_token_response.text
                # As per new RRM change, x-subject-token needs to be included in all RRM API request
                header['x-subject-token'] = auth_token
                bse_get_service_by_name_url = self.url + self.method + "/" + self.payload['service_name']
                self.__logger.info("BSE list all services : " + bse_get_service_by_name_url)
                client = API.APIWrapper(url=bse_get_service_by_name_url, headers=header)
                status_code, response = client.get(verify=False)
                if status_code == 200:
                    self.__logger.info("Step 3 : Successfully authorized, BSE list of running resources")
                    self.__logger.info(response.json())
                else:
                    self.__logger.error("Failed to get service by name with response code {}".format(status_code))
            else:
                self.__logger.error("Failed to Get Capability Token with response code {}".format(status_code))
        else:
            self.__logger.error("Failed to Get Authentication Token with response code {}".format(status_code))
        return status_code, response

    def deh_bse_post_register_service(self):
        """ BSE endpoint that returns a list of the running services """
        header = app.config['DEH_BSE_Request_Header']
        # Step 1 Attributes:
        asc_token_url = app.config['DEH_BSE_ACS_Token_Request_Url']
        asc_token_payload = {"name": app.config['DEH_ACCOUNT_MAIL'], "password": app.config['DEH_ACCOUNT_PASS']}

        # Step 2 Attributes:
        capability_token_url = app.config['DEH_BSE_Capability_Token_Url']
        capability_token_payload = app.config['Request_Capability_Token_Format']
        '''{"token": "$X-Subject-Token", "ac": "$RequestMethod",
            "de": "$ProxyURL", "re": "$Resource"}'''
        capability_token_proxy_url = app.config['DEH_BSE_Proxy_URL']
        capability_token_request_services = app.config['DEH_BSE_Register_Service']

        status_code, response = self.request_acs_token(asc_token_url, asc_token_payload, header)
        if status_code in (200, 201):
            auth_token = response.headers['X-Subject-Token']
            capability_token_payload['token'] = auth_token
            capability_token_payload['ac'] = "POST"
            capability_token_payload['de'] = capability_token_proxy_url
            capability_token_payload['re'] = capability_token_request_services
            status_code, capability_token_response = self.request_capability_token(capability_token_url,
                                                                                   capability_token_payload, header)
            if 'tag' not in self.payload:
                self.payload['tags'] = ["Test"]
            if status_code == 200:
                # Step 3 Register service with BSE:
                bse_service_register_url = self.url + self.method
                header['x-auth-token'] = capability_token_response.text
                deh_id = None
                if 'deh_id' not in self.payload:
                    # GET RRM info
                    method = app.config['DEHEnablerHub_Search_Resource']
                    # deh_enabler_hub_obj = DEHAPIWrapper()
                    parameters = {"name": self.payload['service_name']}
                    status_code, response = self.deh_enabler_hub_resource_search(payload=parameters,
                                                                                 method=method)
                    if status_code == 200 and response.json()[
                        "message"] != "Bad request." and "data" in response.json():
                        contents = response.json()["data"]
                        if len(contents) == 0:
                            self.__logger.info("Service {} not registered to DEH Enabler Hub RRM, "
                                               "Now attempt to register.".format(self.payload['service_name']))
                        else:
                            """#TODO: Handle multiple resources with same name in future"""
                            for resource in contents:
                                deh_id = resource['uid']
                                break
                            # name = response.json()['name']
                payload = {"service_name": self.payload['service_name'],
                           "tags": self.payload['tags'],
                           "meta": {
                               "deh_id": deh_id,
                               "featureList": ["NEW TEST FEATURE LIST"],
                               "applicationCategory": "NEW applicationCategory LIST",
                               "apiModel": {
                                   "dataProtocol": "REST",
                                   "baseUrl": "GOOGLE.COM",
                                   "relativePath": "/path",
                                   "method": "GET",
                                   "successResponse": [200],
                                   "errorResponse": [500],
                                   "topic": "TEST",
                                   "payloadFormat": "JSON"}
                           },
                           "port": 0,
                           "address": "string"}

                payload = {"service_name": self.payload['service_name'],
                           "tags": self.payload['tags'],
                           "meta": {"deh_id": deh_id,
                                    "featureList": ["NEW TEST FEATURE LIST"],
                                    "applicationCategory": "NEW applicationCategory LIST",
                                    "apiModel": {
                                        "dataProtocol": "REST",
                                        "baseUrl": "GOOGLE.COM",
                                        "relativePath": "path",
                                        "method": "GET",
                                        "successResponse": [200],
                                        "errorResponse": [500],
                                        "topic": "DDDDDD",
                                        "payloadFormat": "JSON"}
                                    },
                           "port": 0,
                           "address": "string"}

                payload = {
                        "Service_name": self.payload['service_name'],
                        "Tags": self.payload['tags'],
                        "Meta": {
                            "URLOptionalParams": "{}",
                            "URLRequiredParams": "{}",
                            "applicationCategory": "algorithm",
                            "authentication": "False",
                            "baseUrl": "http://161.27.206.132:9380",
                            "dataEncryption": "False",
                            "dataParams": "{}",
                            "dataProtocol": "REST",
                            "deh_id": deh_id,
                            "errorResponse": "[0]",
                            "featureList": "['feature1']",
                            "method": "GET/POST",
                            "payloadFormat": "JSON-LD",
                            "payloadRepresentation": "{}",
                            "provider": "Engineering",
                            "relativePath": "TEST",
                            "sampleCall": "",
                            "successResponse": "[0]",
                            "topic": "string",
                            "version": "1"
                        },
                        "Port": 9380,
                        "Address": "161.27.206.132"
                    }
                client = API.APIWrapper(url=bse_service_register_url, payload=json.dumps(payload), headers=header)
                status_code, response = client.post(verify=False)
                # response = requests.request("POST", bse_service_register_url, data=payload, headers=header)
                # status_code = response.status_code
                print(response.text)
                if status_code == 200:
                    self.__logger.info("Step 3 : Successfully registered service to BSE")
                    self.__logger.info(response.text)
                else:
                    self.__logger.error("Failed to register services to BSE with response code {}".format(status_code))
            else:
                self.__logger.error("Failed to Get Capability Token with response code {}".format(status_code))
        else:
            self.__logger.error("Failed to Get Authentication Token with response code {}".format(status_code))
            self.__logger.error("Failed to Get Authentication Token with response code {}".format(status_code))
        return status_code, response

    def deh_bse_check_resource_registration(self, service_name):
        """TODO: May be this will be removed if DEH Client is not responsible for registering to BSE"""
        # Check if the service/ resource is registered to BSE, if not register
        response = None
        host = app.config['DEH_BSE_Proxy_URL']
        method = app.config['DEH_BSE_GET_SERVICE']
        """ Note : The service name is case sensitive"""
        deh_bse_obj = DEHAPIWrapper(host, method,
                                    payload={"service_name": service_name})
        status_code, response = deh_bse_obj.deh_bse_get_running_services()
        if status_code == 200 and response.json() == {}:
            self.__logger.info("Service {} not registered to BSE, "
                               "Now attempt to register to BSE.".format(service_name))
            method = app.config['DEH_BSE_Register_Service']
            deh_bse_obj = DEHAPIWrapper(host, method,
                                        payload={"service_name": service_name})
            status_code, response = deh_bse_obj.deh_bse_post_register_service()
            if status_code == 200:
                self.__logger.info("Successfully registered service: {} to BSE.".format(service_name))
            else:
                self.__logger.error("Registration service: {} to BSE failed.".format(service_name))
        else:
            self.__logger.info("Service: {} already registered to BSE.".format(service_name))
        return response

    def deh_rrm_check_resource_registration(self, resource_name, resource_data):
        # Check if the service/ resource is registered to RRM, if not register
        self.__logger.info("Checking if the service/ resource is registered to RRM, if not set to register")
        method = app.config['DEHEnablerHub_Search_Resource']
        deh_enabler_hub_obj = DEHAPIWrapper()
        parameters = {"name": resource_name}
        status_code, response = deh_enabler_hub_obj.deh_enabler_hub_resource_search(payload=parameters,
                                                                                    method=method)
        if status_code == 200 and response.json()["message"] != "Bad request." and "data" in response.json():

            print(response.json())

            contents = response.json()["data"]
            if contents is not None:
                self.__logger.info("Resource Name Attempting To Register : ".format(resource_name))
                self.__logger.info("Resource Data For Resource Name Attempting To Register".format(resource_data))
                if len(contents) == 0:
                    self.__logger.info("Service {} not registered to DEH Enabler Hub RRM, "
                                       "Now attempt to register.".format(resource_name))
                    deh_enabler_hub_obj = DEHAPIWrapper()
                    self.__logger.info("Resource Registration Metadata :{} ".format(resource_data))
                    self.__logger.info("deh_rrm_check_resource_registration Resource Data {}".format(resource_data))
                    status_code, response = deh_enabler_hub_obj.save_deh_resource(resource_data, request_type="POST")
                    if status_code == 200:
                        self.__logger.info("Successfully registered resource: {} "
                                           "to DEH Enabler Hub RRM with response:\n {}."
                                           .format(resource_name, response.text))
                    if status_code == 409:
                        # In case of attempting to register a resource, which is already registered with RRM,
                        # The RRM POST request response : Response Code
                        """
                        {
                        "httpStatus": "CONFLICT",
                        "message": "Resource with a name estimate-animal-welfare-condition-demo1 already exists",
                        "timestamp": "27-04-2021 03:19:39",
                        "path": "/api/v1/resources"
                        }
                        """
                        self.__logger.info("Seems Resource/ Service: {} already registered to DEH Enabler Hub RRM."
                                           .format(resource_name))
                        self.__logger.info("Response : {}.".format(response.json()))
                    else:
                        self.__logger.error("Failure to Register resource: {} to DEH Enabler Hub RRM."
                                            .format(resource_name))

        else:
            self.__logger.error("Failure to connect with RRM to DEH Enabler Hub RRM.")
            self.__logger.error("Response : {}.".format(response.json()))
        return response
