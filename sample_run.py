#!/usr/bin/env python2.7
import cherrypy
import os
import json
import sys
import threading
import traceback
import webbrowser
import datetime
import pprint

from base64 import b64encode
from fitbit.api import Fitbit
from oauthlib.oauth2.rfc6749.errors import MismatchingStateError, MissingTokenError

# Attribution: This is a copy of:
#    https://github.com/orcasgit/python-fitbit/blob/master/gather_keys_oauth2.py
# ...and is licensed under Apache Version 2.0 as a result. 

# Globals; should work around
global_client_id = None
global_client_secret = None


class OAuth2Server:
    def __init__(self, client_id, client_secret,
                 redirect_uri='http://127.0.0.1:8080/'):

        """ Initialize the FitbitOauth2Client """
        self.success_html = """
            <h1>You are now authorized to access the Fitbit API!</h1>
            <br/><h3>You can close this window</h3>"""
        self.failure_html = """
            <h1>ERROR: %s</h1><br/><h3>You can close this window</h3>%s"""

        self.fitbit = Fitbit(
            client_id,
            client_secret,
            redirect_uri=redirect_uri,
            timeout=10,
        )

    def browser_authorize(self):
        """
        Open a browser to the authorization url and spool up a CherryPy
        server to accept the response
        """
        url, _ = self.fitbit.client.authorize_token_url()
        # Open the web browser in a new thread for command-line browser support
        threading.Timer(1, webbrowser.open, args=(url,)).start()
        cherrypy.quickstart(self)

    @cherrypy.expose
    def index(self, state, code=None, error=None):
        """
        Receive a Fitbit response containing a verification code. Use the code
        to fetch the access_token.
        """
        error = None
        if code:
            try:
                self.fitbit.client.fetch_access_token(code)
            except MissingTokenError:
                error = self._fmt_failure(
                    'Missing access token parameter.</br>Please check that '
                    'you are using the correct client_secret')
            except MismatchingStateError:
                error = self._fmt_failure('CSRF Warning! Mismatching state')
        else:
            error = self._fmt_failure('Unknown error while authenticating')
        # Use a thread to shutdown cherrypy so we can return HTML first
        self._shutdown_cherrypy()
        return error if error else self.success_html

    def _fmt_failure(self, message):
        tb = traceback.format_tb(sys.exc_info()[2])
        tb_html = '<pre>%s</pre>' % ('\n'.join(tb)) if tb else ''
        return self.failure_html % (message, tb_html)

    def _shutdown_cherrypy(self):
        """ Shutdown cherrypy in one second, if it's running """
        if cherrypy.engine.state == cherrypy.engine.states.STARTED:
            threading.Timer(1, cherrypy.engine.exit).start()


def read_keys_file():
    try:
        keys = {}
        for line in open('token.txt', 'r'):
            parts = line.strip().split("=",1)
            if len(parts) == 2:
                keys[parts[0]] = parts[1]
        return keys
    except:
        return {}

def save_output_file(client_id, client_secret, item_dict):
    out = open('token.txt', 'w')
    print('TOKEN\n=====\n')
    for key, value in item_dict:
        print('{}={}'.format(key, value))
        out.write('{}={}\n'.format(key, value))
    out.write('client_id={}\n'.format(client_id))
    out.write('client_secret={}\n'.format(client_secret))
    out.close()


def serialize_and_save_inner(obj):
    # There should be exactly one key, and a series of dated values.
    full_key = None
    values = {} # DateStr => ObjType
    if isinstance(obj, dict):
        if len(obj) == 1:
            for key, val in obj.items():
                full_key = key
                if isinstance(val, list):
                    for entry in val:
                        if isinstance(entry, dict):
                            if ('dateTime' in entry) and ('value' in entry):
                                dt = entry['dateTime']
                                objVal = entry['value']
                                try:
                                    datetime.datetime.strptime(dt, "%Y-%m-%d")
                                except ValueError:
                                    print("Error: Bad date string: %s" % dt)
                                    return None
                                values[dt] = objVal
                            else:
                                print("Error: Value in list does not contain 'dateTime' or 'value'")
                                return None
                        else:
                            print("Error: Value in list is not map")
                            return None
                else:
                    print("Error: Top-Level value is not a list")
                    return None
        else:
            print("Error: Object has more than one entry")
            return None
    else:
        print("Error: Object is not a dictionary.")
        return None
    return full_key, values


def serialize_and_save(obj):
    key, values = serialize_and_save_inner(obj)  #TODO: This might not return right?
    if not values:
        # Make debugging easier
        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(obj)
        return False

    # Save them
    for dt, val in values.items():
        dirname = "./data/" + dt
        if not os.path.exists(dirname):
          os.mkdir(dirname)
        filename = dirname + "/" + key
        
        # We currently just overwrite the file; we could check for newer or "greater" data, but not right now.
        out = open(filename, 'w')
        json.dump(val, out)
        out.close()

    return True

def get_all_data(fitbit, startDate, endDate):
    res = True

    # The first time, we need to go back 1 year (or so).
    rangeAmt = 1
    testDate = endDate - datetime.timedelta(days=365)
    if not os.path.exists('./data/' + testDate.strftime("%Y-%m-%d")):
        print("FIRST TIME USE; Requesting a year's worth of data")
        startDate = endDate - datetime.timedelta(days=30)
        rangeAmt = 14


    for i in range(0, rangeAmt):
        if i > 0:
            endDate = endDate - datetime.timedelta(days=30)
            startDate = startDate - datetime.timedelta(days=30)

        st = startDate.strftime("%Y-%m-%d")
        ed = endDate.strftime("%Y-%m-%d")

        print("Getting data for range: %s => %s" % (st, ed))

        # Each of these can grab lots of data
        res = res and serialize_and_save(fitbit.time_series('activities/calories', base_date=st, end_date=ed))
        res = res and serialize_and_save(fitbit.time_series('activities/caloriesBMR', base_date=st, end_date=ed))
        res = res and serialize_and_save(fitbit.time_series('activities/activityCalories', base_date=st, end_date=ed))
        res = res and serialize_and_save(fitbit.time_series('activities/steps', base_date=st, end_date=ed))

        # Only some of these might be useful
        res = res and serialize_and_save(fitbit.time_series('activities/minutesSedentary', base_date=st, end_date=ed))
        res = res and serialize_and_save(fitbit.time_series('activities/minutesLightlyActive', base_date=st, end_date=ed))
        res = res and serialize_and_save(fitbit.time_series('activities/minutesFairlyActive', base_date=st, end_date=ed))
        res = res and serialize_and_save(fitbit.time_series('activities/minutesVeryActive', base_date=st, end_date=ed))

        # This is useful (includes various heart rate zones, and resting heart rate)
        res = res and serialize_and_save(fitbit.time_series('activities/heart', base_date=st, end_date=ed))

    return res



# Token refresh
def my_refresh_cb(keys):
    print("REFRESH_CB: %s" % keys)
    save_output_file(global_client_id, global_client_secret, keys)

def verify_keys(keys):
    global global_client_id
    global global_client_secret

    # First, make sure we have all properties
    user_id = keys.get('user_id', None)
    refresh_token = keys.get('refresh_token', None)
    access_token = keys.get('access_token', None)
    expires_at = keys.get('expires_at', None)
    client_id = keys.get('client_id', None)
    client_secret = keys.get('client_secret', None)
    if not (user_id and refresh_token and access_token and expires_at and client_id and client_secret):
        print("user_id, refresh_token, access_token, expires_at, client_id, and client_secret are not all present; re-authenticating")
        return False

    # No good way around this....
    global_client_id = client_id
    global_client_secret = client_secret

    # This needs a nudge; we don't care about microseconds
    expires_at = expires_at.split(".")[0]

    # If we have everything, try using our token
    # TODO: refresh_cb, and re-use Fitbit object
    fitbit = Fitbit(client_id, client_secret, timeout=10, access_token=access_token, refresh_token=refresh_token, expires_at=expires_at, refresh_cb=my_refresh_cb)
    
    # We always read back 30 days, just to get a window.
    ed = datetime.datetime.now()
    st = ed - datetime.timedelta(days=10)

    # Build up results
    res = get_all_data(fitbit, st, ed)

    return res



if __name__ == '__main__':
    # Make a folder to hold the data.
    if not os.path.exists("./data"):
      os.mkdir("./data")

    # Try reading the token from a file.
    keys = read_keys_file()

    # Certain keys are required to avoid parsing args
    if not verify_keys(keys):
        raise Exception("Keys not verified")



    if len(sys.argv) != 3:
        print("Arguments: client_id and client_secret")
        sys.exit(1)

    server = OAuth2Server(*sys.argv[1:])
    server.browser_authorize()

    profile = server.fitbit.user_profile_get()
    print('You are authorized to access data for the user: {}'.format(profile['user']['fullName']))

    # Write to file, and print
    save_output_file(sys.argv[1], sys.argv[2], server.fitbit.client.session.token.items())
