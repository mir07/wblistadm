import os
import time
import json
import server_settings as settings
import logging
from libs import is_valid_amavisd_address
from threading import Timer
import glob

def createResponse(web, data, status = None):
    web.header('Content-Type', 'application/json')
    if status:
        web.ctx.status = status
    if data:
        if not status:
            web.ctx.status = '200 OK'
        result = "{'data': %s}" % json.dumps(data)
    else:
        if not status:
            if data == None:
                web.ctx.status = '204 NoContent'
            else:
                web.ctx.status = '200 OK'
        if data == None:
            result = None
        else:
            if data:
                result = "{'data': %s}" % json.dumps(data)
            else:
                result = None

    return result

def parseSettings():
    config = {}
    try:
        if settings.log_level == 0:
            config['log_level'] = logging.DEBUG
        elif settings.log_level == 1:
            config['log_level'] = logging.INFO
        elif settings.log_level == 2:
            config['log_level'] = logging.WARNING
        elif settings.log_level == 3:
            config['log_level'] = logging.ERROR
        else:
            config['log_level'] = logging.WARNING
    except AttributeError:
        config['log_level'] = logging.WARNING
    try:
        config['log_file'] = settings.log_file
    except AttributeError:
        config['log_file'] = 'stderr'
    try:
        config['listen'] = settings.listen
    except AttributeError:
        config['listen'] = '127.0.0.1'
    try:
        config['session_timeout'] = settings.session_timeout
    except AttributeError:
        config['session_timeout'] = 60*60*2
    try:
        config['port'] = settings.port
    except AttributeError:
        config['port'] = 8080
    try:
        config['ssl_certificate'] = settings.ssl_certificate
    except AttributeError:
        config['ssl_certificate'] = None
    try:
        config['ssl_private_key'] = settings.ssl_private_key
    except AttributeError:
        config['ssl_private_key'] = None
    try:
        config['debug'] = settings.debug
    except AttributeError:
        config['debug'] = False
    try:
        config['session_dir'] = settings.session_dir
    except AttributeError:
        config['session_dir'] = 'sessions'

    return config
    
def str2Dict(string, delim = '=', group = '&'):
    try:
        params = dict([p.split(delim) for p in string.split(group)])
    except:
        params = {}

    return params

def json2List(string):
    try:
        data = json.loads(string)
    except ValueError, e:
        return str(e)

    list = [v for v in data if is_valid_amavisd_address(v)]

    return list

def cleanSessionsFiles(expire, dir):
    pattern = dir + '/*'
    now = time.time()
    
    logging.info("Timer: %s, dir: %s" % (expire, dir))
    files = glob.glob(pattern)
    for file in files:
        logging.debug('Consider %s for cleaning' % file)
        if now > os.stat(file).st_ctime + expire:
            logging.info("Remove %s" % file)
            os.remove(file)
        else:
            logging.debug("Keeping %s" % file)

class RepeatedTimer(object):
    def __init__(self, interval, function, *args, **kwargs):
        self._timer     = None
        self.interval   = interval
        self.function   = function
        self.args       = args
        self.kwargs     = kwargs
        self.is_running = False
        self.start()

    def _run(self):
        self.is_running = False
        self.start()
        self.function(*self.args, **self.kwargs)

    def start(self):
        if not self.is_running:
            self._timer = Timer(self.interval, self._run)
            self._timer.start()
            self.is_running = True

    def stop(self):
        self._timer.cancel()
        self.is_running = False
