#!/usr/bin/env python
import web
import json
import sys
import os
import logging
from web.wsgiserver import CherryPyWSGIServer
import libs.wblistadm_utils as wb
from libs.utils import *
from libs.auth import *

os.environ['LC_ALL'] = 'C'

rootdir = os.path.abspath(os.path.dirname(__file__)) + '/../'
sys.path.insert(0, rootdir)

urls = (
    '/ticket', 'Ticket', 
    '/show/(whitelist|blacklist)/(.+)', 'ShowList', 
    '/show/(whitelist|blacklist)', 'ShowList',
    '/show(/(?!.*list).+)?', 'ShowList',
    '/add/(whitelist|blacklist)/(.+)', 'AddList', 
    '/add/(whitelist|blacklist)', 'AddList',
    '/delete/(whitelist|blacklist)/(.+)', 'DeleteList', 
    '/delete/(whitelist|blacklist)', 'DeleteList',
)

authCookie = 'WBAuthCookie'
        
def notfound():
    web.header('Content-Type', 'application/json')
    return web.notfound(json.dumps({'ok': 0, 'errcode': 404}))

def internalerror():
    web.header('Content-Type', 'application/json')
    return web.internalerror(json.dumps({'ok': 0, 'errcode': 500}))

def badrequest(message = None):
    if not message:
        message = 'Required data missing'
    error = json.dumps({'err': message, 'errcode': 400})
    status = "400 Bad Request"
    headers = {'Content-Type': 'application/json'}
    raise web.HTTPError(status, headers, error)
    
def unauthorized(message = None):
    if not message:
        message = 'Missing ticket'
    error = json.dumps({'err': message, 'errcode': 401})
    status = "401 Unauthorized"
    headers = {'Content-Type': 'application/json'}
    raise web.HTTPError(status, headers, error)
    
def nomethod(message = None):
    if not message:
        message = 'Method not allowed'
    error = json.dumps({'err': message, 'errcode': 405})
    status = "405 Method Not Allowed"
    headers = {'Content-Type': 'application/json'}
    raise web.HTTPError(status, headers, error)

class Server(web.application):
    def run(self, listen = '0.0.0.0', port = 8080, *middleware):
        func = self.wsgifunc(*middleware)
        return web.httpserver.runsimple(func, (listen, port))

class ShowList:
    def GET(self, function = None, identifier = None):
        session = web.config._session
        wbauth = Cookie(web.cookies().get(authCookie))
        if not wbauth:
            return unauthorized()
        if not session.ticket['ticket'] == wbauth.ticket:
            return unauthorized()
        logging.info("showList (GET): %s %s %s" % (function, identifier,  wbauth))
        if not validateCSRFToken(web.ctx.env, session):
            return unauthorized()
        if not function:
            rows = wb.show_wblist(None, None, silent = True)
            return createResponse(web, rows)
        else:
            if function.startswith('/'):
                identifier = function.lstrip('/')
                function = None
            rows = wb.show_wblist(function, identifier, silent = True)
            return createResponse(web, rows)

class AddList:
    def GET(self, function, identifier = None):
        return nomethod()
        
    def POST(self, function, identifier = None):
        session = web.config._session
        wbauth = Cookie(web.cookies().get(authCookie))
        if not wbauth:
            return unauthorized()
        if not session.ticket['ticket'] == wbauth.ticket:
            return unauthorized()
        if not validateCSRFToken(web.ctx.env, session):
            return unauthorized()
        data = web.data() # you can get data use this method
        if not data:
            return badrequest()
        logging.info("addList (POST): %s" % data)
        wblist = json2List(data)
        if wblist and not type(wblist) == str:
            wb.update_wblist('add', function, wblist, identifier)
            return createResponse(web, '')
        else:
            if wblist:
                return badrequest(wblist)
            else:
                return badrequest()

class DeleteList:
    def GET(self, function, identifier = None):
        return nomethod()
        
    def POST(self, function, identifier = None):
        session = web.config._session
        wbauth = Cookie(web.cookies().get(authCookie))
        if not wbauth:
            return unauthorized()
        if not session.ticket['ticket'] == wbauth.ticket:
            return unauthorized()
        if not validateCSRFToken(web.ctx.env, session):
            return unauthorized()
        data = web.data() # you can get data use this method
        logging.info("deleteList (POST): %s" % data)
        wblist = json2List(data)
        if wblist and not type(wblist) == str:
            wb.update_wblist('delete', function, wblist, identifier)
            return createResponse(web, '')
        else:
            if wblist:
                return badrequest(wblist)
            else:
                return badrequest()

class Ticket:
    def GET(self):
        return nomethod()

    def POST(self):
        session = web.config._session
        config = web.config._config
        data = web.data() # you can get data use this method
        if not data:
            return badrequest()
        ticket = createTicket(session, data)
        logging.info('ticket: ' + str(ticket))
        if not ticket:
            return unauthorized()
        if config['ssl_certificate'] and config['ssl_private_key']:
            secure = True
        else:
            secure = False
        web.setcookie(authCookie, 'ticket='+ticket['ticket'], config['session_timeout'], None, secure)
        return createResponse(web, ticket)
        
class Logger(object):
    def write(self, message):
        if not message == '\n':
            logging.info(message)

if __name__ == "__main__":
    config = parseSettings()
    web.config._config = config

    if config['log_file'] == 'stderr':
        logging.basicConfig(level=config['log_level'],
                            format='* [%(asctime)s] %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S', 
                            stream=sys.stderr)
    else:
        logging.basicConfig(level=logging.DEBUG,
                            format='* [%(asctime)s] %(message)s',
                            datefmt='%Y-%m-%d %H:%M:%S', 
                            filename=config['log_file'])
    sys.stderr = Logger()

    if config['ssl_certificate'] and config['ssl_private_key']:
        CherryPyWSGIServer.ssl_certificate = config['ssl_certificate']
        CherryPyWSGIServer.ssl_private_key = config['ssl_private_key']
        logging.info('Found certificate and key. Enabling HTTPS')
    else:
        logging.info('Certificate and key not found. Disabling HTTPS')

    app = Server(urls, globals())
    if config['debug']:
        web.config.debug = True
        app.internalerror = web.debugerror
    else:
        web.config.debug = False
        app.internalerror = internalerror
    app.notfound = notfound
    if web.config.get('_session') is None:
        session = web.session.Session(app, web.session.DiskStore(config['session_dir']))
        web.config._session = session
    else:
        session = web.config._session
        
    rt = RepeatedTimer(5*60, cleanSessionsFiles, config['session_timeout'], config['session_dir'])
    try:
        app.run(listen = config['listen'], port = config['port'])
    finally:
        rt.stop()
