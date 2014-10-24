#!/usr/bin/env python

import sys
import cherrypy
import ConfigParser
import urlparse
import json
import requests

from requests.auth import HTTPBasicAuth

CONFIG_FILE='oauth2-settings.cfg'


class OAuth2():
    """
    OAuth 2.0 Client (Authorization Code Flow)
    """

    def login(self, appname=None):
        print('##### login #####')
        """
        http://.../oauth2/login/@authz_servername@/
        Redirect to OAuth2.0 Authorization Endpoint
        """

        if not appname:
            print('Error : Please specify appname')
            return 'Please specify appname (http://hostname/oauth2/login/appname/)'

        try:
            cl_conf = OAuth2Config().get_conf(appname)
            cherrypy.session['appname'] = appname
            print('cl_conf={0}'.format(cl_conf))

            query_string = None
            for param in cl_conf.get('authz_edp_params'):
                if query_string is None:
                    query_string = ('{0}={1}'
                                    .format(param, cl_conf.get(param)))
                else:
                    query_string = ('{0}&{1}={2}'
                                    .format(query_string, param,
                                            cl_conf.get(param)))

            url = ('{azu}?{qst}'
                    .format(azu=cl_conf.get('authz_edp_uri'),
                            qst=query_string))

            print('authz url={0}'.format(url))
        except:
            print('Error : {0}'.format(str(sys.exc_info()[1])))
            return 'login error'

        raise cherrypy.HTTPRedirect(url, 302)

    def callback(self, **query):
        print('##### callback #####')
        """
        http://.../oauth2/callback
        OAuth 2.0 redirect_uri (get authorization code)
        """

        print('query={0}'.format(query))
        try:
            authz_resp = {}
            if query.has_key('state'):
                authz_resp['state'] = query.get('state')
            if query.has_key('code'):
                authz_resp['code'] = query.get('code')

            print('authz response={0}'.format(authz_resp))
            if len(authz_resp) == 0:
               raise Exception('callback error(empty response)')
            access_token = self.get_atoken(authz_resp)
            userinfo_resp = self.get_userinfo(access_token)
        except:
            print('Error : {0}'.format(str(sys.exc_info()[1])))
            return 'callback error'

        return userinfo_resp

    def get_atoken(self, authz_resp):
        print('##### get_atoken #####')

        access_token = None
        try:
            appname = cherrypy.session.get('appname')
            cl_conf = OAuth2Config().get_conf(appname)

            url = cl_conf.get('atoken_edp_uri')
            http_method = cl_conf.get('atoken_edp_method')
            atoken_edp_resp = cl_conf.get('atoken_edp_resp')
            atoken_edp_authtype = cl_conf.get('atoken_edp_authtype')

            request_data = {}
            for param in cl_conf.get('atoken_edp_params'):
                if param == 'code':
                    request_data[param] = authz_resp.get(param)
                else:
                    request_data[param] = cl_conf.get(param)

            print('request url={0}'.format(url))
            print('request data={0}'.format(request_data))

            if atoken_edp_authtype == 'cl_secret':
                if http_method == 'POST':
                    resp = requests.post(url, data=request_data)
                elif http_method == 'GET':
                    resp = requests.get(url, params=request_data)
            elif atoken_edp_authtype == 'basic':
                if http_method == 'POST':
                    resp = requests.post(url, data=request_data,
                        auth=HTTPBasicAuth(cl_conf.get('client_id'),
                                           cl_conf.get('client_secret')))
                elif http_method == 'GET':
                    resp = requests.get(url, params=request_data,
                        auth=HTTPBasicAuth(cl_conf.get('client_id'),
                                           cl_conf.get('client_secret')))

            print('response content-type={0}'.format(resp.headers['content-type']))
            print('response encoding={0}'.format(resp.encoding))
            print('response text={0}'.format(resp.text))

            if atoken_edp_resp == 'json':
                print('response json={0}'.format(resp.json()))
                access_token = resp.json().get('access_token')
            elif atoken_edp_resp == 'query_string':
                qs_dic = urlparse.parse_qs(resp.text)
                access_token = qs_dic.get('access_token')

            print('access token={0}'.format(access_token))

        except:
            print('Error : {0}'.format(str(sys.exc_info()[1])))
            raise Exception('access token error')

        return access_token


    def get_userinfo(self, atoken):
        print('##### get_userinfo #####')

        resp = None
        try:
            appname = cherrypy.session.get('appname')
            cl_conf = OAuth2Config().get_conf(appname)
            url = cl_conf.get('userinfo_edp_uri')
            http_method = cl_conf.get('userinfo_edp_method')

            request_headers = {'Authorization' : 'Bearer {0}'.format(atoken)}
            request_data = {}

            if cl_conf.get('userinfo_edp_params'):
                for param in cl_conf.get('userinfo_edp_params'):
                    request_data[param] = cl_conf.get(param)

            print('request url={0}'.format(url))
            print('request data={0}'.format(request_data))
            if http_method == 'GET':
                resp = requests.get(url, params=request_data,
                            headers=request_headers)
                print('response url={0}'.format(resp.url))
                print('response content-type={0}'.format(resp.headers['content-type']))
                print('response encoding={0}'.format(resp.encoding))
                print('response text={0}'.format(resp.text.encode('utf-8')))
                print('response json={0}'.format(resp.json()))
        except:
            print('Error : {0}'.format(str(sys.exc_info()[1])))
            raise Exception('userinfo error')

        if resp is None:
            raise Exception('userinfo error')

        return resp.text

    login.exposed = True
    callback.exposed = True


class OAuth2Config():
    """
    Configuration
    """

    def get_conf(self, client_name):
        conf = ConfigParser.SafeConfigParser()
        conf.read(CONFIG_FILE)

        oauth2conf = {}
        try:
            oauth2conf['client_id'] = conf.get(client_name, 'client_id')
            oauth2conf['client_secret'] = conf.get(client_name,
                                            'client_secret')
            oauth2conf['schema'] = conf.get(client_name, 'schema')

            oauth2conf['authz_edp_uri'] = conf.get(client_name, 'authz_edp_uri')
            oauth2conf['authz_edp_method'] = conf.get(client_name,
                                                'authz_edp_method')
            oauth2conf['authz_edp_params'] = conf.get(client_name,
                                        'authz_edp_params').split('|')

            oauth2conf['atoken_edp_uri'] = conf.get(client_name, 'atoken_edp_uri')
            oauth2conf['atoken_edp_method'] = conf.get(client_name,
                                              'atoken_edp_method')
            oauth2conf['atoken_edp_authtype'] = conf.get(client_name,
                                                'atoken_edp_authtype')
            oauth2conf['atoken_edp_params'] = conf.get(client_name,
                                        'atoken_edp_params').split('|')
            oauth2conf['atoken_edp_resp'] = conf.get(client_name,
                                            'atoken_edp_resp')


            oauth2conf['userinfo_edp_uri'] = conf.get(client_name,
                                         'userinfo_edp_uri')
            oauth2conf['userinfo_edp_method'] = conf.get(client_name,
                                                'userinfo_edp_method')
            oauth2conf['userinfo_edp_params'] = conf.get(client_name,
                                                'userinfo_edp_params').split('|')

            oauth2conf['redirect_uri'] = conf.get(client_name,
                                         'redirect_uri')

            oauth2conf['response_type'] = conf.get(client_name,
                                          'response_type')
            oauth2conf['grant_type'] = conf.get(client_name,
                                       'grant_type')
            oauth2conf['state'] = conf.get(client_name, 'state')
            oauth2conf['scope'] = conf.get(client_name, 'scope')
            oauth2conf['login_hint'] = conf.get(client_name,
                                       'login_hint')
            oauth2conf['approval_prompt'] = conf.get(client_name,
                                            'approval_prompt')

            oauth2conf['realm'] = conf.get(client_name,
                                            'realm')
        except ConfigParser.NoSectionError:
            print('Error : No such section [{sec}]'.format(sec=client_name))
            raise Exception('ConfigParser Error')
        except ConfigParser.NoOptionError:
            print('Error : No such option : {0}'.format(str(sys.exc_info()[1])))
            raise Exception('ConfigParser Error')
        except:
            print('Error : {0}'.format(str(sys.exc_info()[1])))
            raise Exception('ConfigParser Error')

        return oauth2conf


class Root():
    """
    Root Application
    """

    oauth2 = OAuth2()

    def index(self):
        # http://localhost:@port_number@/
        return "Root"

    index.exposed = True

if __name__ == '__main__':
    cherrypy.quickstart(Root(), config='cherrypy-settings.cfg')

