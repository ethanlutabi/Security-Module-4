#!/usr/bin/env python2.7

"""Gruyere - a web application with holes.

Copyright 2017 Google Inc. All rights reserved.

This code is licensed under the
https://creativecommons.org/licenses/by-nd/3.0/us/
Creative Commons Attribution-No Derivative Works 3.0 United States license.

DO NOT COPY THIS CODE!

This application is a small self-contained web application with numerous
security holes. It is provided for use with the Web Application Exploits and
Defenses codelab. You may modify the code for your own use while doing the
codelab but you may not distribute the modified code. Brief excerpts of this
code may be used for educational or instructional purposes provided this
notice is kept intact. By using Gruyere you agree to the Terms of Service
https://www.google.com/intl/en/policies/terms/
"""

__author__ = 'Bruce Leban'

# system modules
from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
import cgi
import cPickle
import os
import random
import sys
import threading
import urllib
from urlparse import urlparse

try:
  sys.dont_write_bytecode = True
except AttributeError:
  pass

# our modules
import data
import gtl


DB_FILE = '/stored-data.txt'
SECRET_FILE = '/secret.txt'

INSTALL_PATH = '.'
RESOURCE_PATH = 'resources'

SPECIAL_COOKIE = '_cookie'
SPECIAL_PROFILE = '_profile'
SPECIAL_DB = '_db'
SPECIAL_PARAMS = '_params'
SPECIAL_UNIQUE_ID = '_unique_id'

COOKIE_UID = 'uid'
COOKIE_ADMIN = 'is_admin'
COOKIE_AUTHOR = 'is_author'


# Set to True to cause the server to exit after processing the current url.
quit_server = False

# A global copy of the database so that _GetDatabase can access it.
stored_data = None

# The HTTPServer object.
http_server = None

# A secret value used to generate hashes to protect cookies from tampering.
cookie_secret = ''

# File extensions of resource files that we recognize.
RESOURCE_CONTENT_TYPES = {
    '.css': 'text/css',
    '.gif': 'image/gif',
    '.htm': 'text/html',
    '.html': 'text/html',
    '.js': 'application/javascript',
    '.jpeg': 'image/jpeg',
    '.jpg': 'image/jpeg',
    '.png': 'image/png',
    '.ico': 'image/x-icon',
    '.text': 'text/plain',
    '.txt': 'text/plain',
}


def main():
  _SetWorkingDirectory()

  global quit_server
  quit_server = False

  insecure_mode = False

  quit_timer = threading.Timer(7200, lambda: _Exit('Timeout'))   # DO NOT CHANGE
  quit_timer.start()                                             # DO NOT CHANGE

  if insecure_mode:                                              # DO NOT CHANGE
    server_name = os.popen('hostname').read().replace('\n', '')  # DO NOT CHANGE
  else:                                                          # DO NOT CHANGE
    server_name = '127.0.0.1'                                    # DO NOT CHANGE
  server_port = 8008                                             # DO NOT CHANGE

  try:                                                           # DO NOT CHANGE
    r = random.SystemRandom()                                    # DO NOT CHANGE
  except NotImplementedError:                                    # DO NOT CHANGE
    _Exit('Could not obtain a CSPRNG source')                    # DO NOT CHANGE

  global server_unique_id                                        # DO NOT CHANGE
  server_unique_id = str(r.randint(2**128, 2**(128+1)))          # DO NOT CHANGE

  global http_server
  http_server = HTTPServer((server_name, server_port),
                           GruyereRequestHandler)

  print >>sys.stderr, '''
      Gruyere started...
          http://%s:%d/
          http://%s:%d/%s/''' % (
              server_name, server_port, server_name, server_port,
              server_unique_id)

  global stored_data
  stored_data = _LoadDatabase()

  while not quit_server:
    try:
      http_server.handle_request()
      _SaveDatabase(stored_data)
    except KeyboardInterrupt:
      print >>sys.stderr, '\nReceived KeyboardInterrupt'
      quit_server = True

  print >>sys.stderr, '\nClosing'
  http_server.socket.close()
  _Exit('quit_server')


def _Exit(reason):
  print >>sys.stderr, '\nExit: ' + reason
  os._exit(0)


def _SetWorkingDirectory():
  """Set the working directory to the directory containing this file."""
  if sys.path[0]:
    os.chdir(sys.path[0])


def _LoadDatabase():
  try:
    f = _Open(INSTALL_PATH, DB_FILE)
    stored_data = cPickle.load(f)
    f.close()
  except (IOError, ValueError):
    _Log('Couldn\'t load data; expected the first time Gruyere is run')
    stored_data = None

  f = _Open(INSTALL_PATH, SECRET_FILE)
  global cookie_secret
  cookie_secret = f.readline()
  f.close()

  return stored_data


def _SaveDatabase(save_database):
  try:
    f = _Open(INSTALL_PATH, DB_FILE, 'w')
    cPickle.dump(save_database, f)
    f.close()
  except IOError:
    _Log('Couldn\'t save data')


def _Open(location, filename, mode='rb'):
  return open(location + filename, mode)


# FIX (DoS - Challenge 5): Sanitise a path component (username or filename)
# to prevent directory traversal. Only alphanumerics, hyphens, underscores
# and dots are allowed. This strips out ../ and other dangerous sequences.
def _SanitizePathComponent(component):
  """Removes characters that could be used for directory traversal.

  Args:
    component: A username or filename string.

  Returns:
    A sanitised string containing only safe characters.
  """
  return ''.join(c for c in component if c.isalnum() or c in ('-', '_', '.'))


class GruyereRequestHandler(BaseHTTPRequestHandler):
  """Handle a http request."""

  NULL_COOKIE = {COOKIE_UID: None, COOKIE_ADMIN: False, COOKIE_AUTHOR: False}

  # FIX (DoS - Challenge 5 & 6):
  # ORIGINAL: _PROTECTED_URLS listed '/quit' instead of '/quitserver'.
  # This meant the actual /quitserver endpoint was completely unprotected —
  # any user, even unauthenticated, could shut down the server.
  # Additionally, the check was case-sensitive so '/RESET' bypassed it entirely.
  #
  # Fix 1: Corrected '/quit' to '/quitserver' so the actual handler is protected.
  # Fix 2: The path comparison in HandleRequest is now done case-insensitively
  #         (see HandleRequest below) to prevent uppercase bypass like '/RESET'.
  # Fix 3: _DoQuitserver and _DoReset now also verify admin status internally
  #         so that even if the URL routing check is bypassed somehow, the
  #         handler itself still enforces the access control requirement.
  _PROTECTED_URLS = [
      '/quitserver',   # FIX: was '/quit' — typo left the real endpoint unprotected
      '/reset',
  ]

  def _GetDatabase(self):
    global stored_data
    if not stored_data:
      stored_data = data.DefaultData()
    return stored_data

  def _ResetDatabase(self):
    stored_data = data.DefaultData()

  def _DoLogin(self, cookie, specials, params):
    database = self._GetDatabase()
    message = ''
    if 'uid' in params and 'pw' in params:
      uid = self._GetParameter(params, 'uid')
      if uid in database:
        if database[uid]['pw'] == self._GetParameter(params, 'pw'):
          (cookie, new_cookie_text) = (
              self._CreateCookie('GRUYERE', uid))
          self._DoHome(cookie, specials, params, new_cookie_text)
          return
      message = 'Invalid user name or password.'
    specials['_message'] = message
    self._SendTemplateResponse('/login.gtl', specials, params)

  def _DoLogout(self, cookie, specials, params):
    (cookie, new_cookie_text) = (
        self._CreateCookie('GRUYERE', None))
    self._DoHome(cookie, specials, params, new_cookie_text)

  def _Do(self, cookie, specials, params):
    self._DoHome(cookie, specials, params)

  def _DoHome(self, cookie, specials, params, new_cookie_text=None):
    database = self._GetDatabase()
    specials[SPECIAL_COOKIE] = cookie
    if cookie and cookie.get(COOKIE_UID):
      specials[SPECIAL_PROFILE] = database.get(cookie[COOKIE_UID])
    else:
      specials.pop(SPECIAL_PROFILE, None)
    self._SendTemplateResponse(
        '/home.gtl', specials, params, new_cookie_text)

  def _DoBadUrl(self, path, cookie, specials, params):
    self._SendError('Invalid request: %s' % (path,), cookie, specials, params)

  def _DoQuitserver(self, cookie, specials, params):
    # FIX (DoS - Challenge 5): Added internal admin check as defence in depth.
    # The URL routing check in HandleRequest is the first line of defence,
    # but placing the check here too ensures that even if routing is bypassed,
    # the handler itself refuses to execute for non-admins.
    if not cookie.get(COOKIE_ADMIN):
      self._SendError('Access denied.', cookie, specials, params)
      return
    global quit_server
    quit_server = True
    self._SendTextResponse('Server quit.', None)

  def _AddParameter(self, name, params, data_dict, default=None):
    if params.get(name):
      data_dict[name] = params[name][0]
    elif default is not None:
      data_dict[name] = default

  def _GetParameter(self, params, name, default=None):
    if params.get(name):
      return params[name][0]
    return default

  def _GetSnippets(self, cookie, specials, create=False):
    database = self._GetDatabase()
    try:
      profile = database[cookie[COOKIE_UID]]
      if create and 'snippets' not in profile:
        profile['snippets'] = []
      snippets = profile['snippets']
    except (KeyError, TypeError):
      _Log('Error getting snippets')
      return None
    return snippets

  def _DoNewsnippet2(self, cookie, specials, params):
    snippet = self._GetParameter(params, 'snippet')
    if not snippet:
      self._SendError('No snippet!', cookie, specials, params)
    else:
      snippets = self._GetSnippets(cookie, specials, True)
      if snippets is not None:
        snippets.insert(0, snippet)
    self._SendRedirect('/snippets.gtl', specials[SPECIAL_UNIQUE_ID])

  def _DoDeletesnippet(self, cookie, specials, params):
    index = self._GetParameter(params, 'index')
    snippets = self._GetSnippets(cookie, specials)
    try:
      del snippets[int(index)]
    except (IndexError, TypeError, ValueError):
      self._SendError(
          'Invalid index (%s)' % (index,),
          cookie, specials, params)
      return
    self._SendRedirect('/snippets.gtl', specials[SPECIAL_UNIQUE_ID])

  def _DoSaveprofile(self, cookie, specials, params):
    profile_data = {}
    uid = self._GetParameter(params, 'uid', cookie[COOKIE_UID])
    newpw = self._GetParameter(params, 'pw')
    self._AddParameter('name', params, profile_data, uid)
    self._AddParameter('pw', params, profile_data)
    self._AddParameter('is_author', params, profile_data)
    self._AddParameter('is_admin', params, profile_data)
    self._AddParameter('private_snippet', params, profile_data)
    self._AddParameter('icon', params, profile_data)
    self._AddParameter('web_site', params, profile_data)
    self._AddParameter('color', params, profile_data)

    database = self._GetDatabase()
    message = None
    new_cookie_text = None
    action = self._GetParameter(params, 'action')
    if action == 'new':
      if uid in database:
        message = 'User already exists.'
      else:
        profile_data['pw'] = newpw
        database[uid] = profile_data
        (cookie, new_cookie_text) = self._CreateCookie('GRUYERE', uid)
        message = 'Account created.'
    elif action == 'update':
      if uid not in database:
        message = 'User does not exist.'
      elif (newpw and database[uid]['pw'] != self._GetParameter(params, 'oldpw')
            and not cookie.get(COOKIE_ADMIN)):
        message = 'Incorrect password.'
      else:
        if newpw:
          profile_data['pw'] = newpw
        database[uid].update(profile_data)
        redirect = '/'
    else:
      message = 'Invalid request'
    _Log('SetProfile(%s, %s): %s' %(str(uid), str(action), str(message)))
    if message:
      self._SendError(message, cookie, specials, params, new_cookie_text)
    else:
      self._SendRedirect(redirect, specials[SPECIAL_UNIQUE_ID])

  def _SendHtmlResponse(self, html, new_cookie_text=None):
    self.send_response(200)
    self.send_header('Content-type', 'text/html')
    self.send_header('Pragma', 'no-cache')
    if new_cookie_text:
      self.send_header('Set-Cookie', new_cookie_text)
    self.send_header('X-XSS-Protection', '0')
    self.end_headers()
    self.wfile.write(html)

  def _SendTextResponse(self, text, new_cookie_text=None):
    self._SendHtmlResponse('<pre>' + cgi.escape(text) + '</pre>',
                           new_cookie_text)

  def _SendTemplateResponse(self, filename, specials, params,
                            new_cookie_text=None):
    f = None
    try:
      f = _Open(RESOURCE_PATH, filename)
      template = f.read()
    finally:
      if f: f.close()
    self._SendHtmlResponse(
        gtl.ExpandTemplate(template, specials, params),
        new_cookie_text)

  def _SendFileResponse(self, filename, cookie, specials, params):
    content_type = None
    if filename.endswith('.gtl'):
      self._SendTemplateResponse(filename, specials, params)
      return

    name_only = filename[filename.rfind('/'):]
    extension = name_only[name_only.rfind('.'):]
    if '.' not in extension:
      content_type = 'text/plain'
    elif extension in RESOURCE_CONTENT_TYPES:
      content_type = RESOURCE_CONTENT_TYPES[extension]
    else:
      self._SendError(
          'Unrecognized file type (%s).' % (filename,),
          cookie, specials, params)
      return
    f = None
    try:
      f = _Open(RESOURCE_PATH, filename, 'rb')
      self.send_response(200)
      self.send_header('Content-type', content_type)
      self.send_header('Cache-control', 'public, max-age=7200')
      self.send_header('X-XSS-Protection', '0')
      self.end_headers()
      self.wfile.write(f.read())
    finally:
      if f: f.close()

  def _SendError(self, message, cookie, specials, params, new_cookie_text=None):
    specials['_message'] = message
    self._SendTemplateResponse(
        '/error.gtl', specials, params, new_cookie_text)

  def _CreateCookie(self, cookie_name, uid):
    if uid is None:
      return (self.NULL_COOKIE, cookie_name + '=; path=/')
    database = self._GetDatabase()
    profile = database[uid]
    if profile.get('is_author', False):
      is_author = 'author'
    else:
      is_author = ''
    if profile.get('is_admin', False):
      is_admin = 'admin'
    else:
      is_admin = ''

    c = {COOKIE_UID: uid, COOKIE_ADMIN: is_admin, COOKIE_AUTHOR: is_author}
    c_data = '%s|%s|%s' % (uid, is_admin, is_author)
    h_data = str(hash(cookie_secret + c_data) & 0x7FFFFFF)
    c_text = '%s=%s|%s; path=/' % (cookie_name, h_data, c_data)
    return (c, c_text)

  def _GetCookie(self, cookie_name):
    cookies = self.headers.get('Cookie')
    if isinstance(cookies, str):
      for c in cookies.split(';'):
        matched_cookie = self._MatchCookie(cookie_name, c)
        if matched_cookie:
          return self._ParseCookie(matched_cookie)
    return self.NULL_COOKIE

  def _MatchCookie(self, cookie_name, cookie):
    try:
      (cn, cd) = cookie.strip().split('=', 1)
      if cn != cookie_name:
        return None
    except (IndexError, ValueError):
      return None
    return cd

  def _ParseCookie(self, cookie):
    try:
      (hashed, cookie_data) = cookie.split('|', 1)
      if hashed != str(hash(cookie_secret + cookie_data) & 0x7FFFFFF):
        return self.NULL_COOKIE
      values = cookie_data.split('|')
      return {
          COOKIE_UID: values[0],
          COOKIE_ADMIN: values[1] == 'admin',
          COOKIE_AUTHOR: values[2] == 'author',
      }
    except (IndexError, ValueError):
      return self.NULL_COOKIE

  def _DoReset(self, cookie, specials, params):
    # FIX (DoS - Challenge 5): Added internal admin check as defence in depth.
    if not cookie.get(COOKIE_ADMIN):
      self._SendError('Access denied.', cookie, specials, params)
      return
    self._ResetDatabase()
    self._SendTextResponse('Server reset to default values...', None)

  def _DoUpload2(self, cookie, specials, params):
    (filename, file_data) = self._ExtractFileFromRequest()

    # FIX (DoS - Challenge 6 — Path Traversal):
    # ORIGINAL: _MakeUserDirectory used the raw uid (username) directly when
    # constructing the directory path. A user registered as '../resources'
    # would cause uploads to be written to the resources/ directory instead
    # of their own upload folder. By uploading a menubar.gtl file there,
    # the attacker replaced the real template with a self-referencing one,
    # causing infinite recursion and a stack overflow crash on every request.
    #
    # Fix: Pass the uid through _SanitizePathComponent() before use.
    # This strips ../ and any non-alphanumeric characters so traversal
    # sequences can never appear in the constructed path.
    # We also sanitise the filename for the same reason.
    safe_uid = _SanitizePathComponent(cookie[COOKIE_UID])
    safe_filename = _SanitizePathComponent(filename)

    if not safe_uid or not safe_filename:
      self._SendError('Invalid filename or username.', cookie, specials, params)
      return

    directory = self._MakeUserDirectory(safe_uid)

    # Additional check: confirm the resolved path stays inside RESOURCE_PATH
    intended_base = os.path.realpath(RESOURCE_PATH)
    resolved_path = os.path.realpath(os.path.join(directory, safe_filename))
    if not resolved_path.startswith(intended_base):
      self._SendError('Invalid upload path.', cookie, specials, params)
      return

    message = None
    url = None
    try:
      f = _Open(directory, safe_filename, 'wb')
      f.write(file_data)
      f.close()
      (host, port) = http_server.server_address
      url = 'http://%s:%d/%s/%s/%s' % (
          host, port, specials[SPECIAL_UNIQUE_ID], safe_uid, safe_filename)
    except IOError, ex:
      message = 'Couldn\'t write file %s: %s' % (safe_filename, ex.message)
      _Log(message)

    specials['_message'] = message
    self._SendTemplateResponse(
        '/upload2.gtl', specials,
        {'url': url})

  def _ExtractFileFromRequest(self):
    form = cgi.FieldStorage(
        fp=self.rfile,
        headers=self.headers,
        environ={'REQUEST_METHOD': 'POST',
                 'CONTENT_TYPE': self.headers.getheader('content-type')})

    upload_file = form['upload_file']
    file_data = upload_file.file.read()
    return (upload_file.filename, file_data)

  def _MakeUserDirectory(self, uid):
    """Creates a separate directory for each user.

    Args:
      uid: The sanitised username. Must have been passed through
           _SanitizePathComponent() before calling this method.

    Returns:
      The new directory path.
    """
    directory = RESOURCE_PATH + os.sep + str(uid) + os.sep
    try:
      print 'mkdir: ', directory
      os.mkdir(directory)
    except Exception:
      pass
    return directory

  def _SendRedirect(self, url, unique_id):
    if not url:
      url = '/'
    url = '/' + unique_id + url
    self.send_response(302)
    self.send_header('Location', url)
    self.send_header('Pragma', 'no-cache')
    self.send_header('Content-type', 'text/html')
    self.send_header('X-XSS-Protection', '0')
    self.end_headers()
    self.wfile.write(
        '''<!DOCTYPE HTML PUBLIC '-//W3C//DTD HTML//EN'>
        <html><body>
        <title>302 Redirect</title>
        Redirected <a href="%s">here</a>
        </body></html>'''
        % (url,))

  def _GetHandlerFunction(self, path):
    try:
      return getattr(GruyereRequestHandler, '_Do' + path[1:].capitalize())
    except AttributeError:
      return None

  def do_POST(self):
    self.DoGetOrPost()

  def do_GET(self):
    self.DoGetOrPost()

  def DoGetOrPost(self):
    url = urlparse(self.path)
    path = url[2]
    query = url[4]

    allowed_ips = ['127.0.0.1']

    request_ip = self.client_address[0]                      # DO NOT CHANGE
    if request_ip not in allowed_ips:                        # DO NOT CHANGE
      print >>sys.stderr, (                                  # DO NOT CHANGE
          'DANGER! Request from bad ip: ' + request_ip)      # DO NOT CHANGE
      _Exit('bad_ip')                                        # DO NOT CHANGE

    if (server_unique_id not in path                         # DO NOT CHANGE
        and path != '/favicon.ico'):                         # DO NOT CHANGE
      if path == '' or path == '/':                          # DO NOT CHANGE
        self._SendRedirect('/', server_unique_id)            # DO NOT CHANGE
        return                                               # DO NOT CHANGE
      else:                                                  # DO NOT CHANGE
        print >>sys.stderr, (                                # DO NOT CHANGE
            'DANGER! Request without unique id: ' + path)    # DO NOT CHANGE
        _Exit('bad_id')                                      # DO NOT CHANGE

    path = path.replace('/' + server_unique_id, '', 1)       # DO NOT CHANGE

    self.HandleRequest(path, query, server_unique_id)

  def HandleRequest(self, path, query, unique_id):
    path = urllib.unquote(path)

    if not path:
      self._SendRedirect('/', server_unique_id)
      return

    params = cgi.parse_qs(query)
    specials = {}
    cookie = self._GetCookie('GRUYERE')
    database = self._GetDatabase()
    specials[SPECIAL_COOKIE] = cookie
    specials[SPECIAL_DB] = database
    specials[SPECIAL_PROFILE] = database.get(cookie.get(COOKIE_UID))
    specials[SPECIAL_PARAMS] = params
    specials[SPECIAL_UNIQUE_ID] = unique_id

    # FIX (DoS - Challenge 5):
    # ORIGINAL: The check compared path against _PROTECTED_URLS using a direct
    # string equality test which is case-sensitive. Visiting '/RESET' bypassed
    # the check entirely because 'RESET' != 'reset', but _GetHandlerFunction
    # capitalises the path before looking up the handler — so '/RESET' still
    # routed to _DoReset. This is a classic check/use mismatch bug.
    #
    # Fix: Normalise path to lowercase before the protected URL check so that
    # '/RESET', '/Reset', '/rEsEt' etc. are all correctly blocked.
    if path.lower() in self._PROTECTED_URLS and not cookie[COOKIE_ADMIN]:
      self._SendError('Invalid request', cookie, specials, params)
      return

    try:
      handler = self._GetHandlerFunction(path)
      if callable(handler):
        (handler)(self, cookie, specials, params)
      else:
        try:
          self._SendFileResponse(path, cookie, specials, params)
        except IOError:
          self._DoBadUrl(path, cookie, specials, params)
    except KeyboardInterrupt:
      _Exit('KeyboardInterrupt')


def _Log(message):
  print >>sys.stderr, message


if __name__ == '__main__':
  main()
