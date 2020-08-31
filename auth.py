#!/usr/bin/env python
'''
ADD STUFF HERE
'''

from collections import namedtuple
Consumer = namedtuple('Consumer', 'key secret')
Token = namedtuple('Token', 'key secret')

def _quote(text):
  return urllib.quote(text, '-._~')

def _encode(params):
  return '&'.join(['%s=%s' % (k, v) for k, v in params])

def _parse_uri(req):
  method = req.get_method()
  if method == 'POST':
    uri = req.get_full_url()
    query = req.get_data() or ''
  else:
    url = req.get_full_url()
    if url.find('?') != -1:
      uri, query = req.get_full_url().split('?', 1)
    else:
      uri = url
      query = ''
  return method, uri, query

class Request(urllib2.Request):
  def __init__(self, url, \
    data=None, headers={}, origin_req_host=None, unverifiable=False, \
    method=None, oauth_params={}):
    urllib2.Request.__init__( \
      self, url, data, headers, origin_req_host, unverifiable)
    self.method = method
    self.oauth_params = oauth_params

  def get_method(self):
    if self.method is not None:
      return self.method
    if self.has_data():
      return 'POST'
    else:
      return 'GET'

class OAuthHandler(urllib2.BaseHandler):
  def __init__(self, consumer, token=None, timeout=None):
    self.consumer = consumer
    self.token = token
    self.timeout = timeout

  def get_signature(self, method, uri, query):
    key = '%s&' % _quote(self.consumer.secret)
    if self.token is not None:
      key += _quote(self.token.secret)
    signature_base = '&'.join((method.upper(), _quote(uri), _quote(query)))
    signature = hmac.new(str(key), signature_base, hashlib.sha1)
    return base64.b64encode(signature.digest())

  def http_request(self, req):
    if not req.has_header('Host'):
      req.add_header('Host', req.get_host())
    method, uri, query = _parse_uri(req)
    if method == 'POST':
      req.add_header('Content-type', 'application/x-www-form-urlencoded')

    query = map(lambda (k, v): (k, urllib.quote(v)), urlparse.parse_qsl(query))

    oauth_params = [
      ('oauth_consumer_key', self.consumer.key),
      ('oauth_signature_method', 'HMAC-SHA1'),
      ('oauth_timestamp', int(time.time())),
      ('oauth_nonce', ''.join([random.choice(ALPHANUM) for i in range(16)])),
      ('oauth_version', '1.0')]
    if self.token is not None:
      oauth_params.append(('oauth_token', self.token.key))
    if hasattr(req, 'oauth_params'):
      oauth_params += req.oauth_params.items()

    query += oauth_params
    query.sort()
    signature = self.get_signature(method, uri, _encode(query))

    oauth_params.append(('oauth_signature', _quote(signature)))
    oauth_params.sort()

    auth = ', '.join(['%s="%s"' % (k, v) for k, v in oauth_params])
    req.headers['Authorization'] = 'OAuth ' + auth

    req = Request(req.get_full_url(), \
      data=req.get_data(), \
      headers=req.headers, \
      origin_req_host=req.get_origin_req_host(), \
      unverifiable=req.is_unverifiable(), \
      method=method)

    req.timeout = self.timeout
    return req

  def https_request(self, req):
    return self.http_request(req)

def _replace_opener():
  filename = os.path.expanduser('~')+'/.'+os.path.basename(sys.argv[0])
  if os.path.isfile(filename):
    f = open(filename, 'r')
    lines = f.readlines()
    key = lines[0].strip()
    secret = lines[1].strip()
  else:
    sys.stderr.write('''TWITTER API AUTHENTICATION SETUP
(1) Open the following link in your browser and register this script...
'>>> https://apps.twitter.com/\n''')
    sys.stderr.write('What is its consumer key? ')
    key = sys.stdin.readline().rstrip('\r\n')
    sys.stderr.write('What is its consumer secret? ')
    secret = sys.stdin.readline().rstrip('\r\n')
    lines = [key, secret]
  consumer = Consumer(key, secret)
  try:
    oauth = lines[2].strip()
    oauth_secret = lines[3].strip()
    atoken = Token(oauth, oauth_secret)
  except IndexError:
    opener = urllib2.build_opener(OAuthHandler(consumer))
    resp = opener.open(Request('https://api.twitter.com/oauth/request_token'))
    rtoken = urlparse.parse_qs(resp.read())
    rtoken = Token(rtoken['oauth_token'][0], rtoken['oauth_token_secret'][0])
    sys.stderr.write('''(2) Now, open this link and authorize the script...
'>>> https://api.twitter.com/oauth/authorize?oauth_token=%s\n''' % rtoken.key)
    sys.stderr.write('What is the PIN? ')
    verifier = sys.stdin.readline().rstrip('\r\n')
    opener = urllib2.build_opener(OAuthHandler(consumer, rtoken))
    resp = opener.open( \
      Request('https://api.twitter.com/oauth/access_token', \
      oauth_params={'oauth_verifier': verifier}))
    atoken = urlparse.parse_qs(resp.read())
    atoken = Token(atoken['oauth_token'][0], atoken['oauth_token_secret'][0])
    f = open(filename, 'w')
    f.write(key+'\n')
    f.write(secret+'\n')
    f.write(atoken.key+'\n')
    f.write(atoken.secret+'\n')
    f.close()
    sys.stderr.write('Setup complete and %s created.\n' % filename)
  opener = urllib2.build_opener(OAuthHandler(consumer, atoken))
  urllib2.install_opener(opener)
