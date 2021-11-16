from functools import partial
from http.server import HTTPServer, SimpleHTTPRequestHandler
import urllib.request
import threading
import time

class QuietHTTPRequestHandler(SimpleHTTPRequestHandler):
	def __init__(self, request, client_address, server, directory=None):
		super().__init__(request, client_address, server, directory=directory)

	def log_message(self, format, *args):
		pass

class StoppableHttpServer:
	def __init__(self, server_address, RequestHandlerClass):
		self.server_address = server_address
		self.RequestHandlerClass = RequestHandlerClass
		self.exit_event = threading.Event()
		
	def __thread(self):
		httpd = HTTPServer(self.server_address, self.RequestHandlerClass)
		while not self.exit_event.is_set():
			httpd.handle_request()
		
	def start(self):
		self.exit_event.clear()
		exit_event = threading.Event()
		t = threading.Thread(target=self.__thread)
		t.start()

	def stop(self):
		self.exit_event.set()
		urllib.request.urlopen("http://%s:%d/" % self.server_address).read()

class AssetsServer(StoppableHttpServer):
	def __init__(self, server_address, assets_folder):
		handler = partial(QuietHTTPRequestHandler, directory=assets_folder)
		super().__init__(server_address, handler)