import json
import logging
from http.server import BaseHTTPRequestHandler
from urllib.parse import urlparse

import requests

class AltoServer(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'application/json')
        self.end_headers()

    def do_GET(self):
        self.send_response(404)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write("not found")

    def do_HEAD(self):
        self._set_headers()

    def do_POST(self):
        request_path = urlparse(self.path).path
        logging.debug('got post on %s ' % str(request_path))
        if request_path != '/costmap/filtered':
            self.send_response(404)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            self.wfile.write(bytes(json.dumps(None), 'UTF-8'))
        else:
            try:
                self.data_string = self.rfile.read(int(self.headers['Content-Length']))
                logging.debug('data_string is %s' % str(self.data_string))
                data = json.loads(self.data_string.decode('utf8'))
                src = data['pids']['srcs'][0]
                dst = data['pids']['dsts'][0]
                final_dst = dst.split('.')[-1]
                cost_metric = data['cost-type']['cost-metric']
                path = src + '.' + dst
                isd_as = str(AltoServer.metric_server.topology.isd_as)
                logging.debug('final dst is %s' % final_dst)
                if src != isd_as and final_dst != isd_as:
                    logging.debug('false isd_as %s' % src)
                    address = AltoServer.metric_server.metric_servers[src][0]
                    url = 'http://' + address['Addr'] + ':' + str(address['L4Port'] + 1100) + '/costmap/filtered'
                    logging.debug(url)
                    r = requests.post(url, json=data)
                    response = r.json()

                    # request = Request(url, urlencode(data).encode())
                    # json = urlopen(request).read().decode()
                    # logging.debug(json)
                elif AltoServer.metric_server.is_core_as():
                    logging.debug('as is core as request child %s' % final_dst)
                    address = AltoServer.metric_server.metric_servers[final_dst][0]
                    url = 'http://' + address['Addr'] + ':' + str(address['L4Port'] + 1100) + '/costmap/filtered'
                    logging.debug(url)
                    r = requests.post(url, json=data)
                    response = r.json()
                else:
                    logging.debug('path is %s' % path)
                    metrics = AltoServer.metric_server.get_metrics_for_path(path)
                    response = {'cost-map': {src: {dst: metrics[cost_metric]}}}

                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(bytes(json.dumps(response), 'UTF-8'))
            except:
                self.send_response(404)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(bytes(json.dumps({}), 'UTF-8'))
