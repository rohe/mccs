#!/usr/bin/env python

import argparse
import cookielib
import importlib
import sys
import time

from urlparse import parse_qs, urlparse

from saml2.client import Saml2Client
from saml2.config import SPConfig, logging
from saml2.s_utils import rndstr

logger = logging.getLogger("saml2.idp_monitor")

__author__ = 'roland'


class Check(object):
    def __init__(self, client):
        self.client = client
        self.cjar = {"browser": cookielib.CookieJar(),
                     "rp": cookielib.CookieJar(),
                     "service": cookielib.CookieJar()}
        self.features = None
        self.login_time = 0

    def my_endpoints(self):
        """
        :returns: All the assertion consumer service endpoints this
            SP publishes.
        """
        return [e for e, b in self.client.config.getattr("endpoints", "sp")[
            "assertion_consumer_service"]]

    def intermit(self, response, piece):
        """
        This method is supposed to handle all needed interactions.
        It also deals with redirects.

        :param response: A response from the IdP
        """
        _response = response
        if _response.status_code >= 400:
            done = True
        else:
            done = False

        while not done:
            rdseq = []
            while _response.status_code in [302, 301, 303]:
                url = _response.headers["location"]
                if url[0] == "/":
                    url = "%s://%s%s" % (piece.scheme, piece.netloc, url)
                if url in rdseq:
                    raise Exception("Loop detected in redirects")
                else:
                    rdseq.append(url)
                    if len(rdseq) > 8:
                        raise Exception(
                            "Too long sequence of redirects: %s" % rdseq)

                # If back to me
                for_me = False
                for redirect_uri in self.my_endpoints():
                    if url.startswith(redirect_uri):
                        # Back at the RP
                        self.client.cookiejar = self.cjar["rp"]
                        for_me = True
                        try:
                            base, query = url.split("?")
                        except ValueError:
                            pass
                        else:
                            _response = parse_qs(query)
                            return _response

                if for_me:
                    done = True
                    break
                else:
                    _response = self.client.send(url, "GET")

                    if _response.status_code >= 400:
                        done = True
                        break

            if _response.status_code in [200, 201]:
                done = True
                break


        return _response


NAGIOS_LINE = ("[{time}] PROCESS_SERVICE_CHECK_RESULT;{host};{svc};{code};{"
               "output}")

RETURN_CODE = {"OK": 0, "WARNING": 1, "CRITICAL": 2, "UNKNOWN": 3}


def print_nagios_line(return_code, nagios_args, entity_id, output):
    _kwargs = {
        "time": time.time(),
        "code": return_code,
        "output": output
    }
    _kwargs.update(nagios_args)
    _kwargs["host"] = entity_id
    print NAGIOS_LINE.format(**_kwargs)


def print_status(nagios, code, nagios_args, entity_id, suppress_output,
                 login_time, output, dump):
    if nagios:
        if dump:
            print_nagios_line(RETURN_CODE[code], nagios_args, entity_id, output)
        else:
            print_nagios_line(RETURN_CODE[code], nagios_args, entity_id, "")
    else:
        if code != "OK":
            print entity_id, code
        elif not suppress_output:
            if login_time:
                print entity_id, "OK %s" % login_time
            else:
                print entity_id, "OK"


def check(client, entity_id, suppress_output=False, login_time=False,
          nagios=False, nagios_args=None, dump=False):

    try:
        _check = Check(client)
    except Exception, err:
        print_status(nagios, "CRITICAL", nagios_args, "%s" % err,
                     suppress_output, 0, "%s" % err, dump)
        return RETURN_CODE["CRITICAL"]

    if login_time:
        _login_time = _check.login_time
    else:
        _login_time = 0

    _client = _check.client
    relay_state = rndstr()
    _id, htargs = _client.prepare_for_authenticate(entity_id,
                                                   relay_state=relay_state)
    _url = htargs["headers"][0][1]
    resp = _client.send(_url, "GET")

    up = urlparse(_url)
    if resp.status_code >= 400:
        print_status(nagios, "CRITICAL", nagios_args, entity_id,
                     suppress_output, _login_time, resp.content, dump)
        return RETURN_CODE["CRITICAL"]

    # resp should be dictionary with keys RelayState, SAMLResponse and endpoint
    try:
        resp = _check.intermit(resp,up)
    except Exception, err:
        print_status(nagios, "UNKNOWN", nagios_args, entity_id,
                     suppress_output, _login_time, "%s" % err, dump)
        return RETURN_CODE["UNKNOWN"]
    else:
        if resp.status_code >= 400:
            print_status(nagios, "CRITICAL", nagios_args, entity_id,
                         suppress_output, _login_time, resp.content, dump)
        else:
            if "ERRO" in resp.content or "Error" in resp.content:
                print_status(nagios, "WARNING", nagios_args,
                             entity_id, suppress_output, _login_time,
                             resp.content, dump)
            else:
                print_status(nagios, "OK", nagios_args, entity_id,
                             suppress_output, login_time, resp.content, dump)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', dest='conf_path')
    parser.add_argument('-e', dest='entity_id')
    parser.add_argument('-t', dest='login_split_time', action='store_true')
    parser.add_argument('-n', dest='count', default="1")
    parser.add_argument(
        '-N', dest='nagios', action='store_true',
        help="If Nagios Passive Service Check Results output should be used")
    parser.add_argument('-S', dest='svc',
                        help="Service description for Nagios output")
    parser.add_argument('-H', dest='host',
                        help="Service host for Nagios output")
    parser.add_argument(dest="config")
    parser.add_argument('-s', dest='sso', action='store_true')
    parser.add_argument('-d', dest="dump", action='store_true')
    args = parser.parse_args()

    #print args
    sys.path.insert(0, ".")
    # If a specific configuration directory is specified look there first
    if args.conf_path:
        sys.path.insert(0, args.conf_path)
    conf = importlib.import_module(args.config)
    sp_config = SPConfig().load(conf.CONFIG, metadata_construction=False)

    client = Saml2Client(sp_config)

    if not args.entity_id:
        # check if there is only one in the metadata store
        entids = client.metadata.items()
        # entids is list of 2-tuples (entity_id, entity description)
        if len(entids) == 1:
            entity_id = entids[0][0]
        else:
            entity_id = args.entity_id
    else:
        entity_id = args.entity_id
        assert client.metadata[entity_id]

    if args.nagios:
        try:
            assert args.count == "1"
            assert args.login_split_time is False
        except AssertionError:
            print "you can't combine -N with -n and -t flags"
            sys.exit(1)
        nagios_args = {"host": args.host, "svc": args.svc}
    else:
        nagios_args = {}

    if args.dump:
        _dump = True
    else:
        _dump = False

    if args.count == "1":
        try:
            check(client, entity_id, login_time=args.login_split_time,
                  nagios=args.nagios, nagios_args=nagios_args, dump=_dump)
        except Exception, err:
            print_status(args.nagios, "UNKNOWN", nagios_args, entity_id,
                         False, 0, "%s" % err, True)
        else:
            pass
    else:
        for i in range(0, int(args.count)):
            check(client, entity_id, suppress_output=True,
                  nagios_args=nagios_args)
            # forget cookies otherwise login only the first time around
            if args.sso:
                client.cookiejar = cookielib.CookieJar()


if __name__ == "__main__":
    main()
