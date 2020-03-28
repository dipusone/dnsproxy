#!/usr/bin/env python3
import argparse
import grp
import logging
import json
import os
import pwd
import socket
import socketserver
import textwrap

from scapy.all import DNS, DNSQR, DNSRR, raw
from scapy.all import Packet, ByteField, StrField, FieldLenField


logger = logging.getLogger(__name__)


class DNSCAA(Packet):
    """
    Simple Implementation of the RFC8659 spec
    """
    name = "DNS CAA response"
    fields_desc = [ByteField("flag", 0),
                   FieldLenField("tag_len", None, fmt="B", length_of="tag"),
                   StrField("tag", "issue"),
                   StrField("value", "")
                   ]


class ThreadingUDPServerWArgs(socketserver.ThreadingUDPServer):
    """
    Simple wrapper class used to pass values to the undeling request handler
    """
    pass


class DNSProxy(socketserver.BaseRequestHandler):
    """
    Proxy class which will intercept the DNS requests for acme records
    and will proxy to others to specified DNS servers
    """

    MAX_TXT_LEN = 255
    ACME_CHALLENDE_FORMAT = "_acme-challenge.{}"

    def handle(self):
        self.data, self.sock = self.request
        acme_request = self.ACME_CHALLENDE_FORMAT.format(self.server.domain)

        try:
            self.dns_request = DNS(self.data)
            qname = self.dns_request[DNSQR].qname.decode()
            logger.info("Requested {} from {}:{}".format(qname,
                                                         *self.client_address))
            if qname.startswith(acme_request):
                self.serve_acme()
            elif self.dns_request[DNSQR].qtype == 257:
                self.serve_caa()
            else:
                self.proxy_request()
        except Exception as e:
            logger.debug(str(e))
            return

    def proxy_request(self):
        """
        Proxy method for serving dns requests
        """
        # get the informations from the father, this is the best way i've found
        destination = self.server.destination
        destination_port = self.server.destination_port

        logger.debug("Forwading requests to {}:{}".format(destination,
                                                          destination_port))

        # Socket since sendig packet with scapy requires root
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # forward the packet
        sock.sendto(raw(self.dns_request), (destination, destination_port))
        # get the response from the server
        data, _ = sock.recvfrom(1024)
        dns_response = DNS(data)
        logger.debug("Received response: {}".format(dns_response.summary()))
        self.sock.sendto(raw(dns_response), self.client_address)

    def serve_caa(self):
        """
        Serve the CAA response for letsencrypt
        """
        logger.debug("Serving CAA for {}:{}".format(*self.client_address))
        dnscaa_response = DNSCAA(value='letsencrypt.org')
        dnsrr_response = DNSRR(type='CAA',
                               rrname=self.dns_request[DNS].qd.qname,
                               rdata=dnscaa_response)
        dns_response = DNS(id=self.dns_request[DNS].id,
                           qd=self.dns_request[DNS].qd,
                           aa=1,
                           qr=1,
                           an=dnsrr_response)
        self.sock.sendto(raw(dns_response), self.client_address)

    def serve_acme(self):
        """
        Interceptor to server the acme response
        """
        logger.debug("Serving Acme for {}:{}".format(*self.client_address))
        with open(self.server.acme_file, 'r') as af:
            composite_dnsrr = None
            for line in af:
                dnsrr_response = self._make_dnsrr(line)
                composite_dnsrr = self.__create_or_append(composite_dnsrr,
                                                          dnsrr_response)

                logger.debug("Adding response: {}".format(line.strip()))

            # RFC 1035 Section 4.1.1
            dns_response = DNS(id=self.dns_request[DNS].id,
                               qd=self.dns_request[DNS].qd,
                               aa=1,
                               qr=1,
                               an=composite_dnsrr)
            self.sock.sendto(raw(dns_response), self.client_address)

    def _make_dnsrr(self, text):
        """
        Make a DNSRR response splitting the text
        in chunks of max MAX_TXT_LEN chars

        :param text: the response for the query
        :type text: str

        :returns: a DNSRR (or stack for DNSSR) for the given text
        :rtype: DNSRR
        """
        composite_dnsrr = None
        for chunk in self._chunk(text.strip(), self.MAX_TXT_LEN):
            dnsrr_response = DNSRR(type='TXT',
                                   rrname=self.dns_request[DNS].qd.qname,
                                   rdata=str(chunk))
            composite_dnsrr = self.__create_or_append(composite_dnsrr,
                                                      dnsrr_response)
        return composite_dnsrr

    def __create_or_append(self, packet, to_add):
        """
        Create a new packet or append the one to add if the packer is not None

        :param packet: the packet to which append the new one. Can be None
        :param to_add: the new packet to append

        :type: packet: DNSRR
        :type: to_add: DNSRR

        :returns: a DNSRR (or stack for DNSSR) for the given text
        :rtype: DNSRR

        """
        if not packet:
            return to_add
        else:
            return packet / to_add

    def _chunk(self, iterable, n):
        """
        Splits the iterable in chunks of len n

        :param iterable: an iterable to split
        :param n: the max len of a chunk

        :type iterable: iterable
        :type n: int

        :yields: a chunk of len n
        :type: iterable
        """
        for chunk in textwrap.wrap(iterable, n):
            yield chunk


def drop_privileges(uid_name='nobody', gid_name='nogroup'):
    """
    Drop the privileges of the script to the uid and group
    specified as arguments

    :param uid_name: the user to use for the new privileges
    :param gid_name: the group to use for the new privileges

    :type uid_name: str
    :type gid_name: str
    """
    if os.getuid() != 0:
        return

    # Get uuid
    running_uid = pwd.getpwnam(uid_name).pw_uid
    running_gid = grp.getgrnam(gid_name).gr_gid

    # Remove all groups
    os.setgroups([])

    # Drop privileges
    os.setgid(running_gid)
    os.setuid(running_uid)

    # Set the umask
    os.umask(0o077)


def parse_config(config_path, args):
    """
    Parse the config file and override the defaults.
    The config must be in JSON format

    :param config_path: the path of the config file to parse
    :param args: an argparse result to override

    :type config_path: str
    :type args: argparse.Namespace

    :returns: an argparse Namespace
    :rtype: argparse.Namespace
    """
    if not os.path.exists(config_path):
        logger.debug('Config file "{}" does not exist'.format(config_path))
        return args
    logger.info("Loading config from {}".format(config_path))

    try:
        with open(config_path, 'r') as cf:
            config = json.load(cf)
        # read the config from the config file and override the args
        for arg in vars(args):
            if arg in config:
                logger.debug("Setting {} to {}".format(arg, config[arg]))
                setattr(args, arg, config[arg])
    except Exception as e:
        logger.debug("Error parsing config {}".format(str(e)))
        logger.info('Invalid config file')
    finally:
        return args


def parse_args():
    """
    Helper method to setup args
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('-c', '--config',
                        type=str, default='/etc/dnsproxy.conf',
                        help='The path of the config file. '
                             'The arguments from the cmd line'
                             'override the ones in the config')

    parser.add_argument('-d', '--destination',
                        default="8.8.8.8",
                        help="Forward dns requests to this host")
    parser.add_argument('-dp', '--destination_port',
                        type=int, default=53,
                        help="Forward dns requests to this port")

    parser.add_argument('-i', '--ip',
                        default="0.0.0.0",
                        help="Start server this IP")
    parser.add_argument('-p', '--port',
                        type=int, default=53,
                        help="Start server this port")
    parser.add_argument('-do', '--domain',
                        default="somedomain.com",
                        help="domain for which hijack the acme requests")

    parser.add_argument('-af', '--acme_file',
                        default="challenge",
                        help="read the acme challenge/response from this file")

    parser.add_argument('-u', '--uid_name',
                        default="nobody",
                        help="the user to use for the new privileges")
    parser.add_argument('-g', '--gid_name',
                        default="nobody",
                        help="the group to use for the new privileges")

    parser.add_argument('-v', '--verbose',
                        action="store_true",
                        help="Verbose output")

    return parser.parse_args()


def init_logger(verbose=False):
    """
    Init the logger and its configurations

    :param verbose: set to True to enable debuggin logs
    :type verbose: bool

    """
    logging.basicConfig(level=logging.DEBUG if verbose else logging.INFO,
                        format='[%(asctime)s] %(message)s',
                        datefmt='%d-%m-%y %H:%M:%S')
    logger.info("Log level set to " + "verbose" if verbose else "info")


if __name__ == '__main__':
    args = parse_args()
    init_logger(args.verbose)

    args = parse_config(args.config, args)

    logger.info("Starting dns_proxy on {}:{}".format(args.ip, args.port))
    server = ThreadingUDPServerWArgs((args.ip, args.port), DNSProxy)
    server.destination = args.destination
    server.destination_port = args.destination_port
    server.domain = args.domain
    server.acme_file = args.acme_file

    drop_privileges(args.uid_name, args.gid_name)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        server.shutdown()
        exit(0)
