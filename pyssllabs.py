#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import urllib2
import json
import time
from datetime import datetime
import sys

SSLLABS_API_ENTRYPOINT = 'https://api.ssllabs.com/api/v2/'
_FMT = '%Y-%m-%d %H:%M:%S'

hasColorama = False

def _c(c):
    return c if hasColorama else ''

def _parse_args():
    ap = argparse.ArgumentParser(description='SSL Server Test with the ssllabs.com API')

    meg = ap.add_mutually_exclusive_group(required=True)
    meg.add_argument('-i', '--info', action='store_true', help='Info')
    meg.add_argument('-H', '--host', dest='host', type=str, metavar='<host>',
                     help='Test a single host e.g. www.example.com')


    meg.add_argument('-S', '--statuscodes', action='store_true',
                     help='Show available status codes and its details')

    meg.add_argument('-file', '--file', action='store_true',
                     help='Show available status codes and its details')

    ap.add_argument('-n', '--nocolor', action='store_true',
                    help='Omit colorized output')

    ap.add_argument('-g', '--grade', action='store_true',
                    help='Output the grade in the form <fqdn>:<grade>')

    ap.add_argument('-s', '--startnew', action='store_true',
                     help='Start new scan. Don\'t deliver cached results.')

    return ap

def _format_timestamp(t):
    return time.strftime(_FMT, time.localtime(t / 1000))

class Info(object):
    version = None
    criteriaVersion = None
    maxAssessments = None
    currentAssessments = None
    messages = None
    clientMaxAssessments = None

class Host(object):
    host = None
    port = None
    protocol = None
    isPublic = None
    status = None
    statusMessage = None
    startTime = None
    testTime = None
    engineVersion = None
    criteriaVersion = None
    cacheExpiryTime = None
    endpoints = []
    certHostnames = []

class EndPoint(object):
    ipAddress = None
    serverName = None
    statusMessage = None
    statusDetails = None
    statusDetailsMessage = None
    grade = None
    hasWarnings = None
    isExceptional = None
    progress = None
    duration = None
    eta = None
    delegation = None
    details = None

class Key(object):
    size = None
    strength = None
    alg = None
    debianFlaw = None
    q = None

class Cert(object):
    subject = None
    commonNames = []
    altNames = []
    notBefore = None
    notAfter = None
    issuerSubject = None
    sigAlg = None
    revocationInfo = None
    crlURIs = []
    ocspURIs = []
    revocationStatus = None
    sgc = None
    validationType = None
    issues = None

class Chain(object):
    certs = []
    issues = None

class Suites(object):
    _list = []
    preference = None

class SimDetails(object):
    results = []

class EndpointDetails(object):
    hostStartTime = None
    key = Key()
    cert = Cert()
    chain = Chain()
    protocols = []
    suites = Suites()
    serverSignature = None
    prefixDelegation = None
    nonPrefixDelegation = None
    vulnBeast = None
    renegSupport = None
    stsResponseHeader = None
    stsMaxAge = None
    stsSubdomains = None
    pkpResponseHeader = None
    sessionResumption = None
    compressionMethods = None
    supportsNpn = None
    npnProtocols = None
    sessionTickets = None
    ocspStapling = None
    sniRequired = None
    httpStatusCode = None
    httpForwarding = None
    supportsRc4 = None
    forwardSecrecy = None
    rc4WithModern = None
    sims = SimDetails()
    heartbleed = None
    heartbeat = None
    openSslCcs = None
    poodleTls = None
    fallbackScsv = None
    freak = None

class ChainCert(object):
    subject = None
    label = None
    notBefore = None
    notAfter = None
    issuerSubject = None
    issuerLabel = None
    sigAlg = None
    issues = None
    keyAlg = None
    keySize = None
    keyStrength = None
    raw = None

class Protocol(object):
    _id = None
    name = None
    version = None
    v2SuitesDisabled = None
    q = None

class SimClient(object):
    _id = None
    name = None
    platform = None
    version = None
    isReference = None

class Simulation(object):
    client = None
    errorCode = None
    attempts = None
    protocolId = None
    suiteId = None

class Suite(object):
    _id = None
    name = None
    cipherStrength = None
    dhStrength = None
    dhP = None
    ghG = None
    dhYs = None
    ecdhBits = None
    ecdhStrength = None
    q = None

class StatusCodes(object):
    statusDetails = None

class SSLLabs(object):
    def info(self):
        f = urllib2.urlopen(SSLLABS_API_ENTRYPOINT + 'info')
        jsn = json.loads(f.read())
        f.close()

        i = Info()
        i.version = jsn.get('engineVersion')
        i.criteriaVersion = jsn.get('criteriaVersion')
        i.maxAssessments = jsn.get('maxAssessments')
        i.currentAssessments = jsn.get('currentAssessments')
        i.messages = jsn.get('messages')
        i.clientMaxAssessments = jsn.get('clientMaxAssessments')

        return i

    def analyze(self, host='www.ssllabs.com', publish='off', startNew='off',
                fromCache='off', maxAge='1', _all='on', ignoreMismatch='off'):

            # TODO: catch HTTP errors
            f = urllib2.urlopen(SSLLABS_API_ENTRYPOINT + 'analyze?'       +
                                'host='           + host          + '&' +
                                'publish='        + publish       + '&' +
                                'startNew='       + startNew      + '&' +
                                'fromCache='      + fromCache     + '&' +
                                'maxAge='         + maxAge        + '&' +
                                'all='            + _all          + '&' +
                                'ignoreMismatch=' + ignoreMismatch)
            jsn = json.loads(f.read())
            f.close()

            h = Host()
            h.host = jsn.get('host')
            h.port = jsn.get('port')
            h.protocol = jsn.get('protocol')
            h.isPublic = jsn.get('isPublic')
            h.status = jsn.get('status')
            h.statusMessage = jsn.get('statusMessage')
            h.startTime = jsn.get('startTime')

            h.testTime = jsn.get('testTime')

            h.engineVersion = jsn.get('engineVersion')
            h.criteriaVersion = jsn.get('criteriaVersion')
            h.cacheExpiryTime = jsn.get('cacheExpiryTime')

            if h.status != 'READY':
                return h

            for e in jsn.get('endpoints'):

                endpoint = EndPoint()
                endpoint.ipAddress = e.get('ipAddress')
                endpoint.serverName = e.get('serverName')
                endpoint.statusMessage = e.get('statusMessage')
                endpoint.statusDetails = e.get('statusDetails')
                endpoint.statusDetailsMessage = e.get('statusDetailsMessage')
                endpoint.grade = e.get('grade')
                endpoint.hasWarnings = e.get('hasWarnings')
                endpoint.isExceptional = e.get('isExceptional')
                endpoint.progress = e.get('progress')
                endpoint.duration = e.get('duration')
                endpoint.eta = e.get('eta')
                endpoint.delegation = e.get('delegation')

                if _all == 'on':
                    endpoint.details = EndpointDetails()
                    endpoint.details.hostStartTime = e.get('details').get('hostStartTime')

                    endpoint.details.key = Key()
                    endpoint.details.key.size = e.get('details').get('key').get('size')
                    endpoint.details.key.strength = e.get('details').get('key').get('strength')
                    endpoint.details.key.alg = e.get('details').get('key').get('alg')
                    endpoint.details.key.debianFlaw = e.get('details').get('key').get('debianFlaw')
                    endpoint.details.key.q = e.get('details').get('key').get('q')

                    endpoint.details.cert = Cert()
                    endpoint.details.cert.subject = e.get('details').get('cert').get('subject')
                    endpoint.details.cert.commonNames = e.get('details').get('cert').get('commonNames')
                    endpoint.details.cert.altNames = e.get('details').get('cert').get('altNames')
                    endpoint.details.cert.notBefore = e.get('details').get('cert').get('notAfter')
                    endpoint.details.cert.issuerSubject = e.get('details').get('cert').get('issuerSubject')
                    endpoint.details.cert.sigAlg = e.get('details').get('cert').get('sigAlg')
                    endpoint.details.cert.issuerLabel = e.get('details').get('cert').get('issuerLabel')
                    endpoint.details.cert.revocationInfo = e.get('details').get('cert').get('revocationInfo')
                    endpoint.details.cert.crlURIs = e.get('details').get('cert').get('crlURIs')
                    endpoint.details.cert.ocspURIs = e.get('details').get('cert').get('ocspURIs')
                    endpoint.details.cert.revocationStatus = e.get('details').get('cert').get('revocationStatus')
                    endpoint.details.cert.sgc = e.get('details').get('cert').get('sgc')
                    endpoint.details.cert.validationType = e.get('details').get('cert').get('validationType')
                    endpoint.details.cert.issues = e.get('details').get('cert').get('issues')

                    endpoint.details.chain = Chain()
                    endpoint.details.chain.certs = []

                    for c in e.get('details').get('chain').get('certs'):
                        cc = ChainCert()

                        cc.subject = c.get('subject')
                        cc.label = c.get('label')
                        cc.notBefore = c.get('notBefore')
                        cc.notAfter = c.get('notAfter')
                        cc.issuerSubject = c.get('issuerSubject')
                        cc.issuerLabel = c.get('issuerLabel')
                        cc.sigAlg = c.get('sigAlg')
                        cc.issues = c.get('issues')
                        cc.keyAlg = c.get('keyAlg')
                        cc.keySize = c.get('keySize')
                        cc.raw = c.get('raw')

                        endpoint.details.chain.certs.append(cc)

                    endpoint.details.chain.issues = e.get('details').get('chain').get('issues')

                    endpoint.details.protocols = []

                    for i in e.get('details').get('protocols'):
                        p = Protocol()
                        p._id = i.get('id')
                        p.name = i.get('name')
                        p.version = i.get('version')
                        p.v2SuitesDisabled = i.get('v2SuitesDisabled')
                        p.q = i.get('q')

                        endpoint.details.protocols.append(p)

                    endpoint.details.suites = Suites()
                    endpoint.details.suites._list = []

                    for i in e.get('details').get('suites').get('list'):
                        s = Suite()
                        s._id = i.get('id')
                        s.name = i.get('name')
                        s.cipherStrength = i.get('cipherStrength')
                        s.dhStrength = i.get('dhStrength')
                        s.dhP = i.get('dhP')
                        s.dhG = i.get('dhG')
                        s.dhYs = i.get('dhYs')
                        s.ecdhBits = i.get('ecdhBits')
                        s.ecdhStrength = i.get('ecdhStrength')
                        s.q = i.get('q')

                        endpoint.details.suites._list.append(s)

                    endpoint.details.serverSignature = e.get('details').get('serverSignature')
                    endpoint.details.prefixDelegation = e.get('details').get('prefixDelegation')
                    endpoint.details.nonPrefixDelegation = e.get('details').get('nonPrefixDelegation')
                    endpoint.details.vulnBeast = e.get('details').get('vulnBeast')
                    endpoint.details.renegSupport = e.get('details').get('renegSupport')
                    endpoint.details.stsResponseHeader = e.get('details').get('stsResponseHeader')
                    endpoint.details.stsMaxAge = e.get('details').get('stsMaxAge')
                    endpoint.details.stsSubdomains = e.get('details').get('stsSubdomains')
                    endpoint.details.pkpResponseHeader = e.get('details').get('pkpResponseHeader')
                    endpoint.details.sessionResumption = e.get('details').get('sessionResumption')
                    endpoint.details.compressionMethods = e.get('details').get('compressionMethods')
                    endpoint.details.supportsNpn = e.get('details').get('supportsNpn')
                    endpoint.details.npnProtocols = e.get('details').get('npnProtocols')
                    endpoint.details.sessionTickets = e.get('details').get('sessionTickets')
                    endpoint.details.ocspStapling = e.get('details').get('ocspStapling')
                    endpoint.details.sniRequired = e.get('details').get('sniRequired')
                    endpoint.details.httpStatusCode = e.get('details').get('httpStatusCode')
                    endpoint.details.httpForwarding = e.get('details').get('httpForwarding')
                    endpoint.details.supportsRc4 = e.get('details').get('supportsRc4')
                    endpoint.details.forwardSecrecy = e.get('details').get('forwardSecrecy')
                    endpoint.details.rc4WithModern = e.get('details').get('rc4WithModern')

                    endpoint.details.sims = SimDetails()

                    endpoint.details.sims.results = []

                    for i in e.get('details').get('sims').get('results'):
                        s = Simulation()
                        s.client = SimClient()
                        s.client._id = i.get('client').get('id')
                        s.client.name = i.get('client').get('text')
                        s.client.platform = i.get('client').get('platform')
                        s.client.version = i.get('client').get('version')
                        s.client.isReference = i.get('client').get('isReference')

                        s._id = i.get('id')
                        s.errorCode = i.get('errorCode')
                        s.attempts = i.get('attempts')
                        s.protocolId = i.get('protocolId')
                        s.suiteId = i.get('suiteId')
                        endpoint.details.sims.results.append(s)

                    endpoint.details.heartbleed = e.get('details').get('heartbleed')
                    endpoint.details.heartbeat = e.get('details').get('heartbeat')
                    endpoint.details.openSslCcs = e.get('details').get('openSslCcs')
                    endpoint.details.poodleTls = e.get('details').get('poodleTls')
                    endpoint.details.fallbackScsv = e.get('details').get('fallbackScsv')
                    endpoint.details.freak = e.get('details').get('freak')

                h.endpoints.append(endpoint)

            return h

    def getStatusCodes(self):
        f = urllib2.urlopen(SSLLABS_API_ENTRYPOINT + 'getStatusCodes')
        jsn = json.loads(f.read())
        f.close()

        s = StatusCodes()
        s.statusDetails = jsn

        return s

if __name__ == '__main__':
    args = _parse_args().parse_args()

    try:
        from colorama import Fore, Style, init
        init(autoreset=True)
        hasColorama = True
    except ImportError:
        print('No color support. Falling back to normal output.')
        args.nocolor = True

    if args.info:

        s = SSLLabs()
        i = s.info()

        if args.nocolor:
            hasColorama = False

        print(_c(Fore.WHITE) + i.messages[0] + '\n')
        print(_c(Fore.BLUE) + 'Criteria Version: ' + '\t' +
              _c(Fore.CYAN) + i.criteriaVersion)
        print(_c(Fore.BLUE) + 'Maximum Assessments: ' + '\t' +
              _c(Fore.CYAN) + str(i.maxAssessments))
        print(_c(Fore.BLUE) + 'Current Assessments: ' + '\t' +
              _c(Fore.CYAN) + str(i.currentAssessments))
        print(_c(Fore.BLUE) + 'Engine Version: ' +'\t' +
              _c(Fore.CYAN) + str(i.version))

    elif args.statuscodes:
        s = SSLLabs()
        c = s.getStatusCodes()

        for key, value in c.statusDetails['statusDetails'].iteritems():
            print(_c(Fore.BLUE) + key + ': ' + _c(Fore.YELLOW) + value)

    elif args.host:

        s = SSLLabs()

        h = s.analyze(args.host, startNew = 'on' if args.startnew else 'off')

        if args.nocolor:
            hasColorama = False

        if h.status == 'READY':

            for endpoint in h.endpoints:
                if not args.grade:
                    msg = endpoint.serverName + ' (' + endpoint.ipAddress + ')' + ':'

                    print(_c(Style.BRIGHT) + _c(Fore.WHITE) + msg)
                    print(len(msg) * '-')

                c = None

                if endpoint.grade in [ 'A+', 'A', 'A-' ]:
                    c = Fore.GREEN
                elif endpoint.grade in [ 'B', 'C', 'D', 'E' ]:
                    c = Fore.YELLOW
                elif endpoint.grade in [ 'F', 'T', 'M' ]:
                    c = Fore.RED

                if args.grade:
                    print(_c(Fore.WHITE) + endpoint.serverName + ': ' +  _c(c) + endpoint.grade)
                    break

                if endpoint.grade == 'T':
                    print(_c(Fore.BLUE) + 'Rating: ' + '\t\t' + _c(c) +
                          _c(Style.BRIGHT) + endpoint.grade + ' (no trust)')
                elif endpoint.grade == 'M':
                    print(_c(Fore.BLUE) + 'Rating: ' + '\t\t' + _c(c) +
                          _c(Style.BRIGHT) +
                          endpoint.grade + ' (certificate name mismatch)')
                elif endpoint.grade == 'F':
                    print(_c(Fore.BLUE) + 'Rating: ' + '\t\t' + _c(c) +
                          _c(Style.BRIGHT) + endpoint.grade)
                else:
                    print(_c(Fore.BLUE) + 'Rating: ' + '\t\t' + _c(c) +
                          endpoint.grade)

                print('')

                if endpoint.details.supportsRc4:
                    print(_c(Fore.BLUE) + 'RC4: ' + '\t\t\t' + 
                          _c(Fore.RED) + 'supported')
                else:
                    print(_c(Fore.BLUE) + 'RC4: ' + '\t\t\t' + 
                          _c(Fore.GREEN) + 'not supported')

                if endpoint.details.heartbleed:
                    print(_c(Fore.BLUE) + 'Heartbleed: ' + '\t\t' + 
                          _c(Fore.RED) + 'vulnerable')
                else:
                    print(_c(Fore.BLUE) + 'Heartbleed: ' + '\t\t' + 
                          _c(Fore.GREEN) + 'not vulnerable')

                if endpoint.details.poodleTls == -1:
                    print(_c(Fore.BLUE) + 'POODLE: ' + '\t\t' +
                          _c(Fore.YELLOW) + 'test failed')
                elif endpoint.details.poodleTls == -0:
                    print(_c(Fore.BLUE) + 'POODLE: ' + '\t\t' +
                          _c(Fore.YELLOW) + 'unknown')
                elif endpoint.details.poodleTls == 1:
                    print(_c(Fore.BLUE) + 'POODLE: ' + '\t\t' +
                          _c(Fore.GREEN) + 'not vulnerable')
                elif endpoint.details.poodleTls == 2:
                    print(_c(Fore.BLUE) + 'POODLE: ' + '\t\t' +
                          _c(Fore.RED) + 'vulnerable')

                if endpoint.details.freak:
                    print(_c(Fore.BLUE) + 'FREAK: ' + '\t\t\t' + 
                          _c(Fore.RED) + 'vulnerable')
                else:
                    print(_c(Fore.BLUE) + 'FREAK: ' + '\t\t\t' + 
                          _c(Fore.GREEN) + 'not vulnerable')
            print('')

            if not args.grade:
                print(_c(Fore.BLUE) + 'Test starting time: ' + '\t' +
                      _c(Fore.CYAN) + _format_timestamp(h.startTime))
                print(_c(Fore.BLUE) + 'Test completion time: ' + '\t' +
                      _c(Fore.CYAN) + _format_timestamp(h.testTime))
                print(_c(Fore.BLUE) + 'Test duration: ' + '\t\t' +
                      _c(Fore.CYAN) + 
                      str(datetime.strptime(_format_timestamp(h.testTime), _FMT) - 
                      datetime.strptime(_format_timestamp(h.startTime), _FMT)))

            if h.cacheExpiryTime:
                print(_c(Fore.BLUE) + 'Cache expiry time: ' + '\t' +
                      _c(Fore.CYAN) + _format_timestamp(h.cacheExpiryTime))

            sys.exit(0)
        elif h.status == 'ERROR':
            print(_c(Fore.RED) + h.statusMessage)

            sys.exit(1)

        elif h.status == 'DNS':
            print(_c(Fore.CYAN) + h.statusMessage + '.' +
                  'Please try again in a few minutes.')

            sys.exit(2)

        elif h.status == 'IN_PROGRESS':
            msg = 'Assessment is in Progress. Please try again in a few minutes.'
            print(_c(Fore.WHITE) + msg)

            print('')

            print(_c(Fore.BLUE) + 'Test starting time: ' + '\t' +
                  _c(Fore.CYAN) + _format_timestamp(h.startTime))

            sys.exit(3)

        else:
            msg = 'Unknown Status'
            print(_c(Fore.RED) + msg)

            sys.exit(255)
