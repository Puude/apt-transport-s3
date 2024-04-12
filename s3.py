#!/usr/bin/python -u
# Copyright (C) 2014 Bashton Ltd
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from urllib.parse import urlparse
import hashlib
import hmac
import sys
import os
import urllib
from configobj import ConfigObj
from boto3.session import Session

import syslog


class AWSCredentials(object):
    """
    Class for dealing with IAM role credentials from meta-data server and later
    on to deal with boto/aws config provided keys
    """

    def __init__(self):
        """
        Loading config file from predefined location.
        Example config file content:
            profile = aws_profile (~/.aws/credentials)
        """
        _CONF_FILE = '/etc/apt/s3auth.conf'

        # Checking if 'file' exists, if it does read it
        if os.path.isfile(os.path.expanduser(_CONF_FILE)):
            config = ConfigObj(os.path.expanduser(_CONF_FILE))
        else:
            raise Exception("Config file: %s doesn't exist" % _CONF_FILE)
            syslog.syslog("Config file: %s doesn't exist" % _CONF_FILE)

        self.profile = config['profile']

        session = Session(profile_name=config['profile'])
        self.s3 = session.resource('s3')

    def getObject(self, url, **kwargs):
        """getObject(url) open the remote file and return a file object."""

        bucket = url.split('/')[0]

        filename = urllib.unquote(
            url.replace(
                '{0}/'.format(bucket),
                '')).decode('utf8')

        obj = self.s3.Object(bucket_name=bucket, key=filename)
        response = obj.get()
        return response


class APTMessage(object):
    MESSAGE_CODES = {
        100: 'Capabilities',
        102: 'Status',
        200: 'URI Start',
        201: 'URI Done',
        400: 'URI Failure',
        600: 'URI Acquire',
        601: 'Configuration',
    }

    def __init__(self, code, headers):
        self.code = code
        self.headers = headers

    def process(self, lines):
        status_line = lines.pop(0)
        self.code = int(status_line.split()[0])
        self.headers = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parts = [p.strip() for p in line.split(':', 1)]
            if len(parts) != 2:
                continue
            self.headers.append(parts)
        return self(self.code, self.headers)

    def encode(self):
        result = '{0} {1}\n'.format(self.code, self.MESSAGE_CODES[self.code])
        for item in self.headers.keys():
            if self.headers[item] is not None:
                result += '{0}: {1}\n'.format(item, self.headers[item])
        return result + '\n'


class S3_method(object):
    __eof = False

    def __init__(self):
        self.iam = AWSCredentials()
        self.send_capabilities()

    def fail(self, message='Failed'):
        self.send_uri_failure({'URI': self.uri, 'Message': message})

    def _read_message(self):
        """
        Apt uses for communication with its methods the text protocol similar
        to http. This function parses the protocol messages from stdin.
        """
        if self.__eof:
            return None
        result = {}
        line = sys.stdin.readline()
        while line == '\n':
            line = sys.stdin.readline()
        if not line:
            self.__eof = True
            return None
        s = line.split(" ", 1)
        result['_number'] = int(s[0])
        result['_text'] = s[1].strip()

        while not self.__eof:
            line = sys.stdin.readline()
            if not line:
                self.__eof = True
                return result
            if line == '\n':
                return result
            s = line.split(":", 1)
            result[s[0]] = s[1].strip()

    def send(self, code, headers):
        message = APTMessage(code, headers)
        sys.stdout.write(message.encode())

    def send_capabilities(self):
        self.send(100, {'Version': '1.0', 'Single-Instance': 'true'})

    def send_status(self, headers):
        self.send(102, headers)

    def send_uri_start(self, headers):
        self.send(200, headers)

    def send_uri_done(self, headers):
        self.send(201, headers)

    def send_uri_failure(self, headers):
        self.send(400, headers)

    def run(self):
        """Loop through requests on stdin"""
        while True:
            message = self._read_message()
            if message is None:
                return 0
            if message['_number'] == 600:
                try:
                    self.fetch(message)
                except Exception as e:
                    self.fail(e.__class__.__name__ + ": " + str(e))
            else:
                return 100

    # We need to be able to quote specific characters to support S3
    # lookups, something urllib and friends don't do easily
    def quote(self, s, unsafe):
        res = list(s)
        for i in range(len(res)):
            c = res[i]
            if c in unsafe:
                res[i] = '%%%02X' % ord(c)
        return ''.join(res)

    def fetch(self, msg):
        self.uri = msg['URI']
        self.uri_parsed = urlparse(self.uri)
        # quote path for +, ~, and spaces
        # see bugs.launchpad.net #1003633 and #1086997
        self.uri_updated = self.uri_parsed.loc +\
            self.quote(self.uri_parsed.path, '+~ ')
        self.filename = msg['Filename']

        response = self.iam.getObject(self.uri_updated)
        self.send_status({'URI': self.uri, 'Message': 'Waiting for headers'})

        if response['ResponseMetadata']['HTTPStatusCode'] != 200:
            self.send_uri_failure({
                'URI': self.uri,
                'Message': 'Failed',
                'FailReason': 'Failed'})
            return

        self.send_uri_start({
            'URI': self.uri,
            'Size': response['ContentLength'],
            'Last-Modified': response['LastModified'].strftime("%Y-%m-%d %H:%M:%S")})

        f = open(self.filename, "w")
        hash_sha256 = hashlib.sha256()
        hash_sha512 = hashlib.sha512()
        hash_md5 = hashlib.md5()
        while True:
            data = response['Body'].read(4096)
            if not len(data):
                break
            hash_sha256.update(data)
            hash_sha512.update(data)
            hash_md5.update(data)
            f.write(data)
        f.close()

        self.send_uri_done({
            'URI': self.uri,
            'Filename': self.filename,
            'Size': response['ContentLength'],
            'Last-Modified': response['LastModified'].strftime("%Y-%m-%d %H:%M:%S"),
            'MD5-Hash': hash_md5.hexdigest(),
            'MD5Sum-Hash': hash_md5.hexdigest(),
            'SHA256-Hash': hash_sha256.hexdigest(),
            'SHA512-Hash': hash_sha512.hexdigest()})

if __name__ == '__main__':
    try:
        method = S3_method()
        ret = method.run()
        sys.exit(ret)
    except KeyboardInterrupt:
        pass
