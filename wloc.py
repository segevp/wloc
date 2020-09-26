#!/bin/env python3

from typing import List
import request_pb2
import response_pb2
import requests

NUL_SOH = b'\x00\x01'
NUL_NUL = b'\x00\x00'
LOCALE = b'en_US'
IDENTIFIER = b'com.apple.locationd'
VERSION = b'14.0.1.18A393'
HEADERS = [LOCALE, IDENTIFIER, VERSION]

URL = 'https://gs-loc.apple.com/clls/wloc'
HTTP_HEADERS = {'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'locationd/1756.1.15 CFNetwork/711.5.6 Darwin/14.0.0'}
HTTP_RESPONSE_OFFSET = 10

KML_FORMAT = """<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2">
  <Document>
    {placemarks}
  </Document>
</kml>"""
KML_PLACEMARK = """<Placemark>
    <name>{bssid}</name>
    <description>hi</description>
    <Point>
        <coordinates>{longitude},{latitude},{altitude}</coordinates>
    </Point>
</Placemark>"""


class BinaryHandler:
    def __init__(self, headers: List[bytes] = None, serialized_message: bytes = None):
        self.headers = headers
        self.serialized_message = serialized_message

    @staticmethod
    def format_len(array) -> bytes:
        return len(array).to_bytes(2, 'big')

    @classmethod
    def build_item(cls, header_text: bytes) -> bytes:
        return b'%b%b' % (cls.format_len(header_text), header_text)

    def build_headers(self) -> bytes:
        final_headers = NUL_SOH + b'%b' + NUL_NUL + NUL_SOH + NUL_NUL
        only_headers = b''.join([self.build_item(header) for header in self.headers])
        final_headers = final_headers % only_headers
        return final_headers

    def compose_data(self) -> bytes:
        return self.build_headers() + self.build_item(self.serialized_message)

    def query(self) -> bytes:
        data = self.compose_data()
        response = requests.post(URL, data=data, headers=HTTP_HEADERS)
        return response.content


class PBFunctions:

    @staticmethod
    def build_request(macs: List[str], limit: int = 100, noise: int = 0) -> request_pb2.Request:
        request_pb = request_pb2.Request()
        request_pb.limit = limit
        request_pb.noise = noise
        for mac in macs:
            request_pb.wifis.add(mac=mac)
        return request_pb

    @staticmethod
    def parse_response(query_response: bytes) -> response_pb2.Response:
        response_pb = response_pb2.Response()
        response_pb.ParseFromString(query_response[HTTP_RESPONSE_OFFSET:])
        return response_pb

    @staticmethod
    def create_kml(response_pb: response_pb2.Response) -> str:
        placemarks = [KML_PLACEMARK.format(bssid=wifi.mac,
                                           latitude=wifi.location.latitude * (10 ** -8),
                                           longitude=wifi.location.longitude * (10 ** -8),
                                           altitude=wifi.location.altitude) for wifi in response_pb.wifis]
        return KML_FORMAT.format(placemarks='\n'.join(placemarks))


msg = PBFunctions.build_request(['E0:CE:C3:8C:1F:D7'])
binary_handler = BinaryHandler(HEADERS, msg.SerializeToString())
query_results = binary_handler.query()
response = PBFunctions.parse_response(query_results)
kml = PBFunctions.create_kml(response)
with open('out.kml', 'w') as f:
    f.write(kml)
