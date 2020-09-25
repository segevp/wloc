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


def format_len(array) -> bytes:
    return len(array).to_bytes(2, 'big')


def create_item(header_text: bytes) -> bytes:
    return b'%b%b' % (format_len(header_text), header_text)


def build_items(headers: List[bytes]) -> bytes:
    final_headers = NUL_SOH + b'%b' + NUL_NUL + NUL_SOH + NUL_NUL
    only_headers = b''.join([create_item(header) for header in headers])
    final_headers = final_headers % only_headers
    return final_headers


def build_request(macs: List[str], limit: int = 3, noise: int = 0) -> request_pb2.Request:
    request = request_pb2.Request()
    request.limit = limit
    request.noise = noise
    for mac in macs:
        request.wifis.add(mac=mac)
    return request


def compose_data(message: request_pb2.Request, headers: List[bytes]) -> bytes:
    serialized_message = message.SerializeToString()
    return build_items(headers) + format_len(serialized_message) + serialized_message


def query(request_pb: request_pb2.Request) -> response_pb2.Response:
    data = compose_data(request_pb, HEADERS)
    response = requests.post(URL, data=data, headers=HTTP_HEADERS)
    return parse_response(response.content)


def parse_response(query_response: bytes) -> response_pb2.Response:
    response_pb = response_pb2.Response()
    response_pb.ParseFromString(query_response[10:])
    return response_pb


def create_kml(response_pb: response_pb2.Response) -> str:
    placemarks = [KML_PLACEMARK.format(bssid=wifi.mac,
                                       latitude=wifi.location.latitude * (10 ** -8),
                                       longitude=wifi.location.longitude * (10 ** -8),
                                       altitude=wifi.location.altitude) for wifi in response_pb.wifis]
    return KML_FORMAT.format(placemarks='\n'.join(placemarks))


msg = build_request(['E0:CE:C3:8C:1F:D7'])
kml = create_kml(query(msg))
with open('out.kml', 'w') as f:
    f.write(kml)
