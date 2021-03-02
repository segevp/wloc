#!/bin/env python3

from typing import List, Dict
from scapy.all import sniff
from pprint import pformat
from requests import post
from argparse import ArgumentParser
from utils import format_for_xml, get_lines
from proto import request_pb2, response_pb2

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
KML_PLACEMARK = """
        <Placemark>
            <name>{name}</name>
            <description>{description}</description>
            <Point>
                <coordinates>{longitude},{latitude},{altitude}</coordinates>
            </Point>
        </Placemark>"""

SNIFFER_START = "Started sniffing for %i seconds..."
SNIFFER_PROGRESS = "Found %i BSSIDs and their names so far..."
SNIFFER_END = "Done! Found the following networks:\n{networks}"
LOCATION_NOT_FOUND = "* Location not found for {bssid}{ssid}"


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
        query_response = post(URL, data=data, headers=HTTP_HEADERS)
        return query_response.content


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

    @classmethod
    def create_kml(cls, response_pb: response_pb2.Response, ssids=None) -> str:
        if ssids is None:
            ssids = {}
        placemarks = []
        for wifi in response_pb.wifis:
            mac = cls.format_mac_address(wifi.mac)
            ssid = ssids.get(mac)
            if wifi.location.latitude == -18000000000:
                print(LOCATION_NOT_FOUND.format(bssid=mac, ssid=f" - {ssid}" if ssid else ''))
                continue
            lat = cls.format_coordinate(wifi.location.latitude)
            lon = cls.format_coordinate(wifi.location.longitude)
            alt = wifi.location.altitude
            placemarks.append(
                KML_PLACEMARK.format(name=format_for_xml(ssid) if ssid else mac, description=mac, latitude=lat,
                                     longitude=lon, altitude=alt))
        return KML_FORMAT.format(placemarks='\n'.join(placemarks))

    @classmethod
    def create_excel(cls, response_pb: response_pb2.Response, ssids=None) -> str:
        rows = ['bssid,ssid,lat,lon,acc,alt,alt_acc']
        if ssids is None:
            ssids = {}
        for wifi in response_pb.wifis:
            mac = cls.format_mac_address(wifi.mac)
            ssid = ssids.get(mac)
            if wifi.location.latitude == -18000000000:
                print(LOCATION_NOT_FOUND.format(bssid=mac, ssid=f" - {ssid}" if ssid else ''))
                continue
            lat = cls.format_coordinate(wifi.location.latitude)
            lon = cls.format_coordinate(wifi.location.longitude)
            acc = wifi.location.accuracy
            alt = wifi.location.altitude
            alt_acc = wifi.location.altitudeAccuracy
            rows.append(f"{mac},{ssid},{lat},{lon},{acc},{alt},{alt_acc}")
        return '\n'.join(rows)

    @staticmethod
    def format_mac_address(mac):
        return ':'.join([f'0{byte}' if len(byte) == 1 else byte for byte in mac.split(':')])

    @staticmethod
    def format_coordinate(coordinate):
        return coordinate * (10 ** -8)


class SniffHandler:
    def __init__(self, iface: str = 'wlan0', timeout: int = 20):
        self.iface = iface
        self.timeout = timeout
        self.bssids_ssids = {}

    def sniff_for_ssids(self) -> Dict[str, bytes]:
        print(SNIFFER_START % self.timeout)
        sniff(iface=self.iface, timeout=self.timeout, filter='wlan type mgt subtype beacon',
              prn=lambda pkt: self.update_ssids(pkt))
        print(SNIFFER_END.format(networks=pformat(self.bssids_ssids)))
        return self.bssids_ssids

    def update_ssids(self, pkt):
        bssid_ssid = {pkt.addr2: pkt.info.decode()}
        self.bssids_ssids.update(bssid_ssid)
        print('\r' + SNIFFER_PROGRESS % len(self.bssids_ssids), end='')


def parse_args():
    parser = ArgumentParser()
    parser.add_argument("-l", "--limit", help="limit query results (default: 100)", type=int, default=400)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-b', '--bssid', nargs='+')
    group.add_argument('-f', '--file', help="load bssids from file", type=str, nargs='?')
    group.add_argument('-s', '--sniff', help="sniffs for bssids and ssids", action='store_true')
    args = parser.parse_args()
    return args.file, args.bssid, args.limit, args.sniff


def query_macs(macs: List[str], query_limit: int):
    msg = PBFunctions.build_request(macs, query_limit)
    binary_handler = BinaryHandler(HEADERS, msg.SerializeToString())
    query_results = binary_handler.query()
    response = PBFunctions.parse_response(query_results)
    return response


def main():
    file, macs, query_limit, to_sniff = parse_args()
    if file:
        macs = get_lines(file) if file else macs
    elif to_sniff:
        sniff_handler = SniffHandler()
        macs = sniff_handler.sniff_for_ssids()
        query_limit = len(macs)
    response = query_macs(macs, query_limit)
    kml = PBFunctions.create_excel(response, macs if to_sniff else None)
    with open('out.kml', 'w') as f:
        f.write(kml)


if __name__ == "__main__":
    main()
