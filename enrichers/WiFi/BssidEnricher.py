import traceback
import requests
import sys
import time
from parsers import GenericParser
import os


class BssidEnricher(GenericParser.GenericParser):
    def __init__(self):
        print("BssidEnricher: Enter your Google Geolocation API Key")
        if True:
            for line in sys.stdin:
                self.api_key = line.rstrip()
                break
        print("Key: "+self.api_key+":")
        self.window_advance_factor = 1
        self.window_size = 3
        self.sleep_time = 2

    def can_handle(self, filename):
        if "mac_address_list" in filename.strip().lower():
            return True
        return False

    def request_location(self, mac1, mac2, mac3, file):
        payload = {
            "considerIp": "false",
            "wifiAccessPoints": [
                {
                    "macAddress": mac1,
                    "signalStrength": -43,
                    "signalToNoiseRatio": 0
                },
                {
                    "macAddress": mac2,
                    "signalStrength": -55,
                    "signalToNoiseRatio": 0
                },
                {
                    "macAddress": mac3,
                    "signalStrength": -55,
                    "signalToNoiseRatio": 0
                }
            ],
        }
        resp = requests.post(
            'https://www.googleapis.com/geolocation/v1/geolocate?key='+self.api_key,
            json=payload)
        data = resp.json()
        try:
            lat = ''
            lng = ''
            accuracy = ''
            error = ''
            if "location" in data:
                if "lat" in data["location"]:
                    lat = str(data["location"]["lat"])
                if "lng" in data["location"]:
                    lng = str(data["location"]["lng"])
            if "accuracy" in data:
                accuracy = str(data["accuracy"])
            file.write(mac1+";"+mac2+";"+mac3+";"+lat+";"+lng+";"+accuracy+";"+error+";\n")
        except Exception as e:
            print(sys.exc_info()[2])
            print(traceback.format_exc())
            print(resp.text)

    def process(self, filepath):
        basename = os.path.basename(filepath)
        outfile = self.output_dir+"bssid-enricher-"+basename+".csv"
        file = open(filepath, 'r')
        fw = open(outfile, 'w')
        lines = file.readlines()
        final_list = []
        for idx, x in enumerate(lines):
            if x.startswith("#"):
                continue
            final_list.append(x.strip())
        window_start = 0
        window_end = self.window_size-1
        fw.write("mac1;mac2;mac3;lat;lng;accuracy;error;\n")
        while window_end < len(final_list):
            mac1 = final_list[window_start]
            mac2 = final_list[window_start+1]
            mac3 = final_list[window_start+2]
            self.request_location(mac1, mac2, mac3, fw)
            window_start = window_start+self.window_advance_factor
            window_end = window_end+self.window_advance_factor
            time.sleep(self.sleep_time)
        fw.close()


