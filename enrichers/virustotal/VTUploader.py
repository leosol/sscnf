import csv
import hashlib
import virustotal_python
import sys
import time
from parsers import GenericParser
import os
from pprint import pprint



class VTUploader(GenericParser.GenericParser):
    def __init__(self, output_dir):
        print("VTUploader: Enter your VT API Key")
        if True:
            for line in sys.stdin:
                self.api_key = line.rstrip()
                break
        print("Key: "+self.api_key+":")
        self.output_dir = output_dir
        self.expected_file = open(self.output_dir + "virustotal-expected.csv", mode='w', newline='', encoding='utf-8')
        self.expected_writer = csv.writer(self.expected_file, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        self.expected_writer.writerow(['file_name'])
        self.completed_file = open(self.output_dir + "virustotal-completed.csv", mode='w', newline='', encoding='utf-8')
        self.completed_writer = csv.writer(self.completed_file, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        self.completed_writer.writerow(['file_name'])
        self.summary_file = open(self.output_dir+"virustotal-summary.csv", mode='w', newline='', encoding='utf-8')
        self.summary_writer = csv.writer(self.summary_file, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        self.summary_writer.writerow(['file_name', 'package', 'main_activity', 'malicious', 'suspicious', 'undetected'])
        self.perm_summary_file = open(self.output_dir + "virustotal-permission-summary.csv", mode='w', newline='', encoding='utf-8')
        self.perm_summary_writer = csv.writer(self.perm_summary_file, delimiter=';', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        self.perm_summary_writer.writerow(['file_name', 'package', 'permission_id', 'permission_desc', 'permission_type'])

    def can_handle(self, filename):
        return True

    def process(self, filepath):
        lwr_filepath = filepath.lower()
        if "upload" in lwr_filepath and "virustotal" in lwr_filepath:
            with virustotal_python.Virustotal(self.api_key) as vtotal:
                basename = os.path.basename(filepath)
                file_name = basename
                self.expected_writer.writerow([file_name])
                file_md5 = hashlib.md5(open(filepath, 'rb').read()).hexdigest()
                if (os.path.getsize(filepath)) > 30*1024*1024:
                    files = {"file": (os.path.basename(filepath), open(os.path.abspath(filepath), "rb"))}
                    resp = vtotal.request("files", files=files, method="POST")
                    resp = vtotal.request(f"files/{file_md5}")
                else:
                    large_file = {
                        "file": (
                            basename,
                            open(filepath, "rb"),
                        )
                    }
                    upload_url = vtotal.request("files/upload_url").data
                    resp = vtotal.request(upload_url, files=large_file, method="POST", large_file=True)
                    resp = vtotal.request(f"files/{file_md5}")
                #pprint(resp.data)
                #pprint(resp.json())
                json_resp = resp.json()
                outfile = self.output_dir + "virustotal-" + basename + ".resp"
                fw = open(outfile, 'w')
                fw.write(str(resp.json()))
                fw.close()
                if 'data' in json_resp and 'attributes' in json_resp['data'] and 'androguard' in json_resp['data']['attributes'] and 'Package' in json_resp['data']['attributes']['androguard']:
                    package = json_resp['data']['attributes']['androguard']['Package']
                else:
                    package = ''
                if 'data' in json_resp and 'attributes' in json_resp['data'] and 'androguard' in json_resp['data']['attributes'] and 'main_activity' in json_resp['data']['attributes']['androguard']:
                    main_activity = json_resp['data']['attributes']['androguard']['main_activity']
                else:
                    main_activity = ''
                if 'data' in json_resp and 'attributes' in json_resp['data'] and 'last_analysis_stats' in json_resp['data']['attributes'] and 'malicious' in json_resp['data']['attributes']['last_analysis_stats']:
                    malicious = json_resp['data']['attributes']['last_analysis_stats']['malicious']
                else:
                    malicious = ''
                if 'data' in json_resp and 'attributes' in json_resp['data'] and 'last_analysis_stats' in json_resp['data']['attributes'] and 'suspicious' in json_resp['data']['attributes']['last_analysis_stats']:
                    suspicious = json_resp['data']['attributes']['last_analysis_stats']['suspicious']
                else:
                    suspicious = ''
                if 'data' in json_resp and 'attributes' in json_resp['data'] and 'last_analysis_stats' in json_resp['data']['attributes'] and 'undetected' in json_resp['data']['attributes']['last_analysis_stats']:
                    undetected = json_resp['data']['attributes']['last_analysis_stats']['undetected']
                else:
                    undetected = ''

                self.summary_writer.writerow([file_name, package, main_activity, malicious, suspicious, undetected])
                for item in json_resp['data']['attributes']['androguard']['permission_details']:
                    permission_id = item
                    full_description = json_resp['data']['attributes']['androguard']['permission_details'][permission_id]['full_description']
                    permission_type = json_resp['data']['attributes']['androguard']['permission_details'][permission_id]['permission_type']
                    self.perm_summary_writer.writerow([file_name, package, permission_id, full_description, permission_type])
                self.completed_writer.writerow([file_name])


