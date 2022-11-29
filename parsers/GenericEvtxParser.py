from lxml import etree
from datetime import datetime

from Evtx.Evtx import Evtx
from Evtx.Views import evtx_file_xml_view
from parsers import GenericParser


class GenericEvtxParser(GenericParser.GenericParser):

    def to_lxml(self, record_xml):
        return etree.fromstring(record_xml)

    def xml_records(self, filename):
        with Evtx(filename) as evtx:
            for xml, record in evtx_file_xml_view(evtx.get_file_header()):
                try:
                    yield self.to_lxml(xml), None
                except etree.XMLSyntaxError as e:
                    yield xml, e

    def get_child(self, node, tag, ns="{http://schemas.microsoft.com/win/2004/08/events/event}"):
        return node.find("%s%s" % (ns, tag))

    def get_child2(self, node, tag, ns="{Event_NS}"):
        return node.find("%s%s" % (ns, tag))

    def print_node(self, node):
        print(etree.tostring(node))
