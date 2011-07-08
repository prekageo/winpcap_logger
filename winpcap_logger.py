"""
A simple network packet logger using WinPcap. It intercepts TCP packets
matching a given filter (Python function) and saves them into normal text output
files for latter analysis.

WARNING: Keep in mind that the utility does not take any special action if a TCP
packet is lost.
"""

from optparse import OptionParser
import ctypes
import winpcapy

def data_to_num(data, offset, len):
    """ Convert data from an array into an integer (big-endian). """
    num = 0
    for i in xrange(len):
        num <<= 8
        num |= data[offset+i]
    return num

def ip_to_str(data, offset):
    """ Convert data from an array into a human-readable IP address. """
    return '%d.%d.%d.%d' % tuple(data[offset:offset+4])

def _packet_handler(param,header,pkt_data):
    """ Handle an intercepted network packet. """
    ether_type = data_to_num(pkt_data, 12, 2)
    if ether_type != 0x0800:
        # if not IP packet return
        return

    ip_header_length = (pkt_data[14] & 15) * 4
    ip_length = data_to_num(pkt_data, 16, 2)
    ip_protocol = pkt_data[23]
    source_ip = ip_to_str(pkt_data, 26)
    dest_ip = ip_to_str(pkt_data, 30)
    ip_data_ofs = 14 + ip_header_length
    if ip_protocol != 6:
        # if not TCP packet return
        return

    tcp = {}
    tcp_source_port = data_to_num(pkt_data, ip_data_ofs, 2)
    tcp_dest_port = data_to_num(pkt_data, ip_data_ofs+2, 2)
    tcp_seq = data_to_num(pkt_data, ip_data_ofs+4, 4)
    tcp_ack = data_to_num(pkt_data, ip_data_ofs+8, 4)
    tcp_header_length = (pkt_data[ip_data_ofs+12]>>4)*4
    tcp_data_ofs = ip_data_ofs+tcp_header_length
    tcp_flags = pkt_data[ip_data_ofs+13]
    tcp_flag_fin = (tcp_flags & 1) == 1
    tcp_flag_syn = (tcp_flags & 2) == 2
    tcp_flag_ack = (tcp_flags & 16) == 16
    tcp_data_len = ip_length - ip_header_length - tcp_header_length
    tcp_data = []
    for i in xrange(tcp_data_len):
        tcp_data.append(chr(pkt_data[tcp_data_ofs+i]))
    tcp_data = ''.join(tcp_data)

    tcp_packet = {}
    tcp_packet['source_ip'] = source_ip
    tcp_packet['source_port'] = tcp_source_port
    tcp_packet['dest_ip'] = dest_ip
    tcp_packet['dest_port'] = tcp_dest_port
    tcp_packet['flag'] = {}
    tcp_packet['flag']['fin'] = tcp_flag_fin
    tcp_packet['flag']['syn'] = tcp_flag_syn
    tcp_packet['flag']['ack'] = tcp_flag_ack
    tcp_packet['data'] = tcp_data
    handle_tcp_packet(tcp_packet)

class TcpConnectionsManager:
    """
    Maintain the state of all TCP connections seen during our execution. Write
    incoming and outgoing data for each connection into separate files.
    """

    curr_id = 0
    map = {}

    class TimeLogEntry:
        """ Represents a line into the time log. """

        def __init__(self, event, conn_info, data_len, snippet, prv):
            """
            Initialize a new line in the time log also associated with the
            previous one for merging purposes.
            """
            self.event = event
            self.conn_info = conn_info
            self.data_len = data_len
            self.prv = prv
            self.snippet = snippet

        def is_same(self, other):
            """ Check if two lines are valid for merging. """
            if self.event != other.event:
                return False
            if self.conn_info['id'] != other.conn_info['id']:
                return False
            return True

        def write(self, file):
            """ Write the line into the log. """
            if self.data_len:
                # If this line has a data length, we may merge.
                self.merge_write(file)
            else:
                self.simple_write(file)
            file.write('\n')
            file.flush()

        def merge_write(self, file):
            """
            Write the line into the log, possibly merging with the previous one.
            """
            if self.prv != None and self.prv.is_same(self):
                # If this line and the previous one are compatible we merge.
                file.seek(self.prv.pos)
                file.write('+%d' % (self.data_len,))
                self.pos = file.tell()
                self.data_len += self.prv.data_len
                self.snippet = (self.prv.snippet[0],self.snippet[1])
                file.write('=%d' % (self.data_len,))
                file.write(' [%r..%r]' % (self.prv.snippet[0],self.snippet[1]))
            else:
                self.simple_write(file)
                file.write(' %d' % (self.data_len,))
                self.pos = file.tell()
                file.write(' [%r..%r]' % (self.snippet[0],self.snippet[1]))

        def simple_write(self, file):
            """ Write the line into the log without merging. """
            file.write('[%5s][%02d][%15s:%05d]' % (self.event,
                self.conn_info['id'], self.conn_info['conn_id'][0],
                self.conn_info['conn_id'][1]))

    def __init__(self):
        """ Open a file to log the time sequence of the TCP events. """
        self.time_log_file = open('general.txt', 'w')
        self.prv_time_log_entry = None

    def new(self, conn_id):
        """
        A new TCP connection is established, so a new pair of files is created.
        """
        base_name = '%02d_%s_%d_%%s.txt' % (self.curr_id, conn_id[1][0],
            conn_id[1][1])
        out_f = open(base_name % ('OUT',), 'wb')
        in_f = open(base_name % ('IN',), 'wb')
        self.map[conn_id] = {
            'id':self.curr_id,
            'conn_id':conn_id[1],
            'closed':False,
            'out_f':out_f,
            'in_f':in_f
        }
        self.curr_id += 1
        self.write_time_log(self.map[conn_id],'OPEN')

    def delete(self, conn_id):
        """ An existing TCP connection closed. """
        rev_conn_id = (conn_id[1],conn_id[0])

        if conn_id in self.map:
            conn_info = self.map[conn_id]
        elif rev_conn_id in self.map:
            conn_info = self.map[rev_conn_id]
        else:
            return False

        if not conn_info['closed']:
            self.write_time_log(conn_info,'CLOSE')

        conn_info['closed'] = True
        conn_info['in_f'].close()
        conn_info['out_f'].close()
        return True

    def data(self, conn_id, data):
        """
        Data arrived on a TCP connection. Log them into the appropriate file.
        """
        rev_conn_id = (conn_id[1],conn_id[0])

        if conn_id in self.map:
            conn_info = self.map[conn_id]
            f = self.map[conn_id]['in_f']
            dir = 'IN'
        elif rev_conn_id in self.map:
            conn_info = self.map[rev_conn_id]
            f = self.map[rev_conn_id]['out_f']
            dir = 'OUT'
        else:
            return False

        if len(data) > 0:
            self.write_time_log(conn_info, dir, len(data),
                (data[:25],data[-25:]))

        if not conn_info['closed']:
            f.write(data)
            f.flush()
        return True

    def write_time_log(self, conn_info, event, data_len=None,snippet=None):
        """ Write a line into the time log. """
        if conn_info == None:
            return

        time_log_entry = self.TimeLogEntry(event,conn_info,data_len,snippet,
            self.prv_time_log_entry)
        time_log_entry.write(self.time_log_file)
        self.prv_time_log_entry = time_log_entry

tcpConnManager = TcpConnectionsManager()

def handle_tcp_packet(tcp_packet):
    """ Handle an intercepted TCP packet. """
    if not filter_tcp_packet(tcp_packet):
        return

    conn_id = (
        (tcp_packet['dest_ip'],tcp_packet['dest_port']),
        (tcp_packet['source_ip'],tcp_packet['source_port'])
    )

    if 0:
      print 'DEBUG: %r,%r'%(tcp_packet['flag'],tcp_packet['data'][:50])
    if tcp_packet['flag']['syn'] and not tcp_packet['flag']['ack']:
        print 'INFO: SYN received %s' % (conn_id,)
        return
    if tcp_packet['flag']['syn'] and tcp_packet['flag']['ack']:
        tcpConnManager.new(conn_id)
        print 'INFO: TCP connection opened %s' % (conn_id,)
    if not tcpConnManager.data(conn_id, tcp_packet['data']):
        print 'ERROR: unknown TCP connection %s' % (conn_id,)
    if tcp_packet['flag']['fin'] and tcp_packet['flag']['ack']:
        if tcpConnManager.delete(conn_id):
            print 'INFO: TCP connection closed %s' % (conn_id,)
        else:
            print 'ERROR: TCP connection closed before opening.'

def start_capture(capture_iface):
    """ Start the network capture on the specified interface. """
    PHAND = ctypes.CFUNCTYPE(None,ctypes.POINTER(ctypes.c_ubyte),
        ctypes.POINTER(winpcapy.pcap_pkthdr),ctypes.POINTER(ctypes.c_ubyte))
    errbuf = ctypes.create_string_buffer(winpcapy.PCAP_ERRBUF_SIZE)

    interfaces = get_interfaces()
    interface = interfaces[capture_iface - 1]
    adhandle = winpcapy.pcap_open_live(interface.name,65536,
        winpcapy.PCAP_OPENFLAG_PROMISCUOUS,1000,errbuf)
    print("Capturing on %s...\n" % (interface.description,))
    winpcapy.pcap_loop(adhandle, -1, PHAND(_packet_handler), None)
    winpcapy.pcap_close(adhandle)

def get_interfaces():
    """ Get a list of available network interfaces. """
    errbuf = ctypes.create_string_buffer(winpcapy.PCAP_ERRBUF_SIZE)

    alldevs = ctypes.POINTER(winpcapy.pcap_if_t)()
    winpcapy.pcap_findalldevs(ctypes.byref(alldevs), errbuf)
    device = alldevs.contents
    interfaces = []
    while True:
        interfaces.append(device)
        if not device.next:
            break
        device = device.next.contents
    return interfaces

def print_interfaces():
    """ Print the list of available network interfaces. """
    interfaces = get_interfaces()

    counter = 1
    print 'Available interfaces'
    for inteface in interfaces:
        print '%2d. %s' % (counter, inteface.description)
        counter += 1

def filter_tcp_packet(tcp_packet):
    """
    Filter TCP packets for inclusion into the log files. Return True when a
    packet should be logged.
    """
    if tcp_packet['source_port'] != 80 and tcp_packet['dest_port'] != 80:
        return False
    return True

def main():
    parser = OptionParser()
    parser.add_option("-i", "--interfaces", action="store_const", const=0,
        dest="action", help="display a list of network interfaces")
    parser.add_option("-c", "--capture", dest="capture_iface", type="int",
        help="begin capture on the specified interface", metavar="IFACE_NUMBER")
    (options, args) = parser.parse_args()

    if options.action == 0:
        print_interfaces()
    elif options.capture_iface != None:
        start_capture(options.capture_iface)
    else:
        parser.print_help()

if __name__ == '__main__':
    main()
