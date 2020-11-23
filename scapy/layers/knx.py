from scapy.fields import BitField, BitEnumField, ByteField, XByteField, ByteEnumField, ShortField, StrField
from scapy.packet import bind_layers, bind_bottom_up, Packet
from scapy.layers.inet import UDP

class KNXAddrField(ShortField):
    def i2repr(self, pkt, x):
        return "%d.%d.%d" % ((x>>12)&0xf, (x>>8)&0xf, (x&0xff))
    def any2i(self, pkt, x):
        if type(x) is str:
            try:
                a,b,c = map(int, x.split("."))
                x = (a<<12)|(b<<8)|c
            except:
                raise ValueError(x)
        ShortField.any2i(self, pkt, x)

class KNXGroupField(ShortField):
    def i2repr(self, pkt, x):
        return "%d/%d/%d" % ((x>>11)&0x1f, (x>>8)&0x7, (x&0xff))
    def any2i(self, pkt, x):
        if type(x) is str:
            try:
                a,b,c = map(int, x.split("/"))
                x = (a<<11)|(b<<8)|c
            except:
                raise ValueError(x)
        ShortField.any2i(self, pkt, x)



class KNXIP(Packet):
    name = "KNXIP"
    fields_desc = [
        ByteField("header_len", None),
        XByteField("version", 0x10),
        ByteEnumField("service_family", 4, {4:"tunneling"}),
        ByteEnumField("service_type", 0x20, {0x20:"request"}),
        ShortField("total_len", None),
        ByteField("struct_len", None),
        ByteField("channel", 0x4d),
        ByteField("counter", 0),
        ByteField("reserved", 0)
    ]

class CEMI(Packet):
    name = "cEMI"
    fields_desc = [
        ByteField("message_code", 0x29),
        ByteField("additional_info_len", None),
        # Ctrl1
        BitEnumField("frame_type", 1, 1, { 1: "standard"}),
        BitField("reserved", 0, 1),
        BitField("repeat_on_error", 1, 1),
        BitEnumField("broadcast", 1, 1, { 1: "domain"}),
        BitEnumField("priority", 3, 2, { 3: "low"}),
        BitField("ack_wanted", 0, 1),
        BitField("confirmation_error", 0, 1),
        # Ctrl2
        BitEnumField("address_type", 1, 1, { 1: "group"}),
        BitField("hop_count", 6, 3),
        BitField("extended_frame_format", 0, 4),
        ##
        KNXAddrField("src", "1.2.3"),
        KNXGroupField("dst", "1/2/3"),
        ByteField("len",None),
        # TCPI
        BitEnumField("packet_type", 0, 1, { 0: "data"}),
        BitEnumField("sequence_type", 0, 1, { 0: "unnumbered"}),
        BitField("reserved2", 0, 4),
        BitEnumField("acpi", 2, 4, { 2: "GroupValueWrite"} ),
        BitField("reserved3", 0, 6),
        StrField("data", "")
    ]


bind_layers(UDP, KNXIP, dport=3671)
bind_bottom_up(UDP, KNXIP, sport=3671)

bind_layers(KNXIP, CEMI)
