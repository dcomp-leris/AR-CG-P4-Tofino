#include <core.p4>
#include <t2na.p4>

/*** Types of variable ***/
typedef bit<32> value_t;
typedef bit<10> index_t;
typedef bit<16> ether_type_t;
typedef bit<32> number_of_ports_t;
typedef bit<32> number_of_queues_t;
const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t VLAN_TAGGED = 16w0x8100;
const ether_type_t ETHERTYPE_ARP = 16w0x0806;
const number_of_ports_t N_PORTS = 512;
const bit<32> Th = 32w0x4E6E; 
const number_of_queues_t N_QUEUES = 512;

/*** Headers ***/
header ethernet_h {
    bit<48> dst;
    bit<48> src;
    bit<16> typ;
}

header vlan_tag_t {
    bit<3>  pcp;      
    bit<1>  dei;     
    bit<12> vlan_id;
}

// IPv4
header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<6>  dscp;
    bit<2>  ecn;
    bit<16> total_len;
    bit<16> id;
    bit<3>  flags;
    bit<13> offset;
    bit<8>  ttl;
    bit<8>  proto;
    bit<16> checksum;
    bit<32> src;
    bit<32> dst;
}

/*
header ipv4_h {
    bit<4>  version;
    bit<4>  ihl;
    bit<5>  diffserv;
    bit<1>  l4s;
    bit<2>  ecn;
    bit<16> total_len;
    bit<16> id;
    bit<3>  flags;
    bit<13> offset;
    bit<8>  ttl;
    bit<8>  proto;
    bit<16> checksum;
    bit<32> src;
    bit<32> dst;
}
*/
header arp_h {
    bit<16> hardware_type;
    bit<16> protocol_type;
    bit<8>  hardware_length;
    bit<8>  protocol_length;
    bit<16> opcode;
    bit<48> sender_mac;
    bit<32> sender_ip;
    bit<48> target_mac;
    bit<32> target_ip;
}

header tcp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<32> seq_no;
    bit<32> ack_no;
    bit<4> data_offset;
    bit<4> res;
    bit<8> flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgent_ptr;
}

header udp_h {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> hdr_length;
    bit<16> checksum;
}

struct headers_t {
    ethernet_h  ethernet;
    arp_h       arp;
    ipv4_h      ipv4;
    vlan_tag_t  vlan;
    tcp_h	tcp;
    udp_h 	udp;
}

struct metadata_t{ }


// ---------------------------------------------------------------------------
// Ingress parser
// ---------------------------------------------------------------------------
parser SwitchIngressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.typ) {
            ETHERTYPE_IPV4 : parse_ipv4;
            VLAN_TAGGED : parse_vlan;
            ETHERTYPE_ARP : parse_arp;
            default : accept;
        }
    }

    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select (hdr.ipv4.proto) {
	    6 : parse_tcp;
	    17 : parse_udp;
	    default : accept;
    	}
    }

    state parse_vlan {
        pkt.extract(hdr.vlan);
        transition accept;
    }

    state parse_tcp {
	pkt.extract(hdr.tcp);
        transition accept;
    }
    state parse_udp {
	pkt.extract(hdr.udp);
        transition accept;
    }
}


// SwitchIngress
control SwitchIngress(
        inout headers_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
        
    Register<bit<32>, bit<32>>(1) reg_check;
    Counter<bit<32>, bit<32>>(1, CounterType_t.PACKETS) counter_pkts;

    RegisterAction<bit<32>, bit<32>, bool>(reg_check) check = {
        void apply(inout bit<32> value, out bool result){
            value = 1;
        }
    };
        
    apply {
        check.execute(10);
        counter_pkts.count(0);
        // Destination-based forwarding, same server/port map as ICEFE:
        // 172.16.0.5 Server1 (luigi) -> 137, 172.16.0.3 Server2 (mario) -> 138,
        // 172.16.0.4 Server3 (peach) -> 136. ARP uses its target IP.
        bit<32> dst_ip = 0;
        if (hdr.ipv4.isValid()) {
            dst_ip = hdr.ipv4.dst;
        } else if (hdr.arp.isValid()) {
            dst_ip = hdr.arp.target_ip;
        }

        if (ig_intr_md.ingress_port == 152) {  //p4tg tofino 1
            ig_tm_md.ucast_egress_port = 137; //luigi
        }
        else if (ig_intr_md.ingress_port == 136 || ig_intr_md.ingress_port == 137 ||
                 ig_intr_md.ingress_port == 138) {
            if (dst_ip == 0xAC100005) {        //Server1 (luigi)
                ig_tm_md.ucast_egress_port = 137;
            }
            else if (dst_ip == 0xAC100003) {   //Server2 (mario)
                ig_tm_md.ucast_egress_port = 138;
            }
            else if (dst_ip == 0xAC100004) {   //Server3 (peach)
                ig_tm_md.ucast_egress_port = 136;
            }
            else {
                ig_intr_dprsr_md.drop_ctl = 1; // unknown destination
            }
            if (ig_tm_md.ucast_egress_port == ig_intr_md.ingress_port) {
                ig_intr_dprsr_md.drop_ctl = 1; // do not reflect to sender
            }
        }



        // if(ig_intr_md.ingress_port == 448) {
        //     ig_tm_md.ucast_egress_port = 137;
        // }

            
        // if (ig_intr_md.ingress_port == 137) {
        //     ig_tm_md.ucast_egress_port = 136;
        // }
            
        // if (ig_intr_md.ingress_port == 136) {
        //     ig_tm_md.ucast_egress_port = 137;
        // } 

        // if(ig_intr_md.ingress_port == 448) {
        //     ig_tm_md.ucast_egress_port = 137;
        // }
        
        // if (hdr.udp.isValid()) {
        //     if (hdr.udp.dst_port == 5001) {
        //         ig_tm_md.qid=0;
        //     } 
        //     else if (hdr.udp.dst_port == 5002) {
        //         ig_tm_md.qid=1;
        //     }
        // } 
        // else {
        //     ig_tm_md.qid=0;
        // }
    }  
    
}

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

        apply {
            pkt.emit(hdr);
        }
}


// ---------------------------------------------------------------------------
// Traffic Manager - non-programmable block (queues)
// ---------------------------------------------------------------------------
// TM will receive the packet cloned at the Egress, and will recirculate this 
// packet to the Ingress.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser EgressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {

    state start {
       pkt.extract(eg_intr_md);
       transition parse_ethernet;
    }
    
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.typ) {
            ETHERTYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition accept;
    }
    
}


control Egress(
        inout headers_t hdr,
        inout metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {

        Register<bit<32>, bit<32>>(N_QUEUES) qdepth;
        
        RegisterAction<bit<32>, bit<32>, bool>(qdepth) qdepth_action = {
            void apply(inout bit<32> value, out bool result) {
                value = (bit<32>)eg_intr_md.deq_qdepth;
            }

        };   


        apply {
            qdepth_action.execute((bit<32>)eg_intr_md.egress_qid);

            if (hdr.ipv4.isValid() && eg_intr_md.deq_congest_stat > 0 ) {
                  hdr.ipv4.ecn = 3; 
            } 
        }

            
}

control EgressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md) {

        apply { 
            pkt.emit(hdr);
        }
    
}


Pipeline(SwitchIngressParser(),
        SwitchIngress(),
        SwitchIngressDeparser(),
        EgressParser(),
        Egress(),
        EgressDeparser()) pipe;

Switch(pipe) main;

