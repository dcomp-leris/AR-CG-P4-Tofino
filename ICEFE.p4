/*
==============================================================================================================
 ICEFE - In-network Classification of Encrypted Flows for L4S  (final version, ICEFE_CNJ_V2)
 Target: Intel Tofino 2 (t2na), SDE 9.13.4.            Authors: Mateus, Alireza Shirmarz (LERIS)
--------------------------------------------------------------------------------------------------------------
 WHAT THE PROGRAM DOES (one packet's journey)
   1. INGRESS: an original IPv4 packet gets a 16-bit flow ID = CRC16(dst IP, dst port, protocol).
      The per-flow decision (shared_register) tells us the flow's class:
          1 = AR (augmented reality), 2 = CG (cloud gaming), 3 = Other, 0 = not classified yet.
      AR/CG -> ECN = ECT(1), DSCP 46/34, queue Q1 (L4S).   Other -> ECN = Not-ECT, DSCP 50, queue Q0.
      Packets that already carry ECT(1)/CE (real L4S senders) are left as they are.
   2. TRAFFIC MANAGER: Q0 (Classic) and Q1 (L4S) share each server port with DWRR 1:32
      (configured by the controller ICEFE.py).
   3. EGRESS: coupled DualPI2 AQM. The controller writes p_base per port; here
          L4S  (Q1): CE-mark if TM congestion flag, OR delay >= 1 ms step, OR random < 2*p_base;
          Classic (Q0): with probability p_base^2 -> CE-mark (ECT(0)) or drop (Not-ECT).
      Egress also measures the flow features (packet size PS, frame size FS, inter-packet gap IPG,
      inter-frame gap IFG; frames are delimited by the RTP marker bit) and, for the first
      packets/frames of every flow (the "budget"), CLONES the packet to mirror port 128.
   4. CLONE back at INGRESS (port 128): the features are smoothed by 4 low-pass filters (LPF),
      5 decision trees (range tables) vote, table_majority picks the final class, and the class is
      written into shared_register[flow ID]. The clone is then dropped. From now on step 1 uses it.
   INT probes (IP protocol 253, see ../INT) are forwarded through a loop-back pass and stamped with
   queue statistics (two hops: swid 1 = port 137 queues, swid 2 = port 136 queues).

 FILE LAYOUT
   (1) Definitions & headers   (2) Ingress: parser / match-action / deparser
   (3) Egress: parser / match-action / deparser       (4) Pipeline and Switch instantiation
 Lines/blocks named "c7_..." are MEASUREMENT instrumentation used by the experiments (counters,
 sampled delay ring, per-flow packet counters). They do not change forwarding or classification
 decisions, except c7_l4s_step (1 ms L4S step marking) and c7_budget (clone budget), which are part
 of the final ICEFE behaviour.
==============================================================================================================
*/
/*
==============================================================================================================
******************************************* (1) Definition & Headers *****************************************
==============================================================================================================
*/
// Standard P4_16 core library (packet_in/out, basic types).
#include <core.p4>
// Tofino 2 architecture: intrinsic metadata, Register, Lpf, Hash, Mirror, ...
#include <t2na.p4>
/*** Types of variable ***/
// Short names for frequently used bit widths.
typedef bit<4> header_type_t;
typedef bit<4> header_info_t;
typedef bit<32> number_of_ports_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;
typedef bit<32> value_t;
typedef bit<10> index_t;
typedef bit<9> ports_t;
// flow_table_width: CRC16 flow ID indexes every per-flow register.
typedef bit<16> flow_id_t;

//Low Pass Filter EWMA Type 
typedef bit<16> lpf_type_16;
typedef bit<32> lpf_type_32;

/*** INT TYPE ***/
// Field widths of the INT header (must match ../INT/sender.py and receiver.py).
typedef bit<6> switchID_v; 
typedef bit<9> ingress_port_v;
typedef bit<9> egress_port_v;
typedef bit<9> egressSpec_v;
typedef bit<7> qid_v;

// Timestamp is 48 bit but store 32 bits
typedef bit<32>  ingress_global_timestamp_v; 
typedef bit<32>  egress_global_timestamp_v; 
typedef bit<32>  enq_timestamp_v;
typedef bit<32> enq_qdepth_v;           //the value stored in the metadata is 19
typedef bit<32> deq_timedelta_v;
//typedef bit<3>  priority_v;
typedef bit<32> deq_qdepth_v;

/*** Constants ***/
// Sizes and protocol constants. N_PORTS: register size indexed by a 9-bit dev port.
const number_of_ports_t N_PORTS                = 512; 
const number_of_ports_t FLOW_TABLE_SIZE        = 65536; // 2^16 flow slots
const header_type_t HEADER_TYPE_NORMAL_PKT     = 0;
const header_type_t HEADER_TYPE_MIRROR_EGRESS  = 1;
const header_type_t HEADER_TYPE_MIRROR_INGRESS  = 2;
const ether_type_t ETHERTYPE_IPV4              = 16w0x0800;
const ether_type_t ETHERTYPE_ARP = 2054; // topology_parser: untagged Ethernet ARP

// CoDel AQM for EC Marking (Min/Max in Nano Seconds)
// Legacy constants of the earlier CoDel version (no longer used by the code below).
const value_t CoDel_Min                     = 2000000; 
const value_t CoDel_Max              = 10000000; 

// Recirculation for INT and Mirroring Packets
// Port 6 (local to each pipe) = internal recirculation used by INT; 128 = clone (mirror) port.
const ports_t recirc_port                        = 6;   // Recirculation INT 
const ports_t MIRROR_PORT                        = 128; // Mirroring Packets

const bit<8> PROTO_INT = 253;                           // ipv4.protocol for INT in Ingress Packet Parsing
const bit<8> PROTO_UDP = 17;                            // ipv4.protocol for UDP in Ingress Packet Parsing
const bit<8> PROTO_TCP = 6;                             //ipv4.protocol  for TCP in Ingress Packet Parsing
const bit<2> RTP_VERSION = 2;

// Internal Header for Mirroring
// Two 4-bit fields at the start of every clone, used to recognise a mirrored packet.
#define INTERNAL_HEADER         \
    header_type_t header_type;  \
    header_info_t header_info

// Reserved Variable 
// Queue roles in THIS version: Q0 = Classic (Not-ECT / ECT(0)), Q1 = L4S (ECT(1)/CE).
#define MAX_HOPS 10
// Number of Queues 
    // Q0: Classic
    // Q1: L4S
#define SERVER_QUEUE_SLOTS 6 // Three fiber ports, Q0 and Q1 per port.
#define NUMBER_OF_QUEUES 2 //CLASSIC L4S AND CG

/*** Packet Headers ***/
/*
The headers were parsed/deparsed:

    (1) Ethernet [14 Byte]
    (2) IPv4 [20 Byte]
    (3) UDP [8 Byte]  Or TCP [2 Byte]
    (4) RTP [12 Byte]
*/
// Ethernet
// Ethernet II header (14 bytes).
header ethernet_h {
    mac_addr_t dst_mac_addr;
    mac_addr_t src_mac_addr;
    bit<16> ether_type;
}

// topology_arp_header: Ethernet/IPv4 ARP; addresses stay unchanged.
header arp_h {
    bit<16> hardware_type;
    bit<16> protocol_type;
    bit<8> hardware_length;
    bit<8> protocol_length;
    bit<16> opcode;
    bit<48> sender_mac;
    bit<32> sender_ip;
    bit<48> target_mac;
    bit<32> target_ip;
}

// IPv4
// IPv4 header (20 bytes, no options). dscp/ecn are rewritten by ICEFE; checksum is recomputed in the deparsers.
header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<6>  dscp;
    //bit<1>  l4s;
    bit<2>  ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    ipv4_addr_t src_addr;
    ipv4_addr_t dst_addr;
}

// UDP
// UDP header (8 bytes); dstPort is part of the flow ID.
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

// TCP
// TCP header (20 bytes, no options); dstPort is part of the flow ID.
header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  reserved;
    bit<9>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// RTP
// RTP header (12 bytes) assumed right after UDP. marker = 1 on the last packet of a video frame;
// version must be 2, otherwise the bytes are not RTP and are ignored for frame features.
header rtp_t {
    bit<2> version;
    bit<1> padding;
    bit<1> extension;
    bit<4> csrcCounter;
    bit<1> marker;
    bit<7> payloadType;
    bit<16> seqNumber;
    bit<32> timestamp;
    bit<32> ssrcID;
    //bit<16> csrcID;

}

//*** Classification Result ***//
// Per-packet vote of each tree (classT1..T5) and the majority result (metadata only, never emitted).
// Class codes: 1 AR, 2 CG, 3 Other; other values are "go to the next table of this tree" codes.
header classification_h {
    bit<8> metadata_classT1;
    bit<8> metadata_classT2;
    bit<8> metadata_classT3;
    bit<8> metadata_classT4;
    bit<8> metadata_classT5;
    // topology_phv_constraint: preserve byte-contiguous classifier SALU input.
    @pa_container_size("ingress", "ig_md.classification.metadata_final_classification", 8)
    @pa_solitary("ingress", "ig_md.classification.metadata_final_classification")
    bit<8> metadata_final_classification;
}


/*** Mirror Header to carry port metadata ***/
// Header prepended to every clone (egress -> mirror port 128 -> ingress). It carries the raw
// features measured in egress: IPG, IFG (ns), packet size, frame size, RTP marker, queue delay, host IFG
// (RTP timestamp difference), and trigger = 1 meaning "classify with this clone".
header mirror_h {
    INTERNAL_HEADER;
    @flexible PortId_t egress_port;
    @flexible MirrorId_t  mirror_session;
    @flexible bit<32> IPG;
    @flexible flow_id_t flowid;
    @flexible bit<32> ifg;
    @flexible bit<16> packet_size;
    @flexible bit<16> frame_size;
    @flexible bit<1> rtp_marker; // RTP Marker is still 1 bit!
    @flexible bit<32> queue_delay;
    @flexible bit<8> has_rtp;
    @flexible bit<32> host_ifg;
    @flexible bit<8> trigger;
    //@flexible bit<48> egress_global_tstamp;
}

//*** Bridge header to carry ingress timestamp from Ingress to Egress ***//
// Bridge header: ingress -> egress hand-over of ingress port, ingress timestamp and chosen queue.
header bridge_h {
    bit<16> bridge_ingress_port; 
    bit<48> ingress_global_tstamp;
    bit<16> bridge_qid;
}

//*** Count the Hops ***//
// INT: id = probe sequence number, count = number of INT records already pushed.
header nodeCount_h{
    bit<16>  id;
    bit<16>  count;
}

// INT record pushed per hop (37 bytes). Filled in egress by add_swtrace().
header InBandNetworkTelemetry_h {
    switchID_v swid;
    ingress_port_v ingress_port;
    egress_port_v egress_port;
    egressSpec_v egress_spec;
    qid_v qid;
    ingress_global_timestamp_v ingress_global_timestamp;
    egress_global_timestamp_v egress_global_timestamp;
    enq_timestamp_v enq_timestamp;
    enq_qdepth_v enq_qdepth;
    deq_timedelta_v deq_timedelta;
    deq_qdepth_v deq_qdepth;
    //priority_v priority;
    deq_timedelta_v processing_time;
    bit<32> number_of_packets_for_average;
    
    
}

// Struct of the headers
// All headers the parsers may extract (order = emit order in the deparsers).
struct headers_t {
    bridge_h            bridge;
    mirror_h            mirror;
    ethernet_h          ethernet;
    arp_h               arp;
    ipv4_h              ipv4;
    tcp_t        tcp;
    udp_t        udp;
    rtp_t        rtp;

    nodeCount_h        nodeCount;
    InBandNetworkTelemetry_h[2] INT;
}

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct Thresholds {
    bit<8> frame_thresh;
    bit<8> packet_thresh;
}

struct Counters {
    bit<8> frame_count;
    bit<8> packet_count;
}

// Per-packet metadata shared by the controls (ig_md in ingress, eg_md in egress).
struct metadata_t{
    classification_h classification; // Alireza 
    bridge_h    bridge;
    mirror_h    mirror;
    MirrorId_t  mirror_session;
    PortId_t    egress_port;
    // topology_metadata: table key shared by IPv4 and ARP.
    bit<32> topology_destination;
    bit<32> topology_source;
    header_type_t header_type;
    header_info_t header_info;
    ingress_metadata_t   ingress_metadata;
    parser_metadata_t   parser_metadata;
    //bit<8> qid; // Alireza
    bit<16> metadata_index;
    bit<32> metadata_enq_qdepth;
    bit<32> metadata_queue_delay;
    bit<32> metadata_totalPkts;
    bit<32> metadata_input_ipg;
    
    bit<32> metadata_ifg;
    bit<32> metadata_ifg_temp;
    bit<32> metadata_ipg;
    bit<32> metadata_ipg_temp;
    bit<32> metadata_queue_delay_new;
    
    bit<16> metadata_frame_size;
    bit<16> metadata_packet_size;
    flow_id_t metadata_flowID;  
    bit<8> metadata_rtp_marker;                                         // Although RTP Marker is 1 bit, it assigned 8 bit to handle easier in Pipeline!
    bit<8> metadata_has_rtp;
    bit<32> metadata_rtp_timestamp; //Alireza added
    bit<32> metadata_host_ifg; // Alireza added
    // Range-table keys: IPG/IFG in 4.096 us units (bits 31..12 of the ns value), 20 bits wide.
    bit<20> metadata_ipg_20lsb;
    bit<20> metadata_ifg_20lsb;
}

// ****************************** (2) Ingress (Parser/Ingress (MA) Processing/Deparser) ******************************************//
/*
Normal Packet ===>	start → parse_port_metadata → parse_ethernet → ...
Mirrored Packet ===>	start → parse_mirror → parse_bridge → parse_ethernet → ...
INT-Tagged Packet ===>	parse_ipv4 → parse_count → parse_one/two_int
*/
// *** (2-1) Ingress Parsing ***//
// Ingress parser: clones (ingress port 128) start with mirror+bridge headers; all others start with Ethernet.
parser IngressParser(
        packet_in pkt,                                              // Received Packets
        out headers_t hdr,                                          
        out metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    
    // Start State in State Machine        
    state start {                                                    // Divide the parsing into 2: (Cloned:ingress port is 128 or 6) or (original packets)
       pkt.extract(ig_intr_md);
        transition select(ig_intr_md.ingress_port){
            (MIRROR_PORT): parse_mirror;                            // If ingress port is mirrorring (cloned), so go to parse mirror headers
            (_): parse_port_metadata;                               // If ingress port is other, so go to pars normal packets
            
        }
    }

    /*** Original PKTS ***/
    state parse_port_metadata{                                      // Original Packets go to Parse Ehterent State!
        pkt.advance(PORT_METADATA_SIZE);                            // Ignore Tofino intinsic Metadata
        transition parse_ethernet;
    }

    /*** Cloned or MIRRORED PKTS ***/
    state parse_mirror{                                             // Extract the Mirrorring header and transmit to bridge state
        pkt.advance(PORT_METADATA_SIZE);                            // Ignore Tofino intinsic Metadata
        pkt.extract(hdr.mirror);        
        transition parse_bridge;
    }

    //*** JUST FOR MIRRPRED PPACKETS ***/
    state parse_bridge{                                             // Extract the bridge header (holds original ingress info like timestamps) and go to Ethernet Header!
        pkt.extract(hdr.bridge);
        transition parse_ethernet;
    }

    
    // *** Ethernet Header Parsing ***//
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP : parse_arp;
            default : accept;
        }
    }

    // *** IPv4 Header Parsing ***//
    // topology_parser: ARP target-IP forwarding without rewriting MACs.
    // ARP is parsed so it can be forwarded by target IP (servers need ARP to resolve each other).
    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {                          // Select next step: (TCP,6), (UDP,17), (INT,253)
            PROTO_UDP: parse_udp;
            PROTO_INT: parse_INT;
            PROTO_TCP: parse_tcp;
            //PROTO_ICMP: parse_icmp;
        default: accept;
      }
    }
    
    // *** TCP Header Parsing ***//
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    // *** UDP Header Parsing ***//
    state parse_udp {
        pkt.extract(hdr.udp);
        transition parse_rtp;
    }

    // *** RTP Header Parsing ***//
    state parse_rtp {
        pkt.extract(hdr.rtp);
        transition accept;
    }
    
    // *** INT Header Parsing ***//
    // INT probe: read nodeCount, then 0, 1 or 2 INT records already present in the packet.
    state parse_INT{ // 
        pkt.extract(hdr.nodeCount);
        //transition accept;
        ig_md.parser_metadata.remaining = hdr.nodeCount.count;
        transition select(ig_md.parser_metadata.remaining) {
            2 : parse_two_INT;
            1: parse_one_INT;
            0: accept;
        }
    }

    // *** Two INT for loop ***// 
    state parse_two_INT{
        pkt.extract(hdr.INT.next);
        pkt.extract(hdr.INT.next);
        transition accept;
    }

    // *** One INT for loop ***//
    state parse_one_INT{
        pkt.extract(hdr.INT.next);
        transition accept;
    }
}
// *** (2-2) Ingress (Match/Action) Processing ***//
// =====================================================================================
//  Ingress match-action: classification of clones, forwarding, ECN/DSCP rewrite, queue choice
// =====================================================================================
control Ingress( 
        inout headers_t hdr,
        inout metadata_t ig_md,
        in ingress_intrinsic_metadata_t ig_intr_md,
        in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
        inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
        inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {


    // c7_ingress: decisions and classes of packets forwarded to port 137.
    // c7 instrumentation: counters of the decisions/classes for packets going to port 137 (receiver).
    bit<8> c7_decision;
    bit<8> c7_dindex;
    bit<8> c7_cindex;
    Counter<bit<64>, bit<8>>(16, CounterType_t.PACKETS_AND_BYTES) c7_ingress_decision;
    Counter<bit<64>, bit<8>>(8, CounterType_t.PACKETS_AND_BYTES) c7_ingress_class;
    // c7_ingress_flow: packets to port 137 per ingress flow ID (smoke test: ingress = egress index).
    // A register: 65536-entry indirect Counters indexed by flow ID stopped all
    // forwarding to port 137 on hardware (bisect builds A/B/C, 2026-10-18).
    Register<bit<32>, flow_id_t>(FLOW_TABLE_SIZE) c7_ingress_flow;
    RegisterAction<bit<32>, flow_id_t, bit<32>>(c7_ingress_flow) c7_ingress_flow_inc = {
        void apply(inout bit<32> value) { value = value + 1; }
    };
    action c7_class_ar()    { c7_cindex = c7_cindex | 8w1; }
    action c7_class_cg()    { c7_cindex = c7_cindex | 8w2; }
    action c7_class_other() { c7_cindex = c7_cindex | 8w3; }
    table c7_ingress_dscp {
        key = { hdr.ipv4.dscp: exact; }
        actions = { c7_class_ar; c7_class_cg; c7_class_other; NoAction; }
        const entries = {
            46 : c7_class_ar();
            34 : c7_class_cg();
            50 : c7_class_other();
        }
        default_action = NoAction();
        size = 4;
    }
    // topology_discovery_register: slot = last 3 bits of .3/.4/.5 address.
    // 511 means unseen. Learned from received IPv4/ARP source addresses on
    // fiber ports only; this is observed lab traffic, not authenticated identity.
    Register<bit<16>, bit<16>>(8, 16w511) topology_source_port;
    RegisterAction<bit<16>, bit<16>, bit<16>>(topology_source_port)
        topology_observe_source = {
        void apply(inout bit<16> value) {
            value = (bit<16>)ig_intr_md.ingress_port;
        }
    };

    // topology_forwarding_action: L2-transparent delivery to a known host.
    // Forwarding: topology_forward maps destination IPv4 (or ARP target IP) -> egress port.
    // The controller installs one entry per server (install_server_topology). Unknown -> drop.
    action topology_set_port(PortId_t port) {
        ig_tm_md.ucast_egress_port = port;
    }
    action topology_drop_unknown() {
        ig_intr_dprsr_md.drop_ctl = ig_intr_dprsr_md.drop_ctl | 3w1;
    }
    table topology_forward {
        key = { ig_md.topology_destination: exact; }
        actions = { topology_set_port; topology_drop_unknown; }
        size = 3;
        default_action = topology_drop_unknown();
    }

    // Stateful Variables For Clasification and Marking!
    // Per-flow state for the classifier (index = 16-bit flow ID). Some registers are only kept for
    // monitoring from bfrt_python (e.g. packet_size_reg, ipg_cloned_packets_reg, ifg_reg).
    Register<flow_id_t, bit<8>> (1) flow_id_reg; //after LPF calculates the EWMA
    Register<bit<16>, _> (FLOW_TABLE_SIZE) packet_size_reg;

    Register<bit<32>, _> (0x100) ingress_timestamp_reg_every_pkt;
    Register<bit<16>, _> (0x100) packet_size_ewma_reg;
    Register<bit<16>, _> (FLOW_TABLE_SIZE) frame_size_reg; //uses mathunit
    Register<bit<16>, _> (0x100) frame_size_ewma_reg; //after LPF calculates the EWMA
    Register<bit<32>, _> (FLOW_TABLE_SIZE) ingress_host_ifg_reg; //Alireza added

    // lpf_type_16 is 16 bit and lpf_type_32 is 32 bit (defined in the global declaration) 

    // low pass filter variables for EWMA
    // Low-pass filters (EWMA in hardware). Index = low 13 bits of the flow ID. The controller sets each
    // slot to SAMPLE mode with 1 ms gain/decay time constants. Output = smoothed feature used by the trees.
    Lpf<lpf_type_16, bit<13>>(size=8192) lpf_packet_size;  // c7: per flow (low bits)
    lpf_type_16 lpf_input_packet_size;
    lpf_type_16 lpf_output_packet_size;

    Lpf<lpf_type_32, bit<13>>(size=8192) lpf_ipg;  // c7: per flow (low bits)
    lpf_type_32 lpf_input_ipg;
    lpf_type_32 lpf_output_ipg;

    Lpf<lpf_type_16, bit<13>>(size=8192) lpf_frame_size;  // c7: per flow (low bits)
    lpf_type_16 lpf_input_frame_size;
    lpf_type_16 lpf_output_frame_size;

    Lpf<lpf_type_32, bit<13>>(size=8192) lpf_ifg;  // c7: per flow (low bits)
    lpf_type_32 lpf_input_ifg;
    lpf_type_32 lpf_output_ifg;
    

    // Function to return the CRC16 of TCP/UDP Flow ID in 16 bits
    // CRC-16 (ARC: poly 0xA001, init 0) over {dst IP, dst port, protocol} = flow ID.
    // The egress uses identical hashes so both sides compute the same ID for the same packet.
    Hash<flow_id_t>(HashAlgorithm_t.CRC16) hash_function_tcp; 
    Hash<flow_id_t>(HashAlgorithm_t.CRC16) hash_function_udp; 

    
    // Write packet size from metadat into 'packet_size_reg'
    RegisterAction<bit<16>, flow_id_t, bit<16>>(packet_size_reg) write_packet_size_reg= {
            void apply(inout bit<16> value) {
                value = ig_md.metadata_packet_size;                                         // Note: Packet Size is EWMA value!          
            }
    };
    // This is only for monitoring the Flow ID Values Stored in the Register!
    RegisterAction<flow_id_t, bit<8>, flow_id_t>(flow_id_reg) write_flow_id_reg = {
            void apply(inout flow_id_t value) {
                value = ig_md.metadata_flowID;

            }
    };


     /*
    ======================================================================
    Shared Register is used for Synching the Flow Classification with Packet ECT(1) Marking
    ----------------------------------------------------------------------
    Shared Register <Flow_ID, Class), Class: 0,1,2,3
    Index = 16-bit CRC16 flow ID (flow_id_t), Value = 8-bit class
    Number of Cuncurrent Flows Capacity = 65536 (FLOW_TABLE_SIZE)
    ======================================================================
    */
    // Shared Register <Flow_ID. Class> 
    // shared_register[flow ID] = final class of the flow (0 until the first classification).
    Register<bit<8>, _> (FLOW_TABLE_SIZE) shared_register;

    // Read Shared Register 
    RegisterAction<bit<8>, flow_id_t, bit<8>>(shared_register) read_shared_register = {
            void apply(inout bit<8> value, out bit<8> output_value) {
                value = value;
                output_value = value;
            }

    };

    //Write the Final Class in Shared Register 
    RegisterAction<bit<8>, flow_id_t, bit<8>>(shared_register)  write_shared_register = {
            void apply(inout bit<8> value) {
                value = (bit<8>) ig_md.classification.metadata_final_classification;  //ig_md.metadata_final_classification;
            }

    };

    //********************************************************************//
    // Update (Read/Write) the ingress timestamp
    RegisterAction<bit<32>, bit<8>, bit<32>>(ingress_timestamp_reg_every_pkt) update_ingress_timestamp_reg_every_pkt = {
            void apply(inout bit<32> value, out bit<32> result) {
                result = value; // We read the previous stored value in the register and return the previous stored value!
                value = ig_intr_prsr_md.global_tstamp[31:0]; // Set new value in the register!
            }
    };

    // Write host ifg from RTP Header!
        RegisterAction<bit<32>, flow_id_t, bit<32>>(ingress_host_ifg_reg) write_ingress_host_ifg_reg = {
            void apply(inout bit<32> value) {
                value = hdr.mirror.host_ifg;
            }
    };

    // Write frame size in 'frame_size_reg'
    RegisterAction<bit<16>, flow_id_t, bit<16>>(frame_size_reg) write_frame_size_reg = {
            void apply(inout bit<16> value, out bit<16> result) {
                value = ig_md.metadata_frame_size;
            }
    };

    // Read frame size from 'frame_size_reg'
    RegisterAction<bit<16>, flow_id_t, bit<16>>(frame_size_reg) read_frame_size_reg = {
            void apply(inout bit<16> value, out bit<16> result) {
                //value = value;
                result = value;
            }
    };


    // Monitoring counters per flow: clones received, and clones with RTP marker (= frames).
    Register<bit<32>, _>(FLOW_TABLE_SIZE) drop_cloned_pkt;
    Register<bit<32>, _>(FLOW_TABLE_SIZE) counter_packets_frame;

    // Write the dropped packets for each interface (Increasing step by step when it is called!)
    RegisterAction<bit<32>, flow_id_t, bit<32>>(drop_cloned_pkt) write_drop_cloned_pkt = {
            void apply(inout bit<32> value) {
                value = value+1;
            }
    };

    // Write the Marker bit counter for each interface (Increasing step by step when it is called!)
    RegisterAction<bit<32>, flow_id_t, bit<32>>(counter_packets_frame) write_counter_packets_frame = {
            void apply(inout bit<32> value) {
                value = value+1;
            }
    };

    /*
    ====================================================================================
    Flow ID Extraction From the Ingress Packets
    ====================================================================================
    */
    // Write RTP Marker Header Value in 'rtp_marker_reg' 
    // Note: rtp_marker_reg is 8 bit while RTP Marker header is one bit! 
    Register<bit<8>, _> (FLOW_TABLE_SIZE) rtp_marker_reg;
    RegisterAction<bit<8>, flow_id_t, bit<8>>(rtp_marker_reg) write_rtp_marker_reg = {
            void apply(inout bit<8> value) {
                value = ig_md.metadata_rtp_marker;
            }

    };

    // Register to read the IPG from cloned packets 
    Register<bit<32>, _> (FLOW_TABLE_SIZE) ipg_cloned_packets_reg;
    
    // Write IPG from Metadata to Register
    RegisterAction<bit<32>, flow_id_t, bit<32>>(ipg_cloned_packets_reg) write_ipg_cloned_packets_reg = {
            void apply(inout bit<32> value) {
                value = ig_md.metadata_ipg;
            }

    };

    // Write IFG in the register 'ifg_reg'
    Register<bit<32>, _> (FLOW_TABLE_SIZE) ifg_reg;
    RegisterAction<bit<32>, flow_id_t, bit<32>>(ifg_reg) write_ifg_reg = {
            void apply(inout bit<32> value) {
                value = ig_md.metadata_ifg;
            }

    };
    
    // Read the IFG register
    RegisterAction<bit<32>, flow_id_t, bit<32>>(ifg_reg) read_ifg_reg = {
            void apply(inout bit<32> value, out bit<32> result) {
                value = value;
                result = value;
            }

    };

    // Queue Delay Accumulative Value for INT
    // Sum of queue delays carried by clones (monitoring only).
    Register<bit<32>, _> (1) queue_delay;
    RegisterAction<bit<32>, bit<8>, bit<32>>(queue_delay) sum_queue_delay = {
            void apply(inout bit<32> value) {
                value = value + ig_md.metadata_queue_delay_new;
            }

    };


    // Write the Class of Tree1 in Register 'metadata_classT1'
    // Last vote of each tree per flow (monitoring/debugging from bfrt_python).
    Register<bit<8>, _> (FLOW_TABLE_SIZE) metadata_classT1;
    RegisterAction<bit<8>, flow_id_t, bit<8>>(metadata_classT1)  write_metadata_classT1 = {
            void apply(inout bit<8> value) {
                value = ig_md.classification.metadata_classT1;
            }

    };

    // Write the Class of Tree 2 in Register 'metadata_classT2'
    Register<bit<8>, _> (FLOW_TABLE_SIZE) metadata_classT2;
    RegisterAction<bit<8>, flow_id_t, bit<8>>(metadata_classT2)  write_metadata_classT2 = {
            void apply(inout bit<8> value) {
                value = ig_md.classification.metadata_classT2;
            }

    };

    // Write the Class of Tree 3 in Register 'metadata_classT3'
    Register<bit<8>, _> (FLOW_TABLE_SIZE) metadata_classT3;
    RegisterAction<bit<8>, flow_id_t, bit<8>>(metadata_classT3)  write_metadata_classT3 = {
            void apply(inout bit<8> value) {
                value = ig_md.classification.metadata_classT3;
            }

    };

    // Write the Class of Tree 4 in Register 'metadata_classT4'
    Register<bit<8>, _> (FLOW_TABLE_SIZE) metadata_classT4;
    RegisterAction<bit<8>, flow_id_t, bit<8>>(metadata_classT4)  write_metadata_classT4 = {
            void apply(inout bit<8> value) {
                value = ig_md.classification.metadata_classT4;
            }

    };

    // Write the Class of Tree 5 in Register 'metadata_classT5'
    Register<bit<8>, _> (FLOW_TABLE_SIZE) metadata_classT5;
    RegisterAction<bit<8>, flow_id_t, bit<8>>(metadata_classT5)  write_metadata_classT5 = {
            void apply(inout bit<8> value) {
                value = ig_md.classification.metadata_classT5;
            }

    };

    /*
    ========================================================================
    Actions Definition: drop pkts, extract flow ID, and Classification
    ========================================================================
    */
        // Define Drop Original Pkts 
    // action drop_regular_pkts(){
    //     ig_intr_dprsr_md.drop_ctl = 0x1;
    // }

    // Define Drop Cloned Pkts
    action drop_cloned_pkts(){
        ig_intr_dprsr_md.drop_ctl = 0x1;
    }

    // Define to Extract FlowID (IP.dst, Port.dst, Protocol) {UDP Packets}
    // Flow ID of UDP and TCP packets (destination-based, so both directions of a flow differ).
    action extract_flowID_ipv4_udp(){
        ig_md.metadata_flowID = hash_function_udp.get({hdr.ipv4.dst_addr, hdr.udp.dstPort, hdr.ipv4.protocol});
    }

    // Define to Extract FlowID (IP.dst, Port.dst, Protocol) {TCP Packets}
    action extract_flowID_ipv4_tcp(){
        ig_md.metadata_flowID = hash_function_tcp.get({hdr.ipv4.dst_addr, hdr.tcp.dstPort, hdr.ipv4.protocol});
    }

    /*
    ###################################################################################
    Classification for each Tree (1-5) 
    ###################################################################################
    */

    //T1
    // -------------------------------------------------------------------------------------
    //  Random forest = 5 trees. Every tree is a short chain of RANGE tables on one feature:
    //    T1: FS -> (code 0) IPG / (code 2) PS        T2: IFG -> (code 0) IPG
    //    T3: FS -> (0) IFG -> (0) IPG                T4: IFG -> (5) IPG / (6) FS
    //    T5: FS -> (0) IPG
    //  Entries come from model.json (loaded by ICEFE.py). A miss leaves the vote unchanged.
    // -------------------------------------------------------------------------------------
    action classify_T1(bit<8> classify_result){
        ig_md.classification.metadata_classT1 = classify_result;
    }

    // action classify_T1_IPG(bit<8> classify_result){
    //     ig_md.classification.metadata_classT1 = classify_result;
    // }

    table table_T1_FS{
        key = {
            ig_md.metadata_frame_size: range;
        }
        actions = {
            classify_T1();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table table_T1_IPG{
        key = {
            ig_md.metadata_ipg_20lsb: range;
        }
        actions = {
            classify_T1();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    // manually added 
    table table_T1_PS{
        key = {
            ig_md.metadata_packet_size: range;  // PS = packet size (was keyed on frame size)
        }
        actions = {
            classify_T1();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    //T2
    action classify_T2(bit<8> classify_result){
        ig_md.classification.metadata_classT2 = classify_result;
    }

  
    
    table table_T2_IFG{
        key = {
            ig_md.metadata_ifg_20lsb: range;
        }
        actions = {
            classify_T2();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table table_T2_IPG{
        key = {
            ig_md.metadata_ipg_20lsb: range;
        }
        actions = {
            classify_T2();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    action classify_T3(bit<8> classify_result){
        ig_md.classification.metadata_classT3 = classify_result;
    }




    //T3
    table table_T3_FS{
        key = {
            ig_md.metadata_frame_size: range;
        }
        actions = {
            classify_T3();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table table_T3_IFG{
        key = {
            ig_md.metadata_ifg_20lsb: range;
        }
        actions = {
            classify_T3();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table table_T3_IPG{
        key = {
            ig_md.metadata_ipg_20lsb: range;
        }
        actions = {
            classify_T3();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    //T4
    action classify_T4(bit<8> classify_result){
        ig_md.classification.metadata_classT4 = classify_result;
    }
 

    
    table table_T4_IFG{
        key = {
            ig_md.metadata_ifg_20lsb: range;
        }
        actions = {
            classify_T4();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table table_T4_IPG{
        key = {
            ig_md.metadata_ipg_20lsb: range;
        }
        actions = {
            classify_T4();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    table table_T4_FS{
        key = {
            ig_md.metadata_frame_size: range;
        }
        actions = {
            classify_T4();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    //T5
    action classify_T5(bit<8> classify_result){
        ig_md.classification.metadata_classT5 = classify_result;
    }



    table table_T5_FS{
        key = {
            ig_md.metadata_frame_size: range;
        }
        actions = {
            classify_T5();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    table table_T5_IPG{
        key = {
            ig_md.metadata_ipg_20lsb: range;
        }
        actions = {
            classify_T5();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    //Aggregation of Trees (majority)
    // Majority vote: exact match on the 5 votes -> final class (entries from majority.txt).
    action trees_aggregation(bit<8> majority){
        //ig_md.metadata_final_classification = (bit<8>) majority;
        ig_md.classification.metadata_final_classification = (bit<8>) majority;
    }
    table table_majority{
        key = {
            ig_md.classification.metadata_classT1: exact;
            ig_md.classification.metadata_classT2: exact;
            ig_md.classification.metadata_classT3: exact;
            ig_md.classification.metadata_classT4: exact;
            ig_md.classification.metadata_classT5: exact;
        }
        actions = {
            trees_aggregation();
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }  
    




    apply {
    /*
    =============================================================================================
    Ingress Processing
    Input: (1) Original Packets or (2) Cloned Packets
    Output: (1) Marked Original Packets with ECT(1), (2) Classify the flow based on the Cloned Packets 
    =============================================================================================
    */   
    
    //******************************************* Check for cloned pkts (Port: 128) *******************************************//
    // ---------------- (A) CLONE coming back from egress: update features and classify ----------------
    if (ig_intr_md.ingress_port == MIRROR_PORT){
        // Flow ID computed in egress and carried in the mirror header.
        ig_md.metadata_flowID = hdr.mirror.flowid; 
        bit<8> temp_index = 0;
        write_flow_id_reg.execute(temp_index);

        ig_md.metadata_rtp_marker = (bit<8>) hdr.mirror.rtp_marker;
        write_rtp_marker_reg.execute(ig_md.metadata_flowID);

        //drop_cloned_pkt.count((bit<32>)ig_md.metadata_flowID); //maybe flowid?  (bit<32>)hdr.mirror.flowid
        write_drop_cloned_pkt.execute(ig_md.metadata_flowID);

        if(hdr.mirror.rtp_marker == 1){
            //counter_packets_frame.count(ig_md.metadata_flowID);
            write_counter_packets_frame.execute(ig_md.metadata_flowID);
        }
        //packet size
        // Packet size (IPv4 total length) -> LPF -> smoothed PS.
        lpf_input_packet_size = hdr.mirror.packet_size;
        lpf_output_packet_size = lpf_packet_size.execute(lpf_input_packet_size, ig_md.metadata_flowID[12:0]);
        //ig_md.metadata_packet_size = hdr.mirror.packet_size;
        ig_md.metadata_packet_size = lpf_output_packet_size;
        write_packet_size_reg.execute(ig_md.metadata_flowID);


        //bit<32> shit = 0;
        //ipg
        // Inter-packet gap (ns) -> LPF -> smoothed IPG.
        lpf_input_ipg = hdr.mirror.IPG;
        lpf_output_ipg = lpf_ipg.execute(lpf_input_ipg, ig_md.metadata_flowID[12:0]);
        //ig_md.metadata_input_ipg = hdr.mirror.IPG;
        ig_md.metadata_ipg = lpf_output_ipg;
        write_ipg_cloned_packets_reg.execute(ig_md.metadata_flowID);


        //frame size
        // Frame size is non-zero only on the last packet of a frame; otherwise reuse the stored value.
        if(hdr.mirror.frame_size != 0){
            lpf_input_frame_size = hdr.mirror.frame_size;
            lpf_output_frame_size = lpf_frame_size.execute(lpf_input_frame_size, ig_md.metadata_flowID[12:0]);
            //ig_md.metadata_frame_size = hdr.mirror.frame_size;
            ig_md.metadata_frame_size = lpf_output_frame_size;
            write_frame_size_reg.execute(ig_md.metadata_flowID);
        }
        else if(hdr.mirror.frame_size == 0){
            ig_md.metadata_frame_size = read_frame_size_reg.execute(ig_md.metadata_flowID);
        }

        //ifg
        // Inter-frame gap: same idea (only known at frame ends).
        if(hdr.mirror.ifg != 0){
            lpf_input_ifg = hdr.mirror.ifg;
            lpf_output_ifg = lpf_ifg.execute(lpf_input_ifg, ig_md.metadata_flowID[12:0]);
            //ig_md.metadata_ifg = hdr.mirror.ifg;
            ig_md.metadata_ifg = lpf_output_ifg;
            write_ifg_reg.execute(ig_md.metadata_flowID);
        }
        else if(hdr.mirror.ifg == 0){
            ig_md.metadata_ifg = read_ifg_reg.execute(ig_md.metadata_flowID);
        }
        

        // IFG Extracted from RTP Header (Deterministic From Host)
        if (hdr.mirror.host_ifg!=0){
            //store_ingress_host_ifg_reg(address) without return
            write_ingress_host_ifg_reg.execute(ig_md.metadata_flowID);
        }
      
        // Accumulative Queue Delay (For monitoring the Queue Delay using INT, so each reading by INT remoe the Register!)
        // queue delay (previous + current. the collect_info python resets when read)
        ig_md.metadata_queue_delay_new = hdr.mirror.queue_delay;
        sum_queue_delay.execute(temp_index); // Register for Accumulative Latency


        // Flow Classification 
        // Convert the 32-bit ns gaps to the 20-bit range keys used by the trees.
        ig_md.metadata_ifg_20lsb = ig_md.metadata_ifg[31:12];  // 4.096 us units up to ~4.29 s (was [19:0], wrapped every 1.05 ms); range keys must be nibble-aligned, so not [29:10]
        ig_md.metadata_ipg_20lsb = ig_md.metadata_ipg[31:12];  // 4.096 us units up to ~4.29 s (was [19:0], wrapped every 1.05 ms); range keys must be nibble-aligned, so not [29:10]

        // Note: Max variable size of the 'Range' for Tables is 20 bits, so we convert the features values received from 
        // cloned packets from 32 bits into 20 bits.


        // Triggering the Classification 

        // Run the forest (only for clones marked trigger = 1).
        if (hdr.mirror.trigger ==1){


        // T1
        table_T1_FS.apply();
        if(ig_md.classification.metadata_classT1 == 0){
            table_T1_IPG.apply();
        }
        if(ig_md.classification.metadata_classT1 == 2){
            table_T1_PS.apply();
        }


        // T2
        table_T2_IFG.apply();
        if(ig_md.classification.metadata_classT2 == 0){
            table_T2_IPG.apply();
        }

        // T3
        table_T3_FS.apply();
        if(ig_md.classification.metadata_classT3 == 0){
            table_T3_IFG.apply();
        }
        if(ig_md.classification.metadata_classT3 == 0){
            table_T3_IPG.apply();
        }

        // T4
        table_T4_IFG.apply();
        if(ig_md.classification.metadata_classT4 == 5){
            table_T4_IPG.apply();
        }
        else if(ig_md.classification.metadata_classT4 == 6){
            table_T4_FS.apply();
        }

        // T5
        table_T5_FS.apply();
        if(ig_md.classification.metadata_classT5 == 0){
            table_T5_IPG.apply();
        }

        // Combine the 5 votes, store votes and the final class of this flow.
        table_majority.apply();
        write_metadata_classT1.execute(ig_md.metadata_flowID);
        write_metadata_classT2.execute(ig_md.metadata_flowID);
        write_metadata_classT3.execute(ig_md.metadata_flowID);
        write_metadata_classT4.execute(ig_md.metadata_flowID);
        write_metadata_classT5.execute(ig_md.metadata_flowID);

        write_shared_register.execute(ig_md.metadata_flowID);
        // set trigger as zero
        hdr.mirror.trigger =0;

        // The clone has done its job: drop it.
        drop_cloned_pkts();
        } // if of the triggering classification
        else{

          drop_cloned_pkts();
        }
    } // end of If block for Cloned Packets


    //******************************************* Original pkts (any port except 128) *******************************************//
    else{
        // topology_forwarding_logic: replace old server-to-server assumptions.
        // Keep the existing INT loop on 136 and legacy non-server paths below.
        // ---------------- (B) ORIGINAL packet: forwarding ----------------
        // From a server port (136 Peach, 137 Luigi, 138 Mario):
        if (ig_intr_md.ingress_port == 136 ||
            ig_intr_md.ingress_port == 137 || ig_intr_md.ingress_port == 138) {
            // INT probe from Peach: first pass (count 0) -> recirculation port; after it -> back to Peach (136).
            if (hdr.nodeCount.isValid() && ig_intr_md.ingress_port == 136) {
                if (hdr.nodeCount.count == 0) {
                    ig_tm_md.ucast_egress_port[8:7] = ig_intr_md.ingress_port[8:7];
                    ig_tm_md.ucast_egress_port[6:0] = recirc_port[6:0];
                } else {
                    ig_tm_md.ucast_egress_port = 136;
                }
            } else {
                // Normal traffic: forward by destination IPv4 (or ARP target IP); remember the source port (discovery).
                ig_md.topology_source = 0;
                ig_md.topology_destination = 0;
                if (hdr.ipv4.isValid()) {
                    ig_md.topology_source = hdr.ipv4.src_addr;
                    ig_md.topology_destination = hdr.ipv4.dst_addr;
                } else if (hdr.arp.isValid()) {
                    if (hdr.arp.hardware_type == 1 && hdr.arp.protocol_type == 2048) {
                        if (hdr.arp.hardware_length == 6 && hdr.arp.protocol_length == 4) {
                            ig_md.topology_source = hdr.arp.sender_ip;
                            ig_md.topology_destination = hdr.arp.target_ip;
                        }
                    }
                }
                // Decimal encodings for 172.16.0.3, .4 and .5.
                // Discovery register is only updated for 172.16.0.3/.4/.5 (Server2 = .6 is installed statically
                // by the controller through SERVER_PORT_MAP, which is what the experiments use).
                if (ig_md.topology_source == 2886729731 ||
                    ig_md.topology_source == 2886729732 ||
                    ig_md.topology_source == 2886729733) {
                    topology_observe_source.execute((bit<16>)ig_md.topology_source[2:0]);
                }
                topology_forward.apply();
                if (ig_tm_md.ucast_egress_port == ig_intr_md.ingress_port) {
                    topology_drop_unknown(); // Do not reflect a frame to its sender.
                }
            }
        }
        // Traffic-generator ports (P4TG on Tofino 1): everything entering on 192 or 152 goes to Luigi (137).
        else if (ig_intr_md.ingress_port == 192) {
            ig_tm_md.ucast_egress_port = 137;
        }

        else if (ig_intr_md.ingress_port == 152) {
            ig_tm_md.ucast_egress_port = 137;
        }

        // Tofino1 (P4TG)
        // 23/0 (448) TF1 -> 1/1(137) Luigi
        else if (ig_intr_md.ingress_port == 448) {
            ig_tm_md.ucast_egress_port = 137;
        }
        // Tofino1 (P4TG)
        // 24/0 (40) TF1 -> 1/1(137) Luigi
        //else if (ig_intr_md.ingress_port == 152) {
          //  ig_tm_md.ucast_egress_port = 137;
        //}

        // Original Packets whose ingress is not 128 (for cloned packets) and is out of list [136,137,440,448] 
        else{
            //Recirculating INT Packets 
            ig_tm_md.ucast_egress_port = 136;
        }

        /***
        ##############################################################################################################
        Packet ECT(1) Marking 
        ##############################################################################################################
        ***/  

        // topology_non_ip: ARP uses Q0 and skips IPv4 classification.
        // ---------------- (C) ORIGINAL IPv4 packet: class -> ECN/DSCP rewrite -> queue ----------------
        // Default queue Q0 (also for ARP and non-IP).
        ig_tm_md.qid = 0;
        if (hdr.ipv4.isValid()) {
        if(hdr.tcp.isValid()){
            extract_flowID_ipv4_tcp();
        }
        else if(hdr.udp.isValid()){
            extract_flowID_ipv4_udp();
        }
        
        
        
        //*** marking_decision --> 0 or 1 or 2 or 3 ***// 
        // 0--> Non-Classified, 1--> AR | 2--> CG | 3--> Other (Non-[Ar or CG])
        // Read the class decided for this flow (0 if the flow is not classified yet).
        bit<2> c7_arrival_ecn = hdr.ipv4.ecn;
        bit<8> marking_decision = read_shared_register.execute(ig_md.metadata_flowID);

        //*** Not Mark INT Packet ***/
        // INT probes are never re-marked.
        if(hdr.nodeCount.isValid()){
            marking_decision = 0;
        }
        c7_decision = marking_decision;

        //*** marking_decision = 1 (AR) ***//
        //*** Action --> Mark ECT(1) & Set DSCP(46)
        // Rewrite rules. A DSCP already set to 46/34/50 forces that class; packets that already are
        // ECT(1) or CE (genuine L4S senders such as TCP Prague) are not touched.
        // AR -> ECT(1), DSCP 46 (EF), green.
        if((marking_decision == 1 || hdr.ipv4.dscp == 46) && (hdr.ipv4.ecn != 1 && hdr.ipv4.ecn != 3)){ // AR
            hdr.ipv4.ecn = 1; //1
            hdr.ipv4.dscp = 46;
            ig_tm_md.packet_color = 2w0;  // GREEN: highest drop protection    
        }
        //*** marking_decision = 2 (CG) ***//
        //*** Action --> Mark ECT(1) & Set DSCP(34)
        // CG -> ECT(1), DSCP 34 (AF41), green.
        else if((marking_decision == 2 || hdr.ipv4.dscp == 34) && (hdr.ipv4.ecn != 1 && hdr.ipv4.ecn != 3)){ // CG 34 or 6w0x22
            hdr.ipv4.ecn = 1; //1
            hdr.ipv4.dscp = 34;
            ig_tm_md.packet_color = 2w0;  // GREEN: highest drop protection
        }

        //*** marking_decision = 3 (Other) ***//
        //*** Action --> Not-ECT & Set DSCP(50)
        // Other -> Not-ECT (ECN 0), DSCP 50, red. (Unclassified flows, decision 0, are left unchanged.)
        else if((marking_decision == 3 || hdr.ipv4.dscp == 50) && (hdr.ipv4.ecn != 1 && hdr.ipv4.ecn != 3)){ // Other or Non-(AR or CG)
            hdr.ipv4.ecn = 0; 
            hdr.ipv4.dscp = 50;
            // ig_tm_md.packet_color = 2w1;  // YELLOW
            ig_tm_md.packet_color = 2w3;  // RED: lowest drop protection
        }

        //else {
            //hdr.ipv4.ecn = 0;
            //hdr.ipv4.dscp = 0;
        //}

        

        /***
        ##############################################################################################################
        L4S vs Classic Queue Allocation
        Queue_ID ==1 ==> L4S
        Queue_ID ==0 ==> Classic 
        ##############################################################################################################
        ***/  
        // Queue choice from the (rewritten) ECN field: ECT(1) -> Q1 (L4S), everything else -> Q0 (Classic).
        // Note: CE packets therefore go to Q0.
        if(hdr.ipv4.ecn == 1){
        ig_tm_md.qid = 1; // Set L4S Queue 
                 }
        // if(hdr.ipv4.ecn == 0){
        //m_md.qid = 0; // Set Classic Queue}
        //
        else{
        ig_tm_md.qid = 0; // Set Classic Queue}
        }  
        // Note: Default Queue ID is 0 for other packets that we let it go on!

        // c7_ingress_logic: count by decision/arrival ECN and by queue/class.
        if (ig_tm_md.ucast_egress_port == 137 && !hdr.nodeCount.isValid()) {
            c7_dindex = (c7_decision << 2) | (bit<8>)c7_arrival_ecn;
            c7_ingress_decision.count(c7_dindex);
            c7_cindex = (bit<8>)ig_tm_md.qid[0:0] << 2;
            c7_ingress_dscp.apply();
            c7_ingress_class.count(c7_cindex);
            c7_ingress_flow_inc.execute(ig_md.metadata_flowID);
        }


        }

        //** Insert ingress timestamp into bridge header to be used in the egress**//
        // Bridge header to egress: ingress port, ingress timestamp, queue id.
        hdr.bridge.setValid();
        hdr.bridge.bridge_ingress_port = (bit<16>)ig_intr_md.ingress_port;
        hdr.bridge.ingress_global_tstamp = ig_intr_prsr_md.global_tstamp;
        hdr.bridge.bridge_qid = (bit<16>)ig_tm_md.qid; 
    }
    
    }    
    
}
// ---------------------------------------------------------------------------
// *** (2-3) Ingress Deparser *** ///
// ---------------------------------------------------------------------------
// Ingress deparser: recompute the IPv4 checksum (DSCP/ECN may have changed) and emit all valid headers.
control IngressDeparser( //SwitchIngressDeparser
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {

    //Mirror() mirror;
    Checksum() ipv4_checksum;

    apply {

        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.dscp,
            //hdr.ipv4.l4s,        
            hdr.ipv4.ecn,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});

        // hdr.udp.checksum = ipv4_checksum.update({
        //     hdr.udp.srcPort,
        //     hdr.udp.length_,
        //     hdr.udp.checksum});
        // pkt.emit(hdr.bridge);
        // pkt.emit(hdr.ethernet);
        // pkt.emit(hdr.ipv4);
        pkt.emit(hdr);
    }
}


/***
-------------------------------------------------------------------------------------------------------------------------------------------
Traffic Manager (TM) - non-programmable block located between Ingress and Egress (e.g., Queue Management)

Note: TM will receive the packet cloned at the Egress, and will recirculate this packet to the Ingress.
// ----------------------------------------------------------------------------------------------------------------------------------------
***/


// ****************************** (3) Egress (Parser/Ingress (MA) Processing/Deparser)  ******************************************//

// ---------------------------------------------------------------------------
// *** (3-1) Egress Parser *** ///
// ---------------------------------------------------------------------------
// Egress parser: packets to port 128 are clones (mirror header only); others start with the bridge header.
parser EgressParser(
        packet_in pkt,
        out headers_t hdr,
        out metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    
    //*** Starts State Machine ***///
    state start {
        pkt.extract(eg_intr_md);
        transition select(eg_intr_md.egress_port){
            (MIRROR_PORT): parse_mirror;                    // Mirror Packet Port = 128 
            (_): parse_bridge;
        }
    }

    /** E2E MIRRORED PKTS (Parsing Cloned Packets)**/
    state parse_mirror{
        pkt.extract(hdr.mirror);
        transition accept;
    }

    //** Parsing Bridge for original Packets **//
    state parse_bridge{
        pkt.extract(hdr.bridge);
        transition parse_ethernet;
    }

    // ** Ethernet Header Parsing **//
    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select (hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4 : parse_ipv4;
            ETHERTYPE_ARP : parse_arp;
            default : accept;
        }
    }

    // ** IPv4 Header Parsing **//
    // topology_parser: ARP target-IP forwarding without rewriting MACs.
    state parse_arp {
        pkt.extract(hdr.arp);
        transition accept;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            PROTO_UDP: parse_udp;
            PROTO_INT: parse_INT;
            PROTO_TCP: parse_tcp;  // TCP flow ID must use the same dst port as ingress
            //PROTO_ICMP: parse_icmp;
        default: accept;
      }
    }

    // ** TCP Header Parsing **//
    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition accept;
    }

    // ** UDP Header Parsing **//
    state parse_udp {
        pkt.extract(hdr.udp);
        transition parse_rtp;
    }

    // ** RTP Header Parsing **//
    state parse_rtp {
        pkt.extract(hdr.rtp);
        transition accept;
    }

    // ** INT Header Parsing **//
    state parse_INT{
        pkt.extract(hdr.nodeCount);
        eg_md.parser_metadata.remaining = hdr.nodeCount.count;
        transition select(eg_md.parser_metadata.remaining) {
            2 : parse_two_INT;
            1: parse_one_INT;
            0: accept;
        }
    }
    // ** INT Header Parsing **//
    state parse_two_INT{
        pkt.extract(hdr.INT.next);
        pkt.extract(hdr.INT.next);
        transition accept;
    }
    // ** INT Header Parsing **//
    state parse_one_INT{
        pkt.extract(hdr.INT.next);
        transition accept;
    }
}




// ---------------------------------------------------------------------------
// *** (3-2) Egress Match/Action (MA) Processing *** ///
// ---------------------------------------------------------------------------
@pa_container_size("egress", "hdr.bridge.ingress_global_tstamp", 32, 16)
// =====================================================================================
//  Egress match-action: queue sampling for the AQM, coupled marking/dropping, INT stamping,
//  feature measurement (PS, IPG, FS, IFG) and clone decision (c7_budget)
// =====================================================================================
control Egress(
        inout headers_t hdr,
        inout metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
        

        // c7_event: 0 none, 1 CE by TM congestion state (Q1), 2 CE by coupled
        // probability (Q1), 3 CE by Classic probability (Q0, ECT(0)), 4 Classic drop,
        // 5 CE by the L4S step threshold (Q1, deq_timedelta >= step).
        // c7_class (from DSCP after the ingress rewrite): 1 AR(46), 2 CG(34),
        // 3 Other(50), 0 any other DSCP (unclassified, INT excluded).
        // c7 instrumentation: per-event counters and a sampled ring buffer of residence time/queue delay/tag
        // (read by the experiment scripts with bfrt_python). Sampling 1-in-(mask+1), mask set by c7_sampling.
        bit<3> c7_event;
        bit<1> c7_eval;
        bit<8> c7_eindex;
        bit<32> c7_residence;
        bit<32> c7_queue;
        bit<32> c7_tag;
        bit<32> c7_seq;
        bit<32> c7_mask;
        bit<32> c7_masked;
        bit<32> c7_slot;
        Counter<bit<64>, bit<8>>(64, CounterType_t.PACKETS_AND_BYTES) c7_egress_event;
        Register<bit<32>, bit<1>>(1) c7_seq_reg;
        Register<bit<32>, bit<1>>(1) c7_slot_reg;
        Register<bit<32>, bit<16>>(65536) c7_residence_ring;
        Register<bit<32>, bit<16>>(65536) c7_queue_ring;
        Register<bit<32>, bit<16>>(65536) c7_tag_ring;
        RegisterAction<bit<32>, bit<1>, bit<32>>(c7_seq_reg) c7_next_seq = {
            void apply(inout bit<32> value, out bit<32> result) {
                result = value;
                value = value + 1;
            }
        };
        RegisterAction<bit<32>, bit<1>, bit<32>>(c7_slot_reg) c7_next_slot = {
            void apply(inout bit<32> value, out bit<32> result) {
                result = value;
                if (value < 65536) { value = value + 1; }
            }
        };
        RegisterAction<bit<32>, bit<16>, bit<32>>(c7_residence_ring) c7_store_residence = {
            void apply(inout bit<32> value) { value = c7_residence; }
        };
        RegisterAction<bit<32>, bit<16>, bit<32>>(c7_queue_ring) c7_store_queue = {
            void apply(inout bit<32> value) { value = c7_queue; }
        };
        RegisterAction<bit<32>, bit<16>, bit<32>>(c7_tag_ring) c7_store_tag = {
            void apply(inout bit<32> value) { value = c7_tag; }
        };
        // Residence = egress-parser - ingress-parser global_tstamp (same clock).
        action c7_compute_residence() {
            c7_residence = (bit<32>)eg_intr_md_from_prsr.global_tstamp -
                           (bit<32>)hdr.bridge.ingress_global_tstamp;
            c7_queue = (bit<32>)eg_intr_md.deq_timedelta;
        }
        table c7_residence_clock {
            actions = { c7_compute_residence; }
            const default_action = c7_compute_residence();
            size = 1;
        }
        // Systematic 1-in-(mask+1) sampling; controller sets mask = 2^k - 1.
        action c7_set_mask(bit<32> mask) { c7_mask = mask; }
        table c7_sampling {
            actions = { c7_set_mask; }
            default_action = c7_set_mask(0);
            size = 1;
        }
        action c7_apply_mask() { c7_masked = c7_seq & c7_mask; }
        table c7_mask_seq {
            actions = { c7_apply_mask; }
            const default_action = c7_apply_mask();
            size = 1;
        }
        action c7_class_ar()    { c7_eindex = c7_eindex | 8w8; }
        action c7_class_cg()    { c7_eindex = c7_eindex | 8w16; }
        action c7_class_other() { c7_eindex = c7_eindex | 8w24; }
        table c7_egress_dscp {
            key = { hdr.ipv4.dscp: exact; }
            actions = { c7_class_ar; c7_class_cg; c7_class_other; NoAction; }
            const entries = {
                46 : c7_class_ar();
                34 : c7_class_cg();
                50 : c7_class_other();
            }
            default_action = NoAction();
            size = 4;
        }

        // c7_l4s_step: RFC 9332 L4S step marking, p_L = max(step, coupled).
        // delta = deq_timedelta - step (ns), computed as deq_timedelta + neg_step
        // with neg_step = 2^32 - step (Tofino cannot subtract action data).
        // Bit 31 clear <=> delay >= step, valid below 2^31 ns. Default 1 ms.
        bit<32> c7_step_delta;
        action c7_set_step(bit<32> neg_step_ns) {
            c7_step_delta = (bit<32>)eg_intr_md.deq_timedelta + neg_step_ns;
        }
        table c7_l4s_step {
            actions = { c7_set_step; }
            default_action = c7_set_step(4293967296);  // 2^32 - 1000000
            size = 1;
        }

        // c7_flow_budget: per-flow observation counters (replace per-slot ones).
        // pkt index: 1-based count of this flow's packets including this one.
        // frame index: completed frames (RTP markers) before this packet.
        // Clone budget state. c7_pkt_cnt / c7_frm_cnt = packets / completed frames seen per flow.
        bit<16> c7_pkt_idx;
        bit<16> c7_frm_idx;
        Register<bit<16>, flow_id_t>(FLOW_TABLE_SIZE) c7_pkt_cnt;
        Register<bit<32>, flow_id_t>(FLOW_TABLE_SIZE) c7_clone_tx;   // register, see c7_ingress_flow
        //C7EGF_BEGIN
        // c7_eg_flow: packets leaving port 137 per flow ID (per-flow loss = ingress - egress).
        Register<bit<32>, flow_id_t>(FLOW_TABLE_SIZE) c7_eg_flow;
        RegisterAction<bit<32>, flow_id_t, bit<32>>(c7_eg_flow) c7_eg_flow_inc = {
            void apply(inout bit<32> value) { value = value + 1; }
        };
        //C7EGF_END
        RegisterAction<bit<32>, flow_id_t, bit<32>>(c7_clone_tx) c7_clone_tx_inc = {
            void apply(inout bit<32> value) { value = value + 1; }
        };
        Register<bit<16>, flow_id_t>(FLOW_TABLE_SIZE) c7_frm_cnt;
        RegisterAction<bit<16>, flow_id_t, bit<16>>(c7_pkt_cnt) c7_pkt_inc = {
            void apply(inout bit<16> value, out bit<16> result) {
                if (value < 16w65535) { value = value + 1; }
                result = value;
            }
        };
        RegisterAction<bit<16>, flow_id_t, bit<16>>(c7_frm_cnt) c7_frm_inc = {
            void apply(inout bit<16> value, out bit<16> result) {
                result = value;
                if (value < 16w65535) { value = value + 1; }
            }
        };
        RegisterAction<bit<16>, flow_id_t, bit<16>>(c7_frm_cnt) c7_frm_read = {
            void apply(inout bit<16> value, out bit<16> result) { result = value; }
        };
        // Local variables (note: a variable declared here can be used inside RegisterActions).
        value_t queue_delay; //IMPORTANTE! DA PRA USAR UMA VARIAVEL DEFINIDA AQUI NA REGISTER ACTION
        bit<32> enq_qdepth;
        value_t EWMA;
        bit<32> EWMA_enq_qdepth;

        bit<16> rand_classic; 
        bit<16> rand_l4s;

        // coupling_variables: 16-bit probability thresholds, all decimal.
        // Threshold P represents P / 65536; 65535 is treated as certainty.
        // Coupled AQM variables.
        bit<16> coupling_random;
        bit<16> coupling_queue;
        bool coupling_decision;
        // coupling_classic_variables: independent full-range Classic draw.
        bit<16> coupling_classic_random;
        bool coupling_classic_decision;
        // coupling_sampling_variables: index = 2 * egress port + logical queue.
        bit<16> coupling_sample_index;
        bit<32> coupling_sample_stamp;

        // *** Variables for Classification Mirroring Threshold *** //
        // ****** Number of RTP Frames ******* //
        // ****** Number of UDP Packets ******* //
        bit<8> frame_counter_value;
        bit<8> packet_counter_value;


        //IPG
        bit<32> IPG;

        // *** Hash Function Using Extern Function *** //
        // Same CRC16 flow ID as in ingress.
        Hash<flow_id_t>(HashAlgorithm_t.CRC16) hash_function_tcp; //2 to the power of 16 possible flows
        Hash<flow_id_t>(HashAlgorithm_t.CRC16) hash_function_udp; //2 to the power of 16 possible flows

        
        // Per-queue statistics. Index metadata_index = 0..5 = (136 Q0, 136 Q1, 137 Q0, 137 Q1, 138 Q0, 138 Q1).
        // mark_ecn_pkt counts CE marks; qdelay_l4s and totalPkts feed the INT records.
        Counter<bit<32>, bit<32>>(SERVER_QUEUE_SLOTS, CounterType_t.PACKETS) mark_ecn_pkt;
        Counter<bit<32>, bit<32>>(SERVER_QUEUE_SLOTS, CounterType_t.PACKETS) thresholdPkts;
        //Counter<bit<32>, bit<16>>(SERVER_QUEUE_SLOTS, CounterType_t.PACKETS) totalPkts;
        //Register<bit<16>, bit<16>>(SERVER_QUEUE_SLOTS) qdelay_classic;

        // *** Dropping/ECN Marking Policy ***
        Register<bit<32>, bit<16>>(SERVER_QUEUE_SLOTS) qdelay_l4s;
        Register<bit<32>, bit<16>>(SERVER_QUEUE_SLOTS) switchLatency;
        Register<bit<16>, bit<16>>(SERVER_QUEUE_SLOTS) dropProbability;
        Register<bit<32>, bit<16>>(SERVER_QUEUE_SLOTS) target_violation;
        Register<bit<32>, bit<16>>(SERVER_QUEUE_SLOTS) totalPkts;


        //IPG
        Register<bit<32>, bit<16>>(SERVER_QUEUE_SLOTS) previous_timestamp_reg;
        Register<bit<32>, bit<16>>(SERVER_QUEUE_SLOTS) IPG_reg;
        //PACKET SIZE
        Register<bit<16>, bit<16>>(SERVER_QUEUE_SLOTS) packet_size_reg;
        
        //TOTALPACKETS TO IPG AND PACKETSIZE
        Register<bit<32>, bit<16>>(SERVER_QUEUE_SLOTS) totalPkts_IPG; //used also for Packet Size

        // 16-bit uniform random number generator for the probabilistic AQM decisions.
        Random<bit<16>>() rand;

        // coupling_register: one shared p_base per egress port, initialized to 0.
        // Python feedback writes this register from Q0/Q1 delay samples.
        // p_base is NOT p_C: p_C = p_base squared.
        // For port 137, write register index 137 (not metadata_index).
        Register<bit<16>, bit<16>>(N_PORTS, 16w0) coupling_base_probability;

        // coupling_sampling_register: Q0/Q1 delay and freshness samples.
        // Separate 32-bit registers avoid an SDE 9.13.4 compiler failure with
        // a paired struct. Python reads delay followed by stamp (not atomic).
        // Stamp bit 31 = nonempty at dequeue; low bits = 65536-ns clock ticks.
        Register<bit<32>, bit<16>>(1024, 32w0) coupling_queue_delay;
        Register<bit<32>, bit<16>>(1024, 32w0) coupling_queue_stamp;
        RegisterAction<bit<32>, bit<16>, bit<32>>(coupling_queue_delay)
            coupling_store_delay = {
            void apply(inout bit<32> value) {
                value = eg_intr_md.deq_timedelta;
            }
        };
        RegisterAction<bit<32>, bit<16>, bit<32>>(coupling_queue_stamp)
            coupling_store_stamp = {
            void apply(inout bit<32> value) {
                value = coupling_sample_stamp;
            }
        };

        // coupling_classic_register: controller derives this from the SAME base.
        // Threshold = round(base * base / 65536); 65535 means certainty.
        // Squaring in Python avoids unsupported general P4 multiplication.
        Register<bit<16>, bit<16>>(N_PORTS, 16w0) coupling_classic_probability;

        // coupling_classic_action: Classic p_C = p_base squared.
        RegisterAction<bit<16>, bit<16>, bool>(coupling_classic_probability)
            coupling_decide_classic = {
            void apply(inout bit<16> value, out bool result) {
                if (coupling_classic_random < value) {
                    result = true;
                } else if (value == 16w65535) {
                    result = true;
                } else {
                    result = false;
                }
            }
        };

        // coupling_action: compare in the stateful ALU, not an MAU condition.
        // coupling_random is uniform over 0..32767 after a right shift by 1.
        // Thus Pr(random < value) = min(1, 2 * value / 65536).
        // Values >= 32768 automatically mark all packets without overflow.
        // Keep the register unchanged; its updates belong to the control plane.
        RegisterAction<bit<16>, bit<16>, bool>(coupling_base_probability)
            coupling_decide = {
            void apply(inout bit<16> value, out bool result) {
                if (coupling_random < value) {
                    result = true;
                } else {
                    result = false;
                }
            }
        };

        // Freshness stamp of the queue sample: bits 30..0 = time in 65.536 us ticks; bit 31 = queue was
        // not empty at dequeue (deq_qdepth != 0). The controller treats samples older than 64 ms as drained.
        action c7_stamp_idle() {
            coupling_sample_stamp = (bit<32>)eg_intr_md_from_prsr.global_tstamp[46:16];
        }
        action c7_stamp_busy() {
            coupling_sample_stamp = 1w1 ++ eg_intr_md_from_prsr.global_tstamp[46:16];
        }
        table c7_stamp {
            key = { eg_intr_md.deq_qdepth: exact; }
            actions = { c7_stamp_idle; c7_stamp_busy; }
            const entries = { 0 : c7_stamp_idle(); }
            const default_action = c7_stamp_busy();
            size = 1;
        }
        // coupling_action: CE marking; existing egress deparser updates checksum.
        action coupling_mark_ce() {
            hdr.ipv4.ecn = 2w3;
            mark_ecn_pkt.count((bit<32>)eg_md.metadata_index);
        }

        // coupling_classic_drop_action: disable forwarding of a Not-ECT packet.
        // Preserve other existing drop_ctl bits.
        action coupling_drop_classic() {
            eg_intr_dprs_md.drop_ctl = eg_intr_dprs_md.drop_ctl | 3w1;
        }
    



        // Declaration of LPF with 1024 index
        // Lpf<bit<32>, bit<16>>(size=1024) queue_delay_lpf;

        
        
        
        // Per-flow feature state: last timestamps (IPG/IFG), running frame size, plus legacy threshold
        // registers of older versions (kept, unused).
        Register<enq_qdepth_v, bit<16>>(SERVER_QUEUE_SLOTS) enq_qdepth_reg;
        Register<bit<16>, bit<16>>(1) index_reg;
        Register<bit<32>, _>(FLOW_TABLE_SIZE) timestamp_ifg_reg;
        Register<bit<16>, _>(FLOW_TABLE_SIZE) frame_size_reg;
        Register<bit<32>, _>(FLOW_TABLE_SIZE) timestamp_ipg_reg;
               
        
        Register<bit<8>, _>(SERVER_QUEUE_SLOTS) frame_counter_threshhold; // for mirroring control
        Register<bit<8>, _>(N_PORTS) frame_counter; // for mirroring control

        Register<bit<8>, _>(SERVER_QUEUE_SLOTS) packet_counter_threshhold; // for mirroring control
        Register<bit<8>, _>(N_PORTS) packet_counter_flowbased; // for mirroring control

        //Packet counter
          RegisterAction<bit<8>, bit<8>, bit<8>>(frame_counter) increase_packet_counter_flowbased = { // for Frame counting threshold
            void apply(inout bit<8> value, out bit<8> result) {
                result = value + 1;
                value =  value + 1; 
            }
        };     

        RegisterAction<bit<8>, bit<8>, bit<8>>(frame_counter_threshhold) read_packet_counter_threshhold = { // for Frame counting threshold
            void apply(inout bit<8> value, out bit<8> result) {
                result = value;
                value =  value; //eg_md.metadata_ipg_temp;
            }
        };           
        //frame counter
         RegisterAction<bit<8>, bit<8>, bit<8>>(frame_counter) increase_frame_counter = { // for Frame counting threshold
            void apply(inout bit<8> value, out bit<8> result) {
                result = value + 1;
                value =  value + 1; 
            }
        };     

        RegisterAction<bit<8>, bit<8>, bit<8>>(frame_counter_threshhold) read_frame_counter_threshhold = { // for Frame counting threshold
            void apply(inout bit<8> value, out bit<8> result) {
                result = value;
                value =  value; //eg_md.metadata_ipg_temp;
            }
        };        
       //frame counter
        // Swap: return previous packet timestamp of the flow, store the current one (-> IPG).
        RegisterAction<bit<32>, flow_id_t, bit<32>>(timestamp_ipg_reg) update_timestamp_ipg_reg = {
            void apply(inout bit<32> value, out bit<32> result) {
                result = value;
                value = eg_md.metadata_ipg_temp;
            }
        }; 



        // At a frame end: return accumulated frame size (+ this packet) and restart from 0.
        RegisterAction<bit<16>, flow_id_t, bit<16>>(frame_size_reg) reset_frame_size_reg = {
            void apply(inout bit<16> value, out bit<16> result) {
                result = value + hdr.udp.length_;
                value = 0;
            }
        }; 


        // Inside a frame: add this packet's UDP length.
        RegisterAction<bit<16>, flow_id_t, bit<16>>(frame_size_reg) increase_frame_size_reg = {
            void apply(inout bit<16> value) {
                value = value + hdr.udp.length_;
            }
        };


        
        // Swap: return previous frame-end timestamp, store the current one (-> IFG).
        RegisterAction<bit<32>, flow_id_t, bit<32>>(timestamp_ifg_reg) update_timestamp_ifg_reg = {
            void apply(inout bit<32> value, out bit<32> result) {
                result = value;
                value = eg_md.metadata_ifg_temp;
            }
        }; 


    // Alireza

        // Host IFG = difference of RTP timestamps between frames (sender clock).
        Register<bit<32>, _> (FLOW_TABLE_SIZE) host_ifg_reg; //Host IFG register

        // Storing previous timestamp
        Register<bit<32>, _> (FLOW_TABLE_SIZE) rtp_timestamp_reg; //Host Timestamp register
        RegisterAction<bit<32>, flow_id_t, bit<32>>(rtp_timestamp_reg) update_rtp_timestamp_reg = {
            void apply(inout bit<32> value, out bit<32> result) {
                result = value;
                value = hdr.rtp.timestamp;

            }
    };
        // Storing the ifg host
        RegisterAction<bit<32>, flow_id_t, bit<32>>(host_ifg_reg) update_host_ifg_reg = {
        void apply(inout bit<32> value) {
                value =  eg_md.metadata_host_ifg;
            }
    };
    // Alireza





        // Per-queue statistics (sum of sizes, timestamps, IPG sums, counters) used for monitoring/INT.
        RegisterAction<bit<16>, bit<16>, bit<16>>(packet_size_reg) increase_packet_size = {
            void apply(inout bit<16> value, out bit<16> result) {
                value = value + hdr.ipv4.total_len;
                result = value + hdr.ipv4.total_len;;
            }
        };        

        RegisterAction<bit<32>, bit<16>, bit<32>>(previous_timestamp_reg) store_previous_timestamp = {
            void apply(inout bit<32> value, out bit<32> result) {
                result = value;
                value = eg_intr_md_from_prsr.global_tstamp[31:0];
            }
        };

        RegisterAction<bit<32>, bit<16>, bit<32>>(IPG_reg) increase_IPG = {
            void apply(inout bit<32> value, out bit<32> result) {
                bit<32> avg_temp;
              
                avg_temp =  (IPG + value);
               
                // update register        
                value = avg_temp;
                result = avg_temp;
            }
        };


        
        RegisterAction<bit<16>, bit<16>, bit<16>>(index_reg) store_index_reg = {
            void apply(inout bit<16> value, out bit<16> result) {
                result = eg_md.metadata_index;
                value = eg_md.metadata_index;
            }
        };
        
        //INT

        RegisterAction<bit<32>, bit<16>, bit<32>>(totalPkts) reset_totalPkts = {
            void apply(inout enq_qdepth_v value, out enq_qdepth_v result) {
                result = value;
                value = 0;
            }
        };

        RegisterAction<bit<32>, bit<16>, bit<32>>(totalPkts) increase_totalPkts = {
            void apply(inout enq_qdepth_v value, out enq_qdepth_v result) {
                value = value + 1;
                result = value +1;
            }
        };

        RegisterAction<bit<32>, bit<16>, bit<32>>(totalPkts_IPG) increase_totalPkts_IPG = {
            void apply(inout bit<32> value, out bit<32> result) {
                value = value + 1;
                result = value +1;
            }
        };
        
        // Add this packet's queue delay to the queue sum; read_qdelay_l4s_action reads and clears it (INT).
        RegisterAction<bit<32>, bit<16>, bit<32>>(qdelay_l4s) qdelay_l4s_action = {
            void apply(inout bit<32> value, out bit<32> result) {
                
                bit<32> avg_temp;
              
                avg_temp =  (queue_delay + value);
               
                // update register        
                value = avg_temp;
                result = avg_temp;
              

            }

        };
        
        
        RegisterAction<bit<32>, bit<16>, bit<32>>(qdelay_l4s) read_qdelay_l4s_action = {
            void apply(inout bit<32> value, out bit<32> result) {
                result = value;
                value = 0;

            }

        };
        

        /*
        RegisterAction<bit<16>, bit<16>,bool>(dropProbability) getProb_l4s = {
            void apply(inout bit<16> value, out bool result){

                if (rand_l4s < value){
                    value = value - 1;
                    result = false; //true;
                }else{
                    value = value + 1;
                    result = false;
                }
            }
        };*/
        
        Register<flow_id_t, bit<8>> (1) flow_id_reg;

        RegisterAction<flow_id_t, bit<8>, flow_id_t>(flow_id_reg) write_flow_id_reg = {
            void apply(inout flow_id_t value) {
                value = eg_md.metadata_flowID ;

            }
        };
    /*
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    Experienced Congestion (EC) Marking/Droping the Packets (L4S and Classic) Queues
    %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
    */
    /*  
        RegisterAction<bit<32>, bit<16>, bit<32>>(target_violation) compute_target_violations = {
            void apply(inout bit<32> value, out bit<32> violation){
                
                value = EWMA;
                


                // No drop 
                if (value <= CoDel_Min){
                    violation = 0;
                }

                //Dropping/Marking with a Probability 
                if ((value > CoDel_Min) && (value < CoDel_Max)){
                    violation = 1;
                }

                ////Dropping/Marking (Queue sounds full!)
                if (value > CoDel_Max){
                    violation = 2;
                }

            }
        };    
    */
    action extract_flowID_ipv4_udp(){
        eg_md.metadata_flowID = hash_function_udp.get({hdr.ipv4.dst_addr, hdr.udp.dstPort, hdr.ipv4.protocol});
    }

    action extract_flowID_ipv4_tcp(){
        eg_md.metadata_flowID = hash_function_tcp.get({hdr.ipv4.dst_addr, hdr.tcp.dstPort, hdr.ipv4.protocol});
    }
        
        

        // decisionMirror: clone this packet to session 1 (-> port 128 -> ingress) with all measured features.
        action decisionMirror(){
            hdr.mirror.egress_port = MIRROR_PORT;
            //hdr.mirror.egress_port = eg_intr_md.egress_port;
            hdr.mirror.header_info = 1;
            hdr.mirror.mirror_session = 1;
            eg_intr_dprs_md.mirror_type = HEADER_TYPE_MIRROR_EGRESS;
            //hdr.mirror.IPG = IPG; THIS IS THE ACCUMMULATIVE ONE
            //hdr.mirror.egress_global_tstamp = (bit<48>)eg_intr_md_from_prsr.global_tstamp;
            eg_intr_dprs_md.mirror_io_select = 1;
            //hdr.mirror.testing = 99;
            hdr.mirror.flowid = eg_md.metadata_flowID;
            hdr.mirror.packet_size = hdr.ipv4.total_len;
            hdr.mirror.frame_size = eg_md.metadata_frame_size;
            hdr.mirror.ifg = eg_md.metadata_ifg;
            hdr.mirror.IPG = eg_md.metadata_ipg;
            hdr.mirror.rtp_marker = hdr.rtp.marker;
            hdr.mirror.has_rtp = eg_md.metadata_has_rtp;
            hdr.mirror.queue_delay = eg_md.metadata_queue_delay_new;
            hdr.mirror.host_ifg = eg_md.metadata_host_ifg; // Alireza added
            hdr.mirror.trigger = 1;
            c7_clone_tx_inc.execute(eg_md.metadata_flowID);
        }

        // NoMirror: no clone (mirror_type 5 is not handled by the deparser, so nothing is emitted).
        action NoMirror(){
            eg_intr_dprs_md.mirror_type =  5;
            hdr.mirror.trigger = 0;
            // hdr.mirror.egress_port = MIRROR_PORT;
            // hdr.mirror.header_info = 1;
            // hdr.mirror.mirror_session = 1;
            // eg_intr_dprs_md.mirror_type =  100 // HEADER_TYPE_MIRROR_EGRESS;
            // //eg_intr_dprs_md.mirror_io_select = 1;
            // //hdr.mirror.testing = 99;
            // hdr.mirror.trigger = 0;
            //drop_cloned_pkts();
        }



        // Table for Thresholds / counters.frame_count < 3 ||  counters.packet_count < 20
        // c7_budget: clone while (pkt, frame) indices fall in a configured range.
        table c7_budget {
            key = {
                c7_pkt_idx: range;
                c7_frm_idx: range;
            }
            actions = { decisionMirror; NoMirror; }
            size = 16;
            default_action = NoMirror();
        }

        // Older threshold tables (not applied any more; the compiler removes them).
        table table_pkt_check{
        key = {
            packet_counter_value: range;
            //frame_counter_value: range;
        }
        actions = {
            decisionMirror;
            NoMirror;
            //NoAction;
        }
        size = 1024;
        //default_action = NoAction();
        default_action = NoMirror();
    }


            // Table for Thresholds / counters.frame_count < 3 ||  counters.packet_count < 20 table_threshold
        table table_frame_check{
        key = {
            //packet_counter_value: range;
            frame_counter_value: range;
        }
        actions = {
            decisionMirror;
            NoMirror;
            //NoAction;
        }
        size = 1024;
        default_action = NoMirror();
    }



        //INT
        RegisterAction<bit<32>, bit<16>, bit<32>>(switchLatency) switchLatencyAction = {
            void apply(inout bit<32> value, out bit<32> result) {
                value = queue_delay;
            }

        };    

        action _drop(){
            eg_intr_dprs_md.drop_ctl = 1;
        }


        // INT: push one record with ingress port, queue id, egress timestamp, queue depth,
        // accumulated queue delay and packet count of the selected queue; IPv4 length grows by 37 bytes.
        action add_swtrace(){
           
            hdr.nodeCount.count = hdr.nodeCount.count + 1;
            hdr.INT.push_front(1);
            hdr.INT[0].setValid();
            //1 para ida, 2 para volta
            
            hdr.INT[0].ingress_port = (bit<9>)hdr.bridge.bridge_ingress_port;
            //hdr.INT[0].egress_port = eg_intr_md.egress_port;
            // hdr.INT[0].egress_spec = (egressSpec_v)standard_metadata.egress_spec;
            // hdr.INT[0].priority = (priority_v)standard_metadata.priority;
            //hdr.INT[0].qid = eg_intr_md.egress_qid;
            hdr.INT[0].qid = (bit<7>)hdr.bridge.bridge_qid;
            // hdr.INT[0].ingress_global_timestamp = (ingress_global_timestamp_v)standard_metadata.ingress_global_timestamp;
            hdr.INT[0].egress_global_timestamp = (bit<32>)eg_intr_md_from_prsr.global_tstamp;
            // hdr.INT[0].enq_timestamp = (enq_timestamp_v)standard_metadata.enq_timestamp;
            hdr.INT[0].enq_qdepth = eg_md.metadata_enq_qdepth;
            // hdr.INT[0].deq_timedelta = (deq_timedelta_v)deq_timedelta_avg;
            // hdr.INT[0].deq_qdepth = (deq_qdepth_v)deq_qdepth_avg;
            hdr.INT[0].processing_time = eg_md.metadata_queue_delay;
            hdr.INT[0].number_of_packets_for_average = eg_md.metadata_totalPkts;

            hdr.ipv4.total_len = hdr.ipv4.total_len + 37;
        }
       
    apply {
        // topology_arp_egress: preserve ARP; skip IP-only classifier telemetry.
        // ARP: just forward (no AQM, no features).
        if (hdr.arp.isValid()) {
            hdr.bridge.setInvalid();
        } else {

        // coupling_queue_snapshot: save logical queue before bridge invalidation.
        // (1) Remember the queue (0/1) and save the queue-delay sample read by the AQM controller.
        coupling_queue = hdr.bridge.bridge_qid;
        c7_eval = 0;
        c7_event = 0;
        // coupling_sampling_logic: sample ordinary IPv4 traffic before dropping
        // or invalidating the bridge header. No changes to INT processing.
        if (hdr.ipv4.isValid() && !hdr.nodeCount.isValid() &&
            coupling_queue <= 16w1) {
            coupling_sample_index = 6w0 ++ eg_intr_md.egress_port ++ coupling_queue[0:0];
            c7_stamp.apply();  // c7: replaces the busy-bit if (same values)
            coupling_store_delay.execute(coupling_sample_index);
            coupling_store_stamp.execute(coupling_sample_index);
        }
            // c7_early: evaluated population = IPv4 (not INT) leaving port 137.
            c7_eval = 0;
            c7_event = 0;
            // Compute (deq_timedelta - step) for the L4S step test below.
            c7_l4s_step.apply();
            if (eg_intr_md.egress_port == 137 && hdr.ipv4.isValid() &&
                !hdr.nodeCount.isValid()) {
                c7_eval = 1;
                c7_residence_clock.apply();
            }
        /*   
        if(hdr.bridge.bridge_qid == 0){
            if(eg_intr_md.egress_port == 136){ 
                eg_md.metadata_index = 0x00; 
            }
            else if(eg_intr_md.egress_port == 137){
                eg_md.metadata_index = 0x01;
            }
            else{ //loopbackport (com int)
                eg_md.metadata_index = 0x01;
            }
        }
        else if(hdr.bridge.bridge_qid == 1){
            if(eg_intr_md.egress_port == 136){ 
                eg_md.metadata_index = 0x02;
            }
            else if(eg_intr_md.egress_port == 137){
                eg_md.metadata_index = 0x03;
            }
            else{//loopbackport com int
                eg_md.metadata_index = 0x03;
            }
        }*/
        // topology_queue_index: separate statistics for all six server queues.
        // (2) Queue statistics index 0..5 (see mark_ecn_pkt above).
        eg_md.metadata_index = 0;
        if (eg_intr_md.egress_port == 137) {
            eg_md.metadata_index = 2;
        } else if (eg_intr_md.egress_port == 138) {
            eg_md.metadata_index = 4;
        }
        // INT_collection_mapping: first pass over internal recirculation reads
        // port 137 statistics (swid=1); the return to Peach reads port 136.
        // Internal recirculation is transport, not the monitored fiber port.
        if (hdr.nodeCount.isValid() && hdr.nodeCount.count == 0) {
            eg_md.metadata_index = 2;
        }
        if (coupling_queue == 1) {
            eg_md.metadata_index = eg_md.metadata_index + 1;
        }

        // else if(hdr.bridge.bridge_qid == 2){
        //     if(eg_intr_md.egress_port == 136){ 
        //         eg_md.metadata_index = 0x04;
        //     }
        //     else if(eg_intr_md.egress_port == 137){
        //         eg_md.metadata_index = 0x05;
        //     }
        //     else{//loopbackport com int
        //         eg_md.metadata_index = 0x05;
        //     }
        // }

        // Store selected metadata index for later use.



        bit<16> nothing = store_index_reg.execute(0); 




        // (3a) INT probe: read and reset the queue statistics and push an INT record.
        if(hdr.nodeCount.isValid()){
            //eg_md.metadata_enq_qdepth = read_enq_qdepth_reg_RegisterAction.execute(eg_md.metadata_index);
            eg_md.metadata_queue_delay = read_qdelay_l4s_action.execute(eg_md.metadata_index); 
            eg_md.metadata_totalPkts = reset_totalPkts.execute(eg_md.metadata_index);
            add_swtrace();
            if (hdr.nodeCount.count == 1){
                hdr.INT[0].swid = 1;
            } else {
                hdr.INT[0].swid = 2;
            }
            hdr.bridge.setInvalid();
            //totalPkts.count(temp_index);
        }
        else{
            //save telemetry average
            //Counter of packets
            //bit<16> temp_index = eg_md.metadata_index;
            //totalPkts.count(temp_index);
            
            
            //if(hdr.ipv4.ecn == 1 || hdr.ipv4.ecn == 2){//n preciso checar. so vai pro index correto e boa
            // (3b) Normal packet: update per-queue statistics...
            increase_totalPkts.execute(eg_md.metadata_index);
            //}
            
            
            /*enq qdepth avg*/
            //bit<32> EWMA_enq_qdepth_temp;
            // if(hdr.ipv4.ecn == 1 || hdr.ipv4.ecn == 2){
            //     EWMA_enq_qdepth_temp = write_enq_qdepth_reg_RegisterAction.execute(eg_md.metadata_index);
            // }

            // EWMA_enq_qdepth = EWMA_enq_qdepth_temp>>1; //alpha = 0.5
            // eg_md.metadata_enq_qdepth = EWMA_enq_qdepth;

            //* Compute queue delay *//
            queue_delay = (bit<32>) eg_intr_md.deq_timedelta; // Alireza New Queue Delay
            //queue_delay = (value_t)eg_intr_md_from_prsr.global_tstamp - (value_t)hdr.bridge.ingress_global_tstamp;
            hdr.bridge.setInvalid();

            // Queue color can be inspected here with eg_intr_md.deq_congest_stat.


            //switchLatencyAction.execute((value_t)eg_intr_md.egress_port); //sei la pra q isso

            bit<32> EWMA_temp;
            
            //if (hdr.ipv4.l4s == 1){
            //if(hdr.ipv4.ecn == 1 || hdr.ipv4.ecn == 2){ //n preciso checar, so ir pro correto (inclui classic)
            EWMA_temp = qdelay_l4s_action.execute(eg_md.metadata_index);
            //}
            //else{

            //     EWMA_temp = qdelay_classic_action.execute((value_t)eg_intr_md.egress_port);
            // }
            
            EWMA = EWMA_temp>>1; //o original ta comentado aqui msm (?)
            //eg_md.metadata_queue_delay = (bit<32>)EWMA; //OBS: o valor aqui ta com 16 bits em, ob2 n sei se tem pra q isso se n ta no int

            //EWMA = queue_delay;


            //INTER PACKET GAP
            bit<32> previous_timestamp = store_previous_timestamp.execute(eg_md.metadata_index);
            IPG = eg_intr_md_from_prsr.global_tstamp[31:0] - previous_timestamp; //previous = 32bits
            increase_IPG.execute(eg_md.metadata_index);
            increase_totalPkts_IPG.execute(eg_md.metadata_index);

            //PACKET SIZE
            increase_packet_size.execute(eg_md.metadata_index);












            
            //* Check if the queue delay reach the target limit *//
            //* 0 = no drop    *//
            //* 1 = Maybe drop *//
            //* 2 = drop       *//

            /*
            bit<32> target_violations;
            target_violations = compute_target_violations.execute(eg_md.metadata_index);
            */
            
            /*
            if (target_violations == 1){
                //Counter of packets
                thresholdPkts.count((bit<32>)eg_md.metadata_index);
            */
                //* rand_classic is a is a random number, used to compute the new drop probability of Classic flows *//
                //** For each new pkt with average queue occupancy between MinTh-MaxTh, the drop probability will be a double *// 
            /*    
                rand_classic = rand.get();
                rand_l4s = rand_classic >> 1; //Coupling       
                bool drop_decision_l4s;
                bool drop_decision_classic;
            */    
            
            /*
                if(hdr.ipv4.ecn == 1 || hdr.ipv4.ecn == 2){ //MARKING L4S + CG QUEUE

                    drop_decision_l4s = getProb_l4s.execute(eg_md.metadata_index);
                    
                    if (drop_decision_l4s == true){
                        
                        mark_ecn_pkt.count((bit<32>)eg_md.metadata_index);
                        hdr.ipv4.ecn = 3;    // Mark EC !!!
                    
                    } 

                }
                // else{

                //     drop_decision_classic = getProb_classic.execute((bit<16>)eg_intr_md.egress_port);

                //     if (drop_decision_classic == true){
                    
                //         decisionMirror();

                //     }

                // }
                
            }
            else if (target_violations == 2){
        
                //if (hdr.ipv4.l4s == 1){
                if(hdr.ipv4.ecn == 1 || hdr.ipv4.ecn == 2){ //MARKING L4S AND CG
                        mark_ecn_pkt.count((bit<32>)eg_md.metadata_index);
                        //hdr.ipv4.ecn = 3;

                }
                // else{

                //         //decisionMirror();

                // }
                    
            }
            */

            // coupling_logic: keep the existing TM congestion-state trigger.
            // Do not assume congestion-state encodings equal packet colors.
            // Native probability is 1 when deq_congest_stat > 0, otherwise 0.
            // L4S p_L = max(p_native, min(1, 2 * p_base)), coupling factor k = 2.
            // Classic queue 0 instead uses p_C = p_base squared below.
            // Not-ECT is never changed to CE; existing CE is preserved.
            // ... and apply the coupled DualPI2 AQM.
            // L4S queue (Q1): (i) ECT(1)/ECT(0) and TM congestion flag -> CE (event 1); only for ECT(1):
            // (ii) queue delay >= 1 ms step -> CE (event 5); (iii) random(0..32767) < p_base -> CE (event 2),
            // i.e. probability min(1, 2 p_base).
            if (hdr.ipv4.isValid() && coupling_queue == 16w1 &&
                (hdr.ipv4.ecn == 2w1 || hdr.ipv4.ecn == 2w2)) {
                if (eg_intr_md.deq_congest_stat > 0) {
                    coupling_mark_ce();
                    c7_event = 1;
                } else if (hdr.ipv4.ecn == 2w1 && c7_step_delta[31:31] == 0) {
                    coupling_mark_ce();
                    c7_event = 5;
                } else if (coupling_queue == 16w1 && hdr.ipv4.ecn == 2w1) {
                    coupling_random = rand.get();
                    coupling_random = coupling_random >> 1;
                    coupling_decision = coupling_decide.execute(
                        (bit<16>)eg_intr_md.egress_port);
                    if (coupling_decision) {
                        coupling_mark_ce();
                        c7_event = 2;
                    }
                }
            }

            // coupling_classic_logic: Classic decision uses the controller's
            // squared threshold, NOT unconditional local TM congestion marking.
            // Preserve already-CE; ECT(1) is expected in queue 1, not queue 0.
            // Classic queue (Q0), Not-ECT or ECT(0): random(0..65535) < p_base^2 ->
            // ECT(0): CE-mark (event 3); Not-ECT: drop (event 4).
            else if (hdr.ipv4.isValid() && coupling_queue == 16w0 &&
                (hdr.ipv4.ecn == 2w0 || hdr.ipv4.ecn == 2w2)) {
                coupling_classic_random = rand.get();
                coupling_classic_decision = coupling_decide_classic.execute(
                    (bit<16>)eg_intr_md.egress_port);
                if (coupling_classic_decision) {
                    if (hdr.ipv4.ecn == 2w2) {
                        coupling_mark_ce();
                        c7_event = 3;
                    } else {
                        coupling_drop_classic();
                        c7_event = 4;
                    }
                }
            }

        }
        
        // Flow ID starts
        // (4) Flow ID of this packet (same hash as ingress).
        if (hdr.ipv4.isValid() && hdr.ipv4.protocol == PROTO_UDP) {
            extract_flowID_ipv4_udp();
        }
        else if(hdr.ipv4.isValid() && hdr.ipv4.protocol == PROTO_TCP){
            extract_flowID_ipv4_tcp();
        }

        // c7_late: count by (queue, class, event) and sample into the ring.
        // (5) c7 measurement: count the event per (queue, class) and store a sampled record.
        if (c7_eval == 1) {
            c7_eindex = ((bit<8>)coupling_queue[0:0] << 5) | (bit<8>)c7_event;
            c7_egress_dscp.apply();
            c7_egress_event.count(c7_eindex);
            c7_eg_flow_inc.execute(eg_md.metadata_flowID);
            c7_seq = c7_next_seq.execute(0);
            c7_sampling.apply();
            c7_mask_seq.apply();
            if (c7_masked == 0) {
                c7_slot = c7_next_slot.execute(0);
                if (c7_slot < 65536) {
                    // tag: flow ID[31:16] | DSCP[15:10] | ECN out[9:8] |
                    //      queue[7] | event[6:4]
                    c7_tag = eg_md.metadata_flowID ++ hdr.ipv4.dscp ++ hdr.ipv4.ecn ++
                             coupling_queue[0:0] ++ c7_event ++ 4w0;
                    c7_store_residence.execute(c7_slot[15:0]);
                    c7_store_queue.execute(c7_slot[15:0]);
                    c7_store_tag.execute(c7_slot[15:0]);
                }
            }
        }


        // Alireza
        Counters counters;
        Thresholds thresholds;

        // increase the packets for each flow
        //bit<8> my_packet_counter = increase_packet_counter_flowbased.execute(eg_md.metadata_flowID);
        //Increase  

        // (6) Features. IPG = time since the previous packet of the same flow (0 for its first packet).
        eg_md.metadata_ipg_temp = (bit<32>) eg_intr_md_from_prsr.global_tstamp;
        bit<32> previous_tstamp_ipg = update_timestamp_ipg_reg.execute(eg_md.metadata_flowID);

        // First packet of a flow (no previous timestamp): IPG = 0, not the raw clock.
        if (previous_tstamp_ipg == 0) {
            eg_md.metadata_ipg = 0;
        } else {
            eg_md.metadata_ipg = (bit<32>)eg_intr_md_from_prsr.global_tstamp - previous_tstamp_ipg;
        }
        
        // frm_thr = 3
        //IFG AND FRAME SIZE
        //SAVE TIMESTAMP OF THE EGRESS WHEN MARKER IS 1 AND JUST READSUBSTITUTE AGAIN WHEN A NEW MARKER
        

        bit<8> counter_frames = 0;
        // Frame features from RTP: at a marker packet (frame end) compute IFG, frame size and host IFG;
        // inside a frame only accumulate the size. Non-RTP flows have FS = IFG = 0.
        if(hdr.rtp.isValid() ){
            if(hdr.rtp.marker == 1){
                if(hdr.rtp.version == RTP_VERSION){
                    eg_md.metadata_has_rtp = 1;

          

                    // STORE THE TIMESTAM
                    eg_md.metadata_ifg_temp = (bit<32>)eg_intr_md_from_prsr.global_tstamp;
                    bit<32> previous_tstamp_ifg;
                    previous_tstamp_ifg = update_timestamp_ifg_reg.execute(eg_md.metadata_flowID);
                    // First frame of a flow: IFG = 0 (ingress then keeps the stored IFG).
                    if (previous_tstamp_ifg == 0) {
                        eg_md.metadata_ifg = 0;
                    } else {
                        eg_md.metadata_ifg = (bit<32>)eg_intr_md_from_prsr.global_tstamp - previous_tstamp_ifg;
                    }

                    //AND SEND PA

                    eg_md.metadata_frame_size = reset_frame_size_reg.execute(eg_md.metadata_flowID);
                    //Alireza start
                    //RTP TIMESTAMP STORE 
                    eg_md.metadata_rtp_timestamp = update_rtp_timestamp_reg.execute(eg_md.metadata_flowID);
                    eg_md.metadata_host_ifg = hdr.rtp.timestamp - eg_md.metadata_rtp_timestamp;

                    update_host_ifg_reg.execute(eg_md.metadata_flowID);

                    // Counting the Frame Number
                    // c7: per-slot frame counter replaced by c7_frm_cnt.
                    //frame_counter_value = counters.frame_count;

                    //counter_frames = increase_frame_counter.execute(eg_md.metadata_flowID);
                    //Alireza end
                }
                else{
                    eg_md.metadata_frame_size = 0;
                    eg_md.metadata_ifg = 0;
                }

            }
            else{
                if(hdr.rtp.version == RTP_VERSION){
                    eg_md.metadata_ifg = 0;
                    eg_md.metadata_frame_size = 0;
                    increase_frame_size_reg.execute(eg_md.metadata_flowID);
                    eg_md.metadata_has_rtp = 1;
                }
                else{
                    eg_md.metadata_ifg = 0;
                    eg_md.metadata_frame_size = 0;
                }
            }
        }
        else{
            eg_md.metadata_frame_size = 0;
            eg_md.metadata_ifg = 0;
        }
        eg_md.metadata_queue_delay_new = (bit<32>) eg_intr_md.deq_timedelta; // Alireza New Queue Delay 
        //eg_md.metadata_queue_delay_new = (bit<32>) eg_intr_md_from_prsr.global_tstamp - (bit<32>)hdr.bridge.ingress_global_tstamp;

        hdr.bridge.setInvalid(); //vai que

        // c7: per-slot packet counter replaced by c7_pkt_cnt.
        //packet_counter_value = counters.packet_count;
        // Read Thresholds from register
        // Legacy reads (results unused).
        read_frame_counter_threshhold.execute((bit<8>)eg_md.metadata_index, thresholds.frame_thresh);
        read_packet_counter_threshhold.execute((bit<8>)eg_md.metadata_index, thresholds.packet_thresh);
        //bit<8> frame_threshhold_value = read_frame_counter_threshhold.execute((bit<8>)eg_md.metadata_index); // set thrshhold value
        //bit<8> packet_threshhold_value = read_packet_counter_threshhold.execute((bit<8>)eg_md.metadata_index); // set thrshhold value
        
        // (7) Clone decision for real egress ports: count packet/frame index of the flow and look up
        // c7_budget; while inside the budget the packet is cloned for classification.
        if(eg_intr_md.egress_port != MIRROR_PORT && eg_intr_md.egress_port != recirc_port){
           
            // if (counters.frame_count < 4 || counters.packet_count < 20){ //  thresholds.packet_thresh){ thresholds.frame_thresh
                //decisionMirror(); //mirrorring is trigered!
            // }
            // else{
            //     NoMirror();
                
            // }
            
            // *** table for thresholds Decision Mirror Triggered ***//
            if (hdr.ipv4.isValid()) {
                c7_pkt_idx = c7_pkt_inc.execute(eg_md.metadata_flowID);
                if (hdr.rtp.isValid() && hdr.rtp.version == RTP_VERSION && hdr.rtp.marker == 1) {
                    c7_frm_idx = c7_frm_inc.execute(eg_md.metadata_flowID);
                } else {
                    c7_frm_idx = c7_frm_read.execute(eg_md.metadata_flowID);
                }
                c7_budget.apply();
            } else {
                NoMirror();
            }

            //table_threshold.apply();
        }

        
        } // topology_arp_egress
     }
}

// Egress deparser: emit the clone (mirror header + packet, truncated to 256 B by the session)
// when decisionMirror() was chosen, recompute the IPv4 checksum (ECN may be CE now) and emit.
control EgressDeparser(
        packet_out pkt,
        inout headers_t hdr,
        in metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_dprs_md) {
    
    Mirror() mirror;
    Checksum() ipv4_checksum;
    
    apply {
        if (eg_intr_dprs_md.mirror_type == HEADER_TYPE_MIRROR_EGRESS){    
            mirror.emit<mirror_h>(hdr.mirror.mirror_session, {hdr.mirror.header_type, 
                                      hdr.mirror.header_info,
                                      hdr.mirror.egress_port,
                                      hdr.mirror.mirror_session,
                                      hdr.mirror.IPG,
                                      hdr.mirror.flowid,
                                      hdr.mirror.ifg,
                                      hdr.mirror.packet_size,
                                      hdr.mirror.frame_size,
                                      hdr.mirror.rtp_marker,
                                      hdr.mirror.queue_delay,
                                      hdr.mirror.has_rtp,
                                      hdr.mirror.host_ifg, // Alireza added
                                      hdr.mirror.trigger
                                      //hdr.mirror.egress_global_tstamp
                                      });
        
        }

        hdr.ipv4.hdr_checksum = ipv4_checksum.update({
            hdr.ipv4.version,
            hdr.ipv4.ihl,
            hdr.ipv4.dscp,
            //hdr.ipv4.l4s,
            hdr.ipv4.ecn,
            hdr.ipv4.total_len,
            hdr.ipv4.identification,
            hdr.ipv4.flags,
            hdr.ipv4.frag_offset,
            hdr.ipv4.ttl,
            hdr.ipv4.protocol,
            hdr.ipv4.src_addr,
            hdr.ipv4.dst_addr});
        
        pkt.emit(hdr);
    }
}


// (4) Pipeline: the same program runs in all 4 pipes of the Tofino 2.
Pipeline(IngressParser(), 
        Ingress(),
        IngressDeparser(),
        EgressParser(),
        Egress(),
        EgressDeparser()) pipe;

Switch(pipe) main;
