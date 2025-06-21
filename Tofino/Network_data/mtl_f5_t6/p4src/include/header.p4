/* CONSTANTS */
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6; // protocol=6 => TCP

/*************************************************************************
*********************** HEADERS ******************************************
*************************************************************************/

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

/* Ethernet */
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

/* IPv4 */
header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  tos;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header features_t{
    bit<16> features_1;
    bit<16> features_2;
    bit<16> features_3;
    bit<16> features_4;
    bit<16> features_5;
    bit<16> features_6;
    bit<16> features_7;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<3>  res;
    bit<3>  ecn;
    bit<6>  ctrl;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header labeling_t {
    bit<2> prediction1;
    bit<2> prediction2;
    bit<2> prediction3;
    bit<2> prediction4;
    bit<4> padding;
    bit<2> prediction5;
    bit<2> prediction6;
}

header maloi_t {
    bit<8> cnt;
    bit<8> layer;
}

header intermediate_data_t {
    bit<16> intermediate_data_1;
    bit<16> intermediate_data_2;
    bit<16> intermediate_data_3;
    bit<16> intermediate_data_4;
    bit<16> intermediate_data_5;
    bit<16> intermediate_data_6;
    bit<16> intermediate_data_7;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;

    maloi_t   maloi;
    features_t features;
    labeling_t labeling;
    intermediate_data_t intermediate_data1;
    intermediate_data_t intermediate_data2;

    tcp_t      tcp;
}

/*************************************************************************
*********************** METADATA *****************************************
*************************************************************************/

header metadata_t {
    bit<16> XNOROutput_1;
    bit<16> XNOROutput_2;
    bit<16> XNOROutput_3;
    bit<16> XNOROutput_4;
    bit<16> XNOROutput_5;
    bit<16> XNOROutput_6;
    bit<16> XNOROutput_7;
    
    bit<16> weight_1;
    bit<16> weight_2;
    bit<16> weight_3;
    bit<16> weight_4;
    bit<16> weight_5;
    bit<16> weight_6;
    bit<16> weight_7;

    bit<8> test;
    
    // bit<8> PopCountOut;

    bit<8> PopCountOut1;
    bit<8> PopCountOut2;
    bit<8> PopCountOut3;

    bit<8> x_1;
    bit<8> x_2;
    bit<8> x_3;
    bit<8> x_4;
    bit<8> x_5;
    bit<8> x_6;
    bit<8> x_7;
}

struct ingress_metadata_t {
	metadata_t meta;
}

struct egress_metadata_t {
	metadata_t meta;
}