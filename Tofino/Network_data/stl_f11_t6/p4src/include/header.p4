/* CONSTANTS */
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;

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

header features_1_t{
    bit<7> padding;
    bit<9> features_1;
    bit<16> features_2;
    bit<16> features_3;
    bit<16> features_4;
    bit<16> features_5;
    bit<16> features_6;
}
header features_2_t{
    bit<16> features_7;
    bit<16> features_8;
    bit<16> features_9;
    bit<16> features_10;
    bit<16> features_11;
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
    bit<11> cnt;
    bit<5> padding;
    bit<8> layer;
}

header intermediate_data_1_t {
    bit<16> intermediate_data_1;
    bit<16> intermediate_data_2;
    bit<16> intermediate_data_3;
    bit<16> intermediate_data_4;
    bit<16> intermediate_data_5;
    bit<16> intermediate_data_6;
}

header intermediate_data_2_t {
    bit<16> intermediate_data_7;
    bit<16> intermediate_data_8;
    bit<16> intermediate_data_9;
    bit<16> intermediate_data_10;
    bit<16> intermediate_data_11;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;

    maloi_t   maloi;
    features_1_t features1;
    features_2_t features2;
    labeling_t labeling;
    intermediate_data_1_t intermediate_data1_1;
    intermediate_data_2_t intermediate_data1_2;

    intermediate_data_1_t intermediate_data2_1;
    intermediate_data_2_t intermediate_data2_2;

    tcp_t      tcp;
}

/*************************************************************************
*********************** METADATA *****************************************
*************************************************************************/

header metadata_t {
    @padding bit<7> padding1;
    bit<9> XNOROutput_1;
    bit<16> XNOROutput_2;
    bit<16> XNOROutput_3;
    bit<16> XNOROutput_4;
    bit<16> XNOROutput_5;
    bit<16> XNOROutput_6;
    bit<16> XNOROutput_7;
    bit<16> XNOROutput_8;
    bit<16> XNOROutput_9;
    bit<16> XNOROutput_10;
    bit<16> XNOROutput_11;
    
    @padding bit<7> padding2;
    bit<9> weight_1;
    bit<16> weight_2;
    bit<16> weight_3;
    bit<16> weight_4;
    bit<16> weight_5;
    bit<16> weight_6;
    bit<16> weight_7;
    bit<16> weight_8;
    bit<16> weight_9;
    bit<16> weight_10;
    bit<16> weight_11;

    bit<8> test;
    
    bit<8> PopCountOut1;
    bit<8> PopCountOut2;
    bit<8> PopCountOut3;
    bit<8> PopCountOut4;
    bit<8> PopCountOut5;

    bit<8> x_1;
    bit<8> x_2;
    bit<8> x_3;
    bit<8> x_4;
    bit<8> x_5;
    bit<8> x_6;
    bit<8> x_7;
    bit<8> x_8;
    bit<8> x_9;
    bit<8> x_10;
    bit<8> x_11;
}

struct ingress_metadata_t {
	metadata_t meta;
}

struct egress_metadata_t {
	metadata_t meta;
}