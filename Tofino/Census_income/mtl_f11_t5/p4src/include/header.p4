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

/* UDP */
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header features_t{
    @padding bit<6> padding;
    bit<2> features_1;
    bit<16> features_2;
    bit<16> features_3;
    bit<16> features_4;
    bit<16> features_5;
}


header labeling_1_t {
    bit<8> prediction6;
    bit<8> prediction12;
}

header labeling_2_t {
    bit<8> prediction10;
    bit<8> prediction2;
}

header labeling_3_t {
    bit<8> prediction13;
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
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;

    maloi_t   maloi;
    features_t features;
    labeling_1_t labeling_1;
    labeling_2_t labeling_2;
    labeling_3_t labeling_3;
    intermediate_data_t intermediate_data1;
    intermediate_data_t intermediate_data2;

    udp_t      udp;
}

/*************************************************************************
*********************** METADATA *****************************************
*************************************************************************/

header metadata_t {
    @padding bit<6> padding1;
    bit<2> XNOROutput_1;
    bit<16> XNOROutput_2;
    bit<16> XNOROutput_3;
    bit<16> XNOROutput_4;
    bit<16> XNOROutput_5;
    
    @padding bit<6> padding2;
    bit<2> weight_1;
    bit<16> weight_2;
    bit<16> weight_3;
    bit<16> weight_4;
    bit<16> weight_5;
    
    bit<8> test;
    
    bit<8> PopCountOut;
    bit<8> x_1;
    bit<8> x_2;
    bit<8> x_3;
    bit<8> x_4;
    bit<8> x_5;
}

struct ingress_metadata_t {
	metadata_t meta;
}

struct egress_metadata_t {
	metadata_t meta;
}