/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

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

/* TCP */
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

/* UDP */
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header features_t{
    bit<90> features;
    bit<6> padding1;
}

header labeling_t {
    bit<4> prediction2;
    bit<4> prediction6;
    bit<4> prediction10;
    bit<4> prediction12;
    bit<4> prediction13;
    bit<4> task_id;
}

struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;

    features_t features;
    labeling_t labeling;

    // tcp_t      tcp;
    udp_t      udp;
}

/*************************************************************************
*********************** METADATA *****************************************
*************************************************************************/

struct metadata {
    bit<90> bnnInput;
    bit<90> NextLayerInput;
    bit<90> bnnInput2;

    bit<90> XNOROutput;
    bit<90> XNOROutput_next;

    // popcount
    bit<128> x;

    bit<16> task6_1;
    bit<16> task6_2;
    bit<16> task6_3;
    bit<16> task6_4;
    bit<16> task6_5;
    bit<16> task6_6;
    bit<16> task6_7;
    bit<16> task6_8;

    bit<16> task12_1;
    bit<16> task12_2;
    bit<16> task12_3;
    bit<16> task12_4;
    bit<16> task12_5;
    bit<16> task12_6;

    bit<16> task10_1;
    bit<16> task10_2;
    bit<16> task10_3;
    
    bit<16> task2_1;
    bit<16> task2_2;
    bit<16> task2_3;
    bit<16> task2_4;
    bit<16> task2_5;
    bit<16> task2_6;
    bit<16> task2_7;
    bit<16> task2_8;

    bit<16> task13_1;
    bit<16> task13_2;
    bit<16> task13_3;
    bit<16> task13_4;

    bit<4> predict2;
    bit<4> predict6;
    bit<4> predict10;
    bit<4> predict12;
    bit<4> predict13;
    
}

/*************************************************************************
************************  PARSER  ****************************************
*************************************************************************/

/* parse ethernet -> ipv4 -> tcp/udp -> labeling_t */
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_udp;
            200: parse_martini;
            default: accept;
        }
    }

    state parse_martini{
        packet.extract(hdr.features);
        packet.extract(hdr.labeling);
        transition parse_udp;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}

/*************************************************************************
*********************** VERIFY CHECKSUM ***********************************
*************************************************************************/
control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply { }
}

/*************************************************************************
************************  INGRESS  ****************************************
*************************************************************************/
control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata)
{
    /*
     * weights_bnn1, weights_bnn2 => bit<45> × 180
     * weights_task6 => bit<45> × 12
     */
    register<bit<45>>(180) weights_bnn1;
    register<bit<45>>(180) weights_bnn2;
    
    register<bit<45>>(1024) weights_task6;
    register<bit<45>>(1024) weights_task12;
    register<bit<45>>(1024) weights_task10;
    register<bit<45>>(1024) weights_task2;
    register<bit<45>>(1024) weights_task13;
    
    bit<128> m1  = 0x55555555555555555555555555555555;
    bit<128> m2  = 0x33333333333333333333333333333333;
    bit<128> m4  = 0x0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f;
    bit<128> m8  = 0x00ff00ff00ff00ff00ff00ff00ff00ff;
    bit<128> m16 = 0x0000ffff0000ffff0000ffff0000ffff;
    bit<128> m32 = 0x00000000ffffffff00000000ffffffff;
    bit<128> m64 = 0x0000000000000000ffffffffffffffff;
    bit<16> L4src = 0;
    bit<16> L4dst = 0;

    /**************************************
     * action drop()
     **************************************/
    action drop() {
        mark_to_drop(standard_metadata);
    }

    /**************************************
     * BuildInput():
     *   meta.bnnInput = hdr.labeling.features
     **************************************/
    action BuildInput() {
        meta.bnnInput = hdr.features.features;
    }

    /**************************************
     * XNOR, BitCount for layer1
     **************************************/
    action XNOR_90(bit<90> w) {
        meta.XNOROutput = ~(w ^ meta.bnnInput);
    }

    action BitCount_90(bit<90> bits) {
        bit<128> x_ = (bit<128>) bits;

        x_ = (x_ & m1 ) + ((x_ >> 1 ) & m1 );
        x_ = (x_ & m2 ) + ((x_ >> 2 ) & m2 );
        x_ = (x_ & m4 ) + ((x_ >> 4 ) & m4 );
        x_ = (x_ & m8 ) + ((x_ >> 8 ) & m8 );
        x_ = (x_ & m16) + ((x_ >>16) & m16);
        x_ = (x_ & m32) + ((x_ >>32) & m32);
        x_ = (x_ & m64) + ((x_ >>64) & m64);

        // threshold ex) 45
        bit<4> activated = (x_ > 45) ? (bit<4>)1 : 0;
        meta.NextLayerInput = meta.NextLayerInput << 1;
        meta.NextLayerInput = meta.NextLayerInput + (bit<90>) activated;
    }

    /**************************************
     * LayerProcess1( offset=0..179 )
     **************************************/
    action LayerProcess1(bit<32> offset, bit<90> input_data) {
        meta.NextLayerInput = 0;
        meta.bnnInput = input_data;

        bit<45> wsub;
        bit<90> w;

        weights_bnn1.read(wsub, offset + 0);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 1);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 2);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 3);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 4);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 5);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 6);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 7);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 8);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 9);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 10);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 11);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 12);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 13);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 14);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 15);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 16);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 17);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 18);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 19);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 20);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 21);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 22);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 23);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 24);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 25);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 26);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 27);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 28);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 29);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 30);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 31);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 32);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 33);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 34);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 35);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 36);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 37);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 38);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 39);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 40);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 41);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 42);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 43);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 44);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 45);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 46);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 47);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 48);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 49);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 50);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 51);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 52);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 53);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 54);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 55);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 56);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 57);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 58);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 59);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 60);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 61);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 62);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 63);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 64);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 65);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 66);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 67);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 68);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 69);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 70);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 71);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 72);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 73);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 74);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 75);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 76);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 77);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 78);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 79);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 80);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 81);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 82);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 83);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 84);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 85);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 86);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 87);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 88);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 89);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 90);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 91);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 92);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 93);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 94);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 95);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 96);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 97);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 98);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 99);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 100);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 101);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 102);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 103);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 104);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 105);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 106);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 107);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 108);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 109);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 110);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 111);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 112);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 113);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 114);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 115);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 116);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 117);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 118);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 119);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 120);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 121);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 122);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 123);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 124);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 125);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 126);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 127);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 128);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 129);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 130);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 131);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 132);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 133);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 134);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 135);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 136);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 137);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 138);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 139);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 140);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 141);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 142);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 143);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 144);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 145);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 146);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 147);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 148);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 149);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 150);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 151);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 152);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 153);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 154);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 155);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 156);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 157);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 158);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 159);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 160);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 161);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 162);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 163);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 164);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 165);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 166);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 167);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 168);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 169);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 170);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 171);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 172);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 173);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 174);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 175);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 176);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 177);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);

        weights_bnn1.read(wsub, offset + 178);
        w = (bit<90>)wsub << 45;
        weights_bnn1.read(wsub, offset + 179);
        w = w + (bit<90>)wsub;
        XNOR_90(w);
        BitCount_90(meta.XNOROutput);


        // finish
        meta.bnnInput2 = meta.NextLayerInput;
    }

    /**************************************
     * XNOR_next, BitCount_next for layer2
     **************************************/
    action XNOR_next_90(bit<90> w) {
        meta.XNOROutput_next = ~(w ^ meta.bnnInput2);
    }

    action BitCount_next_90(bit<90> bits) {
        bit<128> x_ = (bit<128>) bits;

        x_ = (x_ & m1 ) + ((x_ >> 1 ) & m1 );
        x_ = (x_ & m2 ) + ((x_ >> 2 ) & m2 );
        x_ = (x_ & m4 ) + ((x_ >> 4 ) & m4 );
        x_ = (x_ & m8 ) + ((x_ >> 8 ) & m8 );
        x_ = (x_ & m16) + ((x_ >>16) & m16);
        x_ = (x_ & m32) + ((x_ >>32) & m32);
        x_ = (x_ & m64) + ((x_ >>64) & m64);

        bit<4> activated = (x_ > 45) ? (bit<4>)1 : 0;
        meta.NextLayerInput = meta.NextLayerInput << 1;
        meta.NextLayerInput = meta.NextLayerInput + (bit<90>) activated;
    }

    /**************************************
     * LayerProcess2( offset=0..179 )
     **************************************/
    action LayerProcess2(bit<32> offset, bit<90> input_data) {
        meta.NextLayerInput = 0;
        meta.bnnInput2 = input_data;

        bit<45> wsub;
        bit<90> w;

        // offset+0..1
        weights_bnn2.read(wsub, offset+0);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+1);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+2);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+3);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+4);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+5);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+6);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+7);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+8);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+9);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+10);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+11);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+12);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+13);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+14);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+15);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+16);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+17);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+18);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+19);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+20);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+21);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+22);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+23);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+24);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+25);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+26);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+27);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+28);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+29);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+30);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+31);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+32);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+33);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+34);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+35);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+36);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+37);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+38);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+39);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+40);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+41);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+42);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+43);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+44);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+45);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+46);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+47);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset+48);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset+49);
        w = w + (bit<90>) wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 50);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 51);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 52);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 53);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 54);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 55);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 56);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 57);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 58);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 59);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 60);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 61);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 62);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 63);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 64);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 65);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 66);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 67);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 68);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 69);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 70);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 71);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 72);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 73);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 74);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 75);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 76);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 77);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 78);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 79);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 80);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 81);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 82);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 83);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 84);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 85);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 86);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 87);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 88);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 89);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 90);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 91);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 92);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 93);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);
        
                weights_bnn2.read(wsub, offset + 94);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 95);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 96);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 97);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 98);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 99);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 100);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 101);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 102);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 103);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 104);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 105);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 106);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 107);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 108);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 109);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 110);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 111);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 112);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 113);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 114);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 115);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 116);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 117);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 118);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 119);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 120);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 121);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 122);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 123);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 124);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 125);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 126);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 127);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 128);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 129);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 130);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 131);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 132);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 133);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 134);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 135);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 136);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 137);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 138);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 139);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 140);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 141);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 142);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 143);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 144);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 145);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 146);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 147);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 148);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 149);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 150);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 151);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 152);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 153);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 154);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 155);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 156);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 157);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 158);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 159);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 160);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 161);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 162);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 163);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 164);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 165);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 166);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 167);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 168);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 169);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 170);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 171);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 172);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 173);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 174);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 175);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 176);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 177);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        weights_bnn2.read(wsub, offset + 178);
        w = (bit<90>)wsub << 45;
        weights_bnn2.read(wsub, offset + 179);
        w = w + (bit<90>)wsub;
        XNOR_next_90(w);
        BitCount_next_90(meta.XNOROutput_next);

        meta.bnnInput2 = meta.NextLayerInput;
    }


    action XNOR_task6(bit<90> w) {
        meta.XNOROutput = ~(w ^ meta.bnnInput2);
    }

    action BitCount_t6_1(bit<90> bits) {
        bit<128> xx = (bit<128>)bits;

        xx = (xx & m1 ) + ((xx >> 1 ) & m1 );
        xx = (xx & m2 ) + ((xx >> 2 ) & m2 );
        xx = (xx & m4 ) + ((xx >> 4 ) & m4 );
        xx = (xx & m8 ) + ((xx >> 8 ) & m8 );
        xx = (xx & m16) + ((xx >>16) & m16);
        xx = (xx & m32) + ((xx >>32) & m32);
        xx = (xx & m64) + ((xx >>64) & m64);

        meta.task6_1 = (bit<16>)xx;
    }

    action BitCount_t6_2(bit<90> bits) {
        bit<128> xx = (bit<128>)bits;

        xx = (xx & m1 ) + ((xx >> 1 ) & m1 );
        xx = (xx & m2 ) + ((xx >> 2 ) & m2 );
        xx = (xx & m4 ) + ((xx >> 4 ) & m4 );
        xx = (xx & m8 ) + ((xx >> 8 ) & m8 );
        xx = (xx & m16)+ ((xx >>16) & m16);
        xx = (xx & m32)+ ((xx >>32) & m32);
        xx = (xx & m64)+ ((xx >>64) & m64);

        meta.task6_2 = (bit<16>)xx;
    }

    action BitCount_t6_3(bit<90> bits) {
        bit<128> xx = (bit<128>)bits;

        xx = (xx & m1 ) + ((xx >> 1 ) & m1 );
        xx = (xx & m2 ) + ((xx >> 2 ) & m2 );
        xx = (xx & m4 ) + ((xx >> 4 ) & m4 );
        xx = (xx & m8 ) + ((xx >> 8 ) & m8 );
        xx = (xx & m16)+ ((xx >>16) & m16);
        xx = (xx & m32)+ ((xx >>32) & m32);
        xx = (xx & m64)+ ((xx >>64) & m64);

        meta.task6_3 = (bit<16>)xx;
    }

    action BitCount_t6_4(bit<90> bits) {
        bit<128> xx = (bit<128>)bits;

        xx = (xx & m1 ) + ((xx >> 1 ) & m1 );
        xx = (xx & m2 ) + ((xx >> 2 ) & m2 );
        xx = (xx & m4 ) + ((xx >> 4 ) & m4 );
        xx = (xx & m8 ) + ((xx >> 8 ) & m8 );
        xx = (xx & m16)+ ((xx >>16) & m16);
        xx = (xx & m32)+ ((xx >>32) & m32);
        xx = (xx & m64)+ ((xx >>64) & m64);

        meta.task6_4 = (bit<16>)xx;
    }

    action BitCount_t6_5(bit<90> bits) {
        bit<128> xx = (bit<128>)bits;

        xx = (xx & m1 ) + ((xx >> 1 ) & m1 );
        xx = (xx & m2 ) + ((xx >> 2 ) & m2 );
        xx = (xx & m4 ) + ((xx >> 4 ) & m4 );
        xx = (xx & m8 ) + ((xx >> 8 ) & m8 );
        xx = (xx & m16)+ ((xx >>16) & m16);
        xx = (xx & m32)+ ((xx >>32) & m32);
        xx = (xx & m64)+ ((xx >>64) & m64);

        meta.task6_5 = (bit<16>)xx;
    }

    action BitCount_t6_6(bit<90> bits) {
        bit<128> xx = (bit<128>)bits;

        xx = (xx & m1 ) + ((xx >> 1 ) & m1 );
        xx = (xx & m2 ) + ((xx >> 2 ) & m2 );
        xx = (xx & m4 ) + ((xx >> 4 ) & m4 );
        xx = (xx & m8 ) + ((xx >> 8 ) & m8 );
        xx = (xx & m16)+ ((xx >>16) & m16);
        xx = (xx & m32)+ ((xx >>32) & m32);
        xx = (xx & m64)+ ((xx >>64) & m64);

        meta.task6_6 = (bit<16>)xx;
    }
    action BitCount_t6_7(bit<90> bits) {
        bit<128> xx = (bit<128>)bits;

        xx = (xx & m1 ) + ((xx >> 1 ) & m1 );
        xx = (xx & m2 ) + ((xx >> 2 ) & m2 );
        xx = (xx & m4 ) + ((xx >> 4 ) & m4 );
        xx = (xx & m8 ) + ((xx >> 8 ) & m8 );
        xx = (xx & m16)+ ((xx >>16) & m16);
        xx = (xx & m32)+ ((xx >>32) & m32);
        xx = (xx & m64)+ ((xx >>64) & m64);

        meta.task6_7 = (bit<16>)xx;
    }
    action BitCount_t6_8(bit<90> bits) {
        bit<128> xx = (bit<128>)bits;

        xx = (xx & m1 ) + ((xx >> 1 ) & m1 );
        xx = (xx & m2 ) + ((xx >> 2 ) & m2 );
        xx = (xx & m4 ) + ((xx >> 4 ) & m4 );
        xx = (xx & m8 ) + ((xx >> 8 ) & m8 );
        xx = (xx & m16)+ ((xx >>16) & m16);
        xx = (xx & m32)+ ((xx >>32) & m32);
        xx = (xx & m64)+ ((xx >>64) & m64);

        meta.task6_8 = (bit<16>)xx;
    }

    action predict_task6() {
        bit<16> bestVal = meta.task6_1;
        bit<4> bestCls = 0;
        if(meta.task6_2 > bestVal) {bestVal=meta.task6_2; bestCls=1;}
        if(meta.task6_3 > bestVal) {bestVal=meta.task6_3; bestCls=2;}
        if(meta.task6_4 > bestVal) {bestVal=meta.task6_4; bestCls=3;}
        if(meta.task6_5 > bestVal) {bestVal=meta.task6_5; bestCls=4;}
        if(meta.task6_6 > bestVal) {bestVal=meta.task6_6; bestCls=5;}
        if(meta.task6_7 > bestVal) {bestVal=meta.task6_7; bestCls=6;}
        if(meta.task6_8 > bestVal) {bestVal=meta.task6_8; bestCls=7;}

        meta.predict6 = bestCls;
        //hdr.labeling.prediction6 = bestCls;
    }
    
    action XNOR_task12(bit<90> w) {
        meta.XNOROutput = ~(w ^ meta.bnnInput2);
    }
    
    action BitCount_t12_1(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
    
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
    
        meta.task12_1 = (bit<16>) xx;
    }
    
    action BitCount_t12_2(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
    
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
    
        meta.task12_2 = (bit<16>) xx;
    }
    
    action BitCount_t12_3(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
    
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
    
        meta.task12_3 = (bit<16>) xx;
    }
    
    action BitCount_t12_4(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
    
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
    
        meta.task12_4 = (bit<16>) xx;
    }
    
    action BitCount_t12_5(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
    
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
    
        meta.task12_5 = (bit<16>) xx;
    }
    
    action BitCount_t12_6(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
    
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
    
        meta.task12_6 = (bit<16>) xx;
    }
    
    action predict_task12() {
        bit<16> bestVal = meta.task12_1;
        bit<4> bestCls = 0;
        if (meta.task12_2 > bestVal) { bestVal = meta.task12_2; bestCls = 1; }
        if (meta.task12_3 > bestVal) { bestVal = meta.task12_3; bestCls = 2; }
        if (meta.task12_4 > bestVal) { bestVal = meta.task12_4; bestCls = 3; }
        if (meta.task12_5 > bestVal) { bestVal = meta.task12_5; bestCls = 4; }
        if (meta.task12_6 > bestVal) { bestVal = meta.task12_6; bestCls = 5; }
        meta.predict12 = bestCls;
        //hdr.labeling.prediction12 = bestCls;
    }

    action XNOR_task10(bit<90> w) {
        meta.XNOROutput = ~(w ^ meta.bnnInput2);
    }
    
    action BitCount_t10_1(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
    
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
    
        meta.task10_1 = (bit<16>) xx;
    }
    
    action BitCount_t10_2(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
    
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
    
        meta.task10_2 = (bit<16>) xx;
    }
    
    action BitCount_t10_3(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
    
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
    
        meta.task10_3 = (bit<16>) xx;
    }
    
    action predict_task10() {
        bit<16> bestVal = meta.task10_1;
        bit<4> bestCls = 0;
        if (meta.task10_2 > bestVal) { bestVal = meta.task10_2; bestCls = 1; }
        if (meta.task10_3 > bestVal) { bestVal = meta.task10_3; bestCls = 2; }
        meta.predict10 = bestCls;
        //hdr.labeling.prediction10 = bestCls;
    }

    action XNOR_task2(bit<90> w) {
        meta.XNOROutput = ~(w ^ meta.bnnInput2);
    }
    
    action BitCount_t2_1(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
        meta.task2_1 = (bit<16>) xx;
    }
    
    action BitCount_t2_2(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
        meta.task2_2 = (bit<16>) xx;
    }
    
    action BitCount_t2_3(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
        meta.task2_3 = (bit<16>) xx;
    }
    
    action BitCount_t2_4(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
        meta.task2_4 = (bit<16>) xx;
    }
    
    action BitCount_t2_5(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
        meta.task2_5 = (bit<16>) xx;
    }
    
    action BitCount_t2_6(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
        meta.task2_6 = (bit<16>) xx;
    }
    
    action BitCount_t2_7(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
        meta.task2_7 = (bit<16>) xx;
    }
    
    action BitCount_t2_8(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
        meta.task2_8 = (bit<16>) xx;
    }
    
    action predict_task2() {
        bit<16> bestVal = meta.task2_1;
        bit<4> bestCls = 0;
        if (meta.task2_2 > bestVal) { bestVal = meta.task2_2; bestCls = 1; }
        if (meta.task2_3 > bestVal) { bestVal = meta.task2_3; bestCls = 2; }
        if (meta.task2_4 > bestVal) { bestVal = meta.task2_4; bestCls = 3; }
        if (meta.task2_5 > bestVal) { bestVal = meta.task2_5; bestCls = 4; }
        if (meta.task2_6 > bestVal) { bestVal = meta.task2_6; bestCls = 5; }
        if (meta.task2_7 > bestVal) { bestVal = meta.task2_7; bestCls = 6; }
        if (meta.task2_8 > bestVal) { bestVal = meta.task2_8; bestCls = 7; }
        meta.predict2 = bestCls;
        //hdr.labeling.prediction2 = bestCls;
    }

    action XNOR_task13(bit<90> w) {
        meta.XNOROutput = ~(w ^ meta.bnnInput2);
    }
    
    action BitCount_t13_1(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
        meta.task13_1 = (bit<16>) xx;
    }
    
    action BitCount_t13_2(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
        meta.task13_2 = (bit<16>) xx;
    }
    
    action BitCount_t13_3(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
        meta.task13_3 = (bit<16>) xx;
    }
    
    action BitCount_t13_4(bit<90> bits) {
        bit<128> xx = (bit<128>) bits;
        xx = (xx & m1) + ((xx >> 1) & m1);
        xx = (xx & m2) + ((xx >> 2) & m2);
        xx = (xx & m4) + ((xx >> 4) & m4);
        xx = (xx & m8) + ((xx >> 8) & m8);
        xx = (xx & m16) + ((xx >> 16) & m16);
        xx = (xx & m32) + ((xx >> 32) & m32);
        xx = (xx & m64) + ((xx >> 64) & m64);
        meta.task13_4 = (bit<16>) xx;
    }
    
    action predict_task13() {
        bit<16> bestVal = meta.task13_1;
        bit<4> bestCls = 0;
        if (meta.task13_2 > bestVal) { bestVal = meta.task13_2; bestCls = 1; }
        if (meta.task13_3 > bestVal) { bestVal = meta.task13_3; bestCls = 2; }
        if (meta.task13_4 > bestVal) { bestVal = meta.task13_4; bestCls = 3; }
        meta.predict13 = bestCls;
        //hdr.labeling.prediction13 = bestCls;
    }


    apply {
        if (hdr.udp.isValid()){
            L4src=hdr.udp.srcPort;
            L4dst=hdr.udp.dstPort;
        }
        // (1) Build input from labeling: bnnInput = hdr.labeling.features
        if(hdr.labeling.isValid()) {
            BuildInput();

            // (2) LayerProcess1 => bnnInput2
            LayerProcess1(0, meta.bnnInput);

            // (3) LayerProcess2 => bnnInput2
            LayerProcess2(0, meta.bnnInput2);

            // task6 processing:
            {
                bit<45> wsub;
                bit<90> w;

                weights_task6.read(wsub, (bit<32>)0);
                w = (bit<90>)wsub << 45;
                weights_task6.read(wsub, (bit<32>)1);
                w = w + (bit<90>)wsub;
                XNOR_task6(w);
                BitCount_t6_1(meta.XNOROutput);
                

                weights_task6.read(wsub, (bit<32>)2);
                w = (bit<90>)wsub << 45;
                weights_task6.read(wsub, (bit<32>)3);
                w = w + (bit<90>)wsub;
                XNOR_task6(w);
                BitCount_t6_2(meta.XNOROutput);

                weights_task6.read(wsub, (bit<32>)4);
                w = (bit<90>)wsub << 45;
                weights_task6.read(wsub, (bit<32>)5);
                w = w + (bit<90>)wsub;
                XNOR_task6(w);
                BitCount_t6_3(meta.XNOROutput);

                weights_task6.read(wsub, (bit<32>)6);
                w = (bit<90>)wsub << 45;
                weights_task6.read(wsub, (bit<32>)7);
                w = w + (bit<90>)wsub;
                XNOR_task6(w);
                BitCount_t6_4(meta.XNOROutput);

                weights_task6.read(wsub, (bit<32>)8);
                w = (bit<90>)wsub << 45;
                weights_task6.read(wsub, (bit<32>)9);
                w = w + (bit<90>)wsub;
                XNOR_task6(w);
                BitCount_t6_5(meta.XNOROutput);

                weights_task6.read(wsub, (bit<32>)10);
                w = (bit<90>)wsub << 45;
                weights_task6.read(wsub, (bit<32>)11);
                w = w + (bit<90>)wsub;
                XNOR_task6(w);
                BitCount_t6_6(meta.XNOROutput);

                weights_task6.read(wsub, (bit<32>)12);
                w = (bit<90>)wsub << 45;
                weights_task6.read(wsub, (bit<32>)13);
                w = w + (bit<90>)wsub;
                XNOR_task6(w);
                BitCount_t6_7(meta.XNOROutput);

                weights_task6.read(wsub, (bit<32>)14);
                w = (bit<90>)wsub << 45;
                weights_task6.read(wsub, (bit<32>)15);
                w = w + (bit<90>)wsub;
                XNOR_task6(w);
                BitCount_t6_8(meta.XNOROutput);

                predict_task6();
            }
            
            // task12 processing:
            {
                bit<45> wsub;
                bit<90> w;

                weights_task12.read(wsub, (bit<32>)0);
                w = (bit<90>)wsub << 45;
                weights_task12.read(wsub, (bit<32>)1);
                w = w + (bit<90>)wsub;
                XNOR_task12(w);
                BitCount_t12_1(meta.XNOROutput);
                
                weights_task12.read(wsub, (bit<32>)2);
                w = (bit<90>)wsub << 45;
                weights_task12.read(wsub, (bit<32>)3);
                w = w + (bit<90>)wsub;
                XNOR_task12(w);
                BitCount_t12_2(meta.XNOROutput);

                weights_task12.read(wsub, (bit<32>)4);
                w = (bit<90>)wsub << 45;
                weights_task12.read(wsub, (bit<32>)5);
                w = w + (bit<90>)wsub;
                XNOR_task12(w);
                BitCount_t12_3(meta.XNOROutput);

                weights_task12.read(wsub, (bit<32>)6);
                w = (bit<90>)wsub << 45;
                weights_task12.read(wsub, (bit<32>)7);
                w = w + (bit<90>)wsub;
                XNOR_task12(w);
                BitCount_t12_4(meta.XNOROutput);

                weights_task12.read(wsub, (bit<32>)8);
                w = (bit<90>)wsub << 45;
                weights_task12.read(wsub, (bit<32>)9);
                w = w + (bit<90>)wsub;
                XNOR_task12(w);
                BitCount_t12_5(meta.XNOROutput);

                weights_task12.read(wsub, (bit<32>)10);
                w = (bit<90>)wsub << 45;
                weights_task12.read(wsub, (bit<32>)11);
                w = w + (bit<90>)wsub;
                XNOR_task12(w);
                BitCount_t12_6(meta.XNOROutput);
                
                predict_task12();
            }
            
            // Task10 processing:
            {
                bit<45> wsub;
                bit<90> w;

                weights_task10.read(wsub, (bit<32>)0);
                w = (bit<90>)wsub << 45;
                weights_task10.read(wsub, (bit<32>)1);
                w = w + (bit<90>)wsub;
                XNOR_task10(w);
                BitCount_t10_1(meta.XNOROutput);
                
                weights_task10.read(wsub, (bit<32>)2);
                w = (bit<90>)wsub << 45;
                weights_task10.read(wsub, (bit<32>)3);
                w = w + (bit<90>)wsub;
                XNOR_task10(w);
                BitCount_t10_2(meta.XNOROutput);
                
                weights_task10.read(wsub, (bit<32>)4);
                w = (bit<90>)wsub << 45;
                weights_task10.read(wsub, (bit<32>)5);
                w = w + (bit<90>)wsub;
                XNOR_task10(w);
                BitCount_t10_3(meta.XNOROutput);
                
                predict_task10();
            }
        
            // Task2 processing:
            {
                bit<45> wsub;
                bit<90> w;

                weights_task2.read(wsub, (bit<32>)0);
                w = (bit<90>)wsub << 45;
                weights_task2.read(wsub, (bit<32>)1);
                w = w + (bit<90>)wsub;
                XNOR_task2(w);
                BitCount_t2_1(meta.XNOROutput);
                
                weights_task2.read(wsub, (bit<32>)2);
                w = (bit<90>)wsub << 45;
                weights_task2.read(wsub, (bit<32>)3);
                w = w + (bit<90>)wsub;
                XNOR_task2(w);
                BitCount_t2_2(meta.XNOROutput);
                
                weights_task2.read(wsub, (bit<32>)4);
                w = (bit<90>)wsub << 45;
                weights_task2.read(wsub, (bit<32>)5);
                w = w + (bit<90>)wsub;
                XNOR_task2(w);
                BitCount_t2_3(meta.XNOROutput);
                
                weights_task2.read(wsub, (bit<32>)6);
                w = (bit<90>)wsub << 45;
                weights_task2.read(wsub, (bit<32>)7);
                w = w + (bit<90>)wsub;
                XNOR_task2(w);
                BitCount_t2_4(meta.XNOROutput);
                
                weights_task2.read(wsub, (bit<32>)8);
                w = (bit<90>)wsub << 45;
                weights_task2.read(wsub, (bit<32>)9);
                w = w + (bit<90>)wsub;
                XNOR_task2(w);
                BitCount_t2_5(meta.XNOROutput);
                
                weights_task2.read(wsub, (bit<32>)10);
                w = (bit<90>)wsub << 45;
                weights_task2.read(wsub, (bit<32>)11);
                w = w + (bit<90>)wsub;
                XNOR_task2(w);
                BitCount_t2_6(meta.XNOROutput);
                
                weights_task2.read(wsub, (bit<32>)12);
                w = (bit<90>)wsub << 45;
                weights_task2.read(wsub, (bit<32>)13);
                w = w + (bit<90>)wsub;
                XNOR_task2(w);
                BitCount_t2_7(meta.XNOROutput);
                
                weights_task2.read(wsub, (bit<32>)14);
                w = (bit<90>)wsub << 45;
                weights_task2.read(wsub, (bit<32>)15);
                w = w + (bit<90>)wsub;
                XNOR_task2(w);
                BitCount_t2_8(meta.XNOROutput);
                
                predict_task2();
            }
            
            // Task13 processing:
            {
                bit<45> wsub;
                bit<90> w;

                weights_task13.read(wsub, (bit<32>)0);
                w = (bit<90>)wsub << 45;
                weights_task13.read(wsub, (bit<32>)1);
                w = w + (bit<90>)wsub;
                XNOR_task13(w);
                BitCount_t13_1(meta.XNOROutput);

                weights_task13.read(wsub, (bit<32>)2);
                w = (bit<90>)wsub << 45;
                weights_task13.read(wsub, (bit<32>)3);
                w = w + (bit<90>)wsub;
                XNOR_task13(w);
                BitCount_t13_2(meta.XNOROutput);

                weights_task13.read(wsub, (bit<32>)4);
                w = (bit<90>)wsub << 45;
                weights_task13.read(wsub, (bit<32>)5);
                w = w + (bit<90>)wsub;
                XNOR_task13(w);
                BitCount_t13_3(meta.XNOROutput);

                weights_task13.read(wsub, (bit<32>)6);
                w = (bit<90>)wsub << 45;
                weights_task13.read(wsub, (bit<32>)7);
                w = w + (bit<90>)wsub;
                XNOR_task13(w);
                BitCount_t13_4(meta.XNOROutput);
                
                predict_task13();
            }


            // NEW CHCEK task_id
            hdr.labeling.prediction2 = 0;
            hdr.labeling.prediction6 = 0;
            hdr.labeling.prediction10 = 0;
            hdr.labeling.prediction12 = 0;
            hdr.labeling.prediction13 = 0;

            if (hdr.labeling.task_id == 0) {
                hdr.labeling.prediction2 = meta.predict2;
                hdr.labeling.prediction6 = meta.predict6;
                hdr.labeling.prediction10 = meta.predict10;
                hdr.labeling.prediction12 = meta.predict12;
                hdr.labeling.prediction13 = meta.predict13;
            }
            else {
                if (hdr.labeling.task_id == 2)
                    hdr.labeling.prediction2 = meta.predict2;
                else if (hdr.labeling.task_id == 6)
                    hdr.labeling.prediction6 = meta.predict6;
                else if (hdr.labeling.task_id == 10)
                    hdr.labeling.prediction10 = meta.predict10;
                else if (hdr.labeling.task_id == 12)
                    hdr.labeling.prediction12 = meta.predict12;
                else if (hdr.labeling.task_id == 13)
                    hdr.labeling.prediction13 = meta.predict13;
            }
        }
        standard_metadata.egress_spec = 1; // need to change 
    }
}

/*************************************************************************
*********************** E G R E S S  *************************************
*************************************************************************/
control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata)
{
    apply {
        hdr.ethernet.dstAddr = (bit<48>) (standard_metadata.egress_global_timestamp - standard_metadata.ingress_global_timestamp);
     }
}

/*************************************************************************
************ CHECKSUM COMPUTATION ****************************************
*************************************************************************/
control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
   update_checksum(
       hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.tos,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
*********************** DEPARSER *****************************************
*************************************************************************/
control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        
        packet.emit(hdr.features); // need to change 
        packet.emit(hdr.labeling); // need to change 

        // packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

/*************************************************************************
*********************** SWITCH ********************************************
*************************************************************************/
V1Switch(
    MyParser(),
    MyVerifyChecksum(),
    MyIngress(),
    MyEgress(),
    MyComputeChecksum(),
    MyDeparser()
) main;

