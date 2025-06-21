action preprocessing1(bit<9> weight_1, bit<16> weight_2, bit<16> weight_3,
                     bit<16> weight_4, bit<16> weight_5, bit<16> weight_6) {
    ig_md.meta.weight_1 = weight_1;
    ig_md.meta.weight_2 = weight_2;
    ig_md.meta.weight_3 = weight_3;
    ig_md.meta.weight_4 = weight_4;
    ig_md.meta.weight_5 = weight_5;
    ig_md.meta.weight_6 = weight_6;
}

action preprocessing2(bit<16> weight_7, bit<16> weight_8, bit<16> weight_9,
                     bit<16> weight_10, bit<16> weight_11) {
    ig_md.meta.weight_7 = weight_7;
    ig_md.meta.weight_8 = weight_8;
    ig_md.meta.weight_9 = weight_9;
    ig_md.meta.weight_10 = weight_10;
    ig_md.meta.weight_11 = weight_11;
}

action XNOR_shared_2_1() {
    ig_md.meta.XNOROutput_1 = ~(ig_md.meta.weight_1 ^ hdr.intermediate_data1_1.intermediate_data_1[8:0]);
}
action XNOR_task_specific_1() {
    ig_md.meta.XNOROutput_1 = ~(ig_md.meta.weight_1 ^ hdr.intermediate_data2_1.intermediate_data_1[8:0]);
}

#define POP_COUNT(i)\
action popcount##i##(bit<8> x){\
    ig_md.meta.x_##i## = x;\
}\

#define XNOR_SHARED_1(i,j)\
action XNOR_shared_1_##i##(){\
    ig_md.meta.XNOROutput_##i## = ~(ig_md.meta.weight_##i## ^ hdr.features##j##.features_##i##);\
}\

#define XNOR_SHARED_2(i,j)\
action XNOR_shared_2_##i##(){\
    ig_md.meta.XNOROutput_##i## = ~(ig_md.meta.weight_##i## ^ hdr.intermediate_data1_##j##.intermediate_data_##i##);\
}\

#define XNOR_TASK(i,j)\
action XNOR_task_specific_##i##(){\
    ig_md.meta.XNOROutput_##i## = ~(ig_md.meta.weight_##i## ^ hdr.intermediate_data2_##j##.intermediate_data_##i##);\
}\

POP_COUNT(1)
POP_COUNT(2)
POP_COUNT(3)
POP_COUNT(4)
POP_COUNT(5)
POP_COUNT(6)
POP_COUNT(7)
POP_COUNT(8)
POP_COUNT(9)
POP_COUNT(10)
POP_COUNT(11)

XNOR_SHARED_1(1,1)
XNOR_SHARED_1(2,1)
XNOR_SHARED_1(3,1)
XNOR_SHARED_1(4,1)
XNOR_SHARED_1(5,1)
XNOR_SHARED_1(6,1)
XNOR_SHARED_1(7,2)
XNOR_SHARED_1(8,2)
XNOR_SHARED_1(9,2)
XNOR_SHARED_1(10,2)
XNOR_SHARED_1(11,2)

XNOR_SHARED_2(2,1)
XNOR_SHARED_2(3,1)
XNOR_SHARED_2(4,1)
XNOR_SHARED_2(5,1)
XNOR_SHARED_2(6,1)
XNOR_SHARED_2(7,2)
XNOR_SHARED_2(8,2)
XNOR_SHARED_2(9,2)
XNOR_SHARED_2(10,2)
XNOR_SHARED_2(11,2)

XNOR_TASK(2,1)
XNOR_TASK(3,1)
XNOR_TASK(4,1)
XNOR_TASK(5,1)
XNOR_TASK(6,1)
XNOR_TASK(7,2)
XNOR_TASK(8,2)
XNOR_TASK(9,2)
XNOR_TASK(10,2)
XNOR_TASK(11,2)

action set_egress_port(bit<9> egress_spec) {
    ig_tm_md.ucast_egress_port = egress_spec;
    hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    hdr.maloi.cnt = hdr.maloi.cnt + 1;
    hdr.maloi.layer = 3;
}

action do_recirculation1() {
    ig_tm_md.ucast_egress_port = 68;
    hdr.maloi.cnt = hdr.maloi.cnt + 1;
    
}
action do_recirculation2() {
    ig_tm_md.ucast_egress_port = 68;
    hdr.maloi.cnt = hdr.maloi.cnt + 1;
}
action set_inteermediate_data_1_tst(){ 
    hdr.maloi.layer = 1;
    hdr.intermediate_data1_1.setValid();
    hdr.intermediate_data1_2.setValid();
    hdr.ethernet.srcAddr = ig_intr_md.ingress_mac_tstamp;
}
action set_inteermediate_data_1(){ 
    hdr.maloi.layer = 1;
    hdr.intermediate_data1_1.setValid();
    hdr.intermediate_data1_2.setValid();
}
action set_inteermediate_data_2(){
    hdr.intermediate_data2_1.setValid();
    hdr.intermediate_data2_2.setValid();
    hdr.maloi.layer = 2;
}

action total_popcount1(){
    ig_md.meta.PopCountOut1 = ig_md.meta.x_1 + ig_md.meta.x_2;
}
action total_popcount2(){
    ig_md.meta.PopCountOut2 = ig_md.meta.x_3 + ig_md.meta.x_4;
}
action total_popcount3(){
    ig_md.meta.PopCountOut3 = ig_md.meta.x_5 + ig_md.meta.x_6;
}
action total_popcount4(){
    ig_md.meta.PopCountOut4 = ig_md.meta.x_7 + ig_md.meta.x_8;
}
action total_popcount5(){
    ig_md.meta.PopCountOut5 = ig_md.meta.x_9 + ig_md.meta.x_10;
}
action total_popcount6(){
    ig_md.meta.PopCountOut1 = ig_md.meta.PopCountOut1 + ig_md.meta.x_11;
}
action total_popcount7(){
    ig_md.meta.PopCountOut2 = ig_md.meta.PopCountOut2 + ig_md.meta.PopCountOut3;
}
action total_popcount8(){
    ig_md.meta.PopCountOut4 = ig_md.meta.PopCountOut4 + ig_md.meta.PopCountOut5;
}
action total_popcount9(){
    ig_md.meta.PopCountOut2 = ig_md.meta.PopCountOut2 + ig_md.meta.PopCountOut4;
}
action total_popcount10(){
    ig_md.meta.PopCountOut1 = ig_md.meta.PopCountOut1 + ig_md.meta.PopCountOut2;
}


