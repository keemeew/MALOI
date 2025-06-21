action preprocessing(bit<10> weight_1, bit<16> weight_2, bit<16> weight_3,
                     bit<16> weight_4, bit<16> weight_5, bit<16> weight_6) {
    ig_md.meta.weight_1 = weight_1;
    ig_md.meta.weight_2 = weight_2;
    ig_md.meta.weight_3 = weight_3;
    ig_md.meta.weight_4 = weight_4;
    ig_md.meta.weight_5 = weight_5;
    ig_md.meta.weight_6 = weight_6;
}

action XNOR_shared_1_1() {
    ig_md.meta.XNOROutput_1 = ~(ig_md.meta.weight_1 ^ hdr.features.features_1);
}

action XNOR_shared_1_2() {
    ig_md.meta.XNOROutput_2 = ~(ig_md.meta.weight_2 ^ hdr.features.features_2);
}

action XNOR_shared_1_3() {
    ig_md.meta.XNOROutput_3 = ~(ig_md.meta.weight_3 ^ hdr.features.features_3);
}

action XNOR_shared_1_4() {
    ig_md.meta.XNOROutput_4 = ~(ig_md.meta.weight_4 ^ hdr.features.features_4);
}

action XNOR_shared_1_5() {
    ig_md.meta.XNOROutput_5 = ~(ig_md.meta.weight_5 ^ hdr.features.features_5);
}

action XNOR_shared_1_6() {
    ig_md.meta.XNOROutput_6 = ~(ig_md.meta.weight_6 ^ hdr.features.features_6);
}

action XNOR_shared_2_1() {
    ig_md.meta.XNOROutput_1 = ~(ig_md.meta.weight_1 ^ hdr.intermediate_data1.intermediate_data_1[9:0]);
}

action XNOR_shared_2_2() {
    ig_md.meta.XNOROutput_2 = ~(ig_md.meta.weight_2 ^ hdr.intermediate_data1.intermediate_data_2);
}

action XNOR_shared_2_3() {
    ig_md.meta.XNOROutput_3 = ~(ig_md.meta.weight_3 ^ hdr.intermediate_data1.intermediate_data_3);
}

action XNOR_shared_2_4() {
    ig_md.meta.XNOROutput_4 = ~(ig_md.meta.weight_4 ^ hdr.intermediate_data1.intermediate_data_4);
}

action XNOR_shared_2_5() {
    ig_md.meta.XNOROutput_5 = ~(ig_md.meta.weight_5 ^ hdr.intermediate_data1.intermediate_data_5);
}

action XNOR_shared_2_6() {
    ig_md.meta.XNOROutput_6 = ~(ig_md.meta.weight_6 ^ hdr.intermediate_data1.intermediate_data_6);
}

action XNOR_task_specific_1() {
    ig_md.meta.XNOROutput_1 = ~(ig_md.meta.weight_1 ^ hdr.intermediate_data2.intermediate_data_1[9:0]);
}

action XNOR_task_specific_2() {
    ig_md.meta.XNOROutput_2 = ~(ig_md.meta.weight_2 ^ hdr.intermediate_data2.intermediate_data_2);
}

action XNOR_task_specific_3() {
    ig_md.meta.XNOROutput_3 = ~(ig_md.meta.weight_3 ^ hdr.intermediate_data2.intermediate_data_3);
}

action XNOR_task_specific_4() {
    ig_md.meta.XNOROutput_4 = ~(ig_md.meta.weight_4 ^ hdr.intermediate_data2.intermediate_data_4);
}

action XNOR_task_specific_5() {
    ig_md.meta.XNOROutput_5 = ~(ig_md.meta.weight_5 ^ hdr.intermediate_data2.intermediate_data_5);
}

action XNOR_task_specific_6() {
    ig_md.meta.XNOROutput_6 = ~(ig_md.meta.weight_6 ^ hdr.intermediate_data2.intermediate_data_6);
}

action popcount1(bit<8> x){
    ig_md.meta.x_1 = x;
}
action popcount2(bit<8> x){
    ig_md.meta.x_2 = x;
}
action popcount3(bit<8> x){
    ig_md.meta.x_3 = x;
}
action popcount4(bit<8> x){
    ig_md.meta.x_4 = x;
}
action popcount5(bit<8> x){
    ig_md.meta.x_5 = x;
}
action popcount6(bit<8> x){
    ig_md.meta.x_6 = x;
}

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
    hdr.intermediate_data1.setValid();
    hdr.ethernet.srcAddr = ig_intr_md.ingress_mac_tstamp;
}
action set_inteermediate_data_2(){
    hdr.intermediate_data2.setValid();
    hdr.maloi.layer = 2;
}

action total_popcount1(){
    ig_md.meta.PopCountOut = ig_md.meta.x_1 + ig_md.meta.x_2;
}
action total_popcount2(){
    ig_md.meta.PopCountOut = ig_md.meta.PopCountOut + ig_md.meta.x_3;
}
action total_popcount3(){
    ig_md.meta.PopCountOut = ig_md.meta.PopCountOut + ig_md.meta.x_4;
}
action total_popcount4(){
    ig_md.meta.PopCountOut = ig_md.meta.PopCountOut + ig_md.meta.x_5;
}
action total_popcount5(){
    ig_md.meta.PopCountOut = ig_md.meta.PopCountOut + ig_md.meta.x_6;
}