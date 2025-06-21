table tb_preprocess{
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        preprocessing; 
        NoAction;
    }
    default_action = NoAction;
    size = 209;
}

table tb_XNOR_1{
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        XNOR_shared_1_1; 
        XNOR_shared_2_1; 
        XNOR_task_specific_1;
        NoAction;
    }
    default_action = NoAction;
    size = 209;
}

table tb_XNOR_2{
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        XNOR_shared_1_2;
        XNOR_shared_2_2;
        XNOR_task_specific_2;
        NoAction;
    }
    default_action = NoAction;
    size = 209;
}

table tb_XNOR_3{
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        XNOR_shared_1_3;
        XNOR_shared_2_3;
        XNOR_task_specific_3;
        NoAction;
    }
    default_action = NoAction;
    size = 209;
}

table tb_XNOR_4{
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        XNOR_shared_1_4;
        XNOR_shared_2_4;
        XNOR_task_specific_4;
        NoAction;
    }
    default_action = NoAction;
    size = 209;
}

table tb_XNOR_5{
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        XNOR_shared_1_5;
        XNOR_shared_2_5;
        XNOR_task_specific_5;
        NoAction;
    }
    default_action = NoAction;
    size = 209;
}

table tb_XNOR_6{
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        XNOR_shared_1_6;
        XNOR_shared_2_6;
        XNOR_task_specific_6;
        NoAction;
    }
    default_action = NoAction;
    size = 209;
}

table tb_forward {
	key = {
        hdr.maloi.cnt: exact;
	}
	actions = {
		set_egress_port;
        do_recirculation1;
        do_recirculation2;
		NoAction();
	}
	default_action = NoAction();
    size = 209;
}

table tb_popcount1 {
    key = {
        ig_md.meta.XNOROutput_1: exact;
    }
    actions = {
        popcount1();
        NoAction;
    }
    default_action = NoAction;
    size = 1024;
}

table tb_popcount2 {
    key = {
        ig_md.meta.XNOROutput_2: exact;
    }
    actions = {
        popcount2();
        NoAction;
    }
    default_action = NoAction;
    size = 65536;
}

table tb_popcount3 {
    key = {
        ig_md.meta.XNOROutput_3: exact;
    }
    actions = {
        popcount3();
        NoAction;
    }
    default_action = NoAction;
    size = 65536;
}

table tb_popcount4 {
    key = {
        ig_md.meta.XNOROutput_4: exact;
    }
    actions = {
        popcount4();
        NoAction;
    }
    default_action = NoAction;
    size = 65536;
}

table tb_popcount5 {
    key = {
        ig_md.meta.XNOROutput_5: exact;
    }
    actions = {
        popcount5();
        NoAction;
    }
    default_action = NoAction;
    size = 65536;
}

table tb_popcount6 {
    key = {
        ig_md.meta.XNOROutput_6: exact;
    }
    actions = {
        popcount6();
        NoAction;
    }
    default_action = NoAction;
    size = 65536;
}

table tb_set_spaces{
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        set_inteermediate_data_1_tst; 
        set_inteermediate_data_2;
        NoAction;
    }
    default_action = NoAction;
    size = 2;
}