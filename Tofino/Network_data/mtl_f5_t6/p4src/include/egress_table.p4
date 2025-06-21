table tb_activate_one {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        activate1_1_one;
        activate1_2_one;
        activate1_3_one;
        activate1_4_one;
        activate1_5_one;
        activate1_6_one;
        activate1_7_one;
        activate2_1_one; 
        activate2_2_one;
        activate2_3_one; 
        activate2_4_one;
        activate2_5_one; 
        activate2_6_one;
        activate2_7_one;
        NoAction;
    }
    default_action = NoAction;
    size = 224;
}

table tb_activate_zero {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        activate1_1_zero; 
        activate1_2_zero; 
        activate1_3_zero; 
        activate1_4_zero; 
        activate1_5_zero; 
        activate1_6_zero; 
        activate1_7_zero; 
        activate2_1_zero; 
        activate2_2_zero;
        activate2_3_zero; 
        activate2_4_zero;
        activate2_5_zero; 
        activate2_6_zero;
        activate2_7_zero;
        NoAction;
    }
    default_action = NoAction;
    size = 224;
}

table tb_reset_registers1 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        reset_register_task1;
        NoAction;
    }
    default_action = NoAction;
    size = 1;
    const entries = {
        1: reset_register_task1;
    }
}

table tb_reset_registers2 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        reset_register_task2;
        NoAction;
    }
    default_action = NoAction;
    size = 1;
    const entries = {
        1: reset_register_task2;
    }
}

table tb_reset_registers3 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        reset_register_task3;
        NoAction;
    }
    default_action = NoAction;
    size = 1;
    const entries = {
        1: reset_register_task3;
    }
}

table tb_reset_registers4 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        reset_register_task4;
        NoAction;
    }
    default_action = NoAction;
    size = 1;
    const entries = {
        1: reset_register_task4;
    }
}

table tb_reset_registers5 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        reset_register_task5;
        NoAction;
    }
    default_action = NoAction;
    size = 1;
    const entries = {
        1: reset_register_task5;
    }
}
table tb_reset_registers6 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        reset_register_task6;
        NoAction;
    }
    default_action = NoAction;
    size = 1;
    const entries = {
        1: reset_register_task6;
    }
}

table tb_predict_task1 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        task1_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 2;
}

table tb_predict_task2 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        task2_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 2;
}

table tb_predict_task3 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        task3_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 2;
}

table tb_predict_task4 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        task4_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 2;
}

table tb_predict_task5 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        task5_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 2;
}
table tb_predict_task6 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        task6_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 3;
}

table tb_real_predict_task1 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        real_task1_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 2;
}
table tb_real_predict_task2 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        real_task2_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 2;
}
table tb_real_predict_task3 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        real_task3_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 2;
}
table tb_real_predict_task4 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        real_task4_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 2;
}
table tb_real_predict_task5 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        real_task5_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 2;
}   
table tb_real_predict_task6 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        real_task6_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 3;
}   

table tb_invalid{
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        invalid_header;
        NoAction;
    }
    default_action = NoAction;
    size = 1;
}