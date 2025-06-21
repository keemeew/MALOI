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
        activate2_1_one;
        activate2_2_one;
        activate2_3_one;
        activate2_4_one;
        activate2_5_one;
        NoAction;
    }
    default_action = NoAction;
    size = 132;
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
        activate2_1_zero;
        activate2_2_zero;
        activate2_3_zero;
        activate2_4_zero;
        activate2_5_zero;
        NoAction;
    }
    default_action = NoAction;
    size = 132;
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

table tb_reset_registers12 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        reset_register_task12;
        NoAction;
    }
    default_action = NoAction;
    size = 1;
    const entries = {
        1: reset_register_task12;
    }
}

table tb_reset_registers10 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        reset_register_task10;
        NoAction;
    }
    default_action = NoAction;
    size = 1;
    const entries = {
        1: reset_register_task10;
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

table tb_reset_registers13 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        reset_register_task13;
        NoAction;
    }
    default_action = NoAction;
    size = 1;
    const entries = {
        1: reset_register_task13;
    }
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
    size = 8;
}

table tb_predict_task12 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        task12_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 6;
}

table tb_predict_task10 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        task10_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 3;
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
    size = 8;
}

table tb_predict_task13 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        task13_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 4;
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
    size = 8;
}

table tb_real_predict_task12 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        real_task12_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 6;
}

table tb_real_predict_task10 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        real_task10_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 3;
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
    size = 8;
}

table tb_real_predict_task13 {
    key = {
        hdr.maloi.cnt: exact;
    }
    actions = {
        real_task13_predict;
        NoAction;
    }
    default_action = NoAction;
    size = 4;
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