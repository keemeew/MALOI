Register<bit<32>, bit<12>>(1) task1;
Register<bit<32>, bit<12>>(1) task2;
Register<bit<32>, bit<12>>(1) task3;
Register<bit<32>, bit<12>>(1) task4;
Register<bit<32>, bit<12>>(1) task5;
Register<bit<32>, bit<12>>(1) task6;

RegisterAction <bit<32>, bit<12>, bit<32>>(task1) task1_prediction = {
    void apply(inout bit<32> value, out bit<32> read_value){
        if(value < (bit<32>)eg_md.meta.PopCountOut1){
            value = (bit<32>)eg_md.meta.PopCountOut1;
        }
        read_value = value;
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task2) task2_prediction = {
    void apply(inout bit<32> value, out bit<32> read_value){
        if(value < (bit<32>)eg_md.meta.PopCountOut1){
            value = (bit<32>)eg_md.meta.PopCountOut1;
        }
        read_value = value;
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task3) task3_prediction = {
    void apply(inout bit<32> value, out bit<32> read_value){
        if(value < (bit<32>)eg_md.meta.PopCountOut1){
            value = (bit<32>)eg_md.meta.PopCountOut1;
        }
        read_value = value; 
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task4) task4_prediction = {
    void apply(inout bit<32> value, out bit<32> read_value){
        if(value < (bit<32>)eg_md.meta.PopCountOut1){
            value = (bit<32>)eg_md.meta.PopCountOut1;
        }
        read_value = value;   
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task5) task5_prediction = {
    void apply(inout bit<32> value, out bit<32> read_value){
        if(value < (bit<32>)eg_md.meta.PopCountOut1){
            value = (bit<32>)eg_md.meta.PopCountOut1;
        }
        read_value = value;   
    }
};
RegisterAction <bit<32>, bit<12>, bit<32>>(task6) task6_prediction = {
    void apply(inout bit<32> value, out bit<32> read_value){
        if(value < (bit<32>)eg_md.meta.PopCountOut1){
            value = (bit<32>)eg_md.meta.PopCountOut1;
        }
        read_value = value;   
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task1) task1_reset = {
    void apply(inout bit<32> value){
        value = 0;
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task2) task2_reset = {
    void apply(inout bit<32> value){
        value = 0;
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task3) task3_reset = {
    void apply(inout bit<32> value){
        value = 0;
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task4) task4_reset = {
    void apply(inout bit<32> value){
        value = 0;
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task5) task5_reset = {
    void apply(inout bit<32> value){
        value = 0;
    }
};
RegisterAction <bit<32>, bit<12>, bit<32>>(task6) task6_reset = {
    void apply(inout bit<32> value){
        value = 0;
    }
};