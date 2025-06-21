Register<bit<32>, bit<12>>(1) task6;
Register<bit<32>, bit<12>>(1) task12;
Register<bit<32>, bit<12>>(1) task10;
Register<bit<32>, bit<12>>(1) task2;
Register<bit<32>, bit<12>>(1) task13;

RegisterAction <bit<32>, bit<12>, bit<32>>(task6) task6_prediction = {
    void apply(inout bit<32> value, out bit<32> read_value){
        if(value < (bit<32>)eg_md.meta.PopCountOut){
            value = (bit<32>)eg_md.meta.PopCountOut;
        }
        read_value = value;
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task12) task12_prediction = {
    void apply(inout bit<32> value, out bit<32> read_value){
        if(value < (bit<32>)eg_md.meta.PopCountOut){
            value = (bit<32>)eg_md.meta.PopCountOut;
        }
        read_value = value;
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task10) task10_prediction = {
    void apply(inout bit<32> value, out bit<32> read_value){
        if(value < (bit<32>)eg_md.meta.PopCountOut){
            value = (bit<32>)eg_md.meta.PopCountOut;
        }
        read_value = value; 
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task2) task2_prediction = {
    void apply(inout bit<32> value, out bit<32> read_value){
        if(value < (bit<32>)eg_md.meta.PopCountOut){
            value = (bit<32>)eg_md.meta.PopCountOut;
        }
        read_value = value;   
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task13) task13_prediction = {
    void apply(inout bit<32> value, out bit<32> read_value){
        if(value < (bit<32>)eg_md.meta.PopCountOut){
            value = (bit<32>)eg_md.meta.PopCountOut;
        }
        read_value = value;   
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task6) task6_reset = {
    void apply(inout bit<32> value){
        value = 0;
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task12) task12_reset = {
    void apply(inout bit<32> value){
        value = 0;
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task10) task10_reset = {
    void apply(inout bit<32> value){
        value = 0;
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task2) task2_reset = {
    void apply(inout bit<32> value){
        value = 0;
    }
};

RegisterAction <bit<32>, bit<12>, bit<32>>(task13) task13_reset = {
    void apply(inout bit<32> value){
        value = 0;
    }
};