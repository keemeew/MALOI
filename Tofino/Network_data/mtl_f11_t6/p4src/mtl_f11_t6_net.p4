/* -*- P4_16 -*- */
#include <core.p4>
#include <tna.p4>

#include "include/header.p4"
#include "include/parser.p4"

/*************************************************************************
************************  INGRESS  ****************************************
*************************************************************************/
control SwitchIngress(inout headers hdr, 
					  inout ingress_metadata_t ig_md, 
					  in ingress_intrinsic_metadata_t ig_intr_md, 
					  in ingress_intrinsic_metadata_from_parser_t ig_prsr_md, 
					  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md, 
		  			  inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    
    #include "include/ingress_action.p4"
    #include "include/ingress_table.p4"
    
    apply {
        if (hdr.maloi.isValid()) { 
            tb_preprocess1.apply(); 
            tb_preprocess2.apply(); 
            
            tb_XNOR_1.apply();
            tb_XNOR_2.apply();
            tb_XNOR_3.apply();
            tb_XNOR_4.apply();
            tb_XNOR_5.apply();
            tb_XNOR_6.apply();
            tb_XNOR_7.apply();
            tb_XNOR_8.apply();
            tb_XNOR_9.apply();
            tb_XNOR_10.apply();
            tb_XNOR_11.apply();

            tb_popcount1.apply();
            tb_popcount2.apply();
            tb_popcount3.apply();
            tb_popcount4.apply();
            tb_popcount5.apply();
            tb_popcount6.apply();
            tb_popcount7.apply();
            tb_popcount8.apply();
            tb_popcount9.apply();
            tb_popcount10.apply();
            tb_popcount11.apply();

            total_popcount1();
            total_popcount2();
            total_popcount3();
            total_popcount4();
            total_popcount5();
            total_popcount6();
            total_popcount7();
            total_popcount8();
            total_popcount9();
            total_popcount10();

            tb_set_spaces.apply();
        }
        tb_forward.apply();
    }
}

/*************************************************************************
*********************** E G R E S S  *************************************
*************************************************************************/
control SwitchEgress(inout headers hdr, 
					 inout egress_metadata_t eg_md, 
 					 in egress_intrinsic_metadata_t eg_intr_md, 
					 in egress_intrinsic_metadata_from_parser_t eg_prsr_md, 
					 inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md, 
					 inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    
    #include "include/egress_register.p4"
    #include "include/egress_action.p4"
    #include "include/egress_table.p4"
    
    apply {
        tb_activate_zero.apply();
        if (eg_md.meta.PopCountOut1 > 84){
            tb_activate_one.apply();
        }

        tb_reset_registers1.apply();
        tb_reset_registers2.apply();
        tb_reset_registers3.apply();
        tb_reset_registers4.apply();
        tb_reset_registers5.apply();
        tb_reset_registers6.apply();
        
        tb_predict_task1.apply();
        tb_predict_task2.apply();
        tb_predict_task3.apply();
        tb_predict_task4.apply();
        tb_predict_task5.apply();
        tb_predict_task6.apply();
        
        if (eg_md.meta.test == eg_md.meta.PopCountOut1){
            tb_real_predict_task1.apply();
            tb_real_predict_task2.apply();
            tb_real_predict_task3.apply();
            tb_real_predict_task4.apply();
            tb_real_predict_task5.apply();
            tb_real_predict_task6.apply();
        }
        hdr.ethernet.dstAddr = eg_prsr_md.global_tstamp;
        tb_invalid.apply();
     }     
}

/*************************************************************************
*********************** SWITCH ********************************************
*************************************************************************/

Pipeline(SwitchIngressParser(),
	SwitchIngress(),
	SwitchIngressDeparser(),
	SwitchEgressParser(),
	SwitchEgress(),
	SwitchEgressDeparser()
) pipe;

Switch(pipe) main;