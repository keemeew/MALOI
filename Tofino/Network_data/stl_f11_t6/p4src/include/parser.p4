/*************************************************************************
********************  Ingress Parser  ************************************
*************************************************************************/

parser SwitchIngressParser(packet_in packet,
                           out headers hdr,
                           out ingress_metadata_t ig_md,
                           out ingress_intrinsic_metadata_t ig_intr_md)
{
    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);

        transition parse_ethernet;
    }
    
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        ig_md.meta.setValid();
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_tcp;
            200: parse_martini;
            default: accept;
        }
    }

    state parse_martini{
        packet.extract(hdr.maloi);
        packet.extract(hdr.features1);
        packet.extract(hdr.features2);
        packet.extract(hdr.labeling);
        transition select(hdr.maloi.layer) {
            1: parse_intermediate_data1;
            2: parse_intermediate_data2;
            3: parse_final;
            default: parse_tcp;
        }
    }
    state parse_intermediate_data1 {
        packet.extract(hdr.intermediate_data1_1);
        packet.extract(hdr.intermediate_data1_2);
        transition parse_tcp;
    }
    state parse_intermediate_data2 {
        packet.extract(hdr.intermediate_data1_1);
        packet.extract(hdr.intermediate_data1_2);
        packet.extract(hdr.intermediate_data2_1);
        packet.extract(hdr.intermediate_data2_2);
        transition parse_tcp;
    }

    state parse_final{
        packet.extract(hdr.intermediate_data1_1);
        packet.extract(hdr.intermediate_data1_2);
        packet.extract(hdr.intermediate_data2_1);
        packet.extract(hdr.intermediate_data2_2);
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

}

/*************************************************************************
*******************  Ingress Deparser  ***********************************
*************************************************************************/

control SwitchIngressDeparser(packet_out packet, 
                             inout headers hdr,
                             in ingress_metadata_t ig_md,
                             in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
		apply {
            packet.emit(ig_md.meta);
            packet.emit(hdr);
		}
}

/*************************************************************************
********************* Egress Parser **************************************
*************************************************************************/

parser SwitchEgressParser(packet_in packet,
                          out headers hdr,
                          out egress_metadata_t eg_md, 
                          out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        packet.extract(eg_intr_md);
        packet.extract(eg_md.meta);
        
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17: parse_tcp;
            200: parse_martini;
            default: accept;
        }
    }

    state parse_martini{
        packet.extract(hdr.maloi);
        packet.extract(hdr.features1);
        packet.extract(hdr.features2);
        packet.extract(hdr.labeling);
        transition select(hdr.maloi.layer) {
            1: parse_intermediate_data1;
            2: parse_intermediate_data2;
            3: parse_final;
            default: parse_tcp;
        }
    }
    state parse_intermediate_data1 {
        packet.extract(hdr.intermediate_data1_1);
        packet.extract(hdr.intermediate_data1_2);
        transition parse_tcp;
    }
    state parse_intermediate_data2 {
        packet.extract(hdr.intermediate_data1_1);
        packet.extract(hdr.intermediate_data1_2);
        packet.extract(hdr.intermediate_data2_1);
        packet.extract(hdr.intermediate_data2_2);
        transition parse_tcp;
    }

    state parse_final{
        packet.extract(hdr.intermediate_data1_1);
        packet.extract(hdr.intermediate_data1_2);
        packet.extract(hdr.intermediate_data2_1);
        packet.extract(hdr.intermediate_data2_2);
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
}

/*************************************************************************
******************** Egress Deparser *************************************
*************************************************************************/

control SwitchEgressDeparser(packet_out packet, 
                             inout headers hdr,
                             in egress_metadata_t eg_md, 
                             in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
		apply {
            packet.emit(hdr.ethernet);
            packet.emit(hdr.ipv4);
            packet.emit(hdr.maloi);
            packet.emit(hdr.features1);
            packet.emit(hdr.features2);
            packet.emit(hdr.labeling);
            packet.emit(hdr.intermediate_data1_1);
            packet.emit(hdr.intermediate_data1_2);
            packet.emit(hdr.intermediate_data2_1);
            packet.emit(hdr.intermediate_data2_2);
            packet.emit(hdr.tcp);
		}
}