// Initial base code taken from: github.com/hyojoonkim/Meta4

#include <core.p4>
#include <tna.p4>

#define NUM_IPV4_DST_IP 100
#define TABLE_SIZE 65536
#define TABLE_SIZE2 110000
#define TIMEOUT 100000000 // 100 seconds
#define LABEL_LENGTH_C 56
#define HASH_LENGTH_C 16
#define RECIRCULATE_ID_C 220
#define RND_DOMAIN_THRESH 16598
#define NXDomain 3
#define DONE_RECIRC 7
#define RECIRC_LABEL 1
#define RECIRC_CHARS 10
#define NUM_STATIC_BIGRAMS 1444 // from top-1m domains

typedef bit<48> MacAddress;
typedef bit<32> IPv4Address;
typedef bit<128> IPv6Address;
typedef bit<32> known_domain_id;
typedef bit<32> BigramVal;

header ethernet_h {
    MacAddress dst;
    MacAddress src;
    bit<16> etherType; 
}
header ipv4_h {
    bit<4> version;
    bit<4> ihl;
    bit<8> tos;
    bit<16> len;
    bit<16> id;
    bit<3> flags;
    bit<13> frag;
    bit<8> ttl;
    bit<8> proto;
    bit<16> chksum;
    IPv4Address src;
    IPv4Address dst; 
}
header tcp_h {
    bit<16> sport;
    bit<16> dport;
    bit<32> seq;
    bit<32> ack;
    bit<4> dataofs;
    bit<4> reserved;
    bit<8> flags;
    bit<16> window;
    bit<16> chksum;
    bit<16> urgptr; 
}
header udp_h {
    bit<16> sport;
    bit<16> dport;
    bit<16> len;
    bit<16> chksum; 
}
header dns_h {
    bit<16> id;
    bit<1> is_response;
    bit<4> opcode;
    bit<1> auth_answer;
    bit<1> trunc;
    bit<1> recur_desired;
    bit<1> recur_avail;
    bit<1> reserved;
    bit<1> authentic_data;
    bit<1> checking_disabled;
    bit<4> resp_code;
    bit<16> q_count;
    bit<16> answer_count;
    bit<16> auth_rec;
    bit<16> addn_rec;
}
header dns_q_label {
    bit<8> label;
}
header dns_q_part_1 {
    bit<8> part;
}
header dns_q_part_2 {
    bit<16> part;
}
header dns_q_part_4 {
    bit<32> part;
}
header dns_q_part_8 {
    bit<64> part;
}
struct dns_qtype_class {
    bit<16> type;
    bit<16> class;
}
header dns_query_tc{
    dns_qtype_class tc_query;
}
header dns_a {
    bit<16> qname_pointer;
    dns_qtype_class tc_ans;
    bit<32> ttl;
    bit<8> rd_length_1;
    bit<8> rd_length_2;
}
header dns_a_ip {
    bit<32> rdata; //IPV4 is always 32 bit.
}
header resubmit_data_t {
    bit<1> stage_indicator; // 0 or 1 for stage 1 or 2 in the sip/cip table
    bit<7> _padding0;
    bit<8> _padding1;
    bit<16> _padding2;
    bit<32> _padding3;
}
header recirculate_h {
    bit<8> recirculate_id;
    bit<8> recirculate_bit;
    bit<8> recirculate_counter;
    bit<16> hash_concat_hashes;
    bit<16> hash_last_label;
    bit<16> hash_prelast_label;
    
    // structural domain name features 
    bit<8> domain_name_length;
    bit<8> num_subdomains;
    bit<8> is_valid_tld;
    bit<8> has_single_subd;
    bit<8> num_underscores;
    

    BigramVal ans;
    bit<8> i;
    bit<16> rnd_nxds;
    bit<16> all_nxds;
    BigramVal dns_reqs;
    BigramVal ip_reqs;
    bit<32> i_arrival;
    bit<32> src_ip;
}

header resubmit_data_skimmed_t {
    bit<1> stage_indicator; // 0 or 1 for stage 1 or 2 in the sip/cip table
    // @A added
    bit<7> _padding0;
}

// List of all recognized headers
struct Parsed_packet { 
    recirculate_h recirculate;
    ethernet_h ethernet;
    ipv4_h ipv4;
    udp_h udp;
    dns_h dns_header;

    dns_q_label label1;
    dns_q_part_1 q1_part1;
    dns_q_part_2 q1_part2;
    dns_q_part_4 q1_part4;

    dns_q_label label2;

    dns_query_tc query_tc;

    dns_a dns_answer;
    dns_a_ip dns_ip;

}

// user defined metadata: can be used to share information between
// TopParser, TopPipe, and TopDeparser 
struct ig_metadata_t {
    recirculate_h recirculate_metadata; 
    bit<1> is_response;
    bit<1> do_dns;
    bit<1> recur_desired;
    bit<1> response_set;
	bit<1> is_dns;
	bit<1> is_ip;
    bit<1> is_recirc_division;
    bit<1> contains_single_char_subdomain;
    bit<1>  unused1;

    bit<3> last_label; // Value is 1,2,3,4,5 or 0 corresponding to which dns_q_label is the last label (of value 0). If this value is 0, there is an error.
    bit<1> unused2;
    bit<32> domain_id_dns;
    bit<32> domain_id;
    bit<32> index_1_dns;
    bit<32> index_2_dns;
    bit<1> parsed_dns_query;
    bit<2> min_table;

    bit<1> parsed_answer;
}
struct IP_domain_hash_t {
    bit<32> domain_hash;
    bit<32> ip;
}
struct timestamp_t { 
    bit<32> timestamp;
}
struct eg_metadata_t {
    recirculate_h recirculate_metadata;
    bit<4> is_ip;
    bit<4> is_dns; 
    bit<16> index;
    bit<32> iarrival;
}

struct digest_t {
    bit<32> ip_addr;
    bit<16> nxds;
    bit<16> rnd_nxds;
    bit<32> ip_reqs;
    bit<32> dns_reqs;
    bit<8> domain_name_length;
    bit<8> num_subdomains;
    bit<8> is_valid_tld;
    bit<8> has_single_subd;
    bit<8> num_underscores;
}

parser TofinoIngressParser(
        packet_in pkt,
        inout ig_metadata_t ig_md,
        out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        pkt.extract(ig_intr_md);
        pkt.advance(64);
        transition accept;
    }

    
}

// parsers
parser SwitchIngressParser(packet_in pkt,
           out Parsed_packet p,
           out ig_metadata_t ig_md,
           out ingress_intrinsic_metadata_t ig_intr_md) {

    TofinoIngressParser() tofino_parser;

    ParserCounter() counter;

    state start {
        tofino_parser.apply(pkt, ig_md, ig_intr_md);
        transition check_recirculate;
    }
    state check_recirculate {
        // parse recirculated packet here.1
        bit<8> recirculate_id = pkt.lookahead<bit<8>>();
        transition select(recirculate_id){
            // If the first 8 bits of MAC destination address is 220, then it's a recirculated packet
            RECIRCULATE_ID_C: parse_recirculate; 
            _: parse_ethernet;
        }
    }
    state parse_recirculate {
        pkt.extract(p.recirculate);
        transition select(p.recirculate.recirculate_bit){
            DONE_RECIRC: accept;
            20:  accept;
            21: accept;
            22: accept;
            default: parse_ethernet;
        }
    }
    state parse_ethernet {
        pkt.extract(p.ethernet);
        ig_md.do_dns = 0;
        ig_md.recur_desired = 0;
        ig_md.response_set = 0;
		ig_md.is_dns = 0;
		ig_md.is_ip = 0;
        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }
	state parse_ip {
        pkt.extract(p.ipv4);
		ig_md.is_ip = 1;
        ig_md.is_dns = 0;
		transition select(p.ipv4.proto) {
			17: parse_udp;
			default: accept;
		}
	}
    state parse_udp {
        pkt.extract(p.udp);
		transition select(p.udp.dport) {
			53: parse_dns_header;
			default: parse_udp_2;
		}
	}
	state parse_udp_2 {
		transition select(p.udp.sport) {
			53: parse_dns_header;
			default: accept;
        }
    }
	state parse_dns_header {
        pkt.extract(p.dns_header);
		ig_md.is_dns = 1;
        ig_md.last_label = 0;
		transition select(p.dns_header.is_response) {
            0: is_request_state;
            1: is_reponse_state;
			default: accept;
		}
	}
    state is_request_state {
        ig_md.is_response = 0;
        transition accept;
    }
    state is_reponse_state {
        ig_md.is_response = 1;
        transition parse_dns_query1;
    }
    // Parsel DNS Query Label 1
    state parse_dns_query1 {
        pkt.extract(p.label1);
        ig_md.last_label = 1;
        ig_md.recirculate_metadata.recirculate_bit = 0;

        transition select(p.label1.label) {
            0: parse_query_tc;
            1: parse_dns_q1_len1;
            2: parse_dns_q1_len2;
            3: parse_dns_q1_len3;
            4: parse_dns_q1_len4;
            5: parse_dns_q1_len5;
            6: parse_dns_q1_len6;
            7: parse_dns_q1_len7;
            0x8 &&& 0x8: parse_dns_q1_gr7; // from 8 to 15
            0x10 &&& 0x10: parse_dns_q1_gr7; // from 16 to 31
            0x20 &&& 0x20: parse_dns_q1_gr7; // from 32 to 63
            default: accept;
        }
    }


    state parse_dns_q1_len1 {
        pkt.extract(p.q1_part1);
        transition select (p.recirculate.recirculate_bit) {
            // if recirculate header is valid and recirculate_bit == 10 --> label_len > 1
            RECIRC_CHARS: parse_dns_query2; 
            // 1-if recirculate header is valid and recirculate_bit anything other than 10
            default: set_single_char_metadata; 
        }
    }
    state set_single_char_metadata {
        ig_md.contains_single_char_subdomain = 1;
        transition parse_dns_query2;
    }
    state parse_dns_q1_len2 {
        pkt.extract(p.q1_part2);
        transition parse_dns_query2;
    }
    state parse_dns_q1_len3 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        transition parse_dns_query2;
    }
    state parse_dns_q1_len4 {
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }
    state parse_dns_q1_len5 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }
    state parse_dns_q1_len6 {
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }
    state parse_dns_q1_len7 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        transition parse_dns_query2;
    }
    state parse_dns_q1_gr7 {
        pkt.extract(p.q1_part1);
        pkt.extract(p.q1_part2);
        pkt.extract(p.q1_part4);
        // do not continue to query 2, set recirculate_bit and accept 
        ig_md.recirculate_metadata.recirculate_bit = RECIRC_CHARS;
        transition accept;
    }
    // Parsel DNS Query Additional label
    state parse_dns_query2 {
        pkt.extract(p.label2);
        ig_md.last_label = 5;

        transition select(p.label2.label) {
            0: parse_query_tc;
            default: accept;
        }
    }
    state parse_query_tc {
        pkt.extract(p.query_tc);
        ig_md.parsed_answer = 0;
        ig_md.parsed_dns_query = 1;
        transition parse_dns_answer;
    }
    state parse_dns_answer {
        pkt.extract(p.dns_answer);
        transition select(p.dns_answer.tc_ans.type) {
            1: parse_a_ip;
            5: parse_cname_arbiter;
            default: accept;
        }
    }

    state parse_cname {
        counter.set(p.dns_answer.rd_length_2);
        transition select(counter.is_zero()) {
            true: parse_dns_answer;
            false: parse_cname_byte;
        }
    }
    // Parse normally up to CNAME length: 50 bytes
    // For 51 or more, parse with parse_cname_over50
    state parse_cname_arbiter {
        transition select(p.dns_answer.rd_length_2) {
            1: parse_cname;
            2: parse_cname; 
            3: parse_cname;
            4: parse_cname;
            5: parse_cname;
            6: parse_cname;
            7: parse_cname;
            8: parse_cname;
            9: parse_cname;
            10: parse_cname;
            11: parse_cname;
            12: parse_cname;
            13: parse_cname;
            14: parse_cname;
            15: parse_cname;
            16: parse_cname;
            17: parse_cname;
            18: parse_cname;
            19: parse_cname;
            20: parse_cname;
            21: parse_cname;
            22: parse_cname;
            23: parse_cname;
            24: parse_cname;
            25: parse_cname;
            26: parse_cname;
            27: parse_cname;
            28: parse_cname;
            29: parse_cname;
            30: parse_cname;
            31: parse_cname;
            32: parse_cname;
            33: parse_cname;
            34: parse_cname;
            35: parse_cname;
            36: parse_cname;
            37: parse_cname;
            38: parse_cname;
            39: parse_cname;
            40: parse_cname;
            41: parse_cname;
            42: parse_cname;
            43: parse_cname;
            44: parse_cname;
            45: parse_cname;
            46: parse_cname;
            47: parse_cname;
            48: parse_cname;
            49: parse_cname;
            50: parse_cname;
            default: parse_cname_over50;
        }
    }

    // A state just for hopping to parse_cname_cut50
    // Might not even need, but whatever. 
    state parse_cname_over50 {
        counter.set(p.dns_answer.rd_length_2);

        transition parse_cname_cut50;
    }

    // Advance 50 bytes (400 bits) and decrement 50 from ParserCounter.
    // After that, perform same parsing procedure as parse_cname
    state parse_cname_cut50 {
        pkt.advance(400);
        counter.decrement(8w50);

        transition select(counter.is_zero()) {
            true: parse_dns_answer;
            false: parse_cname_byte;
        }
    }

    state parse_cname_byte{
        pkt.advance(8);
        counter.decrement(8w1);
        transition select(counter.is_zero()) {
            true: parse_dns_answer;
            false: parse_cname_byte;
        }
    }

    state parse_a_ip {
        pkt.extract(p.dns_ip);
        ig_md.parsed_answer = 1;

        transition accept;
    }
}
/**************************END OF PARSER**************************/

// ---------------------------------------------------------------------------
// Ingress Deparser
// ---------------------------------------------------------------------------
control SwitchIngressDeparser(
        packet_out pkt,
        inout Parsed_packet headers,
        in ig_metadata_t ig_md,
        in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
         
    Digest<digest_t>() digest;

    apply {

        if (ig_intr_dprsr_md.digest_type == 1) {
            digest.pack({headers.recirculate.src_ip, headers.recirculate.all_nxds, 
                        headers.recirculate.rnd_nxds, headers.recirculate.dns_reqs,
                        headers.recirculate.ip_reqs, headers.recirculate.domain_name_length,
                        headers.recirculate.num_subdomains, headers.recirculate.is_valid_tld,
                        headers.recirculate.has_single_subd, headers.recirculate.num_underscores});
        }
        pkt.emit(headers);

    }
}


control calc_long_hash (in bit<LABEL_LENGTH_C> label, out bit<HASH_LENGTH_C> hash) (bit<16> coeff) {
    CRCPolynomial<bit<16>>(coeff = coeff, reversed = false, msb = false, extended = false,  
    init = 0xFFFF, xor = 0xFFFF ) poly;
    Hash<bit<HASH_LENGTH_C>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;
    action do_hash(){
        hash = hash_algo.get({label});
    }
    apply{
        do_hash();
    }
}

control calc_concat_hash (inout bit<HASH_LENGTH_C> hash_concat_hashes, in bit<16> full_label_1_hash) (bit<16> coeff) {
    CRCPolynomial<bit<16>>(coeff = coeff, reversed = false, msb = false, extended = false,  
    init = 0xFFFF, xor = 0xFFFF ) poly;
    Hash<bit<HASH_LENGTH_C>>(HashAlgorithm_t.CUSTOM, poly) hash_algo;
    action do_hash(){
        bit<16> zeros_hex = 0x0000;
        hash_concat_hashes = hash_algo.get({hash_concat_hashes, full_label_1_hash});
    }
    apply{
        do_hash();
    }
}




// ---------------------------------------------------------------------------
// Egress parser
// ---------------------------------------------------------------------------
parser SwitchEgressParser(
        packet_in pkt,
        out Parsed_packet p,
        out eg_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md
        ) {


    state start {
        pkt.extract(eg_intr_md);

        transition check_recirculate;
    }

    state check_recirculate {
        // parse recirculated packet here
        bit<8> recirculate_id = pkt.lookahead<bit<8>>();
        transition select(recirculate_id){
            RECIRCULATE_ID_C: parse_recirculate; // Hoping that the first 8 bits of MAC destination address is not 220
            _: parse_ethernet;
        }
    }
    state parse_recirculate {
        pkt.extract(eg_md.recirculate_metadata);
        transition parse_ethernet;
    }
    state parse_ethernet {
        pkt.extract(p.ethernet);
        transition select(p.ethernet.etherType) {
			0x800: parse_ip;
			default: accept;
		}
    }
	state parse_ip {
        pkt.extract(p.ipv4);
        eg_md.is_ip = 1;
        eg_md.is_dns = 0;
		transition select(p.ipv4.proto) {
			17: parse_udp;
			default: accept;
		}
	}
    state parse_udp {
        pkt.extract(p.udp);
		transition select(p.udp.dport, p.udp.sport) {
            (53,_): parse_dns_header;
            (_, 53): parse_dns_header;
			default: accept;
		}
	}
    state parse_dns_header {
        bit<17> partial_dns = pkt.lookahead<bit<17>>();
        bit<1> is_response = partial_dns[16:16];
        transition select(is_response){
            0: parse_dns_request;
            1: parse_dns_response;
            default: accept;
        }
    }
    state parse_dns_request {
        eg_md.is_dns = 1; // request
        transition accept;
    }
    state parse_dns_response {
        eg_md.is_dns = 2; // response
        transition accept;
    }
}

// ---------------------------------------------------------------------------
// Egress Deparser
// ---------------------------------------------------------------------------
control SwitchEgressDeparser(
        packet_out pkt,
        inout Parsed_packet headers,
        in eg_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t eg_intr_md_for_dprsr) {
    apply {
         // I am dropping the packet before being sent to the host with the recirculated header, so basically this recirculated header is just for the switch to hold metadata infromation, the host won't be receiving bogus DNS pakcets 
        pkt.emit(eg_md.recirculate_metadata);
        pkt.emit(headers);
    }
}

// ---------------------------------------------------------------------------
// Ingress Control
// ---------------------------------------------------------------------------
control SwitchIngress(inout Parsed_packet headers,
                inout ig_metadata_t ig_md,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {


   
    BigramVal is_random;
    // Last two hashes
    calc_concat_hash(coeff=0x1021) H_last_label;
    // Define the hashes for the label
    calc_long_hash(coeff=0x1021) hash_label_1;
    calc_concat_hash(coeff=0x1021) hash_concat;
    // label 1
    bit<LABEL_LENGTH_C> full_label_1; 
    bit<HASH_LENGTH_C> full_label_1_hash;  
    bit<HASH_LENGTH_C> hash_concat_hashes; // init (for recirculation purposes) 
    bit<8> recirculate_counter;
    bit<HASH_LENGTH_C> hash_prelast_label;
    bit<HASH_LENGTH_C> hash_last_label;

    action set_full_label_zero(inout bit<LABEL_LENGTH_C> full_label){
        full_label = (bit<LABEL_LENGTH_C>) 0;
    }
    action send(PortId_t port){
        ig_intr_tm_md.ucast_egress_port = port;
    }
    action drop() {
        ig_intr_dprsr_md.drop_ctl = 1;
    }
    

    // Define Hash
    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_1_dns;
    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_2_dns;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_1;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_2;

   bit<16> hash_last_label_var;


    action recirculation(PortId_t port){
        ig_intr_tm_md.ucast_egress_port = port;
    }

    // For basic destination IP forwarding
    table ipv4_host {
        key = {
            headers.ipv4.dst: exact;
        }
        actions = {
            send;
            NoAction;
        }
        size = NUM_IPV4_DST_IP;
        default_action = NoAction();
    }
    action map_bigram_hdr(BigramVal freq){
        headers.recirculate.ans = headers.recirculate.ans + freq;
    }
    // Tables static_bigrams1 .. N are for calculating the bigram frequency value, they are populated offline 
    table static_bigrams1 {
        key = {
            headers.q1_part1.part: exact;
        }
        actions = {
            map_bigram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigrams2 {
        key = {
            headers.q1_part2.part: exact;
        }
        actions = {
            map_bigram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigrams3 {
        key = {
            headers.q1_part4.part[15:0]: exact;
        }
        actions = {
            map_bigram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigrams4 {
        key = {
            headers.q1_part4.part[23:8]: exact;
        }
        actions = {
            map_bigram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigrams5 {
        key = {
            headers.q1_part4.part[31:16]: exact;
        }
        actions = {
            map_bigram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigrams6 {
        key = {
            headers.q1_part1.part: exact;
            headers.q1_part2.part[15:8]: exact;
        }
        actions = {
            map_bigram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    
    table static_bigrams7 {
        key = {
            headers.q1_part2.part[7:0]: exact;
            headers.q1_part4.part[31:24]: exact;
        }
        actions = {
            map_bigram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    table static_bigrams8 {
        key = {
            headers.q1_part1.part: exact;
            headers.q1_part4.part[31:24]: exact;
        }
        actions = {
            map_bigram_hdr;
        }
        size = NUM_STATIC_BIGRAMS;
    }
    action is_valid_tld_act(){
        headers.recirculate.is_valid_tld = 1;
    }
    // For checking if the TLD is valid or not, the key is the hash value of the TLD, and it is matched against a populated table containing the hashes of all TLDs
    table is_valid_tld {
        key = {
           hash_last_label: exact;
        }
        actions = {
            is_valid_tld_act;
        } 
        size = 1500;
    }
 
    apply {
        
        // For basic forwarding
        ipv4_host.apply();

        // NXD parsing is done
        if (headers.recirculate.isValid() && headers.recirculate.recirculate_bit == 20) {
            if (headers.recirculate.i == 1) {
                drop();
            }
            else {
                recirculation(68);    
            }
        }
        else if (headers.recirculate.isValid() && headers.recirculate.recirculate_bit == 21) {
            recirculation(68);
        }
        else if (headers.recirculate.isValid() && (headers.recirculate.recirculate_bit == 22)){
            // Send digest to control plane with the collected features
            ig_intr_dprsr_md.digest_type = 1;
            drop();
        }
        
        // DNS NXDomain reply 
        else if (ig_md.is_dns == 1 && headers.dns_header.resp_code == NXDomain)  {
            ig_md.domain_id_dns = 0;

            // if this is a recirculated packet, set the hash_concat_hashes, increment the recirculate_counter, and set the recirculate bit 
            if (headers.recirculate.isValid()){
                hash_concat_hashes = headers.recirculate.hash_concat_hashes;
                headers.recirculate.recirculate_counter = headers.recirculate.recirculate_counter + 1;
                headers.recirculate.recirculate_bit = ig_md.recirculate_metadata.recirculate_bit;

                hash_last_label = headers.recirculate.hash_last_label;
                hash_prelast_label = headers.recirculate.hash_prelast_label;

            }
            // This will only enter one time (recirculation is invalid), if this is the first time parsing and recirculation (more_labels recirc) is needed
            else if (headers.label2.isValid() && headers.label2.label != 0){
                    headers.recirculate.setValid();
                    headers.recirculate.src_ip = headers.ipv4.dst;
                    hash_concat_hashes = 0x0000;
                    headers.recirculate.recirculate_id = RECIRCULATE_ID_C;
                    headers.recirculate.hash_concat_hashes = 0x0000;
                    headers.recirculate.recirculate_counter = 0x00;
                    hash_last_label = 0x0000;
                    hash_prelast_label = 0x0000;
                    headers.recirculate.recirculate_bit = RECIRC_LABEL;

                    // increase the number of NXDomains
                    // Check if the current label has length 1 
                    if(headers.label1.label == 1){
                        headers.recirculate.has_single_subd = 1;
                    }
            }
            // This will only enter one time (recirculation is invalid), if this is the first time parsing and recirculation (per_label recirc) is needed
            else if (ig_md.recirculate_metadata.recirculate_bit == RECIRC_CHARS) {
                    
                    headers.recirculate.setValid();
                    headers.recirculate.src_ip = headers.ipv4.dst;
                    hash_concat_hashes = 0x0000;
                    headers.recirculate.recirculate_id = RECIRCULATE_ID_C;
                    headers.recirculate.hash_concat_hashes = 0x0000;
                    headers.recirculate.recirculate_counter = 0x00;
                    hash_last_label = 0x0000;
                    hash_prelast_label = 0x0000;
                    headers.recirculate.recirculate_bit = RECIRC_CHARS;

            }
            
            // Calculate the hashes of the label 1
            set_full_label_zero(full_label_1);

            if (headers.q1_part1.isValid()){
                full_label_1[7:0] = headers.q1_part1.part;
                //bigram_reg_index1 = (bit<16>)headers.q1_part1.part;
                // 1st character (e.g., $g)

                // Count underscores
                if (headers.q1_part1.part == 0x5F) {
                    headers.recirculate.num_underscores = headers.recirculate.num_underscores + 1; 
                }

                // Don't count the last label
                if (headers.label2.label != 0){
                    static_bigrams1.apply();
                }
                
            }
            if (headers.q1_part2.isValid()){
                full_label_1[23:8] = headers.q1_part2.part;
                
                // Count underscores
                if (headers.q1_part2.part[7:0] == 0x5F) {
                    headers.recirculate.num_underscores = headers.recirculate.num_underscores + 1; 
                }
                if (headers.q1_part2.part[15:8] == 0x5F) {
                    headers.recirculate.num_underscores = headers.recirculate.num_underscores + 1; 
                }

                // Two characters (e.g., oo)
                //bigram_reg_index2 = headers.q1_part2.part;
                if (headers.label2.label != 0){
                    static_bigrams2.apply();
                }
            }

            if (headers.q1_part2.isValid() && headers.q1_part1.isValid() && headers.label2.label != 0) {
                //bigram_reg_index6[7:0] = headers.q1_part1.part;
                //bigram_reg_index6[15:8] = headers.q1_part2.part[7:0];
                static_bigrams6.apply();
            }
            
            if (headers.q1_part4.isValid()){
                full_label_1[55:24] = headers.q1_part4.part;
                if (headers.label2.label != 0){
                    static_bigrams3.apply();
                    static_bigrams4.apply();
                    static_bigrams5.apply();
                }
            }

            // Count underscores
            if (headers.q1_part4.part[7:0] == 0x5F) {
                headers.recirculate.num_underscores = headers.recirculate.num_underscores + 1; 
            }
            if (headers.q1_part4.part[15:8] == 0x5F) {
                headers.recirculate.num_underscores = headers.recirculate.num_underscores + 1; 
            }
            if (headers.q1_part4.part[23:16] == 0x5F) {
                headers.recirculate.num_underscores = headers.recirculate.num_underscores + 1; 
            }
            if (headers.q1_part4.part[31:24] == 0x5F) {
                headers.recirculate.num_underscores = headers.recirculate.num_underscores + 1; 
            }
            
            if (headers.q1_part4.isValid() && headers.q1_part2.isValid() && headers.label2.label != 0){
                static_bigrams7.apply();
            }
            else if (headers.q1_part4.isValid() && headers.q1_part1.isValid() && headers.label2.label != 0){
                static_bigrams8.apply();
            }
            hash_label_1.apply(full_label_1, full_label_1_hash);
            H_last_label.apply(hash_last_label, full_label_1_hash);



            // if the label is above 7 chars
            if (ig_md.recirculate_metadata.recirculate_bit == RECIRC_CHARS) {
                // Remove headers label_1 characters
                headers.label1.label = headers.label1.label - 7;  
                headers.q1_part1.setInvalid();
                headers.q1_part2.setInvalid();
                headers.q1_part4.setInvalid();

                headers.recirculate.domain_name_length = headers.recirculate.domain_name_length + 7; 
                
                // set recirculate bit
                recirculation(68);
                headers.recirculate.recirculate_bit = RECIRC_CHARS;
                headers.recirculate.hash_last_label = hash_last_label;
            }
            else {
                // If no label has more than 7 characters
                headers.recirculate.domain_name_length = headers.recirculate.domain_name_length + headers.label1.label;
                // Only add up to the TLD
                if(headers.label2.label != 0){
                    // check if the domain has a single label subdomain
                    if(headers.label2.label == 1){
                        headers.recirculate.has_single_subd = 1;
                    }
                }
            }
        
            hash_concat.apply(hash_concat_hashes, full_label_1_hash);
            headers.recirculate.hash_concat_hashes = hash_concat_hashes;
            

            // If there are more labels
            if (headers.label2.isValid() && headers.label2.label != 0){
                
                // copy the original packet 

                // Remove headers
                headers.label1.setInvalid();
                headers.q1_part1.setInvalid();
                headers.q1_part2.setInvalid();
                headers.q1_part4.setInvalid();

                // add the number of subdomains
                headers.recirculate.num_subdomains = headers.recirculate.num_subdomains + 1;

                recirculation(68);
                // set recirculate bit
                headers.recirculate.recirculate_bit = RECIRC_LABEL;

                // update hash_prelast_label (don't worry about the last_label)
                hash_prelast_label = hash_last_label;
                headers.recirculate.hash_prelast_label = hash_prelast_label;
                hash_last_label_var = headers.recirculate.hash_last_label;
                headers.recirculate.hash_last_label = 0;
            }
            
            // No label has more than 7 characters + no more labels
            if (ig_md.parsed_dns_query == 1){
                // By removing all DNS query name headers, we are terminating the recirculation ...
                headers.label1.setInvalid();
                headers.q1_part1.setInvalid();
                headers.q1_part2.setInvalid();
                headers.q1_part4.setInvalid();

                // Here, we should check if the TLD is valid or not
                // The TLD can be obtained from the hash 
                // headers.recirculate.hash_last_label = hash_last_label_var;
                is_valid_tld.apply();

                headers.recirculate.recirculate_bit = DONE_RECIRC;

                headers.recirculate.recirculate_id = RECIRCULATE_ID_C;
                recirculation(68);

                
            }
            
        }
            
    }
    
}

// ---------------------------------------------------------------------------
// Egress Control
// ---------------------------------------------------------------------------
control SwitchEgress(
        inout Parsed_packet headers,
        inout eg_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    
    bit<1> is_first;
    calc_long_hash(coeff=0x1021) hash_dns;
    calc_long_hash(coeff=0x1021) hash_ip;
     calc_long_hash(coeff=0x1021) hash_ip_domain_nxd1;
    calc_long_hash(coeff=0x1021) hash_ip_domain_nxd2;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) is_first_IP_hash;

    bit<16> index;
    BigramVal is_random;

    

    
    // ************************************************************ DNS and IP register ************************************************************
    // ************************************************************      Start        ************************************************************

    // maybe here instead of putting "_" in the unique_ips, I should specify the size of the register (it should match the number of IP addresses stored)
    Register<bit<8>, _>(TABLE_SIZE2) unique_ips;
    RegisterAction<bit<8>, _, bit<1>> (unique_ips) is_unique_ips = {
        void apply(inout bit<8> value, out bit<1> is_first) {
            if (value == 0){
                is_first = 1;
            } else {
                is_first = 0;
            }
            value = value + 1;
        }
    };

    Register<bit<32>, _>(TABLE_SIZE2) dns_reqs;
    RegisterAction<bit<32>, _, bit<32>> (dns_reqs) get_dns_reqs = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            result = register_data;
        }
    };
    RegisterAction<bit<32>, _, void> (dns_reqs) update_dns_reqs = {
        void apply(inout bit<32> register_data) {

            register_data = register_data + 1;
        }
    };

    Register<bit<32>, _>(TABLE_SIZE2) ip_reqs;
    RegisterAction<bit<32>, _, bit<32>> (ip_reqs) get_ip_reqs = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            result = register_data;
        }
    };
    RegisterAction<bit<32>, _, void> (ip_reqs) update_ips_reqs = {
        void apply(inout bit<32> register_data) {

            register_data = register_data + 1;
        }
    };

    
    Register<bit<32>, _>(TABLE_SIZE2) nxd_reg1;
    RegisterAction<bit<32>, _, void> (nxd_reg1) update_NXDomain = {
        void apply(inout bit<32> value) {
            if (eg_md.recirculate_metadata.ans < RND_DOMAIN_THRESH) {
                value = value + 1; // Add 1 to the lower part [15:0] representing the number of random domains 
            }
            else {
                value = value + 0x10000; // Add 1 to the upper part [31:16] and keep the first 16 bits the same (representing random values)
            }
        }
    };
    RegisterAction<bit<32>, _, bit<32>> (nxd_reg1) get_NXDomain = {// data type of register, box_num_t, return type
        void apply(inout bit<32> register_data, out bit<32> result) {
            result = register_data; 
        }
    };
    

    // ************************************************************ NXD iarrival register ************************************************************
    // ************************************************************      Start        ************************************************************
    Register<bit<32>, _>(TABLE_SIZE2) nxd_iarrival;
    // update time of iarrival of this packet (NXD)
    RegisterAction<bit<32>, _, void> (nxd_iarrival) update_nxd_iarrival = {
        void apply(inout bit<32> register_data) {
            
            // register_data = eg_md.iarrival; //lpf_output_2;
            register_data = (bit<32>)eg_intr_md_from_prsr.global_tstamp;
            
        }
    };
    RegisterAction<bit<32>, _, bit<32>> (nxd_iarrival) get_nxd_iarrival = {
        void apply(inout bit<32> register_data, out bit<32> result) {
            result =  register_data;
        }
    };
    // ************************************************************ NXD iarrival register ************************************************************
    // ************************************************************      End        ************************************************************


    // ************************************************************ IP_domain_nxd, tmstamp register1, register2 ************************************************************
    // ************************************************************      Start        ************************************************************
    Register<IP_domain_hash_t, _>(TABLE_SIZE) ip_domain_hash1;
    RegisterAction<IP_domain_hash_t, _, bit<1>> (ip_domain_hash1) get_ip_domain_hash1 = {
        void apply(inout IP_domain_hash_t register_data, out bit<1> result) {

            if (register_data.domain_hash == (bit<32>)eg_md.recirculate_metadata.hash_concat_hashes && register_data.ip == eg_md.recirculate_metadata.src_ip) {
                result = 1;
            }
            else {
                result = 0;
            }
        }
    };
    RegisterAction<IP_domain_hash_t, _, void> (ip_domain_hash1) update_ip_domain_hash1 = {
        void apply(inout IP_domain_hash_t register_data) {
            register_data.domain_hash = (bit<32>)eg_md.recirculate_metadata.hash_concat_hashes;
            register_data.ip = eg_md.recirculate_metadata.src_ip;
        }
    };
    
    Register<IP_domain_hash_t, _>(TABLE_SIZE) ip_domain_hash2;
    RegisterAction<IP_domain_hash_t, _, bit<1>> (ip_domain_hash2) get_ip_domain_hash2 = {
        void apply(inout IP_domain_hash_t register_data, out bit<1> result) {

            if (register_data.domain_hash == (bit<32>)eg_md.recirculate_metadata.hash_concat_hashes && register_data.ip == eg_md.recirculate_metadata.src_ip) {
                result = 1;
            }
            else {
                result = 0;
            }
        }
    };
    RegisterAction<IP_domain_hash_t, _, void> (ip_domain_hash2) update_ip_domain_hash2 = {
        void apply(inout IP_domain_hash_t register_data) {
            register_data.domain_hash = (bit<32>) eg_md.recirculate_metadata.hash_concat_hashes;
            register_data.ip = eg_md.recirculate_metadata.src_ip;
        }
    };

    Register<bit<32>,_>(TABLE_SIZE) tstamp_reg_1;
    RegisterAction<bit<32>,_,bit<1>> (tstamp_reg_1) tstamp_reg_1_check_tstamp_action = {
        void apply(inout bit<32> value, out bit<1> timed_out) {
            if (value + TIMEOUT < (bit<32>)eg_intr_md_from_prsr.global_tstamp) {
                timed_out = 1;
            }
            else {
                timed_out = 0;
            }
        }
    };
    RegisterAction<bit<32>,_,void> (tstamp_reg_1) tstamp_reg_1_update_tstamp_action = {
        void apply(inout bit<32> value) {
            value = (bit<32>)eg_intr_md_from_prsr.global_tstamp;
        }
    };

    Register<timestamp_t,_>(TABLE_SIZE) tstamp_reg_2;
    RegisterAction<timestamp_t,_,bit<1>> (tstamp_reg_2) tstamp_reg_2_check_tstamp_action = {
        void apply(inout timestamp_t value, out bit<1> timed_out) {
            if (value.timestamp + TIMEOUT < (bit<32>)eg_intr_md_from_prsr.global_tstamp) {
                timed_out = 1;
            }
            else {
                timed_out = 0;
            }
        }
    };
    RegisterAction<timestamp_t,_,void> (tstamp_reg_2) tstamp_reg_2_update_tstamp_action = {
        void apply(inout timestamp_t value) {
            value.timestamp = (bit<32>)eg_intr_md_from_prsr.global_tstamp;
        }
    };
    // ************************************************************  IP_domain_nxd, tmstamp register1, register2 ************************************************************
    // ************************************************************      End        ************************************************************


    // LPF for iarrivals of hosts
    Lpf<bit<32>, bit<16>>(size=10024) lpf_1;
    Lpf<bit<32>, bit<16>>(size=10024) lpf_2;
    bit<32> lpf_input;
    bit<32> lpf_output_1;
    bit<32> lpf_output_2;


    apply {
        

        if (eg_md.recirculate_metadata.isValid()) {

            bit<LABEL_LENGTH_C> ip56 = (bit<LABEL_LENGTH_C>) eg_md.recirculate_metadata.src_ip;
            bit<16> ip56_hash;
            hash_ip.apply(ip56, ip56_hash);

            bit<LABEL_LENGTH_C> ip_domain_nxd1;
            bit<LABEL_LENGTH_C> ip_domain_nxd2;
            bit<16> ip_domain_nxd1_hash;
            bit<16> ip_domain_nxd2_hash;

            // index 1
            ip_domain_nxd1[15:0] = eg_md.recirculate_metadata.hash_concat_hashes;
            ip_domain_nxd1[47:16] = eg_md.recirculate_metadata.src_ip;
            ip_domain_nxd2[15:0] = eg_md.recirculate_metadata.hash_concat_hashes;
            ip_domain_nxd2[47:16] = eg_md.recirculate_metadata.src_ip;
            ip_domain_nxd2[55:48] = 8w0211;

            hash_ip_domain_nxd1.apply(ip_domain_nxd1, ip_domain_nxd1_hash);
            hash_ip_domain_nxd2.apply(ip_domain_nxd2, ip_domain_nxd2_hash);
            
            
            // NXD, after the domain has been fully parsed
            // Check if the domain + src_ip has been seen before
            if (eg_md.recirculate_metadata.recirculate_bit == DONE_RECIRC) {
                // Check if the ip+nxd has been seen before 
                // Check if the domain has been queried before, if yes drop the packet ...

                // Check register 1
                bit<1> is_match_1 = 0;
                bit<1> already_matched = 0;
                is_match_1 = get_ip_domain_hash1.execute(ip_domain_nxd1_hash);
                
                if (is_match_1 == 1) {
                    // update timestamp1 next recirculation
                    tstamp_reg_1_update_tstamp_action.execute(ip_domain_nxd1_hash);
                    already_matched = 1;
                    // Drop the packet (next recirculation)
                    eg_md.recirculate_metadata.i = 1;
                }
                else {
                    // Check if the entry there has an expired timeout
                        bit<1> timed_out = 1;

                        timed_out = tstamp_reg_1_check_tstamp_action.execute(ip_domain_nxd1_hash);
                       

                        // If entry timed out, replace entry. For this, resubmit packet.
                        if (timed_out == 1) {
                            already_matched = 1;
                            eg_md.recirculate_metadata.i = 2;
                        }

                        // else, there is a collision and no timeout, need to check Reg2 (already_matched = 0)
                }
                if (already_matched == 0) {
                    bit<1> is_match_2 = 0;

                    is_match_2 = get_ip_domain_hash2.execute(ip_domain_nxd2_hash);

                    // If sip and cip matches, just update timestamp
                    if (is_match_2 == 1) {
                        // update timestamp2
                        tstamp_reg_2_update_tstamp_action.execute(ip_domain_nxd2_hash);
                        // Drop the packet
                        eg_md.recirculate_metadata.i = 1;
                    }
                    else {
                        // Check timestamp
                        bit<1> timed_out = 0;

                        timed_out = tstamp_reg_2_check_tstamp_action.execute(ip_domain_nxd2_hash);
                        
                        // If entry timed out, replace entry. For this, resubmit packet.
                        if (timed_out == 1) {
                            eg_md.recirculate_metadata.i = 4;
                        }
                    }
                }
                eg_md.recirculate_metadata.recirculate_bit = 20;     
            }
            else if (eg_md.recirculate_metadata.recirculate_bit == 20) {
                bit<1> proceed_packet = 0;
                // update reg1
                if (eg_md.recirculate_metadata.i == 2) {
                   update_ip_domain_hash1.execute(ip_domain_nxd1_hash);
                   tstamp_reg_1_update_tstamp_action.execute(ip_domain_nxd1_hash);
                   eg_md.recirculate_metadata.i = 5;
                   proceed_packet = 1;
                }
                // update reg2
                else if (eg_md.recirculate_metadata.i == 4) {
                    update_ip_domain_hash2.execute(ip_domain_nxd2_hash);
                    tstamp_reg_2_update_tstamp_action.execute(ip_domain_nxd2_hash);
                    eg_md.recirculate_metadata.i = 5;
                    proceed_packet = 1;
                }
                // /*
                if (proceed_packet == 1){
                    // Check if the domain is random or not (finished DPI)
                    update_NXDomain.execute(ip56_hash);
                    // Get inter-arrival time
                    eg_md.recirculate_metadata.i_arrival = get_nxd_iarrival.execute(ip56_hash);
                }
                // */
                eg_md.recirculate_metadata.recirculate_bit = 21;
            }
            else if (eg_md.recirculate_metadata.recirculate_bit == 21) {
                // Get Nb of NXDs, rnd NXDs, DNS reqs, IP reqs
                // eg_md.recirculate_metadata.ans = get_NXDomain_rnd.execute(ip56_hash);

                // Get information
                bit<32> total_nxds = get_NXDomain.execute(ip56_hash);
                eg_md.recirculate_metadata.rnd_nxds = total_nxds[15:0];
                eg_md.recirculate_metadata.all_nxds = total_nxds[31:16] + eg_md.recirculate_metadata.rnd_nxds;
                eg_md.recirculate_metadata.dns_reqs = get_dns_reqs.execute(ip56_hash);
                eg_md.recirculate_metadata.ip_reqs = get_ip_reqs.execute(ip56_hash);
                eg_md.recirculate_metadata.i_arrival = eg_md.recirculate_metadata.i_arrival - (bit<32>)eg_intr_md_from_prsr.global_tstamp;
                // update timestamp
                update_nxd_iarrival.execute(ip56_hash);
                eg_md.recirculate_metadata.recirculate_bit = 22;
            }
            
        }
         // Non-DNS packets
        else if (eg_md.is_ip == 1 && eg_md.is_dns == 0) { // normal packets (will not be recirculated)
            index = is_first_IP_hash.get(headers.ipv4.src + headers.ipv4.dst);
            is_first = is_unique_ips.execute(index);

            if (is_first == 1){
                
                bit<LABEL_LENGTH_C> ip56 = (bit<LABEL_LENGTH_C>) headers.ipv4.src;
                bit<16> ip56_hash;
                hash_ip.apply(ip56, ip56_hash);

                // update_unique_IP_req.execute(ip56_hash);
                update_ips_reqs.execute(ip56_hash);
                // Resubmit packet to send a message digest
            }
        } 
        //DNS requests (obv no recircualtion if it is a request)
        else if (eg_md.is_dns == 1) {
            bit<LABEL_LENGTH_C> ip56 = (bit<LABEL_LENGTH_C>) headers.ipv4.src;
            bit<16> ip56_hash;
            hash_dns.apply(ip56, ip56_hash);
            // update_DNS_requests.execute(ip56_hash);
            update_dns_reqs.execute(ip56_hash);
            // Resubmit packet to send a message digest
        }
    }
   
}



Pipeline(SwitchIngressParser(),
         SwitchIngress(),
         SwitchIngressDeparser(),
         SwitchEgressParser(),
         SwitchEgress(),
         SwitchEgressDeparser()
        ) pipe;

Switch(pipe) main;

