/*
 * Copyright (c) 2009, 2010, 2011, 2012, 2013, 2014 Nicira, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <config.h>

#include "ofproto/ofproto-dpif-hsa.h"
#include "ofproto/ofproto-provider.h"

#include "dynamic-string.h"
#include "flow.h"
#include "list.h"
#include "match.h"
#include "nx-match.h"
#include "ofproto.h"
#include "ofp-actions.h"
#include "sort.h"
#include "unixctl.h"
#include "util.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(hsa);

/* Always starts the analysis from OpenFlow table 0. */
#define TABLE_DEFAULT 0

#define INDENT_DEFAULT 0

enum flow_attr {
    FLOW_TUN,
    FLOW_META,
    FLOW_REGS,
    FLOW_SKB_PRIO,
    FLOW_PKT_MARK,
    FLOW_RECIRC_ID,
    FLOW_IN_PORT,
    FLOW_ACTSET_OUTPUT,
    FLOW_DL_DST,
    FLOW_DL_SRC,
    FLOW_DL_TYPE,
    FLOW_VLAN_TCI,
    FLOW_MPLS_LSE,
    FLOW_IPV6_SRC,
    FLOW_IPV6_DST,
    FLOW_IPV6_LABEL,
    FLOW_NW_SRC,
    FLOW_NW_DST,
    FLOW_NW_FRAG,
    FLOW_NW_TOS,
    FLOW_NW_TTL,
    FLOW_NW_PROTO,
    FLOW_ARP_SHA,
    FLOW_ARP_THA,
    FLOW_ND_TARGET,
    FLOW_TCP_FLAGS,
    FLOW_TP_SRC,
    FLOW_TP_DST,
    FLOW_IGMP_GROUP_IP4,
    FLOW_DP_HASH,
    __FLOW_ATTR_MAX
};

/* Representation of header space.
 *
 * Difference between match_hs and match_flow.
 *
 *    - match_hs represents the header space shaped as the header space
 *      matched by flows and applied with their actions.
 *
 *    - match_flow represents the input flow space/format that results in
 *      the output and header space.
 *
 *    - an example is that the flow action will only change the shape of
 *      match_hs but not match_flow.
 * */
struct header_space {
    struct ovs_list list_node;
    struct match match_hs;          /* Header space. */
    struct match match_flow;        /* Input flow format to get the output.*/
    struct ovs_list flow_contrain[__FLOW_ATTR_MAX]; /* Flow contrains, one for */
                                                    /* flow attribute. */
};

/* Rule used for head space analysis. */
struct hsa_rule {
    struct ovs_list node;           /* In owning table's 'rules'. */
    uint8_t table_id;               /* Table id. */
    int prio;                       /* Priority. */
    struct match match;             /* Flow and wildcards. */
    uint32_t ofpacts_len;           /* Action length.  */
    struct ofpact *ofpacts;         /* OpenFlow actions. */
};

/* Flow table for header space analysis. */
struct hsa_table {
    struct ovs_list rules;          /* Contains 'struct hsa_rule's. */
    size_t n_rules;                 /* Number of rules in the table. */
};

/* Global 'struct hsa_table's, one for each OpenFlow table. */
static struct hsa_table *hsa_tables;
/* Number of tables in 'hsa_tables'. */
static int n_hsa_tables;
/* Initial 'struct header_space' for conducting analysis. */
static struct header_space *hs;
/* Global control of debugging mode. */
static bool debug_enabled = true;

static struct header_space *hs_clone(const struct header_space *);
static void hs_destroy(struct header_space *);

static void hsa_init(struct ofproto *, ofp_port_t ofp_port, struct ds *);
static void hsa_finish(void);
static void hsa_calculate(struct header_space *, uint8_t table_id,
                          struct ds *, int indent);
static void hsa_match_print(struct ds *, struct match *, int indent);
static void hsa_rule_print(struct ds *, struct hsa_rule *, int indent);
static int hsa_rule_compare(size_t a, size_t b, void *aux);
static void hsa_rule_apply_match(struct header_space *, struct hsa_rule *);
static void hsa_rule_apply_actions(struct header_space *, struct hsa_rule *,
                                   uint8_t cur_table_id);
static void hsa_rule_swap(size_t a, size_t b, void *aux);
static bool hsa_rule_check_match(struct header_space *, struct hsa_rule *);
static bool hsa_rule_is_exact_match(struct header_space *, struct hsa_rule *);


static void
hsa_match_print(struct ds *out, struct match *match, int indent)
{
    ds_put_char_multiple(out, '\t', indent);
    match_format(match, out, OFP_DEFAULT_PRIORITY);
    ds_put_cstr(out, "\n");
}

static void
hsa_rule_print(struct ds *out, struct hsa_rule *rule, int indent)
{
    ds_put_char_multiple(out, '\t', indent);
    ds_put_format(out, "table_id=%"PRIu8", ", rule->table_id);
    match_format(&rule->match, out, rule->prio);
    ds_put_cstr(out, ",actions=");
    ofpacts_format(rule->ofpacts, rule->ofpacts_len, out);
    ds_put_cstr(out, "\n");
}

/* This compares is implemented for sorting in descending order. */
static int
hsa_rule_compare(size_t a, size_t b, void *aux)
{
    struct ovs_list *rules = aux;
    struct hsa_rule *r1, *r2;

    r1 = CONTAINER_OF(list_at_position(rules, a), struct hsa_rule, node);
    r2 = CONTAINER_OF(list_at_position(rules, b), struct hsa_rule, node);

    return r2->prio - r1->prio;
}

/* Swaps the two elements at position 'a' and 'b'. */
static void
hsa_rule_swap(size_t a, size_t b, void *aux)
{
    struct ovs_list *rules = aux;

    list_swap(list_at_position(rules, a), list_at_position(rules, b));
}

/* Returns true if the 'hs' applied with 'rule' wildcards can match
 * the flow in 'rule'. */
static bool
hsa_rule_check_match(struct header_space *hs, struct hsa_rule *rule)
{
    return flow_equal_except(&hs->match_hs.flow, &rule->match.flow,
                             &rule->match.wc);
}

#define FLOW_ATTRS                               \
    /* tunnel. */                                \
    FLOW_ATTR(tunnel.tun_id)                     \
    FLOW_ATTR(tunnel.ip_src)                     \
    FLOW_ATTR(tunnel.ip_dst)                     \
    FLOW_ATTR(tunnel.flags)                      \
    FLOW_ATTR(tunnel.ip_tos)                     \
    FLOW_ATTR(tunnel.ip_ttl)                     \
    FLOW_ATTR(tunnel.tp_src)                     \
    FLOW_ATTR(tunnel.tp_dst)                     \
    /* metadata and regs. */                     \
    FLOW_ATTR(metadata)                          \
    FLOW_ATTR(regs)                              \
    FLOW_ATTR(skb_priority)                      \
    FLOW_ATTR(pkt_mark)                          \
    FLOW_ATTR(recirc_id)                         \
    FLOW_ATTR(in_port)                           \
    FLOW_ATTR(actset_output)                     \
    /* L2. */                                    \
    FLOW_ATTR(dl_dst)                            \
    FLOW_ATTR(dl_src)                            \
    FLOW_ATTR(dl_type)                           \
    FLOW_ATTR(vlan_tci)                          \
    FLOW_ATTR(mpls_lse)                          \
    /* L3. */                                    \
    FLOW_ATTR(ipv6_src)                          \
    FLOW_ATTR(ipv6_dst)                          \
    FLOW_ATTR(ipv6_label)                        \
    FLOW_ATTR(nw_src)                            \
    FLOW_ATTR(nw_dst)                            \
    FLOW_ATTR(nw_frag)                           \
    FLOW_ATTR(nw_tos)                            \
    FLOW_ATTR(nw_ttl)                            \
    FLOW_ATTR(nw_proto)                          \
    FLOW_ATTR(arp_sha)                           \
    FLOW_ATTR(arp_tha)                           \
    FLOW_ATTR(nd_target)                         \
    FLOW_ATTR(tcp_flags)                         \
    /* L4. */                                    \
    FLOW_ATTR(tp_src)                            \
    FLOW_ATTR(tp_dst)                            \
    FLOW_ATTR(igmp_group_ip4)                    \
    FLOW_ATTR(dp_hash)

/* If the field 'hs->flow.wc' and 'rule->match.wc'
 * the flow in 'rule'. */
static bool
hsa_rule_is_exact_match(struct header_space *hs, struct hsa_rule *rule)
{
    struct flow *masks_hs = &hs->match_hs.wc.masks;
    struct flow *masks_rule = &rule->match.wc.masks;
    bool is_exact = false;

    /* If the field is fully masked in 'hs' and masked in the 'rule',
     * then there is a exact match (i.e. the following rules with lower
     * priority can never match the 'hs'. */
#define FLOW_ATTR(ATTR)                                           \
    if (flow_wildcard_is_fully_masked(&masks_hs->ATTR, sizeof masks_hs->ATTR) \
        && !flow_wildcard_is_fully_unmasked(&masks_rule->ATTR, sizeof masks_rule->ATTR)) { \
        is_exact = true;                                                \
        goto out;                                                       \
    }
    FLOW_ATTRS
#undef FLOW_ATTR

out:
    return is_exact;
}

/* Applies the 'rule's flow format and wildcards to header
 * space 'hs'. */
static void
hsa_rule_apply_match(struct header_space *hs, struct hsa_rule *rule)
{
    struct flow *masks = &rule->match.wc.masks;
    struct flow *flow = &rule->match.flow;

    /* If the field in rule is masked, applies 'field & field mask'
     * to header space. */
#define FLOW_ATTR(ATTR)                                                 \
    if (!flow_wildcard_is_fully_unmasked(&masks->ATTR,                  \
                                         sizeof masks->ATTR)) {         \
        flow_wildcard_apply(&hs->match_hs.flow.ATTR,                    \
                            &hs->match_hs.wc.masks.ATTR,                \
                            &flow->ATTR, &masks->ATTR, sizeof flow->ATTR); \
        flow_wildcard_apply(&hs->match_flow.flow.ATTR,                  \
                            &hs->match_flow.wc.masks.ATTR,              \
                            &flow->ATTR, &masks->ATTR, sizeof flow->ATTR); \
    }
    FLOW_ATTRS
#undef FLOW_ATTR
}

/* Applies various output actions. */
static void
hsa_rule_apply_output_action__(struct header_space *hs, ofp_port_t port)
{
    switch (port) {
    /* Just assume the architecture of having one integration bridge */
    case OFPP_IN_PORT:
    case OFPP_TABLE:
    case OFPP_FLOOD:
    case OFPP_ALL:
    case OFPP_NONE:
    case OFPP_LOCAL:
    case OFPP_NORMAL:
        /* Should not see such actions installed from controller. */
        ovs_assert(true)
        break;
    case OFPP_CONTROLLER:
        /* Do not thing. */
        break;
    default:
        if (port != hs->match_hs.flow.in_port.ofp_port) {
            /* LOG output to port (name), bridge will always be br-int. */
        } else {
            /* WARN output to in_port. */
        }
        break;
    }
}

/* Applies the 'rule's actions to header space 'hs'. */
static void
hsa_rule_apply_actions(struct header_space *hs, struct hsa_rule *rule,
                       uint8_t cur_table_id)
{
    const struct ofpact *ofpacts = rule->ofpacts;
    size_t ofpacts_len = rule->ofpacts_len;
    struct flow *hs_flow = &hs->match_hs.flow;
    struct flow_wildcards *hs_wc = &hs->match_hs.wc;
    const struct ofpact *a;

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        const struct ofpact_set_field *set_field;
        const struct mf_field *mf;

        switch (a->type) {
        /* Output. */
        case OFPACT_OUTPUT:
            hsa_rule_apply_output_action__(hs, ofpact_get_OUTPUT(a)->port);
            break;

        case OFPACT_RESUBMIT: {
            const struct ofpact_resubmit *resubmit = ofpact_get_RESUBMIT(a);
            ofp_port_t in_port = resubmit->in_port;
            uint8_t table_id;

            if (in_port == OFPP_IN_PORT) {
                in_port = hs->match_hs.flow.in_port.ofp_port;
            }

            table_id = resubmit->table_id;
            if (table_id == 255) {
                table_id = cur_table_id;
            }

            /* TODO: Fix me. */
            hsa_calculate(hs, table_id, NULL, INDENT_DEFAULT);
            break;
        }

        case OFPACT_BUNDLE: {
            /* Only supports hrw algorithm. */
            const struct ofpact_bundle *bundle = ofpact_get_BUNDLE(a);
            int i;

            /* Assumes all slaves are enabled. */
            for (i = 0; i < bundle->n_slaves; i++) {
                ofp_port_t port = bundle->slaves[i];

                /* Copies 'hs', sets the 'bundle->dst'. */
                nxm_reg_load(&bundle->dst, ofp_to_u16(port), &hs->match_hs.flow,
                             &hs->match_hs.wc);
                /* TODO, removes the current 'hs' and appends 'hs' to
                 * hs list. */
            }
            break;
        }

        case OFPACT_OUTPUT_REG: {
            const struct ofpact_output_reg *or = ofpact_get_OUTPUT_REG(a);
            uint64_t port = mf_get_subfield(&or->src, &hs->match_hs.flow);

            if (port <= UINT16_MAX) {
                union mf_subvalue value;

                memset(&value, 0xff, sizeof value);
                mf_write_subfield_flow(&or->src, &value, &hs->match_hs.wc.masks);
                hsa_rule_apply_output_action__(hs, port);
            }
        }



        /* Set fields. */
        case OFPACT_SET_VLAN_VID:
            hs_wc->masks.vlan_tci |= htons(VLAN_VID_MASK | VLAN_CFI);
            if (hs_flow->vlan_tci & htons(VLAN_CFI) ||
                ofpact_get_SET_VLAN_VID(a)->push_vlan_if_needed) {
                hs_flow->vlan_tci &= ~htons(VLAN_VID_MASK);
                hs_flow->vlan_tci |= (htons(ofpact_get_SET_VLAN_VID(a)->vlan_vid)
                                      | htons(VLAN_CFI));
            }
            break;

        case OFPACT_SET_VLAN_PCP:
            hs_wc->masks.vlan_tci |= htons(VLAN_PCP_MASK | VLAN_CFI);
            if (hs_flow->vlan_tci & htons(VLAN_CFI) ||
                ofpact_get_SET_VLAN_PCP(a)->push_vlan_if_needed) {
                hs_flow->vlan_tci &= ~htons(VLAN_PCP_MASK);
                hs_flow->vlan_tci |= htons((ofpact_get_SET_VLAN_PCP(a)->vlan_pcp
                                         << VLAN_PCP_SHIFT) | VLAN_CFI);
            }
            break;

        case OFPACT_STRIP_VLAN:
            memset(&hs_wc->masks.vlan_tci, 0xff, sizeof hs_wc->masks.vlan_tci);
            hs_flow->vlan_tci = htons(0);
            break;

        case OFPACT_PUSH_VLAN:
            /* XXX 802.1AD(QinQ) */
            memset(&hs_wc->masks.vlan_tci, 0xff, sizeof hs_wc->masks.vlan_tci);
            hs_flow->vlan_tci = htons(VLAN_CFI);
            break;

        case OFPACT_SET_ETH_SRC:
            memset(&hs_wc->masks.dl_src, 0xff, sizeof hs_wc->masks.dl_src);
            memcpy(hs_flow->dl_src, ofpact_get_SET_ETH_SRC(a)->mac,
                   ETH_ADDR_LEN);
            break;

        case OFPACT_SET_ETH_DST:
            memset(&hs_wc->masks.dl_dst, 0xff, sizeof hs_wc->masks.dl_dst);
            memcpy(hs_flow->dl_dst, ofpact_get_SET_ETH_DST(a)->mac,
                   ETH_ADDR_LEN);
            break;

        case OFPACT_SET_IPV4_SRC:
            if (hs_flow->dl_type == htons(ETH_TYPE_IP)) {
                memset(&hs_wc->masks.nw_src, 0xff, sizeof hs_wc->masks.nw_src);
                hs_flow->nw_src = ofpact_get_SET_IPV4_SRC(a)->ipv4;
            }
            break;

        case OFPACT_SET_IPV4_DST:
            if (hs_flow->dl_type == htons(ETH_TYPE_IP)) {
                memset(&hs_wc->masks.nw_dst, 0xff, sizeof hs_wc->masks.nw_dst);
                hs_flow->nw_dst = ofpact_get_SET_IPV4_DST(a)->ipv4;
            }
            break;

        case OFPACT_SET_IP_DSCP:
            if (is_ip_any(hs_flow)) {
                hs_wc->masks.nw_tos |= IP_DSCP_MASK;
                hs_flow->nw_tos &= ~IP_DSCP_MASK;
                hs_flow->nw_tos |= ofpact_get_SET_IP_DSCP(a)->dscp;
            }
            break;

        case OFPACT_SET_IP_ECN:
            if (is_ip_any(hs_flow)) {
                hs_wc->masks.nw_tos |= IP_ECN_MASK;
                hs_flow->nw_tos &= ~IP_ECN_MASK;
                hs_flow->nw_tos |= ofpact_get_SET_IP_ECN(a)->ecn;
            }
            break;

        case OFPACT_SET_IP_TTL:
            if (is_ip_any(hs_flow)) {
                hs_wc->masks.nw_ttl = 0xff;
                hs_flow->nw_ttl = ofpact_get_SET_IP_TTL(a)->ttl;
            }
            break;

        case OFPACT_SET_L4_SRC_PORT:
            if (is_ip_any(hs_flow)
                && !(hs_flow->nw_frag & FLOW_NW_FRAG_LATER)) {
                memset(&hs_wc->masks.nw_proto, 0xff,
                       sizeof hs_wc->masks.nw_proto);
                memset(&hs_wc->masks.tp_src, 0xff,
                       sizeof hs_wc->masks.tp_src);
                hs_flow->tp_src = htons(ofpact_get_SET_L4_SRC_PORT(a)->port);
            }
            break;

        case OFPACT_SET_L4_DST_PORT:
            if (is_ip_any(hs_flow)
                && !(hs_flow->nw_frag & FLOW_NW_FRAG_LATER)) {
                memset(&hs_wc->masks.nw_proto, 0xff,
                       sizeof hs_wc->masks.nw_proto);
                memset(&hs_wc->masks.tp_dst, 0xff,
                       sizeof hs_wc->masks.tp_dst);
                hs_flow->tp_dst = htons(ofpact_get_SET_L4_DST_PORT(a)->port);
            }
            break;

        case OFPACT_SET_TUNNEL:
            hs_flow->tunnel.tun_id = htonll(ofpact_get_SET_TUNNEL(a)->tun_id);
            break;

        case OFPACT_REG_MOVE:
            /* Move function, */
            nxm_execute_reg_move(ofpact_get_REG_MOVE(a), hs_flow, hs_wc);
            break;

        case OFPACT_SET_FIELD:
            set_field = ofpact_get_SET_FIELD(a);
            mf = set_field->field;

            /* Set field action only ever overwrites packet's outermost
             * applicable header fields.  Do nothing if no header exists. */
            if (mf->id == MFF_VLAN_VID) {
                hs_wc->masks.vlan_tci |= htons(VLAN_CFI);
                if (!(hs_flow->vlan_tci & htons(VLAN_CFI))) {
                    break;
                }
            }
            /* A flow may wildcard nw_frag.  Do nothing if setting a trasport
             * header field on a packet that does not have them. */
            mf_mask_field_and_prereqs(mf, &hs_wc->masks);
            if (mf_are_prereqs_ok(mf, hs_flow)) {
                mf_set_flow_value_masked(mf, &set_field->value,
                                         &set_field->mask, hs_flow);
            }
            break;



        /* DO NOT SUPPORT OR DO NOT AFFECT HEADER SPACE */
        case OFPACT_CONTROLLER:
        case OFPACT_GROUP:
        case OFPACT_STACK_PUSH:
        case OFPACT_STACK_POP:
        case OFPACT_PUSH_MPLS:
        case OFPACT_POP_MPLS:
        case OFPACT_SET_MPLS_LABEL:
        case OFPACT_SET_MPLS_TC:
        case OFPACT_SET_MPLS_TTL:
        case OFPACT_DEC_MPLS_TTL:
        case OFPACT_DEC_TTL:
        case OFPACT_NOTE:
        case OFPACT_MULTIPATH:
        case OFPACT_LEARN:
        case OFPACT_CLEAR_ACTIONS:
        case OFPACT_EXIT:
        case OFPACT_WRITE_ACTIONS:
        case OFPACT_METER:
        case OFPACT_SAMPLE:
        case OFPACT_SET_QUEUE:
        case OFPACT_ENQUEUE:
        case OFPACT_POP_QUEUE:
        case OFPACT_WRITE_METADATA:
        case OFPACT_GOTO_TABLE:
        case OFPACT_FIN_TIMEOUT:
            break;
        }
    }
}

/* Masks in_port, metadata, regs and ipv6. */
static void
hs_init__(struct header_space *hs, ofp_port_t in_port)
{
    hs->match_hs.flow.in_port.ofp_port = in_port;
    WC_MASK_FIELD(&hs->match_hs.wc, in_port);
    WC_MASK_FIELD(&hs->match_hs.wc, regs);
    WC_MASK_FIELD(&hs->match_hs.wc, metadata);
    WC_MASK_FIELD(&hs->match_hs.wc, ipv6_src);
    WC_MASK_FIELD(&hs->match_hs.wc, ipv6_dst);

    hs->match_flow.flow.in_port.ofp_port = in_port;
    WC_MASK_FIELD(&hs->match_flow.wc, in_port);
    WC_MASK_FIELD(&hs->match_flow.wc, regs);
    WC_MASK_FIELD(&hs->match_flow.wc, metadata);
    WC_MASK_FIELD(&hs->match_flow.wc, ipv6_src);
    WC_MASK_FIELD(&hs->match_flow.wc, ipv6_dst);
}

/* Given the 'ofproto' of a bridge, copies all flows from each oftable
 * into a sorted list with descending priority.  Also, initilizes 'hs'. */
static void
hsa_init(struct ofproto *ofproto, ofp_port_t ofp_port, struct ds *out)
{
    struct oftable *oftable;
    uint8_t table_id = 0;
    size_t i;

    n_hsa_tables = ofproto->n_tables;
    hsa_tables = xmalloc(n_hsa_tables * sizeof *hsa_tables);
    for (i = 0; i < n_hsa_tables; i++) {
        list_init(&hsa_tables[i].rules);
    }

    OFPROTO_FOR_EACH_TABLE (oftable, ofproto) {
        struct hsa_table *table = &hsa_tables[table_id];
        struct ovs_list *rules = &table->rules;
        struct rule *rule;

        table->n_rules = oftable->cls.n_rules;
        CLS_FOR_EACH (rule, cr, &oftable->cls) {
            struct hsa_rule *hsa_rule = xmalloc(sizeof *hsa_rule);
            const struct rule_actions *actions = rule_get_actions(rule);

            hsa_rule->table_id = table_id;
            hsa_rule->prio = rule->cr.priority;
            hsa_rule->ofpacts_len = actions->ofpacts_len;
            hsa_rule->ofpacts = xmalloc(hsa_rule->ofpacts_len);
            memcpy(hsa_rule->ofpacts, actions->ofpacts, hsa_rule->ofpacts_len);
            minimatch_expand(&rule->cr.match, &hsa_rule->match);
            list_insert(rules, &hsa_rule->node);
        }
        sort(table->n_rules, hsa_rule_compare, hsa_rule_swap, rules);
        table_id++;
    }

    /* Initializes the 'hs', sets and masks the 'in_port' and 'regs'. */
    hs = xzalloc(sizeof *hs);
    hs_init__(hs, ofp_port);

    if (debug_enabled) {
        ds_put_char_multiple(out, '\t', INDENT_DEFAULT);
        ds_put_cstr(out, "Header-Space init done:\n");
        hsa_match_print(out, &hs->match_hs, INDENT_DEFAULT);
    }
}

/* Destroys all created 'hsa_rule's and 'hsa_table's. */
static void
hsa_finish(void)
{
    size_t i;

    for (i = 0; i < n_hsa_tables; i++) {
        struct ovs_list *rules = &hsa_tables[i].rules;
        struct hsa_rule *rule, *next;

        if (list_is_empty(rules)) {
            continue;
        }
        LIST_FOR_EACH_SAFE (rule, next, node, rules) {
            list_remove(&rule->node);
            free(rule->ofpacts);
            free(rule);
        }
    }
    free(hsa_tables);
    free(hs);
}

/* Clones the header space 'hs' and returns the copy. */
static struct header_space *
hs_clone(const struct header_space *hs)
{
    struct header_space *clone = xzalloc(sizeof *clone);

    clone->match_hs = hs->match_hs;
    clone->match_flow = hs->match_flow;

    /* Copies the constraints. */

    return clone;
}

static void
hs_destroy(struct header_space *hs)
{
    free(hs);
}

/* Given header space 'hs', finds matches from 'hsa_table' with id
 * 'table_id' and applies the actions of matched rules to 'hs'.  */
static void
hsa_calculate(struct header_space *hs, uint8_t table_id, struct ds *out,
              int indent)
{
    struct hsa_table *table = &hsa_tables[table_id];
    struct ovs_list *rules = &table->rules;
    struct hsa_rule *rule;
    bool skip_rest = false;

    if (debug_enabled) {
        ds_put_char_multiple(out, '\t', indent);
        ds_put_format(out, "Lookup from table %"PRIu8"\n", table_id);
        ds_put_char_multiple(out, '\t', indent);
        hsa_match_print(out, &hs->match_hs, indent);
    }

    LIST_FOR_EACH(rule, node, rules) {
        /* Found a match, clones the 'hs' and applies match's wc
         * to 'hs'. */
        if (hsa_rule_check_match(hs, rule)) {
            struct header_space *clone = hs_clone(hs);

            /* Check if we can skip the rest of the table. */
            skip_rest = hsa_rule_is_exact_match(hs, rule);

            /* Apply the flow fields. */
            hsa_rule_apply_match(hs, rule);

            if (debug_enabled) {
                ds_put_char_multiple(out, '\t', indent);
                ds_put_cstr(out, "Found match rule:");
                hsa_rule_print(out, rule, indent);
                ds_put_char_multiple(out, '\t', indent);
                ds_put_cstr(out, "Header-Space changed to:");
                hsa_match_print(out, &hs->match_hs, indent);
            }

            /* Apply the actions. */
            hsa_rule_apply_actions(hs, rule, table_id);

            /* Skips the rest rules in table. */
            if (skip_rest) {
                break;
            } else {
                /* Otherwise, add the contraints to 'hs'. */
            }

            hs_destroy(clone);
        }
    }
}

static void
ofproto_dpif_unixctl_hsa_calc(struct unixctl_conn *conn, int argc OVS_UNUSED,
                              const char *argv[], void *aux OVS_UNUSED)
{
    struct ds out = DS_EMPTY_INITIALIZER;
    struct ofproto *ofproto;
    struct ofport *port;
    ofp_port_t ofp_port;
    size_t i;

    ofproto = ofproto_lookup(argv[1]);
    if (!ofproto) {
        unixctl_command_reply_error(conn, "no such bridge");
        return;
    }

    ofp_port = OFP_PORT_C(atoi(argv[2]));
    port = ofproto_get_port(ofproto, ofp_port);
    if (!port) {
        unixctl_command_reply_error(conn, "no such port");
        return;
    }

    hsa_init(ofproto, ofp_port, &out);

    if (debug_enabled) {
        ds_put_char_multiple(&out, '\t', INDENT_DEFAULT);
        ds_put_format(&out, "Flows dump from bridge (%s):\n", argv[1]);
        for (i = 0; i < n_hsa_tables; i++) {
            struct ovs_list *rules = &hsa_tables[i].rules;
            struct hsa_rule *rule;

            if (list_is_empty(rules)) {
                continue;
            }
            LIST_FOR_EACH(rule, node, rules) {
                hsa_rule_print(&out, rule, INDENT_DEFAULT + 1);
            }
        }
    }

    /* Starts the HSA with global header space and table 0. */
    hsa_calculate(hs, TABLE_DEFAULT, &out, INDENT_DEFAULT);

    /* Cleans up. */
    hsa_finish();

    unixctl_command_reply(conn, ds_cstr(&out));
    ds_destroy(&out);
}

static void
hsa_unixctl_init(void)
{
    unixctl_command_register("hsa/calculate", "bridge ofport", 2, 2,
                             ofproto_dpif_unixctl_hsa_calc, NULL);
}

/* Public functions. */

void
ofproto_dpif_hsa_init(void)
{
    static bool registered;

    if (registered) {
        return;
    }
    registered = true;
    hsa_unixctl_init();
}
