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

/* Records a previous match whose header space partition is
 * delayed. */
struct hsa_constraint {
    struct ovs_list list_node;
    struct match match;             /* A previous match. */
};

/* A list of 'struct hsa_constraint's. */
struct hsa_constraint_list {
    struct ovs_list list;           /* Contains 'struct hsa_constraint's. */
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

/* Stores 'struct header_space's. */
struct hsa_list {
    struct ovs_list hs_list;        /* Contains 'hs's. */
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
 *
 * Delayed Subtraction
 * ===================
 *
 * Header Space is not partitioned during the calculation by the matched
 * rules.  Instead, the previously matched rules from the same table are
 * cached in the 'constraints' and calculated in the output stage.
 *
 * */
struct header_space {
    struct ovs_list list_node;
    struct match match_hs;          /* Header space. */
    struct match match_flow;        /* Input flow format to get the output.*/
    ofp_port_t output;              /* Output port. */

    /* Contraints from previous matches. */
    struct hsa_constraint_list constraints;
    /* Mask of the fields that has not been set by actions.
     * So, 'constraints' will not contain such field. */
    struct flow_wildcards valid_fields;
};

/* Global 'struct hsa_table's, one for each OpenFlow table. */
static struct hsa_table *hsa_tables;
/* Number of tables in 'hsa_tables'. */
static int n_hsa_tables;
/* Initial 'struct header_space' for conducting analysis. */
static struct header_space *hs_start;
/* Analysis result. */
struct hsa_list *hsa_result;
/* Global control of debugging mode. */
static bool debug_enabled = true;

struct hsbt;
struct hsbt_list;

/* hsa operations. */
static struct header_space *hs_clone(const struct header_space *);
static struct header_space *hs_create(void);
static void hs_destroy(struct header_space *);

static void hsa_hs_apply_constraint(struct header_space *, struct hsa_rule *);

static void hsa_init(struct ofproto *, ofp_port_t ofp_port, struct ds *);
static void hsa_finish(void);
static struct hsa_list *hsa_list_create(void);
static void hsa_list_destroy(struct hsa_list *);
static struct hsa_list *hsa_calculate(struct header_space *, uint8_t table_id,
                                      struct ds *, int indent);
static void hsa_match_print(struct ds *, struct match *);
static void log_match(struct match *, char *aux);
static void hsa_rule_print(struct ds *, struct hsa_rule *);
static void log_rule(struct hsa_rule *, char *aux);
static int hsa_rule_compare(size_t a, size_t b, void *aux);
static void hsa_rule_apply_match(struct header_space *, struct hsa_rule *);
static struct hsa_list *hsa_rule_apply_actions(struct header_space *,
                                               struct hsa_rule *,
                                               uint8_t cur_table_id, struct ds *,
                                               int indent);
static void hsa_hsbt_apply_match(struct hsbt_list *, struct hsa_rule *);
static void hsa_rule_swap(size_t a, size_t b, void *aux);
static bool hsa_rule_check_match(struct header_space *, struct hsa_rule *);
static bool hsa_hsbt_check_match(struct hsbt_list *, struct hsa_rule *);

static void hsa_print_result(struct ds *, struct hsa_list *);


/* Byte arrays representation of header space.
 *
 * Encode each bit into two bits:
 * 0 -> 01
 * 1 -> 10
 * x -> 11 (x - wildcard masked bit)
 * z -> 00 (z - no intersection on the bit)
 */
struct hsbt {
    struct ovs_list list_node;
    char *hs_arr;               /* 'match' as byte array. */
    size_t len;                 /* Length of each 'hs_arr' */
};

/* List of 'struct hsbt's.  This is used to represent to partitioned
 * header space by rule matching. */
struct hsbt_list {
    struct ovs_list list;      /* Contains 'struct hsbt's. */
};

/* hsa byte array operations. */
static void log_hsbt(struct hsbt *, char *name);
static struct hsbt *hsbt_create(size_t len);
static struct hsbt *hsbt_create_all_wildcarded(size_t len);
static void hsbt_destroy(struct hsbt *);
static struct hsbt_list *hsbt_list_create(void);
static void hsbt_list_destroy(struct hsbt_list *);
static void hsbt_list_move(struct hsbt_list *, struct hsbt_list *);
static void hsbt_list_apply_hsbt(struct hsbt_list *, struct hsbt *);
static struct hsbt *match_to_hsbt(struct match *);
static void match_from_hsbt(struct hsbt *, struct match *);
static struct hsbt_list *hsbt_complement(struct hsbt *);
static struct hsbt *hsbt_intersect(struct hsbt *, struct hsbt *);
static struct hsbt_list *hsbt_diff(struct hsbt *, struct hsbt *);

/* Returns 'struct hsbt' with byte array of 'len' long. */
static struct hsbt *
hsbt_create(size_t len)
{
    struct hsbt *ret = xmalloc(sizeof *ret);

    ret->hs_arr = xmalloc(len * sizeof *ret->hs_arr);
    ret->len = len;

    return ret;
}

/* Destroys the 'struct hsbt'. */
static void
hsbt_destroy(struct hsbt *hsbt)
{
    free(hsbt->hs_arr);
    free(hsbt);
}

/* Returns byte array of 'len' long, all wildcarded. */
static struct hsbt *
hsbt_create_all_wildcarded(size_t len)
{
    struct hsbt *ret = hsbt_create(len);

    memset(ret->hs_arr, 0xFF, len);

    return ret;
}

/* Creates and returns 'struct hsbt_list *'. */
static struct hsbt_list *
hsbt_list_create(void)
{
    struct hsbt_list *hsbt_list = xmalloc(sizeof *hsbt_list);

    list_init(&hsbt_list->list);

    return hsbt_list;
}

/* Destroys the 'hsbt_list' and all its elements. */
static void
hsbt_list_destroy(struct hsbt_list *hsbt_list)
{
    struct hsbt *iter, *next;

    LIST_FOR_EACH_SAFE (iter, next, list_node, &hsbt_list->list) {
        list_remove(&iter->list_node);
        hsbt_destroy(iter);
    }
    free(hsbt_list);
}

/* Moves the contents from 'src' to 'dst'. */
static void
hsbt_list_move(struct hsbt_list *dst, struct hsbt_list *src)
{
    list_splice(&dst->list, list_front(&src->list), &src->list);
}

/* Subtracts 'hsbt' from each element of 'hsbt_list'.
 * This function will own the 'hsbt'. */
static void
hsbt_list_apply_hsbt(struct hsbt_list *hsbt_list, struct hsbt *hsbt)
{
    struct hsbt_list *old_hsbt_list = hsbt_list_create();
    struct hsbt *iter;

    hsbt_list_move(old_hsbt_list, hsbt_list);

    LIST_FOR_EACH (iter, list_node, &old_hsbt_list->list) {
        struct hsbt_list *diff = hsbt_diff(iter, hsbt);

        if (!list_is_empty(&diff->list)) {
            hsbt_list_move(hsbt_list, diff);
        }
        hsbt_list_destroy(diff);
    }
    hsbt_list_destroy(old_hsbt_list);
}

/* Logs the 'hsbt'. */
static void
log_hsbt(struct hsbt *hsbt, char *name)
{
    struct ds out = DS_EMPTY_INITIALIZER;
    uint16_t *arr = (uint16_t *) hsbt->hs_arr;
    size_t i;

    ds_put_format(&out, "hsbt %s: ", name);
    for (i = 0; i < hsbt->len / 2; i++) {
        ds_put_format(&out, "%x ", (arr[i] & 0xffff));
    }
    VLOG_INFO("%s", ds_cstr(&out));
    ds_destroy(&out);
}

/* Converts 'hs' to byte array representation. */
static struct hsbt *
match_to_hsbt(struct match *match)
{
    struct hsbt *hsbt = hsbt_create(2 * sizeof(struct flow));
    uint16_t *arr = (uint16_t *) hsbt->hs_arr;
    char *flow = (char *) &match->flow;
    char *wc = (char *) &match->wc;
    size_t i, j;

    /* Encode byte by byte from 'match'. */
    for (i = 0; i < sizeof(struct flow); i++) {
        uint16_t encode = 0;

        for (j = 0; j < 8; j++) {
            uint8_t flow_bit = (flow[i] >> j) & 0x01;
            uint8_t wc_bit = (wc[i] >> j) & 0x01;

            /* If wc_bit is set, checks the bit.  Otherwise, sets to 'x'.*/
            if (wc_bit) {
                encode = encode | ((flow_bit ? 0x0002 : 0x0001) << (2*j));
            } else {
                encode = encode | (0x0003 << (2*j));
            }
        }
        arr[i] = encode;
    }

    return hsbt;
}

/* Restors 'match' from 'hsbt'. */
static void
match_from_hsbt(struct hsbt *hsbt, struct match *match)
{
    uint16_t *arr = (uint16_t *) hsbt->hs_arr;
    char *flow = (char *) &match->flow;
    char *wc = (char *) &match->wc;
    size_t len = hsbt->len / 2;
    size_t i, j;

    memset(match, 0, sizeof *match);

    /* Restores byte by byte from 'hsbt'. */
    for (i = 0; i < len; i++) {
        uint16_t encode = arr[i];

        for (j = 0; j < 8; j++) {
            switch ((encode >> (2*j)) & 0x0003) {
            /* wildcard unmasked (don't care), sets wc bit to '0'. */
            case 0x03:
                wc[i] = wc[i] | (0x00 << j);
                break;
            /* exact match '1'. */
            case 0x02:
                flow[i] = flow[i] | (0x01 << j);
                wc[i] = wc[i] | (0x01 << j);
                break;
            /* exact match '0'. */
            case 0x01:
                flow[i] = flow[i] | (0x00 << j);
                wc[i] = wc[i] | (0x01 << j);
                break;
            /* no intersection, error! */
            default:
                ovs_assert(false);
            }
        }
    }
}

/* Given the byte array representation 'hsbt', returns its complement
 * as a list of 'hsbt's as an union. */
static struct hsbt_list *
hsbt_complement(struct hsbt *hsbt)
{
    struct hsbt_list *hsbt_list = hsbt_list_create();
    size_t i, j;

    for (i = 0; i < hsbt->len; i++) {
        char byte = hsbt->hs_arr[i];

        for (j = 0; j < 4; j++) {
            struct hsbt *flip = NULL;

            /* If a non-wildcarded bit is found, finds the flip. */
            if (((byte >> 2*j) & 0x03) == 0x01) {
                flip = hsbt_create_all_wildcarded(hsbt->len);
                flip->hs_arr[i] = ((0xfe << 2*j) & 0xff) | ((0xff >> (8 - 2*j)) & 0xff);
            } else if (((byte >> 2*j) & 0x03) == 0x02) {
                flip = hsbt_create_all_wildcarded(hsbt->len);
                flip->hs_arr[i] = ((0xfd << 2*j) & 0xff) | ((0xff >> (8 - 2*j)) & 0xff);
            }

            if (flip) {
                list_insert(&hsbt_list->list, &flip->list_node);
            }
        }
    }

    return hsbt_list;
}

/* Given two 'hsbt's, returns the intersection of them.
 * 'comp_1' and 'comp_2' must be of same length.  Returns
 * NULL when the intersection is empty. */
static struct hsbt *
hsbt_intersect(struct hsbt *comp_1, struct hsbt *comp_2)
{
    struct hsbt *result = hsbt_create(comp_1->len);
    size_t i;

    for (i = 0; i < comp_1->len; i++) {
        char *byte = &result->hs_arr[i];

        *byte = comp_1->hs_arr[i] & comp_2->hs_arr[i];
        if ((*byte & 0x03) == 0 || (*byte & 0x0c) == 0
            || (*byte & 0x30) == 0 || (*byte & 0xc0) == 0) {
            hsbt_destroy(result);

            return NULL;
        }
    }

    return result;
}

/* Given two 'hsbt's, returns the difference of the two.
 * 'comp_1' and 'comp_2' must be of same length.  Returns
 * the list of 'hsbt's as an union. */
static struct hsbt_list *
hsbt_diff(struct hsbt *comp_1, struct hsbt *comp_2)
{
    struct hsbt_list *result = hsbt_list_create();
    struct hsbt_list *complement;
    struct hsbt *iter;

    complement = hsbt_complement(comp_2);

    LIST_FOR_EACH (iter, list_node, &complement->list) {
        struct hsbt *intersect = hsbt_intersect(comp_1, iter);

        if (intersect) {
            list_insert(&result->list, &intersect->list_node);
        }
    }

    return result;
}


static void
hsa_match_print(struct ds *out, struct match *match)
{
    match_format(match, out, OFP_DEFAULT_PRIORITY);
    ds_put_cstr(out, "\n");
}

static void
log_match(struct match *match, char *aux)
{
    struct ds out = DS_EMPTY_INITIALIZER;

    ds_put_format(&out, "match (%s): ", aux);
    hsa_match_print(&out, match);
    VLOG_INFO("%s", ds_cstr(&out));
    ds_destroy(&out);
}

static void
hsa_rule_print(struct ds *out, struct hsa_rule *rule)
{
    ds_put_format(out, "table_id=%"PRIu8", ", rule->table_id);
    match_format(&rule->match, out, rule->prio);
    ds_put_cstr(out, ",actions=");
    ofpacts_format(rule->ofpacts, rule->ofpacts_len, out);
    ds_put_cstr(out, "\n");
}

static void
log_rule(struct hsa_rule *rule, char *aux)
{
    struct ds out = DS_EMPTY_INITIALIZER;

    ds_put_format(&out, "rule (%s): ", aux);
    hsa_rule_print(&out, rule);
    VLOG_INFO("%s", ds_cstr(&out));
    ds_destroy(&out);
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
    struct flow_wildcards wc;

    flow_wildcards_and(&wc, &hs->match_hs.wc, &rule->match.wc);

    return flow_equal_except(&hs->match_hs.flow, &rule->match.flow, &wc);
}

/* Given the 'hsbt_list', checks if 'rule' can still match some of the
 * partitioned header space.  */
static bool
hsa_hsbt_check_match(struct hsbt_list *hsbt_list, struct hsa_rule *rule)
{
    struct hsbt *hsbt_flow = match_to_hsbt(&rule->match);
    struct hsbt *iter;

    LIST_FOR_EACH (iter, list_node, &hsbt_list->list) {
        if (hsbt_intersect(iter, hsbt_flow)) {
            hsbt_destroy(hsbt_flow);
            return true;
        }
    }

    return false;
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
    FLOW_ATTR(regs[0])                           \
    FLOW_ATTR(regs[1])                           \
    FLOW_ATTR(regs[2])                           \
    FLOW_ATTR(regs[3])                           \
    FLOW_ATTR(regs[4])                           \
    FLOW_ATTR(regs[5])                           \
    FLOW_ATTR(regs[6])                           \
    FLOW_ATTR(regs[7])                           \
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

/* Applies the 'rule's flow format and wildcards to header
 * space 'hs'. */
static void
hsa_rule_apply_match(struct header_space *hs, struct hsa_rule *rule)
{
    struct flow *masks = &rule->match.wc.masks;
    struct flow *flow = &rule->match.flow;

    /* If the field in rule is masked, applies 'field & field mask'
     * to header space.  If the 'field' in 'match_flow' and 'match_hs'
     * are different, does not set 'match_flow', since that indicates
     * the 'field' has been set by action. */
#define FLOW_ATTR(ATTR)                                                 \
    if (!flow_wildcard_is_fully_unmasked(&masks->ATTR,                  \
                                         sizeof masks->ATTR)) {         \
        if (!memcmp(&hs->match_flow.flow.ATTR, &hs->match_hs.flow.ATTR, \
                    sizeof hs->match_flow.flow.ATTR)) {                 \
            flow_wildcard_apply(&hs->match_flow.flow.ATTR,              \
                                &hs->match_flow.wc.masks.ATTR,          \
                                &flow->ATTR, &masks->ATTR, sizeof flow->ATTR); \
        }                                                               \
        flow_wildcard_apply(&hs->match_hs.flow.ATTR,                    \
                            &hs->match_hs.wc.masks.ATTR,                \
                            &flow->ATTR, &masks->ATTR, sizeof flow->ATTR); \
    }
    FLOW_ATTRS
#undef FLOW_ATTR
}

/* Given the 'hsbt_list', applies the 'rule' to partition the header
 * space.  If 'hsbt_list' comes out empty, it means entire header space
 * has been taken and no following rules could match. */
static void
hsa_hsbt_apply_match(struct hsbt_list *hsbt_list, struct hsa_rule *rule)
{
    struct hsbt *hsbt_flow = match_to_hsbt(&rule->match);

    hsbt_list_apply_hsbt(hsbt_list, hsbt_flow);
}

/* Appends the 'rule' as constraint to 'hs'.  Caution, only the
 * 'hs->valid_fields' of 'rule' are used. */
static void
hsa_hs_apply_constraint(struct header_space *hs, struct hsa_rule *rule)
{
    struct hsa_constraint *c = xmalloc(sizeof *c);

    c->match = rule->match;

    /* If the 'ATTR' in 'match_flow' and 'match_hs' are different,
     * unmask the 'ATTR' in 'hs->valid_fields'.  This is to avoid
     * adding 'ATTR's set by actions as constraint. */
#define FLOW_ATTR(ATTR)                                                 \
    if (!memcmp(&hs->match_flow.flow.ATTR, &hs->match_hs.flow.ATTR,     \
                sizeof hs->match_flow.flow.ATTR)) {                     \
        WC_UNMASK_FIELD(&hs->valid_fields, ATTR);                       \
    }
    FLOW_ATTRS
#undef FLOW_ATTR

    list_insert(&hs->constraints.list, &c->list_node);
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
        ovs_assert(false);
        break;
    case OFPP_CONTROLLER:
        /* Do not thing. */
        break;
    default:
        if (port != hs->match_hs.flow.in_port.ofp_port) {
            /* Clones the 'hs' with the output, attachs to the result
             * list. */
            struct header_space *clone = hs_clone(hs);

            clone->output = port;
            list_insert(&hsa_result->hs_list, &clone->list_node);
        } else {
            VLOG_ERR("output to input port: %"PRIu16, port);
        }
        break;
    }
}

/* Applies the 'rule's actions to header space 'hs'.  This may generate
 * more 'struct header space's (i.e. by the resubmit action).  Returns the
 * list of 'struct header space's after action application.
 *
 * This function takes ownership of 'hs'. */
static struct hsa_list *
hsa_rule_apply_actions(struct header_space *input_hs, struct hsa_rule *rule,
                       uint8_t cur_table_id, struct ds *out, int indent)
{
    const struct ofpact *ofpacts = rule->ofpacts;
    struct hsa_list *ret = hsa_list_create();
    size_t ofpacts_len = rule->ofpacts_len;
    const struct ofpact *a;

    /* 'ret' could be changed by multiple 'resubmit' actions. */
    list_insert(&ret->hs_list, &input_hs->list_node);

    OFPACT_FOR_EACH (a, ofpacts, ofpacts_len) {
        struct header_space *hs, *next;
        struct hsa_list *new_ret = hsa_list_create();

        /* Executes action for each 'hs'. */
        LIST_FOR_EACH_SAFE (hs, next, list_node, &ret->hs_list) {
            struct flow *hs_flow = &hs->match_hs.flow;
            struct flow_wildcards *hs_wc = &hs->match_hs.wc;
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
                struct hsa_list *list;
                uint8_t table_id;

                if (in_port == OFPP_IN_PORT) {
                    in_port = hs->match_hs.flow.in_port.ofp_port;
                }

                table_id = resubmit->table_id;
                if (table_id == 255) {
                    table_id = cur_table_id;
                }

                list = hsa_calculate(hs, table_id, out, indent + 1);

                /* If 'list' is empty, the 'hs' has no match from the table.
                 * just attaches 'hs' to 'ret'.  Otherwise, splices 'list' to
                 * 'ret'. */
                if (list_is_empty(&list->hs_list)) {
                    list_remove(&hs->list_node);
                    list_insert(&new_ret->hs_list, &hs->list_node);
                } else {
                    list_splice(&new_ret->hs_list, list_front(&list->hs_list),
                                &list->hs_list);
                }
                hsa_list_destroy(list);

                break;
            }

            case OFPACT_BUNDLE: {
                const struct ofpact_bundle *bundle = ofpact_get_BUNDLE(a);
                int i;

                /* Assumes all slaves are enabled and subject to selection.
                 * So, sets the 'bundle->dst' for each slave. */
                for (i = 0; i < bundle->n_slaves; i++) {
                    struct header_space *clone = hs_clone(hs);
                    ofp_port_t port = bundle->slaves[i];

                    nxm_reg_load(&bundle->dst, ofp_to_u16(port),
                                 &clone->match_hs.flow,
                                 &clone->match_hs.wc);
                    list_insert(&new_ret->hs_list, &clone->list_node);
                }
                break;
            }

            case OFPACT_OUTPUT_REG: {
                const struct ofpact_output_reg *or = ofpact_get_OUTPUT_REG(a);
                uint64_t port = mf_get_subfield(&or->src, &hs->match_hs.flow);

                if (port <= UINT16_MAX) {
                    union mf_subvalue value;

                    memset(&value, 0xFF, sizeof value);
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

        if (!list_is_empty(&new_ret->hs_list)) {
            hsa_list_destroy(ret);
            ret = new_ret;
        }
    }

    return ret;
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

    /* Initializes the 'hs_start', sets and masks the 'in_port' and 'regs'. */
    hs_start = hs_create();
    hs_init__(hs_start, ofp_port);

    if (debug_enabled) {
        ds_put_char_multiple(out, '\t', INDENT_DEFAULT);
        ds_put_cstr(out, "Header-Space init done:\n");
        hsa_match_print(out, &hs_start->match_hs);
    }

    hsa_result = hsa_list_create();
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
    hs_destroy(hs_start);
    free(hsa_result);
}

static struct hsa_list *
hsa_list_create(void)
{
    struct hsa_list *list = xmalloc(sizeof *list);

    list_init(&list->hs_list);

    return list;
}

static void
hsa_list_destroy(struct hsa_list *list)
{
    struct header_space *iter, *next;

    LIST_FOR_EACH_SAFE (iter, next, list_node, &list->hs_list) {
        list_remove(&iter->list_node);
        hs_destroy(iter);
    }
    free(list);
}

/* Creates and returns a newly zalloc'ed 'hs'. */
static struct header_space *
hs_create(void)
{
    struct header_space *hs = xzalloc(sizeof *hs);

    hs->output = OFPP_NONE;
    flow_wildcards_init_catchall(&hs->valid_fields);
    list_init(&hs->constraints.list);

    return hs;
}

/* Clones the header space 'hs' and returns the copy. */
static struct header_space *
hs_clone(const struct header_space *hs)
{
    struct header_space *clone = hs_create();
    struct hsa_constraint *iter;

    clone->match_hs = hs->match_hs;
    clone->match_flow = hs->match_flow;

    /* Copies the constraints. */
    LIST_FOR_EACH (iter, list_node, &hs->constraints.list) {
        struct hsa_constraint *copy = xmalloc(sizeof *copy);

        copy->match = iter->match;
        list_insert(&clone->constraints.list, &copy->list_node);
    }
    clone->valid_fields = hs->valid_fields;

    return clone;
}

/* Destroys a header space.  */
static void
hs_destroy(struct header_space *hs)
{
    struct hsa_constraint *iter, *next;

    /* Destroys constraints. */
    LIST_FOR_EACH_SAFE (iter, next, list_node, &hs->constraints.list) {
        list_remove(&iter->list_node);
        free(iter);
    }

    free(hs);
}

/* Given header space 'hs', finds matches from 'hsa_table' with id
 * 'table_id' and applies the actions of matched rules to 'hs'.  Returns
 * a list of all new 'hs's. */
static struct hsa_list *
hsa_calculate(struct header_space *hs, uint8_t table_id, struct ds *out,
              int indent)
{
    struct hsa_table *table = &hsa_tables[table_id];
    struct ovs_list *rules = &table->rules;
    struct hsa_rule *rule;
    struct hsa_list *ret = hsa_list_create();
    struct hsbt_list *hsbt_list = hsbt_list_create();
    struct hsbt *hsbt_hs = match_to_hsbt(&hs->match_hs);

    /* Initializes the partition match. */
    list_insert(&hsbt_list->list, &hsbt_hs->list_node);
    log_match(&hs->match_hs, "hsa_calculate");

    if (debug_enabled) {
        ds_put_char_multiple(out, '\t', indent);
        ds_put_format(out, "Lookup from table %"PRIu8", for header space:\n",
                      table_id);
        ds_put_char_multiple(out, '\t', indent);
        hsa_match_print(out, &hs->match_hs);
    }

    LIST_FOR_EACH(rule, node, rules) {
        /* Found a match, clones the 'hs' and applies match's wc
         * to 'hs'. */
        if (hsa_rule_check_match(hs, rule)
            && hsa_hsbt_check_match(hsbt_list, rule)) {
            struct header_space *clone = hs_clone(hs);
            struct hsa_list *list;

            /* Applies the flow fields. */
            hsa_rule_apply_match(clone, rule);
            hsa_hsbt_apply_match(hsbt_list, rule);
            hsa_hs_apply_constraint(hs, rule);

            if (debug_enabled) {
                ds_put_char_multiple(out, '\t', indent);
                ds_put_cstr(out, "Found match rule:");
                hsa_rule_print(out, rule);
                ds_put_char_multiple(out, '\t', indent);
                ds_put_cstr(out, "Header-Space changed to:");
                hsa_match_print(out, &clone->match_hs);
            }

            /* Applies the actions. */
            list = hsa_rule_apply_actions(clone, rule, table_id, out, indent);

            /* Otherwise, adds the contraints to 'hs'. */
            /* Fix me, to-do. */

            /* Splices the 'action_list' to 'ret'. */
            list_splice(&ret->hs_list, list_front(&list->hs_list),
                        &list->hs_list);

            hsa_list_destroy(list);
        }
    }

    hsbt_list_destroy(hsbt_list);

    return ret;
}


static void
hsa_print_result(struct ds *out, struct hsa_list *result)
{
    struct header_space *hs;

    ds_put_cstr(out, "\n\n\nOUTPUT\n======\n");
    ds_put_cstr(out, "Port No      Input Header Space\n");
    ds_put_cstr(out, "=======      ==================\n");
    LIST_FOR_EACH (hs, list_node, &result->hs_list) {
        if (list_is_empty(&hs->constraints.list)) {
            ds_put_format(out, "%-16"PRIu16"   ", hs->output);
            hsa_match_print(out, &hs->match_flow);
        } else {
            struct hsbt_list *hsbt_list = hsbt_list_create();
            struct hsbt *hsbt_hs = match_to_hsbt(&hs->match_flow);
            struct hsbt *iter;
            struct hsa_constraint *c;

            list_insert(&hsbt_list->list, &hsbt_hs->list_node);

            LIST_FOR_EACH (c, list_node, &hs->constraints.list) {
                struct hsbt *hsbt_c = match_to_hsbt(&c->match);

                hsbt_list_apply_hsbt(hsbt_list, hsbt_c);
                hsbt_destroy(hsbt_c);
            }

            ovs_assert(!list_is_empty(&hsbt_list->list));

            /* Restores the 'match' from 'hsbt'. */
            LIST_FOR_EACH (iter, list_node, &hsbt_list->list) {
                struct match output;

                match_from_hsbt(iter, &output);
                ds_put_format(out, "%-16"PRIu16"   ", hs->output);
                hsa_match_print(out, &output);
            }

            hsbt_list_destroy(hsbt_list);
        }
    }
}


static void
ofproto_dpif_unixctl_hsa_calc(struct unixctl_conn *conn, int argc OVS_UNUSED,
                              const char *argv[], void *aux OVS_UNUSED)
{
    struct ds out = DS_EMPTY_INITIALIZER;
    struct hsa_list *list;
    struct ofproto *ofproto;
    ofp_port_t ofp_port;
    size_t i;

    ofproto = ofproto_lookup(argv[1]);
    if (!ofproto) {
        unixctl_command_reply_error(conn, "no such bridge");
        return;
    }

    ofp_port = OFP_PORT_C(atoi(argv[2]));

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
                hsa_rule_print(&out, rule);
            }
        }
    }

    /* Starts the HSA with global header space and table 0. */
    list = hsa_calculate(hs_start, TABLE_DEFAULT, &out, INDENT_DEFAULT);

    /* Print output. */
    hsa_print_result(&out, hsa_result);

    /* Cleans up. */
    hsa_list_destroy(list);
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
