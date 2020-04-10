/*
API  for "files sender"
Kit of varios functions 
for programm  "file sender"
It contains protocols for files sender 

*/

#include <math.h>
#include <stdio.h>
#include "protocol.h"


#if defined(CONFIG_IP_PNP_DHCP)
#define IPCONFIG_DHCP
#endif
#if defined(CONFIG_IP_PNP_BOOTP) || defined(CONFIG_IP_PNP_DHCP)
#define IPCONFIG_BOOTP
#endif
#if defined(CONFIG_IP_PNP_RARP)
#define IPCONFIG_RARP
#endif
#if defined(IPCONFIG_BOOTP) || defined(IPCONFIG_RARP)
#define IPCONFIG_DYNAMIC
#endif

/* Define the friendly delay before and after opening net devices */
#define CONF_POST_OPEN		10	/* After opening: 10 msecs */

/* Define the timeout for waiting for a DHCP/BOOTP/RARP reply */
#define CONF_OPEN_RETRIES 	2	/* (Re)open devices twice */
#define CONF_SEND_RETRIES 	6	/* Send six requests per open */
#define CONF_BASE_TIMEOUT	(HZ*2)	/* Initial timeout: 2 seconds */
#define CONF_TIMEOUT_RANDOM	(HZ)	/* Maximum amount of randomization */
#define CONF_TIMEOUT_MULT	*7/4	/* Rate of timeout growth */
#define CONF_TIMEOUT_MAX	(HZ*30)	/* Maximum allowed timeout */
#define CONF_NAMESERVERS_MAX   3       /* Maximum number of nameservers
					   - '3' from resolv.h */
#define CONF_NTP_SERVERS_MAX   3	/* Maximum number of NTP servers */

#define NONE cpu_to_be32(INADDR_NONE)
#define ANY cpu_to_be32(INADDR_ANY)

/* Wait for carrier timeout default in seconds */
static unsigned int carrier_timeout = 120;

/*
 * Public IP configuration
 */

/* This is used by platforms which might be able to set the ipconfig
 * variables using firmware environment vars.  If this is set, it will
 * ignore such firmware variables.
 */
int ic_set_manually __initdata = 0;		/* IPconfig parameters set manually */

static int ic_enable __initdata;		/* IP config enabled? */

/* Protocol choice */
int ic_proto_enabled __initdata = 0
#ifdef IPCONFIG_BOOTP
			| IC_BOOTP
#endif
#ifdef CONFIG_IP_PNP_DHCP
			| IC_USE_DHCP
#endif
#ifdef IPCONFIG_RARP
			| IC_RARP
#endif
			;

#define MAX_SEQ 1 

#define NF_CT_PPTP_VERSION "3.1"

typedef enum {frame_arrival , cksum_err , timeout} event_type;


int get_location_another_computer()
{
   int get_location();
   int get_mac_address();
   int buffer_in [] = {}; // buffer for income
   int buffer_out [] = {};// buffer for outcome

   return address_PC;
}

struct protocol_PAR 
{
  // simplex sending 

  void sender3(void)
  {
     seq_nr next_frame_to_send;

     frame s;
     packet buffer;
     event_type event;

     next_frame_to_send =0;

     from_network_layer(&buffer);
     
     while(true)
     {
         s.info = buffer;
         s.seq = next_frame_to_send;
         to_physical_layer(&s);
         start_timer(s.seq);
         wait_for_event(&event);
         if (event == frame_arrival){
              from_physical_layer(&s); /* get acception */
              if (s.ack == next_frame_to_send)
              {
                  from_network_layer(&buffer);

                  inc(next_frame_to_send); /*dont touch variable*/
              }
         }
     }
     
  } 

  void receiver3(void)
  {

      seq_nr frame_expected;
      frame r, s;
      event_type event;

      frame_expected = 0 ;
      while(true)
      {
          wait_for_event(&event);

          if (event == frame_arrival) 
          {
              from_physical_layer(&r);
              if (r.seq == frame_expected)
              {
                  to_network_layer(&r.info); 
                  inc(frame_expected); /*dont touch variable*/
              }

              s.ack = 1 - frame_expected;

              to_physical_layer(%s);
          }
      }


  }
  
};

struct PPTP 
{

    MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harald Welte <laforge@gnumonks.org>");
MODULE_DESCRIPTION("Netfilter connection tracking helper module for PPTP");
MODULE_ALIAS("ip_conntrack_pptp");
MODULE_ALIAS_NFCT_HELPER("pptp");

static DEFINE_SPINLOCK(nf_pptp_lock);

int
(*nf_nat_pptp_hook_outbound)(struct sk_buff *skb,
			     struct nf_conn *ct, enum ip_conntrack_info ctinfo,
			     unsigned int protoff, struct PptpControlHeader *ctlh,
			     union pptp_ctrl_union *pptpReq) __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_pptp_hook_outbound);

int
(*nf_nat_pptp_hook_inbound)(struct sk_buff *skb,
			    struct nf_conn *ct, enum ip_conntrack_info ctinfo,
			    unsigned int protoff, struct PptpControlHeader *ctlh,
			    union pptp_ctrl_union *pptpReq) __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_pptp_hook_inbound);

void
(*nf_nat_pptp_hook_exp_gre)(struct nf_conntrack_expect *expect_orig,
			    struct nf_conntrack_expect *expect_reply)
			    __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_pptp_hook_exp_gre);

void
(*nf_nat_pptp_hook_expectfn)(struct nf_conn *ct,
			     struct nf_conntrack_expect *exp) __read_mostly;
EXPORT_SYMBOL_GPL(nf_nat_pptp_hook_expectfn);

#if defined(DEBUG) || defined(CONFIG_DYNAMIC_DEBUG)
/* PptpControlMessageType names */
const char *const pptp_msg_name[] = {
	"UNKNOWN_MESSAGE",
	"START_SESSION_REQUEST",
	"START_SESSION_REPLY",
	"STOP_SESSION_REQUEST",
	"STOP_SESSION_REPLY",
	"ECHO_REQUEST",
	"ECHO_REPLY",
	"OUT_CALL_REQUEST",
	"OUT_CALL_REPLY",
	"IN_CALL_REQUEST",
	"IN_CALL_REPLY",
	"IN_CALL_CONNECT",
	"CALL_CLEAR_REQUEST",
	"CALL_DISCONNECT_NOTIFY",
	"WAN_ERROR_NOTIFY",
	"SET_LINK_INFO"
};
EXPORT_SYMBOL(pptp_msg_name);
#endif

#define SECS *HZ
#define MINS * 60 SECS
#define HOURS * 60 MINS

#define PPTP_GRE_TIMEOUT 		(10 MINS)
#define PPTP_GRE_STREAM_TIMEOUT 	(5 HOURS)

static void pptp_expectfn(struct nf_conn *ct,
			 struct nf_conntrack_expect *exp)
{
	struct net *net = nf_ct_net(ct);
	typeof(nf_nat_pptp_hook_expectfn) nf_nat_pptp_expectfn;
	pr_debug("increasing timeouts\n");

	/* increase timeout of GRE data channel conntrack entry */
	ct->proto.gre.timeout	     = PPTP_GRE_TIMEOUT;
	ct->proto.gre.stream_timeout = PPTP_GRE_STREAM_TIMEOUT;

	/* Can you see how rusty this code is, compared with the pre-2.6.11
	 * one? That's what happened to my shiny newnat of 2002 ;( -HW */

	nf_nat_pptp_expectfn = rcu_dereference(nf_nat_pptp_hook_expectfn);
	if (nf_nat_pptp_expectfn && ct->master->status & IPS_NAT_MASK)
		nf_nat_pptp_expectfn(ct, exp);
	else {
		struct nf_conntrack_tuple inv_t;
		struct nf_conntrack_expect *exp_other;

		/* obviously this tuple inversion only works until you do NAT */
		nf_ct_invert_tuple(&inv_t, &exp->tuple);
		pr_debug("trying to unexpect other dir: ");
		nf_ct_dump_tuple(&inv_t);

		exp_other = nf_ct_expect_find_get(net, nf_ct_zone(ct), &inv_t);
		if (exp_other) {
			/* delete other expectation.  */
			pr_debug("found\n");
			nf_ct_unexpect_related(exp_other);
			nf_ct_expect_put(exp_other);
		} else {
			pr_debug("not found\n");
		}
	}
}

static int destroy_sibling_or_exp(struct net *net, struct nf_conn *ct,
				  const struct nf_conntrack_tuple *t)
{
	const struct nf_conntrack_tuple_hash *h;
	const struct nf_conntrack_zone *zone;
	struct nf_conntrack_expect *exp;
	struct nf_conn *sibling;

	pr_debug("trying to timeout ct or exp for tuple ");
	nf_ct_dump_tuple(t);

	zone = nf_ct_zone(ct);
	h = nf_conntrack_find_get(net, zone, t);
	if (h)  {
		sibling = nf_ct_tuplehash_to_ctrack(h);
		pr_debug("setting timeout of conntrack %p to 0\n", sibling);
		sibling->proto.gre.timeout	  = 0;
		sibling->proto.gre.stream_timeout = 0;
		nf_ct_kill(sibling);
		nf_ct_put(sibling);
		return 1;
	} else {
		exp = nf_ct_expect_find_get(net, zone, t);
		if (exp) {
			pr_debug("unexpect_related of expect %p\n", exp);
			nf_ct_unexpect_related(exp);
			nf_ct_expect_put(exp);
			return 1;
		}
	}
	return 0;
}

/* timeout GRE data connections */
static void pptp_destroy_siblings(struct nf_conn *ct)
{
	struct net *net = nf_ct_net(ct);
	const struct nf_ct_pptp_master *ct_pptp_info = nfct_help_data(ct);
	struct nf_conntrack_tuple t;

	nf_ct_gre_keymap_destroy(ct);

	/* try original (pns->pac) tuple */
	memcpy(&t, &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple, sizeof(t));
	t.dst.protonum = IPPROTO_GRE;
	t.src.u.gre.key = ct_pptp_info->pns_call_id;
	t.dst.u.gre.key = ct_pptp_info->pac_call_id;
	if (!destroy_sibling_or_exp(net, ct, &t))
		pr_debug("failed to timeout original pns->pac ct/exp\n");

	/* try reply (pac->pns) tuple */
	memcpy(&t, &ct->tuplehash[IP_CT_DIR_REPLY].tuple, sizeof(t));
	t.dst.protonum = IPPROTO_GRE;
	t.src.u.gre.key = ct_pptp_info->pac_call_id;
	t.dst.u.gre.key = ct_pptp_info->pns_call_id;
	if (!destroy_sibling_or_exp(net, ct, &t))
		pr_debug("failed to timeout reply pac->pns ct/exp\n");
}

/* expect GRE connections (PNS->PAC and PAC->PNS direction) */
static int exp_gre(struct nf_conn *ct, __be16 callid, __be16 peer_callid)
{
	struct nf_conntrack_expect *exp_orig, *exp_reply;
	enum ip_conntrack_dir dir;
	int ret = 1;
	typeof(nf_nat_pptp_hook_exp_gre) nf_nat_pptp_exp_gre;

	exp_orig = nf_ct_expect_alloc(ct);
	if (exp_orig == NULL)
		goto out;

	exp_reply = nf_ct_expect_alloc(ct);
	if (exp_reply == NULL)
		goto out_put_orig;

	/* original direction, PNS->PAC */
	dir = IP_CT_DIR_ORIGINAL;
	nf_ct_expect_init(exp_orig, NF_CT_EXPECT_CLASS_DEFAULT,
			  nf_ct_l3num(ct),
			  &ct->tuplehash[dir].tuple.src.u3,
			  &ct->tuplehash[dir].tuple.dst.u3,
			  IPPROTO_GRE, &peer_callid, &callid);
	exp_orig->expectfn = pptp_expectfn;

	/* reply direction, PAC->PNS */
	dir = IP_CT_DIR_REPLY;
	nf_ct_expect_init(exp_reply, NF_CT_EXPECT_CLASS_DEFAULT,
			  nf_ct_l3num(ct),
			  &ct->tuplehash[dir].tuple.src.u3,
			  &ct->tuplehash[dir].tuple.dst.u3,
			  IPPROTO_GRE, &callid, &peer_callid);
	exp_reply->expectfn = pptp_expectfn;

	nf_nat_pptp_exp_gre = rcu_dereference(nf_nat_pptp_hook_exp_gre);
	if (nf_nat_pptp_exp_gre && ct->status & IPS_NAT_MASK)
		nf_nat_pptp_exp_gre(exp_orig, exp_reply);
	if (nf_ct_expect_related(exp_orig, 0) != 0)
		goto out_put_both;
	if (nf_ct_expect_related(exp_reply, 0) != 0)
		goto out_unexpect_orig;

	/* Add GRE keymap entries */
	if (nf_ct_gre_keymap_add(ct, IP_CT_DIR_ORIGINAL, &exp_orig->tuple) != 0)
		goto out_unexpect_both;
	if (nf_ct_gre_keymap_add(ct, IP_CT_DIR_REPLY, &exp_reply->tuple) != 0) {
		nf_ct_gre_keymap_destroy(ct);
		goto out_unexpect_both;
	}
	ret = 0;

out_put_both:
	nf_ct_expect_put(exp_reply);
out_put_orig:
	nf_ct_expect_put(exp_orig);
out:
	return ret;

out_unexpect_both:
	nf_ct_unexpect_related(exp_reply);
out_unexpect_orig:
	nf_ct_unexpect_related(exp_orig);
	goto out_put_both;
}

static int
pptp_inbound_pkt(struct sk_buff *skb, unsigned int protoff,
		 struct PptpControlHeader *ctlh,
		 union pptp_ctrl_union *pptpReq,
		 unsigned int reqlen,
		 struct nf_conn *ct,
		 enum ip_conntrack_info ctinfo)
{
	struct nf_ct_pptp_master *info = nfct_help_data(ct);
	u_int16_t msg;
	__be16 cid = 0, pcid = 0;
	typeof(nf_nat_pptp_hook_inbound) nf_nat_pptp_inbound;

	msg = ntohs(ctlh->messageType);
	pr_debug("inbound control message %s\n", pptp_msg_name[msg]);

	switch (msg) {
	case PPTP_START_SESSION_REPLY:
		/* server confirms new control session */
		if (info->sstate < PPTP_SESSION_REQUESTED)
			goto invalid;
		if (pptpReq->srep.resultCode == PPTP_START_OK)
			info->sstate = PPTP_SESSION_CONFIRMED;
		else
			info->sstate = PPTP_SESSION_ERROR;
		break;

	case PPTP_STOP_SESSION_REPLY:
		/* server confirms end of control session */
		if (info->sstate > PPTP_SESSION_STOPREQ)
			goto invalid;
		if (pptpReq->strep.resultCode == PPTP_STOP_OK)
			info->sstate = PPTP_SESSION_NONE;
		else
			info->sstate = PPTP_SESSION_ERROR;
		break;

	case PPTP_OUT_CALL_REPLY:
		/* server accepted call, we now expect GRE frames */
		if (info->sstate != PPTP_SESSION_CONFIRMED)
			goto invalid;
		if (info->cstate != PPTP_CALL_OUT_REQ &&
		    info->cstate != PPTP_CALL_OUT_CONF)
			goto invalid;

		cid = pptpReq->ocack.callID;
		pcid = pptpReq->ocack.peersCallID;
		if (info->pns_call_id != pcid)
			goto invalid;
		pr_debug("%s, CID=%X, PCID=%X\n", pptp_msg_name[msg],
			 ntohs(cid), ntohs(pcid));

		if (pptpReq->ocack.resultCode == PPTP_OUTCALL_CONNECT) {
			info->cstate = PPTP_CALL_OUT_CONF;
			info->pac_call_id = cid;
			exp_gre(ct, cid, pcid);
		} else
			info->cstate = PPTP_CALL_NONE;
		break;

	case PPTP_IN_CALL_REQUEST:
		/* server tells us about incoming call request */
		if (info->sstate != PPTP_SESSION_CONFIRMED)
			goto invalid;

		cid = pptpReq->icreq.callID;
		pr_debug("%s, CID=%X\n", pptp_msg_name[msg], ntohs(cid));
		info->cstate = PPTP_CALL_IN_REQ;
		info->pac_call_id = cid;
		break;

	case PPTP_IN_CALL_CONNECT:
		/* server tells us about incoming call established */
		if (info->sstate != PPTP_SESSION_CONFIRMED)
			goto invalid;
		if (info->cstate != PPTP_CALL_IN_REP &&
		    info->cstate != PPTP_CALL_IN_CONF)
			goto invalid;

		pcid = pptpReq->iccon.peersCallID;
		cid = info->pac_call_id;

		if (info->pns_call_id != pcid)
			goto invalid;

		pr_debug("%s, PCID=%X\n", pptp_msg_name[msg], ntohs(pcid));
		info->cstate = PPTP_CALL_IN_CONF;

		/* we expect a GRE connection from PAC to PNS */
		exp_gre(ct, cid, pcid);
		break;

	case PPTP_CALL_DISCONNECT_NOTIFY:
		/* server confirms disconnect */
		cid = pptpReq->disc.callID;
		pr_debug("%s, CID=%X\n", pptp_msg_name[msg], ntohs(cid));
		info->cstate = PPTP_CALL_NONE;

		/* untrack this call id, unexpect GRE packets */
		pptp_destroy_siblings(ct);
		break;

	case PPTP_WAN_ERROR_NOTIFY:
	case PPTP_SET_LINK_INFO:
	case PPTP_ECHO_REQUEST:
	case PPTP_ECHO_REPLY:
		/* I don't have to explain these ;) */
		break;

	default:
		goto invalid;
	}

	nf_nat_pptp_inbound = rcu_dereference(nf_nat_pptp_hook_inbound);
	if (nf_nat_pptp_inbound && ct->status & IPS_NAT_MASK)
		return nf_nat_pptp_inbound(skb, ct, ctinfo,
					   protoff, ctlh, pptpReq);
	return NF_ACCEPT;

invalid:
	pr_debug("invalid %s: type=%d cid=%u pcid=%u "
		 "cstate=%d sstate=%d pns_cid=%u pac_cid=%u\n",
		 msg <= PPTP_MSG_MAX ? pptp_msg_name[msg] : pptp_msg_name[0],
		 msg, ntohs(cid), ntohs(pcid),  info->cstate, info->sstate,
		 ntohs(info->pns_call_id), ntohs(info->pac_call_id));
	return NF_ACCEPT;
}

static int
pptp_outbound_pkt(struct sk_buff *skb, unsigned int protoff,
		  struct PptpControlHeader *ctlh,
		  union pptp_ctrl_union *pptpReq,
		  unsigned int reqlen,
		  struct nf_conn *ct,
		  enum ip_conntrack_info ctinfo)
{
	struct nf_ct_pptp_master *info = nfct_help_data(ct);
	u_int16_t msg;
	__be16 cid = 0, pcid = 0;
	typeof(nf_nat_pptp_hook_outbound) nf_nat_pptp_outbound;

	msg = ntohs(ctlh->messageType);
	pr_debug("outbound control message %s\n", pptp_msg_name[msg]);

	switch (msg) {
	case PPTP_START_SESSION_REQUEST:
		/* client requests for new control session */
		if (info->sstate != PPTP_SESSION_NONE)
			goto invalid;
		info->sstate = PPTP_SESSION_REQUESTED;
		break;

	case PPTP_STOP_SESSION_REQUEST:
		/* client requests end of control session */
		info->sstate = PPTP_SESSION_STOPREQ;
		break;

	case PPTP_OUT_CALL_REQUEST:
		/* client initiating connection to server */
		if (info->sstate != PPTP_SESSION_CONFIRMED)
			goto invalid;
		info->cstate = PPTP_CALL_OUT_REQ;
		/* track PNS call id */
		cid = pptpReq->ocreq.callID;
		pr_debug("%s, CID=%X\n", pptp_msg_name[msg], ntohs(cid));
		info->pns_call_id = cid;
		break;

	case PPTP_IN_CALL_REPLY:
		/* client answers incoming call */
		if (info->cstate != PPTP_CALL_IN_REQ &&
		    info->cstate != PPTP_CALL_IN_REP)
			goto invalid;

		cid = pptpReq->icack.callID;
		pcid = pptpReq->icack.peersCallID;
		if (info->pac_call_id != pcid)
			goto invalid;
		pr_debug("%s, CID=%X PCID=%X\n", pptp_msg_name[msg],
			 ntohs(cid), ntohs(pcid));

		if (pptpReq->icack.resultCode == PPTP_INCALL_ACCEPT) {
			/* part two of the three-way handshake */
			info->cstate = PPTP_CALL_IN_REP;
			info->pns_call_id = cid;
		} else
			info->cstate = PPTP_CALL_NONE;
		break;

	case PPTP_CALL_CLEAR_REQUEST:
		/* client requests hangup of call */
		if (info->sstate != PPTP_SESSION_CONFIRMED)
			goto invalid;
		/* FUTURE: iterate over all calls and check if
		 * call ID is valid.  We don't do this without newnat,
		 * because we only know about last call */
		info->cstate = PPTP_CALL_CLEAR_REQ;
		break;

	case PPTP_SET_LINK_INFO:
	case PPTP_ECHO_REQUEST:
	case PPTP_ECHO_REPLY:
		/* I don't have to explain these ;) */
		break;

	default:
		goto invalid;
	}

	nf_nat_pptp_outbound = rcu_dereference(nf_nat_pptp_hook_outbound);
	if (nf_nat_pptp_outbound && ct->status & IPS_NAT_MASK)
		return nf_nat_pptp_outbound(skb, ct, ctinfo,
					    protoff, ctlh, pptpReq);
	return NF_ACCEPT;

invalid:
	pr_debug("invalid %s: type=%d cid=%u pcid=%u "
		 "cstate=%d sstate=%d pns_cid=%u pac_cid=%u\n",
		 msg <= PPTP_MSG_MAX ? pptp_msg_name[msg] : pptp_msg_name[0],
		 msg, ntohs(cid), ntohs(pcid),  info->cstate, info->sstate,
		 ntohs(info->pns_call_id), ntohs(info->pac_call_id));
	return NF_ACCEPT;
}

static const unsigned int pptp_msg_size[] = {
	[PPTP_START_SESSION_REQUEST]  = sizeof(struct PptpStartSessionRequest),
	[PPTP_START_SESSION_REPLY]    = sizeof(struct PptpStartSessionReply),
	[PPTP_STOP_SESSION_REQUEST]   = sizeof(struct PptpStopSessionRequest),
	[PPTP_STOP_SESSION_REPLY]     = sizeof(struct PptpStopSessionReply),
	[PPTP_OUT_CALL_REQUEST]       = sizeof(struct PptpOutCallRequest),
	[PPTP_OUT_CALL_REPLY]	      = sizeof(struct PptpOutCallReply),
	[PPTP_IN_CALL_REQUEST]	      = sizeof(struct PptpInCallRequest),
	[PPTP_IN_CALL_REPLY]	      = sizeof(struct PptpInCallReply),
	[PPTP_IN_CALL_CONNECT]	      = sizeof(struct PptpInCallConnected),
	[PPTP_CALL_CLEAR_REQUEST]     = sizeof(struct PptpClearCallRequest),
	[PPTP_CALL_DISCONNECT_NOTIFY] = sizeof(struct PptpCallDisconnectNotify),
	[PPTP_WAN_ERROR_NOTIFY]	      = sizeof(struct PptpWanErrorNotify),
	[PPTP_SET_LINK_INFO]	      = sizeof(struct PptpSetLinkInfo),
};

/* track caller id inside control connection, call expect_related */
static int
conntrack_pptp_help(struct sk_buff *skb, unsigned int protoff,
		    struct nf_conn *ct, enum ip_conntrack_info ctinfo)

{
	int dir = CTINFO2DIR(ctinfo);
	const struct nf_ct_pptp_master *info = nfct_help_data(ct);
	const struct tcphdr *tcph;
	struct tcphdr _tcph;
	const struct pptp_pkt_hdr *pptph;
	struct pptp_pkt_hdr _pptph;
	struct PptpControlHeader _ctlh, *ctlh;
	union pptp_ctrl_union _pptpReq, *pptpReq;
	unsigned int tcplen = skb->len - protoff;
	unsigned int datalen, reqlen, nexthdr_off;
	int oldsstate, oldcstate;
	int ret;
	u_int16_t msg;

#if IS_ENABLED(CONFIG_NF_NAT)
	if (!nf_ct_is_confirmed(ct) && (ct->status & IPS_NAT_MASK)) {
		struct nf_conn_nat *nat = nf_ct_ext_find(ct, NF_CT_EXT_NAT);

		if (!nat && !nf_ct_ext_add(ct, NF_CT_EXT_NAT, GFP_ATOMIC))
			return NF_DROP;
	}
#endif
	/* don't do any tracking before tcp handshake complete */
	if (ctinfo != IP_CT_ESTABLISHED && ctinfo != IP_CT_ESTABLISHED_REPLY)
		return NF_ACCEPT;

	nexthdr_off = protoff;
	tcph = skb_header_pointer(skb, nexthdr_off, sizeof(_tcph), &_tcph);
	BUG_ON(!tcph);
	nexthdr_off += tcph->doff * 4;
	datalen = tcplen - tcph->doff * 4;

	pptph = skb_header_pointer(skb, nexthdr_off, sizeof(_pptph), &_pptph);
	if (!pptph) {
		pr_debug("no full PPTP header, can't track\n");
		return NF_ACCEPT;
	}
	nexthdr_off += sizeof(_pptph);
	datalen -= sizeof(_pptph);

	/* if it's not a control message we can't do anything with it */
	if (ntohs(pptph->packetType) != PPTP_PACKET_CONTROL ||
	    ntohl(pptph->magicCookie) != PPTP_MAGIC_COOKIE) {
		pr_debug("not a control packet\n");
		return NF_ACCEPT;
	}

	ctlh = skb_header_pointer(skb, nexthdr_off, sizeof(_ctlh), &_ctlh);
	if (!ctlh)
		return NF_ACCEPT;
	nexthdr_off += sizeof(_ctlh);
	datalen -= sizeof(_ctlh);

	reqlen = datalen;
	msg = ntohs(ctlh->messageType);
	if (msg > 0 && msg <= PPTP_MSG_MAX && reqlen < pptp_msg_size[msg])
		return NF_ACCEPT;
	if (reqlen > sizeof(*pptpReq))
		reqlen = sizeof(*pptpReq);

	pptpReq = skb_header_pointer(skb, nexthdr_off, reqlen, &_pptpReq);
	if (!pptpReq)
		return NF_ACCEPT;

	oldsstate = info->sstate;
	oldcstate = info->cstate;

	spin_lock_bh(&nf_pptp_lock);

	/* FIXME: We just blindly assume that the control connection is always
	 * established from PNS->PAC.  However, RFC makes no guarantee */
	if (dir == IP_CT_DIR_ORIGINAL)
		/* client -> server (PNS -> PAC) */
		ret = pptp_outbound_pkt(skb, protoff, ctlh, pptpReq, reqlen, ct,
					ctinfo);
	else
		/* server -> client (PAC -> PNS) */
		ret = pptp_inbound_pkt(skb, protoff, ctlh, pptpReq, reqlen, ct,
				       ctinfo);
	pr_debug("sstate: %d->%d, cstate: %d->%d\n",
		 oldsstate, info->sstate, oldcstate, info->cstate);
	spin_unlock_bh(&nf_pptp_lock);

	return ret;
}

static const struct nf_conntrack_expect_policy pptp_exp_policy = {
	.max_expected	= 2,
	.timeout	= 5 * 60,
};

/* control protocol helper */
static struct nf_conntrack_helper pptp __read_mostly = {
	.name			= "pptp",
	.me			= THIS_MODULE,
	.tuple.src.l3num	= AF_INET,
	.tuple.src.u.tcp.port	= cpu_to_be16(PPTP_CONTROL_PORT),
	.tuple.dst.protonum	= IPPROTO_TCP,
	.help			= conntrack_pptp_help,
	.destroy		= pptp_destroy_siblings,
	.expect_policy		= &pptp_exp_policy,
};

static int __init nf_conntrack_pptp_init(void)
{
	NF_CT_HELPER_BUILD_BUG_ON(sizeof(struct nf_ct_pptp_master));

	return nf_conntrack_helper_register(&pptp);
}

static void __exit nf_conntrack_pptp_fini(void)
{
	nf_conntrack_helper_unregister(&pptp);
}

module_init(nf_conntrack_pptp_init);
module_exit(nf_conntrack_pptp_fini);

};

struct SPPP
{
 #define MAX_PKT 1024 /*Define size of package in byties*/

typedef enum {false ,true} boolean:

typedef unsigned int seq_nr : /*numbers or  coniformations*/

typedef struct 
{
	//definating of package
	unsigned char data[MAX_PKT];
};

typedef enum {data , ack , nak} frame_kind; // define  a type of package 

// we transport data here
typedef struct 
{
	frame_kind kind;/*type cadr*/
	seq_nr seq;/*number in line */
	seq_nr ack;/*number of coniformation*/
	packet info;/* package of network level*/


} frame; 


void wait_for_event(event_type *event);

/*get package from network level*/
void from_network_layer (packet *p);

/*send  information  to network level*/
void  to_network_layer (packet *p);

/**/
void from_physical_layer (frame *r);

/**/
void to_physical_layer(frame *s);


/**/
void start_timer(seq_nr k );

/**/
void stop_ack_timer(seq_nr);

// add second timer and allow event ack_timeout

void start_ack_timer();

void stop_ack_timer();

// allow to network level to init event network_layer_ready
void enable_network_layer(void);

void disable_network_layer(void);

// we are increasing  variable "k"

#define inc(k) if (k<MAX_SEQ)  k=k+1; else k=0

} ;

struct ipconfig 
{
static int ic_host_name_set __initdata;	/* Host name set by us? */

__be32 ic_myaddr = NONE;		/* My IP address */
static __be32 ic_netmask = NONE;	/* Netmask for local subnet */
__be32 ic_gateway = NONE;	/* Gateway IP address */

#ifdef IPCONFIG_DYNAMIC
static __be32 ic_addrservaddr = NONE;	/* IP Address of the IP addresses'server */
#endif

__be32 ic_servaddr = NONE;	/* Boot server IP address */

__be32 root_server_addr = NONE;	/* Address of NFS server */
u8 root_server_path[256] = { 0, };	/* Path to mount as root */

/* vendor class identifier */
static char vendor_class_identifier[253] __initdata;

#if defined(CONFIG_IP_PNP_DHCP)
static char dhcp_client_identifier[253] __initdata;
#endif

/* Persistent data: */

#ifdef IPCONFIG_DYNAMIC
static int ic_proto_used;			/* Protocol used, if any */
#else
#define ic_proto_used 0
#endif
static __be32 ic_nameservers[CONF_NAMESERVERS_MAX]; /* DNS Server IP addresses */
static __be32 ic_ntp_servers[CONF_NTP_SERVERS_MAX]; /* NTP server IP addresses */
static u8 ic_domain[64];		/* DNS (not NIS) domain name */

/*
 * Private state.
 */

/* Name of user-selected boot device */
static char user_dev_name[IFNAMSIZ] __initdata = { 0, };

/* Protocols supported by available interfaces */
static int ic_proto_have_if __initdata;

/* MTU for boot device */
static int ic_dev_mtu __initdata;

#ifdef IPCONFIG_DYNAMIC
static DEFINE_SPINLOCK(ic_recv_lock);
static volatile int ic_got_reply __initdata;    /* Proto(s) that replied */
#endif
#ifdef IPCONFIG_DHCP
static int ic_dhcp_msgtype __initdata;	/* DHCP msg type received */
#endif


/*
 *	Network devices
 */

struct ic_device {
	struct ic_device *next;
	struct net_device *dev;
	unsigned short flags;
	short able;
	__be32 xid;
};

static struct ic_device *ic_first_dev __initdata;	/* List of open device */
static struct ic_device *ic_dev __initdata;		/* Selected device */

static bool __init ic_is_init_dev(struct net_device *dev)
{
	if (dev->flags & IFF_LOOPBACK)
		return false;
	return user_dev_name[0] ? !strcmp(dev->name, user_dev_name) :
	    (!(dev->flags & IFF_LOOPBACK) &&
	     (dev->flags & (IFF_POINTOPOINT|IFF_BROADCAST)) &&
	     strncmp(dev->name, "dummy", 5));
}

static int __init ic_open_devs(void)
{
	struct ic_device *d, **last;
	struct net_device *dev;
	unsigned short oflags;
	unsigned long start, next_msg;

	last = &ic_first_dev;
	rtnl_lock();

	/* bring loopback and DSA master network devices up first */
	for_each_netdev(&init_net, dev) {
		if (!(dev->flags & IFF_LOOPBACK) && !netdev_uses_dsa(dev))
			continue;
		if (dev_change_flags(dev, dev->flags | IFF_UP, NULL) < 0)
			pr_err("IP-Config: Failed to open %s\n", dev->name);
	}

	for_each_netdev(&init_net, dev) {
		if (ic_is_init_dev(dev)) {
			int able = 0;
			if (dev->mtu >= 364)
				able |= IC_BOOTP;
			else
				pr_warn("DHCP/BOOTP: Ignoring device %s, MTU %d too small\n",
					dev->name, dev->mtu);
			if (!(dev->flags & IFF_NOARP))
				able |= IC_RARP;
			able &= ic_proto_enabled;
			if (ic_proto_enabled && !able)
				continue;
			oflags = dev->flags;
			if (dev_change_flags(dev, oflags | IFF_UP, NULL) < 0) {
				pr_err("IP-Config: Failed to open %s\n",
				       dev->name);
				continue;
			}
			if (!(d = kmalloc(sizeof(struct ic_device), GFP_KERNEL))) {
				rtnl_unlock();
				return -ENOMEM;
			}
			d->dev = dev;
			*last = d;
			last = &d->next;
			d->flags = oflags;
			d->able = able;
			if (able & IC_BOOTP)
				get_random_bytes(&d->xid, sizeof(__be32));
			else
				d->xid = 0;
			ic_proto_have_if |= able;
			pr_debug("IP-Config: %s UP (able=%d, xid=%08x)\n",
				 dev->name, able, d->xid);
		}
	}

	/* no point in waiting if we could not bring up at least one device */
	if (!ic_first_dev)
		goto have_carrier;

	/* wait for a carrier on at least one device */
	start = jiffies;
	next_msg = start + msecs_to_jiffies(20000);
	while (time_before(jiffies, start +
			   msecs_to_jiffies(carrier_timeout * 1000))) {
		int wait, elapsed;

		for_each_netdev(&init_net, dev)
			if (ic_is_init_dev(dev) && netif_carrier_ok(dev))
				goto have_carrier;

		msleep(1);

		if (time_before(jiffies, next_msg))
			continue;

		elapsed = jiffies_to_msecs(jiffies - start);
		wait = (carrier_timeout * 1000 - elapsed + 500) / 1000;
		pr_info("Waiting up to %d more seconds for network.\n", wait);
		next_msg = jiffies + msecs_to_jiffies(20000);
	}
have_carrier:
	rtnl_unlock();

	*last = NULL;

	if (!ic_first_dev) {
		if (user_dev_name[0])
			pr_err("IP-Config: Device `%s' not found\n",
			       user_dev_name);
		else
			pr_err("IP-Config: No network devices available\n");
		return -ENODEV;
	}
	return 0;
}

static void __init ic_close_devs(void)
{
	struct ic_device *d, *next;
	struct net_device *dev;

	rtnl_lock();
	next = ic_first_dev;
	while ((d = next)) {
		next = d->next;
		dev = d->dev;
		if (d != ic_dev && !netdev_uses_dsa(dev)) {
			pr_debug("IP-Config: Downing %s\n", dev->name);
			dev_change_flags(dev, d->flags, NULL);
		}
		kfree(d);
	}
	rtnl_unlock();
}

/*
 *	Interface to various network functions.
 */

static inline void
set_sockaddr(struct sockaddr_in *sin, __be32 addr, __be16 port)
{
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = addr;
	sin->sin_port = port;
}

/*
 *	Set up interface addresses and routes.
 */

static int __init ic_setup_if(void)
{
	struct ifreq ir;
	struct sockaddr_in *sin = (void *) &ir.ifr_ifru.ifru_addr;
	int err;

	memset(&ir, 0, sizeof(ir));
	strcpy(ir.ifr_ifrn.ifrn_name, ic_dev->dev->name);
	set_sockaddr(sin, ic_myaddr, 0);
	if ((err = devinet_ioctl(&init_net, SIOCSIFADDR, &ir)) < 0) {
		pr_err("IP-Config: Unable to set interface address (%d)\n",
		       err);
		return -1;
	}
	set_sockaddr(sin, ic_netmask, 0);
	if ((err = devinet_ioctl(&init_net, SIOCSIFNETMASK, &ir)) < 0) {
		pr_err("IP-Config: Unable to set interface netmask (%d)\n",
		       err);
		return -1;
	}
	set_sockaddr(sin, ic_myaddr | ~ic_netmask, 0);
	if ((err = devinet_ioctl(&init_net, SIOCSIFBRDADDR, &ir)) < 0) {
		pr_err("IP-Config: Unable to set interface broadcast address (%d)\n",
		       err);
		return -1;
	}
	/* Handle the case where we need non-standard MTU on the boot link (a network
	 * using jumbo frames, for instance).  If we can't set the mtu, don't error
	 * out, we'll try to muddle along.
	 */
	if (ic_dev_mtu != 0) {
		rtnl_lock();
		if ((err = dev_set_mtu(ic_dev->dev, ic_dev_mtu)) < 0)
			pr_err("IP-Config: Unable to set interface mtu to %d (%d)\n",
			       ic_dev_mtu, err);
		rtnl_unlock();
	}
	return 0;
}

static int __init ic_setup_routes(void)
{
	/* No need to setup device routes, only the default route... */

	if (ic_gateway != NONE) {
		struct rtentry rm;
		int err;

		memset(&rm, 0, sizeof(rm));
		if ((ic_gateway ^ ic_myaddr) & ic_netmask) {
			pr_err("IP-Config: Gateway not on directly connected network\n");
			return -1;
		}
		set_sockaddr((struct sockaddr_in *) &rm.rt_dst, 0, 0);
		set_sockaddr((struct sockaddr_in *) &rm.rt_genmask, 0, 0);
		set_sockaddr((struct sockaddr_in *) &rm.rt_gateway, ic_gateway, 0);
		rm.rt_flags = RTF_UP | RTF_GATEWAY;
		if ((err = ip_rt_ioctl(&init_net, SIOCADDRT, &rm)) < 0) {
			pr_err("IP-Config: Cannot add default route (%d)\n",
			       err);
			return -1;
		}
	}

	return 0;
}

/*
 *	Fill in default values for all missing parameters.
 */

static int __init ic_defaults(void)
{
	/*
	 *	At this point we have no userspace running so need not
	 *	claim locks on system_utsname
	 */

	if (!ic_host_name_set)
		sprintf(init_utsname()->nodename, "%pI4", &ic_myaddr);

	if (root_server_addr == NONE)
		root_server_addr = ic_servaddr;

	if (ic_netmask == NONE) {
		if (IN_CLASSA(ntohl(ic_myaddr)))
			ic_netmask = htonl(IN_CLASSA_NET);
		else if (IN_CLASSB(ntohl(ic_myaddr)))
			ic_netmask = htonl(IN_CLASSB_NET);
		else if (IN_CLASSC(ntohl(ic_myaddr)))
			ic_netmask = htonl(IN_CLASSC_NET);
		else if (IN_CLASSE(ntohl(ic_myaddr)))
			ic_netmask = htonl(IN_CLASSE_NET);
		else {
			pr_err("IP-Config: Unable to guess netmask for address %pI4\n",
			       &ic_myaddr);
			return -1;
		}
		pr_notice("IP-Config: Guessing netmask %pI4\n",
			  &ic_netmask);
	}

	return 0;
}

/*
 *	RARP support.
 */

#ifdef IPCONFIG_RARP

static int ic_rarp_recv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

static struct packet_type rarp_packet_type __initdata = {
	.type =	cpu_to_be16(ETH_P_RARP),
	.func =	ic_rarp_recv,
};

static inline void __init ic_rarp_init(void)
{
	dev_add_pack(&rarp_packet_type);
}

static inline void __init ic_rarp_cleanup(void)
{
	dev_remove_pack(&rarp_packet_type);
}

/*
 *  Process received RARP packet.
 */
static int __init
ic_rarp_recv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct arphdr *rarp;
	unsigned char *rarp_ptr;
	__be32 sip, tip;
	unsigned char *tha;		/* t for "target" */
	struct ic_device *d;

	if (!net_eq(dev_net(dev), &init_net))
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return NET_RX_DROP;

	if (!pskb_may_pull(skb, sizeof(struct arphdr)))
		goto drop;

	/* Basic sanity checks can be done without the lock.  */
	rarp = (struct arphdr *)skb_transport_header(skb);

	/* If this test doesn't pass, it's not IP, or we should
	 * ignore it anyway.
	 */
	if (rarp->ar_hln != dev->addr_len || dev->type != ntohs(rarp->ar_hrd))
		goto drop;

	/* If it's not a RARP reply, delete it. */
	if (rarp->ar_op != htons(ARPOP_RREPLY))
		goto drop;

	/* If it's not Ethernet, delete it. */
	if (rarp->ar_pro != htons(ETH_P_IP))
		goto drop;

	if (!pskb_may_pull(skb, arp_hdr_len(dev)))
		goto drop;

	/* OK, it is all there and looks valid, process... */
	rarp = (struct arphdr *)skb_transport_header(skb);
	rarp_ptr = (unsigned char *) (rarp + 1);

	/* One reply at a time, please. */
	spin_lock(&ic_recv_lock);

	/* If we already have a reply, just drop the packet */
	if (ic_got_reply)
		goto drop_unlock;

	/* Find the ic_device that the packet arrived on */
	d = ic_first_dev;
	while (d && d->dev != dev)
		d = d->next;
	if (!d)
		goto drop_unlock;	/* should never happen */

	/* Extract variable-width fields */
	rarp_ptr += dev->addr_len;
	memcpy(&sip, rarp_ptr, 4);
	rarp_ptr += 4;
	tha = rarp_ptr;
	rarp_ptr += dev->addr_len;
	memcpy(&tip, rarp_ptr, 4);

	/* Discard packets which are not meant for us. */
	if (memcmp(tha, dev->dev_addr, dev->addr_len))
		goto drop_unlock;

	/* Discard packets which are not from specified server. */
	if (ic_servaddr != NONE && ic_servaddr != sip)
		goto drop_unlock;

	/* We have a winner! */
	ic_dev = d;
	if (ic_myaddr == NONE)
		ic_myaddr = tip;
	ic_servaddr = sip;
	ic_addrservaddr = sip;
	ic_got_reply = IC_RARP;

drop_unlock:
	/* Show's over.  Nothing to see here.  */
	spin_unlock(&ic_recv_lock);

drop:
	/* Throw the packet out. */
	kfree_skb(skb);
	return 0;
}


/*
 *  Send RARP request packet over a single interface.
 */
static void __init ic_rarp_send_if(struct ic_device *d)
{
	struct net_device *dev = d->dev;
	arp_send(ARPOP_RREQUEST, ETH_P_RARP, 0, dev, 0, NULL,
		 dev->dev_addr, dev->dev_addr);
}
#endif

/*
 *  Predefine Nameservers
 */
static inline void __init ic_nameservers_predef(void)
{
	int i;

	for (i = 0; i < CONF_NAMESERVERS_MAX; i++)
		ic_nameservers[i] = NONE;
}

/* Predefine NTP servers */
static inline void __init ic_ntp_servers_predef(void)
{
	int i;

	for (i = 0; i < CONF_NTP_SERVERS_MAX; i++)
		ic_ntp_servers[i] = NONE;
}

/*
 *	DHCP/BOOTP support.
 */

#ifdef IPCONFIG_BOOTP

struct bootp_pkt {		/* BOOTP packet format */
	struct iphdr iph;	/* IP header */
	struct udphdr udph;	/* UDP header */
	u8 op;			/* 1=request, 2=reply */
	u8 htype;		/* HW address type */
	u8 hlen;		/* HW address length */
	u8 hops;		/* Used only by gateways */
	__be32 xid;		/* Transaction ID */
	__be16 secs;		/* Seconds since we started */
	__be16 flags;		/* Just what it says */
	__be32 client_ip;		/* Client's IP address if known */
	__be32 your_ip;		/* Assigned IP address */
	__be32 server_ip;		/* (Next, e.g. NFS) Server's IP address */
	__be32 relay_ip;		/* IP address of BOOTP relay */
	u8 hw_addr[16];		/* Client's HW address */
	u8 serv_name[64];	/* Server host name */
	u8 boot_file[128];	/* Name of boot file */
	u8 exten[312];		/* DHCP options / BOOTP vendor extensions */
};

/* packet ops */
#define BOOTP_REQUEST	1
#define BOOTP_REPLY	2

/* DHCP message types */
#define DHCPDISCOVER	1
#define DHCPOFFER	2
#define DHCPREQUEST	3
#define DHCPDECLINE	4
#define DHCPACK		5
#define DHCPNAK		6
#define DHCPRELEASE	7
#define DHCPINFORM	8

static int ic_bootp_recv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev);

static struct packet_type bootp_packet_type __initdata = {
	.type =	cpu_to_be16(ETH_P_IP),
	.func =	ic_bootp_recv,
};

/*
 *  Initialize DHCP/BOOTP extension fields in the request.
 */

static const u8 ic_bootp_cookie[4] = { 99, 130, 83, 99 };

#ifdef IPCONFIG_DHCP

static void __init
ic_dhcp_init_options(u8 *options, struct ic_device *d)
{
	u8 mt = ((ic_servaddr == NONE)
		 ? DHCPDISCOVER : DHCPREQUEST);
	u8 *e = options;
	int len;

	pr_debug("DHCP: Sending message type %d (%s)\n", mt, d->dev->name);

	memcpy(e, ic_bootp_cookie, 4);	/* RFC1048 Magic Cookie */
	e += 4;

	*e++ = 53;		/* DHCP message type */
	*e++ = 1;
	*e++ = mt;

	if (mt == DHCPREQUEST) {
		*e++ = 54;	/* Server ID (IP address) */
		*e++ = 4;
		memcpy(e, &ic_servaddr, 4);
		e += 4;

		*e++ = 50;	/* Requested IP address */
		*e++ = 4;
		memcpy(e, &ic_myaddr, 4);
		e += 4;
	}

	/* always? */
	{
		static const u8 ic_req_params[] = {
			1,	/* Subnet mask */
			3,	/* Default gateway */
			6,	/* DNS server */
			12,	/* Host name */
			15,	/* Domain name */
			17,	/* Boot path */
			26,	/* MTU */
			40,	/* NIS domain name */
			42,	/* NTP servers */
		};

		*e++ = 55;	/* Parameter request list */
		*e++ = sizeof(ic_req_params);
		memcpy(e, ic_req_params, sizeof(ic_req_params));
		e += sizeof(ic_req_params);

		if (ic_host_name_set) {
			*e++ = 12;	/* host-name */
			len = strlen(utsname()->nodename);
			*e++ = len;
			memcpy(e, utsname()->nodename, len);
			e += len;
		}
		if (*vendor_class_identifier) {
			pr_info("DHCP: sending class identifier \"%s\"\n",
				vendor_class_identifier);
			*e++ = 60;	/* Class-identifier */
			len = strlen(vendor_class_identifier);
			*e++ = len;
			memcpy(e, vendor_class_identifier, len);
			e += len;
		}
		len = strlen(dhcp_client_identifier + 1);
		/* the minimum length of identifier is 2, include 1 byte type,
		 * and can not be larger than the length of options
		 */
		if (len >= 1 && len < 312 - (e - options) - 1) {
			*e++ = 61;
			*e++ = len + 1;
			memcpy(e, dhcp_client_identifier, len + 1);
			e += len + 1;
		}
	}

	*e++ = 255;	/* End of the list */
}

#endif /* IPCONFIG_DHCP */

static void __init ic_bootp_init_ext(u8 *e)
{
	memcpy(e, ic_bootp_cookie, 4);	/* RFC1048 Magic Cookie */
	e += 4;
	*e++ = 1;		/* Subnet mask request */
	*e++ = 4;
	e += 4;
	*e++ = 3;		/* Default gateway request */
	*e++ = 4;
	e += 4;
#if CONF_NAMESERVERS_MAX > 0
	*e++ = 6;		/* (DNS) name server request */
	*e++ = 4 * CONF_NAMESERVERS_MAX;
	e += 4 * CONF_NAMESERVERS_MAX;
#endif
	*e++ = 12;		/* Host name request */
	*e++ = 32;
	e += 32;
	*e++ = 40;		/* NIS Domain name request */
	*e++ = 32;
	e += 32;
	*e++ = 17;		/* Boot path */
	*e++ = 40;
	e += 40;

	*e++ = 57;		/* set extension buffer size for reply */
	*e++ = 2;
	*e++ = 1;		/* 128+236+8+20+14, see dhcpd sources */
	*e++ = 150;

	*e++ = 255;		/* End of the list */
}


/*
 *  Initialize the DHCP/BOOTP mechanism.
 */
static inline void __init ic_bootp_init(void)
{
	/* Re-initialise all name servers and NTP servers to NONE, in case any
	 * were set via the "ip=" or "nfsaddrs=" kernel command line parameters:
	 * any IP addresses specified there will already have been decoded but
	 * are no longer needed
	 */
	ic_nameservers_predef();
	ic_ntp_servers_predef();

	dev_add_pack(&bootp_packet_type);
}


/*
 *  DHCP/BOOTP cleanup.
 */
static inline void __init ic_bootp_cleanup(void)
{
	dev_remove_pack(&bootp_packet_type);
}


/*
 *  Send DHCP/BOOTP request to single interface.
 */
static void __init ic_bootp_send_if(struct ic_device *d, unsigned long jiffies_diff)
{
	struct net_device *dev = d->dev;
	struct sk_buff *skb;
	struct bootp_pkt *b;
	struct iphdr *h;
	int hlen = LL_RESERVED_SPACE(dev);
	int tlen = dev->needed_tailroom;

	/* Allocate packet */
	skb = alloc_skb(sizeof(struct bootp_pkt) + hlen + tlen + 15,
			GFP_KERNEL);
	if (!skb)
		return;
	skb_reserve(skb, hlen);
	b = skb_put_zero(skb, sizeof(struct bootp_pkt));

	/* Construct IP header */
	skb_reset_network_header(skb);
	h = ip_hdr(skb);
	h->version = 4;
	h->ihl = 5;
	h->tot_len = htons(sizeof(struct bootp_pkt));
	h->frag_off = htons(IP_DF);
	h->ttl = 64;
	h->protocol = IPPROTO_UDP;
	h->daddr = htonl(INADDR_BROADCAST);
	h->check = ip_fast_csum((unsigned char *) h, h->ihl);

	/* Construct UDP header */
	b->udph.source = htons(68);
	b->udph.dest = htons(67);
	b->udph.len = htons(sizeof(struct bootp_pkt) - sizeof(struct iphdr));
	/* UDP checksum not calculated -- explicitly allowed in BOOTP RFC */

	/* Construct DHCP/BOOTP header */
	b->op = BOOTP_REQUEST;
	if (dev->type < 256) /* check for false types */
		b->htype = dev->type;
	else if (dev->type == ARPHRD_FDDI)
		b->htype = ARPHRD_ETHER;
	else {
		pr_warn("Unknown ARP type 0x%04x for device %s\n", dev->type,
			dev->name);
		b->htype = dev->type; /* can cause undefined behavior */
	}

	/* server_ip and your_ip address are both already zero per RFC2131 */
	b->hlen = dev->addr_len;
	memcpy(b->hw_addr, dev->dev_addr, dev->addr_len);
	b->secs = htons(jiffies_diff / HZ);
	b->xid = d->xid;

	/* add DHCP options or BOOTP extensions */
#ifdef IPCONFIG_DHCP
	if (ic_proto_enabled & IC_USE_DHCP)
		ic_dhcp_init_options(b->exten, d);
	else
#endif
		ic_bootp_init_ext(b->exten);

	/* Chain packet down the line... */
	skb->dev = dev;
	skb->protocol = htons(ETH_P_IP);
	if (dev_hard_header(skb, dev, ntohs(skb->protocol),
			    dev->broadcast, dev->dev_addr, skb->len) < 0) {
		kfree_skb(skb);
		printk("E");
		return;
	}

	if (dev_queue_xmit(skb) < 0)
		printk("E");
}


/*
 *  Copy BOOTP-supplied string if not already set.
 */
static int __init ic_bootp_string(char *dest, char *src, int len, int max)
{
	if (!len)
		return 0;
	if (len > max-1)
		len = max-1;
	memcpy(dest, src, len);
	dest[len] = '\0';
	return 1;
}


/*
 *  Process BOOTP extensions.
 */
static void __init ic_do_bootp_ext(u8 *ext)
{
	u8 servers;
	int i;
	__be16 mtu;

	u8 *c;

	pr_debug("DHCP/BOOTP: Got extension %d:", *ext);
	for (c=ext+2; c<ext+2+ext[1]; c++)
		pr_debug(" %02x", *c);
	pr_debug("\n");

	switch (*ext++) {
	case 1:		/* Subnet mask */
		if (ic_netmask == NONE)
			memcpy(&ic_netmask, ext+1, 4);
		break;
	case 3:		/* Default gateway */
		if (ic_gateway == NONE)
			memcpy(&ic_gateway, ext+1, 4);
		break;
	case 6:		/* DNS server */
		servers= *ext/4;
		if (servers > CONF_NAMESERVERS_MAX)
			servers = CONF_NAMESERVERS_MAX;
		for (i = 0; i < servers; i++) {
			if (ic_nameservers[i] == NONE)
				memcpy(&ic_nameservers[i], ext+1+4*i, 4);
		}
		break;
	case 12:	/* Host name */
		ic_bootp_string(utsname()->nodename, ext+1, *ext,
				__NEW_UTS_LEN);
		ic_host_name_set = 1;
		break;
	case 15:	/* Domain name (DNS) */
		ic_bootp_string(ic_domain, ext+1, *ext, sizeof(ic_domain));
		break;
	case 17:	/* Root path */
		if (!root_server_path[0])
			ic_bootp_string(root_server_path, ext+1, *ext,
					sizeof(root_server_path));
		break;
	case 26:	/* Interface MTU */
		memcpy(&mtu, ext+1, sizeof(mtu));
		ic_dev_mtu = ntohs(mtu);
		break;
	case 40:	/* NIS Domain name (_not_ DNS) */
		ic_bootp_string(utsname()->domainname, ext+1, *ext,
				__NEW_UTS_LEN);
		break;
	case 42:	/* NTP servers */
		servers = *ext / 4;
		if (servers > CONF_NTP_SERVERS_MAX)
			servers = CONF_NTP_SERVERS_MAX;
		for (i = 0; i < servers; i++) {
			if (ic_ntp_servers[i] == NONE)
				memcpy(&ic_ntp_servers[i], ext+1+4*i, 4);
		}
		break;
	}
}


/*
 *  Receive BOOTP reply.
 */
static int __init ic_bootp_recv(struct sk_buff *skb, struct net_device *dev, struct packet_type *pt, struct net_device *orig_dev)
{
	struct bootp_pkt *b;
	struct iphdr *h;
	struct ic_device *d;
	int len, ext_len;

	if (!net_eq(dev_net(dev), &init_net))
		goto drop;

	/* Perform verifications before taking the lock.  */
	if (skb->pkt_type == PACKET_OTHERHOST)
		goto drop;

	skb = skb_share_check(skb, GFP_ATOMIC);
	if (!skb)
		return NET_RX_DROP;

	if (!pskb_may_pull(skb,
			   sizeof(struct iphdr) +
			   sizeof(struct udphdr)))
		goto drop;

	b = (struct bootp_pkt *)skb_network_header(skb);
	h = &b->iph;

	if (h->ihl != 5 || h->version != 4 || h->protocol != IPPROTO_UDP)
		goto drop;

	/* Fragments are not supported */
	if (ip_is_fragment(h)) {
		net_err_ratelimited("DHCP/BOOTP: Ignoring fragmented reply\n");
		goto drop;
	}

	if (skb->len < ntohs(h->tot_len))
		goto drop;

	if (ip_fast_csum((char *) h, h->ihl))
		goto drop;

	if (b->udph.source != htons(67) || b->udph.dest != htons(68))
		goto drop;

	if (ntohs(h->tot_len) < ntohs(b->udph.len) + sizeof(struct iphdr))
		goto drop;

	len = ntohs(b->udph.len) - sizeof(struct udphdr);
	ext_len = len - (sizeof(*b) -
			 sizeof(struct iphdr) -
			 sizeof(struct udphdr) -
			 sizeof(b->exten));
	if (ext_len < 0)
		goto drop;

	/* Ok the front looks good, make sure we can get at the rest.  */
	if (!pskb_may_pull(skb, skb->len))
		goto drop;

	b = (struct bootp_pkt *)skb_network_header(skb);
	h = &b->iph;

	/* One reply at a time, please. */
	spin_lock(&ic_recv_lock);

	/* If we already have a reply, just drop the packet */
	if (ic_got_reply)
		goto drop_unlock;

	/* Find the ic_device that the packet arrived on */
	d = ic_first_dev;
	while (d && d->dev != dev)
		d = d->next;
	if (!d)
		goto drop_unlock;  /* should never happen */

	/* Is it a reply to our BOOTP request? */
	if (b->op != BOOTP_REPLY ||
	    b->xid != d->xid) {
		net_err_ratelimited("DHCP/BOOTP: Reply not for us on %s, op[%x] xid[%x]\n",
				    d->dev->name, b->op, b->xid);
		goto drop_unlock;
	}

	/* Parse extensions */
	if (ext_len >= 4 &&
	    !memcmp(b->exten, ic_bootp_cookie, 4)) { /* Check magic cookie */
		u8 *end = (u8 *) b + ntohs(b->iph.tot_len);
		u8 *ext;

#ifdef IPCONFIG_DHCP
		if (ic_proto_enabled & IC_USE_DHCP) {
			__be32 server_id = NONE;
			int mt = 0;

			ext = &b->exten[4];
			while (ext < end && *ext != 0xff) {
				u8 *opt = ext++;
				if (*opt == 0)	/* Padding */
					continue;
				ext += *ext + 1;
				if (ext >= end)
					break;
				switch (*opt) {
				case 53:	/* Message type */
					if (opt[1])
						mt = opt[2];
					break;
				case 54:	/* Server ID (IP address) */
					if (opt[1] >= 4)
						memcpy(&server_id, opt + 2, 4);
					break;
				}
			}

			pr_debug("DHCP: Got message type %d (%s)\n", mt, d->dev->name);

			switch (mt) {
			case DHCPOFFER:
				/* While in the process of accepting one offer,
				 * ignore all others.
				 */
				if (ic_myaddr != NONE)
					goto drop_unlock;

				/* Let's accept that offer. */
				ic_myaddr = b->your_ip;
				ic_servaddr = server_id;
				pr_debug("DHCP: Offered address %pI4 by server %pI4\n",
					 &ic_myaddr, &b->iph.saddr);
				/* The DHCP indicated server address takes
				 * precedence over the bootp header one if
				 * they are different.
				 */
				if ((server_id != NONE) &&
				    (b->server_ip != server_id))
					b->server_ip = ic_servaddr;
				break;

			case DHCPACK:
				if (memcmp(dev->dev_addr, b->hw_addr, dev->addr_len) != 0)
					goto drop_unlock;

				/* Yeah! */
				break;

			default:
				/* Urque.  Forget it*/
				ic_myaddr = NONE;
				ic_servaddr = NONE;
				goto drop_unlock;
			}

			ic_dhcp_msgtype = mt;

		}
#endif /* IPCONFIG_DHCP */

		ext = &b->exten[4];
		while (ext < end && *ext != 0xff) {
			u8 *opt = ext++;
			if (*opt == 0)	/* Padding */
				continue;
			ext += *ext + 1;
			if (ext < end)
				ic_do_bootp_ext(opt);
		}
	}

	/* We have a winner! */
	ic_dev = d;
	ic_myaddr = b->your_ip;
	ic_servaddr = b->server_ip;
	ic_addrservaddr = b->iph.saddr;
	if (ic_gateway == NONE && b->relay_ip)
		ic_gateway = b->relay_ip;
	if (ic_nameservers[0] == NONE)
		ic_nameservers[0] = ic_servaddr;
	ic_got_reply = IC_BOOTP;

drop_unlock:
	/* Show's over.  Nothing to see here.  */
	spin_unlock(&ic_recv_lock);

drop:
	/* Throw the packet out. */
	kfree_skb(skb);

	return 0;
}


#endif


/*
 *	Dynamic IP configuration -- DHCP, BOOTP, RARP.
 */

#ifdef IPCONFIG_DYNAMIC

static int __init ic_dynamic(void)
{
	int retries;
	struct ic_device *d;
	unsigned long start_jiffies, timeout, jiff;
	int do_bootp = ic_proto_have_if & IC_BOOTP;
	int do_rarp = ic_proto_have_if & IC_RARP;

	/*
	 * If none of DHCP/BOOTP/RARP was selected, return with an error.
	 * This routine gets only called when some pieces of information
	 * are missing, and without DHCP/BOOTP/RARP we are unable to get it.
	 */
	if (!ic_proto_enabled) {
		pr_err("IP-Config: Incomplete network configuration information\n");
		return -1;
	}

#ifdef IPCONFIG_BOOTP
	if ((ic_proto_enabled ^ ic_proto_have_if) & IC_BOOTP)
		pr_err("DHCP/BOOTP: No suitable device found\n");
#endif
#ifdef IPCONFIG_RARP
	if ((ic_proto_enabled ^ ic_proto_have_if) & IC_RARP)
		pr_err("RARP: No suitable device found\n");
#endif

	if (!ic_proto_have_if)
		/* Error message already printed */
		return -1;

	/*
	 * Setup protocols
	 */
#ifdef IPCONFIG_BOOTP
	if (do_bootp)
		ic_bootp_init();
#endif
#ifdef IPCONFIG_RARP
	if (do_rarp)
		ic_rarp_init();
#endif

	/*
	 * Send requests and wait, until we get an answer. This loop
	 * seems to be a terrible waste of CPU time, but actually there is
	 * only one process running at all, so we don't need to use any
	 * scheduler functions.
	 * [Actually we could now, but the nothing else running note still
	 *  applies.. - AC]
	 */
	pr_notice("Sending %s%s%s requests .",
		  do_bootp
		  ? ((ic_proto_enabled & IC_USE_DHCP) ? "DHCP" : "BOOTP") : "",
		  (do_bootp && do_rarp) ? " and " : "",
		  do_rarp ? "RARP" : "");

	start_jiffies = jiffies;
	d = ic_first_dev;
	retries = CONF_SEND_RETRIES;
	get_random_bytes(&timeout, sizeof(timeout));
	timeout = CONF_BASE_TIMEOUT + (timeout % (unsigned int) CONF_TIMEOUT_RANDOM);
	for (;;) {
#ifdef IPCONFIG_BOOTP
		if (do_bootp && (d->able & IC_BOOTP))
			ic_bootp_send_if(d, jiffies - start_jiffies);
#endif
#ifdef IPCONFIG_RARP
		if (do_rarp && (d->able & IC_RARP))
			ic_rarp_send_if(d);
#endif

		if (!d->next) {
			jiff = jiffies + timeout;
			while (time_before(jiffies, jiff) && !ic_got_reply)
				schedule_timeout_uninterruptible(1);
		}
#ifdef IPCONFIG_DHCP
		/* DHCP isn't done until we get a DHCPACK. */
		if ((ic_got_reply & IC_BOOTP) &&
		    (ic_proto_enabled & IC_USE_DHCP) &&
		    ic_dhcp_msgtype != DHCPACK) {
			ic_got_reply = 0;
			/* continue on device that got the reply */
			d = ic_dev;
			pr_cont(",");
			continue;
		}
#endif /* IPCONFIG_DHCP */

		if (ic_got_reply) {
			pr_cont(" OK\n");
			break;
		}

		if ((d = d->next))
			continue;

		if (! --retries) {
			pr_cont(" timed out!\n");
			break;
		}

		d = ic_first_dev;

		timeout = timeout CONF_TIMEOUT_MULT;
		if (timeout > CONF_TIMEOUT_MAX)
			timeout = CONF_TIMEOUT_MAX;

		pr_cont(".");
	}

#ifdef IPCONFIG_BOOTP
	if (do_bootp)
		ic_bootp_cleanup();
#endif
#ifdef IPCONFIG_RARP
	if (do_rarp)
		ic_rarp_cleanup();
#endif

	if (!ic_got_reply) {
		ic_myaddr = NONE;
		return -1;
	}

	pr_info("IP-Config: Got %s answer from %pI4, my address is %pI4\n",
		((ic_got_reply & IC_RARP) ? "RARP"
		: (ic_proto_enabled & IC_USE_DHCP) ? "DHCP" : "BOOTP"),
		&ic_addrservaddr, &ic_myaddr);

	return 0;
}

#endif /* IPCONFIG_DYNAMIC */

#ifdef CONFIG_PROC_FS
/* proc_dir_entry for /proc/net/ipconfig */
static struct proc_dir_entry *ipconfig_dir;

/* Name servers: */
static int pnp_seq_show(struct seq_file *seq, void *v)
{
	int i;

	if (ic_proto_used & IC_PROTO)
		seq_printf(seq, "#PROTO: %s\n",
			   (ic_proto_used & IC_RARP) ? "RARP"
			   : (ic_proto_used & IC_USE_DHCP) ? "DHCP" : "BOOTP");
	else
		seq_puts(seq, "#MANUAL\n");

	if (ic_domain[0])
		seq_printf(seq,
			   "domain %s\n", ic_domain);
	for (i = 0; i < CONF_NAMESERVERS_MAX; i++) {
		if (ic_nameservers[i] != NONE)
			seq_printf(seq, "nameserver %pI4\n",
				   &ic_nameservers[i]);
	}
	if (ic_servaddr != NONE)
		seq_printf(seq, "bootserver %pI4\n",
			   &ic_servaddr);
	return 0;
}

/* Create the /proc/net/ipconfig directory */
static int __init ipconfig_proc_net_init(void)
{
	ipconfig_dir = proc_net_mkdir(&init_net, "ipconfig", init_net.proc_net);
	if (!ipconfig_dir)
		return -ENOMEM;

	return 0;
}

/* Create a new file under /proc/net/ipconfig */
static int ipconfig_proc_net_create(const char *name,
				    const struct proc_ops *proc_ops)
{
	char *pname;
	struct proc_dir_entry *p;

	if (!ipconfig_dir)
		return -ENOMEM;

	pname = kasprintf(GFP_KERNEL, "%s%s", "ipconfig/", name);
	if (!pname)
		return -ENOMEM;

	p = proc_create(pname, 0444, init_net.proc_net, proc_ops);
	kfree(pname);
	if (!p)
		return -ENOMEM;

	return 0;
}

/* Write NTP server IP addresses to /proc/net/ipconfig/ntp_servers */
static int ntp_servers_show(struct seq_file *seq, void *v)
{
	int i;

	for (i = 0; i < CONF_NTP_SERVERS_MAX; i++) {
		if (ic_ntp_servers[i] != NONE)
			seq_printf(seq, "%pI4\n", &ic_ntp_servers[i]);
	}
	return 0;
}
DEFINE_PROC_SHOW_ATTRIBUTE(ntp_servers);
#endif /* CONFIG_PROC_FS */

/*
 *  Extract IP address from the parameter string if needed. Note that we
 *  need to have root_server_addr set _before_ IPConfig gets called as it
 *  can override it.
 */
__be32 __init root_nfs_parse_addr(char *name)
{
	__be32 addr;
	int octets = 0;
	char *cp, *cq;

	cp = cq = name;
	while (octets < 4) {
		while (*cp >= '0' && *cp <= '9')
			cp++;
		if (cp == cq || cp - cq > 3)
			break;
		if (*cp == '.' || octets == 3)
			octets++;
		if (octets < 4)
			cp++;
		cq = cp;
	}
	if (octets == 4 && (*cp == ':' || *cp == '\0')) {
		if (*cp == ':')
			*cp++ = '\0';
		addr = in_aton(name);
		memmove(name, cp, strlen(cp) + 1);
	} else
		addr = NONE;

	return addr;
}

#define DEVICE_WAIT_MAX		12 /* 12 seconds */

static int __init wait_for_devices(void)
{
	int i;

	for (i = 0; i < DEVICE_WAIT_MAX; i++) {
		struct net_device *dev;
		int found = 0;

		/* make sure deferred device probes are finished */
		wait_for_device_probe();

		rtnl_lock();
		for_each_netdev(&init_net, dev) {
			if (ic_is_init_dev(dev)) {
				found = 1;
				break;
			}
		}
		rtnl_unlock();
		if (found)
			return 0;
		ssleep(1);
	}
	return -ENODEV;
}

/*
 *	IP Autoconfig dispatcher.
 */

static int __init ip_auto_config(void)
{
	__be32 addr;
#ifdef IPCONFIG_DYNAMIC
	int retries = CONF_OPEN_RETRIES;
#endif
	int err;
	unsigned int i;

	/* Initialise all name servers and NTP servers to NONE (but only if the
	 * "ip=" or "nfsaddrs=" kernel command line parameters weren't decoded,
	 * otherwise we'll overwrite the IP addresses specified there)
	 */
	if (ic_set_manually == 0) {
		ic_nameservers_predef();
		ic_ntp_servers_predef();
	}

#ifdef CONFIG_PROC_FS
	proc_create_single("pnp", 0444, init_net.proc_net, pnp_seq_show);

	if (ipconfig_proc_net_init() == 0)
		ipconfig_proc_net_create("ntp_servers", &ntp_servers_proc_ops);
#endif /* CONFIG_PROC_FS */

	if (!ic_enable)
		return 0;

	pr_debug("IP-Config: Entered.\n");
#ifdef IPCONFIG_DYNAMIC
 try_try_again:
#endif
	/* Wait for devices to appear */
	err = wait_for_devices();
	if (err)
		return err;

	/* Setup all network devices */
	err = ic_open_devs();
	if (err)
		return err;

	/* Give drivers a chance to settle */
	msleep(CONF_POST_OPEN);

	/*
	 * If the config information is insufficient (e.g., our IP address or
	 * IP address of the boot server is missing or we have multiple network
	 * interfaces and no default was set), use BOOTP or RARP to get the
	 * missing values.
	 */
	if (ic_myaddr == NONE ||
#if defined(CONFIG_ROOT_NFS) || defined(CONFIG_CIFS_ROOT)
	    (root_server_addr == NONE &&
	     ic_servaddr == NONE &&
	     (ROOT_DEV == Root_NFS || ROOT_DEV == Root_CIFS)) ||
#endif
	    ic_first_dev->next) {
#ifdef IPCONFIG_DYNAMIC
		if (ic_dynamic() < 0) {
			ic_close_devs();

			/*
			 * I don't know why, but sometimes the
			 * eepro100 driver (at least) gets upset and
			 * doesn't work the first time it's opened.
			 * But then if you close it and reopen it, it
			 * works just fine.  So we need to try that at
			 * least once before giving up.
			 *
			 * Also, if the root will be NFS-mounted, we
			 * have nowhere to go if DHCP fails.  So we
			 * just have to keep trying forever.
			 *
			 * 				-- Chip
			 */
#ifdef CONFIG_ROOT_NFS
			if (ROOT_DEV ==  Root_NFS) {
				pr_err("IP-Config: Retrying forever (NFS root)...\n");
				goto try_try_again;
			}
#endif
#ifdef CONFIG_CIFS_ROOT
			if (ROOT_DEV == Root_CIFS) {
				pr_err("IP-Config: Retrying forever (CIFS root)...\n");
				goto try_try_again;
			}
#endif

			if (--retries) {
				pr_err("IP-Config: Reopening network devices...\n");
				goto try_try_again;
			}

			/* Oh, well.  At least we tried. */
			pr_err("IP-Config: Auto-configuration of network failed\n");
			return -1;
		}
#else /* !DYNAMIC */
		pr_err("IP-Config: Incomplete network configuration information\n");
		ic_close_devs();
		return -1;
#endif /* IPCONFIG_DYNAMIC */
	} else {
		/* Device selected manually or only one device -> use it */
		ic_dev = ic_first_dev;
	}

	addr = root_nfs_parse_addr(root_server_path);
	if (root_server_addr == NONE)
		root_server_addr = addr;

	/*
	 * Use defaults wherever applicable.
	 */
	if (ic_defaults() < 0)
		return -1;

	/*
	 * Record which protocol was actually used.
	 */
#ifdef IPCONFIG_DYNAMIC
	ic_proto_used = ic_got_reply | (ic_proto_enabled & IC_USE_DHCP);
#endif

#ifndef IPCONFIG_SILENT
	/*
	 * Clue in the operator.
	 */
	pr_info("IP-Config: Complete:\n");

	pr_info("     device=%s, hwaddr=%*phC, ipaddr=%pI4, mask=%pI4, gw=%pI4\n",
		ic_dev->dev->name, ic_dev->dev->addr_len, ic_dev->dev->dev_addr,
		&ic_myaddr, &ic_netmask, &ic_gateway);
	pr_info("     host=%s, domain=%s, nis-domain=%s\n",
		utsname()->nodename, ic_domain, utsname()->domainname);
	pr_info("     bootserver=%pI4, rootserver=%pI4, rootpath=%s",
		&ic_servaddr, &root_server_addr, root_server_path);
	if (ic_dev_mtu)
		pr_cont(", mtu=%d", ic_dev_mtu);
	/* Name servers (if any): */
	for (i = 0; i < CONF_NAMESERVERS_MAX; i++) {
		if (ic_nameservers[i] != NONE) {
			if (i == 0)
				pr_info("     nameserver%u=%pI4",
					i, &ic_nameservers[i]);
			else
				pr_cont(", nameserver%u=%pI4",
					i, &ic_nameservers[i]);
		}
		if (i + 1 == CONF_NAMESERVERS_MAX)
			pr_cont("\n");
	}
	/* NTP servers (if any): */
	for (i = 0; i < CONF_NTP_SERVERS_MAX; i++) {
		if (ic_ntp_servers[i] != NONE) {
			if (i == 0)
				pr_info("     ntpserver%u=%pI4",
					i, &ic_ntp_servers[i]);
			else
				pr_cont(", ntpserver%u=%pI4",
					i, &ic_ntp_servers[i]);
		}
		if (i + 1 == CONF_NTP_SERVERS_MAX)
			pr_cont("\n");
	}
#endif /* !SILENT */

	/*
	 * Close all network devices except the device we've
	 * autoconfigured and set up routes.
	 */
	if (ic_setup_if() < 0 || ic_setup_routes() < 0)
		err = -1;
	else
		err = 0;

	ic_close_devs();

	return err;
}

late_initcall(ip_auto_config);


/*
 *  Decode any IP configuration options in the "ip=" or "nfsaddrs=" kernel
 *  command line parameter.  See Documentation/admin-guide/nfs/nfsroot.rst.
 */
static int __init ic_proto_name(char *name)
{
	if (!strcmp(name, "on") || !strcmp(name, "any")) {
		return 1;
	}
	if (!strcmp(name, "off") || !strcmp(name, "none")) {
		return 0;
	}
#ifdef CONFIG_IP_PNP_DHCP
	else if (!strncmp(name, "dhcp", 4)) {
		char *client_id;

		ic_proto_enabled &= ~IC_RARP;
		client_id = strstr(name, "dhcp,");
		if (client_id) {
			char *v;

			client_id = client_id + 5;
			v = strchr(client_id, ',');
			if (!v)
				return 1;
			*v = 0;
			if (kstrtou8(client_id, 0, dhcp_client_identifier))
				pr_debug("DHCP: Invalid client identifier type\n");
			strncpy(dhcp_client_identifier + 1, v + 1, 251);
			*v = ',';
		}
		return 1;
	}
#endif
#ifdef CONFIG_IP_PNP_BOOTP
	else if (!strcmp(name, "bootp")) {
		ic_proto_enabled &= ~(IC_RARP | IC_USE_DHCP);
		return 1;
	}
#endif
#ifdef CONFIG_IP_PNP_RARP
	else if (!strcmp(name, "rarp")) {
		ic_proto_enabled &= ~(IC_BOOTP | IC_USE_DHCP);
		return 1;
	}
#endif
#ifdef IPCONFIG_DYNAMIC
	else if (!strcmp(name, "both")) {
		ic_proto_enabled &= ~IC_USE_DHCP; /* backward compat :-( */
		return 1;
	}
#endif
	return 0;
}

static int __init ip_auto_config_setup(char *addrs)
{
	char *cp, *ip, *dp;
	int num = 0;

	ic_set_manually = 1;
	ic_enable = 1;

	/*
	 * If any dhcp, bootp etc options are set, leave autoconfig on
	 * and skip the below static IP processing.
	 */
	if (ic_proto_name(addrs))
		return 1;

	/* If no static IP is given, turn off autoconfig and bail.  */
	if (*addrs == 0 ||
	    strcmp(addrs, "off") == 0 ||
	    strcmp(addrs, "none") == 0) {
		ic_enable = 0;
		return 1;
	}

	/* Initialise all name servers and NTP servers to NONE */
	ic_nameservers_predef();
	ic_ntp_servers_predef();

	/* Parse string for static IP assignment.  */
	ip = addrs;
	while (ip && *ip) {
		if ((cp = strchr(ip, ':')))
			*cp++ = '\0';
		if (strlen(ip) > 0) {
			pr_debug("IP-Config: Parameter #%d: `%s'\n", num, ip);
			switch (num) {
			case 0:
				if ((ic_myaddr = in_aton(ip)) == ANY)
					ic_myaddr = NONE;
				break;
			case 1:
				if ((ic_servaddr = in_aton(ip)) == ANY)
					ic_servaddr = NONE;
				break;
			case 2:
				if ((ic_gateway = in_aton(ip)) == ANY)
					ic_gateway = NONE;
				break;
			case 3:
				if ((ic_netmask = in_aton(ip)) == ANY)
					ic_netmask = NONE;
				break;
			case 4:
				if ((dp = strchr(ip, '.'))) {
					*dp++ = '\0';
					strlcpy(utsname()->domainname, dp,
						sizeof(utsname()->domainname));
				}
				strlcpy(utsname()->nodename, ip,
					sizeof(utsname()->nodename));
				ic_host_name_set = 1;
				break;
			case 5:
				strlcpy(user_dev_name, ip, sizeof(user_dev_name));
				break;
			case 6:
				if (ic_proto_name(ip) == 0 &&
				    ic_myaddr == NONE) {
					ic_enable = 0;
				}
				break;
			case 7:
				if (CONF_NAMESERVERS_MAX >= 1) {
					ic_nameservers[0] = in_aton(ip);
					if (ic_nameservers[0] == ANY)
						ic_nameservers[0] = NONE;
				}
				break;
			case 8:
				if (CONF_NAMESERVERS_MAX >= 2) {
					ic_nameservers[1] = in_aton(ip);
					if (ic_nameservers[1] == ANY)
						ic_nameservers[1] = NONE;
				}
				break;
			case 9:
				if (CONF_NTP_SERVERS_MAX >= 1) {
					ic_ntp_servers[0] = in_aton(ip);
					if (ic_ntp_servers[0] == ANY)
						ic_ntp_servers[0] = NONE;
				}
				break;
			}
		}
		ip = cp;
		num++;
	}

	return 1;
}
__setup("ip=", ip_auto_config_setup);

static int __init nfsaddrs_config_setup(char *addrs)
{
	return ip_auto_config_setup(addrs);
}
__setup("nfsaddrs=", nfsaddrs_config_setup);

static int __init vendor_class_identifier_setup(char *addrs)
{
	if (strlcpy(vendor_class_identifier, addrs,
		    sizeof(vendor_class_identifier))
	    >= sizeof(vendor_class_identifier))
		pr_warn("DHCP: vendorclass too long, truncated to \"%s\"\n",
			vendor_class_identifier);
	return 1;
}
__setup("dhcpclass=", vendor_class_identifier_setup);

static int __init set_carrier_timeout(char *str)
{
	ssize_t ret;

	if (!str)
		return 0;

	ret = kstrtouint(str, 0, &carrier_timeout);
	if (ret)
		return 0;

	return 1;
}
__setup("carrier_timeout=", set_carrier_timeout);

};

/*****************************************************/


struct ip_options
{
void ip_options_build(struct sk_buff *skb, struct ip_options *opt,
		      __be32 daddr, struct rtable *rt, int is_frag)
{
	unsigned char *iph = skb_network_header(skb);

	memcpy(&(IPCB(skb)->opt), opt, sizeof(struct ip_options));
	memcpy(iph+sizeof(struct iphdr), opt->__data, opt->optlen);
	opt = &(IPCB(skb)->opt);

	if (opt->srr)
		memcpy(iph+opt->srr+iph[opt->srr+1]-4, &daddr, 4);

	if (!is_frag) {
		if (opt->rr_needaddr)
			ip_rt_get_source(iph+opt->rr+iph[opt->rr+2]-5, skb, rt);
		if (opt->ts_needaddr)
			ip_rt_get_source(iph+opt->ts+iph[opt->ts+2]-9, skb, rt);
		if (opt->ts_needtime) {
			__be32 midtime;

			midtime = inet_current_timestamp();
			memcpy(iph+opt->ts+iph[opt->ts+2]-5, &midtime, 4);
		}
		return;
	}
	if (opt->rr) {
		memset(iph+opt->rr, IPOPT_NOP, iph[opt->rr+1]);
		opt->rr = 0;
		opt->rr_needaddr = 0;
	}
	if (opt->ts) {
		memset(iph+opt->ts, IPOPT_NOP, iph[opt->ts+1]);
		opt->ts = 0;
		opt->ts_needaddr = opt->ts_needtime = 0;
	}
}

/*
 * Provided (sopt, skb) points to received options,
 * build in dopt compiled option set appropriate for answering.
 * i.e. invert SRR option, copy anothers,
 * and grab room in RR/TS options.
 *
 * NOTE: dopt cannot point to skb.
 */

int __ip_options_echo(struct net *net, struct ip_options *dopt,
		      struct sk_buff *skb, const struct ip_options *sopt)
{
	unsigned char *sptr, *dptr;
	int soffset, doffset;
	int	optlen;

	memset(dopt, 0, sizeof(struct ip_options));

	if (sopt->optlen == 0)
		return 0;

	sptr = skb_network_header(skb);
	dptr = dopt->__data;

	if (sopt->rr) {
		optlen  = sptr[sopt->rr+1];
		soffset = sptr[sopt->rr+2];
		dopt->rr = dopt->optlen + sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->rr, optlen);
		if (sopt->rr_needaddr && soffset <= optlen) {
			if (soffset + 3 > optlen)
				return -EINVAL;
			dptr[2] = soffset + 4;
			dopt->rr_needaddr = 1;
		}
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->ts) {
		optlen = sptr[sopt->ts+1];
		soffset = sptr[sopt->ts+2];
		dopt->ts = dopt->optlen + sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->ts, optlen);
		if (soffset <= optlen) {
			if (sopt->ts_needaddr) {
				if (soffset + 3 > optlen)
					return -EINVAL;
				dopt->ts_needaddr = 1;
				soffset += 4;
			}
			if (sopt->ts_needtime) {
				if (soffset + 3 > optlen)
					return -EINVAL;
				if ((dptr[3]&0xF) != IPOPT_TS_PRESPEC) {
					dopt->ts_needtime = 1;
					soffset += 4;
				} else {
					dopt->ts_needtime = 0;

					if (soffset + 7 <= optlen) {
						__be32 addr;

						memcpy(&addr, dptr+soffset-1, 4);
						if (inet_addr_type(net, addr) != RTN_UNICAST) {
							dopt->ts_needtime = 1;
							soffset += 8;
						}
					}
				}
			}
			dptr[2] = soffset;
		}
		dptr += optlen;
		dopt->optlen += optlen;
	}
	if (sopt->srr) {
		unsigned char *start = sptr+sopt->srr;
		__be32 faddr;

		optlen  = start[1];
		soffset = start[2];
		doffset = 0;
		if (soffset > optlen)
			soffset = optlen + 1;
		soffset -= 4;
		if (soffset > 3) {
			memcpy(&faddr, &start[soffset-1], 4);
			for (soffset -= 4, doffset = 4; soffset > 3; soffset -= 4, doffset += 4)
				memcpy(&dptr[doffset-1], &start[soffset-1], 4);
			/*
			 * RFC1812 requires to fix illegal source routes.
			 */
			if (memcmp(&ip_hdr(skb)->saddr,
				   &start[soffset + 3], 4) == 0)
				doffset -= 4;
		}
		if (doffset > 3) {
			dopt->faddr = faddr;
			dptr[0] = start[0];
			dptr[1] = doffset+3;
			dptr[2] = 4;
			dptr += doffset+3;
			dopt->srr = dopt->optlen + sizeof(struct iphdr);
			dopt->optlen += doffset+3;
			dopt->is_strictroute = sopt->is_strictroute;
		}
	}
	if (sopt->cipso) {
		optlen  = sptr[sopt->cipso+1];
		dopt->cipso = dopt->optlen+sizeof(struct iphdr);
		memcpy(dptr, sptr+sopt->cipso, optlen);
		dptr += optlen;
		dopt->optlen += optlen;
	}
	while (dopt->optlen & 3) {
		*dptr++ = IPOPT_END;
		dopt->optlen++;
	}
	return 0;
}

/*
 *	Options "fragmenting", just fill options not
 *	allowed in fragments with NOOPs.
 *	Simple and stupid 8), but the most efficient way.
 */

void ip_options_fragment(struct sk_buff *skb)
{
	unsigned char *optptr = skb_network_header(skb) + sizeof(struct iphdr);
	struct ip_options *opt = &(IPCB(skb)->opt);
	int  l = opt->optlen;
	int  optlen;

	while (l > 0) {
		switch (*optptr) {
		case IPOPT_END:
			return;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		optlen = optptr[1];
		if (optlen < 2 || optlen > l)
		  return;
		if (!IPOPT_COPIED(*optptr))
			memset(optptr, IPOPT_NOOP, optlen);
		l -= optlen;
		optptr += optlen;
	}
	opt->ts = 0;
	opt->rr = 0;
	opt->rr_needaddr = 0;
	opt->ts_needaddr = 0;
	opt->ts_needtime = 0;
}

/* helper used by ip_options_compile() to call fib_compute_spec_dst()
 * at most one time.
 */
static void spec_dst_fill(__be32 *spec_dst, struct sk_buff *skb)
{
	if (*spec_dst == htonl(INADDR_ANY))
		*spec_dst = fib_compute_spec_dst(skb);
}

/*
 * Verify options and fill pointers in struct options.
 * Caller should clear *opt, and set opt->data.
 * If opt == NULL, then skb->data should point to IP header.
 */

int __ip_options_compile(struct net *net,
			 struct ip_options *opt, struct sk_buff *skb,
			 __be32 *info)
{
	__be32 spec_dst = htonl(INADDR_ANY);
	unsigned char *pp_ptr = NULL;
	struct rtable *rt = NULL;
	unsigned char *optptr;
	unsigned char *iph;
	int optlen, l;

	if (skb) {
		rt = skb_rtable(skb);
		optptr = (unsigned char *)&(ip_hdr(skb)[1]);
	} else
		optptr = opt->__data;
	iph = optptr - sizeof(struct iphdr);

	for (l = opt->optlen; l > 0; ) {
		switch (*optptr) {
		case IPOPT_END:
			for (optptr++, l--; l > 0; optptr++, l--) {
				if (*optptr != IPOPT_END) {
					*optptr = IPOPT_END;
					opt->is_changed = 1;
				}
			}
			goto eol;
		case IPOPT_NOOP:
			l--;
			optptr++;
			continue;
		}
		if (unlikely(l < 2)) {
			pp_ptr = optptr;
			goto error;
		}
		optlen = optptr[1];
		if (optlen < 2 || optlen > l) {
			pp_ptr = optptr;
			goto error;
		}
		switch (*optptr) {
		case IPOPT_SSRR:
		case IPOPT_LSRR:
			if (optlen < 3) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 4) {
				pp_ptr = optptr + 2;
				goto error;
			}
			/* NB: cf RFC-1812 5.2.4.1 */
			if (opt->srr) {
				pp_ptr = optptr;
				goto error;
			}
			if (!skb) {
				if (optptr[2] != 4 || optlen < 7 || ((optlen-3) & 3)) {
					pp_ptr = optptr + 1;
					goto error;
				}
				memcpy(&opt->faddr, &optptr[3], 4);
				if (optlen > 7)
					memmove(&optptr[3], &optptr[7], optlen-7);
			}
			opt->is_strictroute = (optptr[0] == IPOPT_SSRR);
			opt->srr = optptr - iph;
			break;
		case IPOPT_RR:
			if (opt->rr) {
				pp_ptr = optptr;
				goto error;
			}
			if (optlen < 3) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 4) {
				pp_ptr = optptr + 2;
				goto error;
			}
			if (optptr[2] <= optlen) {
				if (optptr[2]+3 > optlen) {
					pp_ptr = optptr + 2;
					goto error;
				}
				if (rt) {
					spec_dst_fill(&spec_dst, skb);
					memcpy(&optptr[optptr[2]-1], &spec_dst, 4);
					opt->is_changed = 1;
				}
				optptr[2] += 4;
				opt->rr_needaddr = 1;
			}
			opt->rr = optptr - iph;
			break;
		case IPOPT_TIMESTAMP:
			if (opt->ts) {
				pp_ptr = optptr;
				goto error;
			}
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] < 5) {
				pp_ptr = optptr + 2;
				goto error;
			}
			if (optptr[2] <= optlen) {
				unsigned char *timeptr = NULL;
				if (optptr[2]+3 > optlen) {
					pp_ptr = optptr + 2;
					goto error;
				}
				switch (optptr[3]&0xF) {
				case IPOPT_TS_TSONLY:
					if (skb)
						timeptr = &optptr[optptr[2]-1];
					opt->ts_needtime = 1;
					optptr[2] += 4;
					break;
				case IPOPT_TS_TSANDADDR:
					if (optptr[2]+7 > optlen) {
						pp_ptr = optptr + 2;
						goto error;
					}
					if (rt)  {
						spec_dst_fill(&spec_dst, skb);
						memcpy(&optptr[optptr[2]-1], &spec_dst, 4);
						timeptr = &optptr[optptr[2]+3];
					}
					opt->ts_needaddr = 1;
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				case IPOPT_TS_PRESPEC:
					if (optptr[2]+7 > optlen) {
						pp_ptr = optptr + 2;
						goto error;
					}
					{
						__be32 addr;
						memcpy(&addr, &optptr[optptr[2]-1], 4);
						if (inet_addr_type(net, addr) == RTN_UNICAST)
							break;
						if (skb)
							timeptr = &optptr[optptr[2]+3];
					}
					opt->ts_needtime = 1;
					optptr[2] += 8;
					break;
				default:
					if (!skb && !ns_capable(net->user_ns, CAP_NET_RAW)) {
						pp_ptr = optptr + 3;
						goto error;
					}
					break;
				}
				if (timeptr) {
					__be32 midtime;

					midtime = inet_current_timestamp();
					memcpy(timeptr, &midtime, 4);
					opt->is_changed = 1;
				}
			} else if ((optptr[3]&0xF) != IPOPT_TS_PRESPEC) {
				unsigned int overflow = optptr[3]>>4;
				if (overflow == 15) {
					pp_ptr = optptr + 3;
					goto error;
				}
				if (skb) {
					optptr[3] = (optptr[3]&0xF)|((overflow+1)<<4);
					opt->is_changed = 1;
				}
			}
			opt->ts = optptr - iph;
			break;
		case IPOPT_RA:
			if (optlen < 4) {
				pp_ptr = optptr + 1;
				goto error;
			}
			if (optptr[2] == 0 && optptr[3] == 0)
				opt->router_alert = optptr - iph;
			break;
		case IPOPT_CIPSO:
			if ((!skb && !ns_capable(net->user_ns, CAP_NET_RAW)) || opt->cipso) {
				pp_ptr = optptr;
				goto error;
			}
			opt->cipso = optptr - iph;
			if (cipso_v4_validate(skb, &optptr)) {
				pp_ptr = optptr;
				goto error;
			}
			break;
		case IPOPT_SEC:
		case IPOPT_SID:
		default:
			if (!skb && !ns_capable(net->user_ns, CAP_NET_RAW)) {
				pp_ptr = optptr;
				goto error;
			}
			break;
		}
		l -= optlen;
		optptr += optlen;
	}

eol:
	if (!pp_ptr)
		return 0;

error:
	if (info)
		*info = htonl((pp_ptr-iph)<<24);
	return -EINVAL;
}
EXPORT_SYMBOL(__ip_options_compile);

int ip_options_compile(struct net *net,
		       struct ip_options *opt, struct sk_buff *skb)
{
	int ret;
	__be32 info;

	ret = __ip_options_compile(net, opt, skb, &info);
	if (ret != 0 && skb)
		icmp_send(skb, ICMP_PARAMETERPROB, 0, info);
	return ret;
}
EXPORT_SYMBOL(ip_options_compile);

/*
 *	Undo all the changes done by ip_options_compile().
 */

void ip_options_undo(struct ip_options *opt)
{
	if (opt->srr) {
		unsigned  char *optptr = opt->__data+opt->srr-sizeof(struct  iphdr);
		memmove(optptr+7, optptr+3, optptr[1]-7);
		memcpy(optptr+3, &opt->faddr, 4);
	}
	if (opt->rr_needaddr) {
		unsigned  char *optptr = opt->__data+opt->rr-sizeof(struct  iphdr);
		optptr[2] -= 4;
		memset(&optptr[optptr[2]-1], 0, 4);
	}
	if (opt->ts) {
		unsigned  char *optptr = opt->__data+opt->ts-sizeof(struct  iphdr);
		if (opt->ts_needtime) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2]-1], 0, 4);
			if ((optptr[3]&0xF) == IPOPT_TS_PRESPEC)
				optptr[2] -= 4;
		}
		if (opt->ts_needaddr) {
			optptr[2] -= 4;
			memset(&optptr[optptr[2]-1], 0, 4);
		}
	}
}

static struct ip_options_rcu *ip_options_get_alloc(const int optlen)
{
	return kzalloc(sizeof(struct ip_options_rcu) + ((optlen + 3) & ~3),
		       GFP_KERNEL);
}

static int ip_options_get_finish(struct net *net, struct ip_options_rcu **optp,
				 struct ip_options_rcu *opt, int optlen)
{
	while (optlen & 3)
		opt->opt.__data[optlen++] = IPOPT_END;
	opt->opt.optlen = optlen;
	if (optlen && ip_options_compile(net, &opt->opt, NULL)) {
		kfree(opt);
		return -EINVAL;
	}
	kfree(*optp);
	*optp = opt;
	return 0;
}

int ip_options_get_from_user(struct net *net, struct ip_options_rcu **optp,
			     unsigned char __user *data, int optlen)
{
	struct ip_options_rcu *opt = ip_options_get_alloc(optlen);

	if (!opt)
		return -ENOMEM;
	if (optlen && copy_from_user(opt->opt.__data, data, optlen)) {
		kfree(opt);
		return -EFAULT;
	}
	return ip_options_get_finish(net, optp, opt, optlen);
}

int ip_options_get(struct net *net, struct ip_options_rcu **optp,
		   unsigned char *data, int optlen)
{
	struct ip_options_rcu *opt = ip_options_get_alloc(optlen);

	if (!opt)
		return -ENOMEM;
	if (optlen)
		memcpy(opt->opt.__data, data, optlen);
	return ip_options_get_finish(net, optp, opt, optlen);
}

void ip_forward_options(struct sk_buff *skb)
{
	struct   ip_options *opt	= &(IPCB(skb)->opt);
	unsigned char *optptr;
	struct rtable *rt = skb_rtable(skb);
	unsigned char *raw = skb_network_header(skb);

	if (opt->rr_needaddr) {
		optptr = (unsigned char *)raw + opt->rr;
		ip_rt_get_source(&optptr[optptr[2]-5], skb, rt);
		opt->is_changed = 1;
	}
	if (opt->srr_is_hit) {
		int srrptr, srrspace;

		optptr = raw + opt->srr;

		for ( srrptr = optptr[2], srrspace = optptr[1];
		     srrptr <= srrspace;
		     srrptr += 4
		     ) {
			if (srrptr + 3 > srrspace)
				break;
			if (memcmp(&opt->nexthop, &optptr[srrptr-1], 4) == 0)
				break;
		}
		if (srrptr + 3 <= srrspace) {
			opt->is_changed = 1;
			ip_hdr(skb)->daddr = opt->nexthop;
			ip_rt_get_source(&optptr[srrptr-1], skb, rt);
			optptr[2] = srrptr+4;
		} else {
			net_crit_ratelimited("%s(): Argh! Destination lost!\n",
					     __func__);
		}
		if (opt->ts_needaddr) {
			optptr = raw + opt->ts;
			ip_rt_get_source(&optptr[optptr[2]-9], skb, rt);
			opt->is_changed = 1;
		}
	}
	if (opt->is_changed) {
		opt->is_changed = 0;
		ip_send_check(ip_hdr(skb));
	}
}

int ip_options_rcv_srr(struct sk_buff *skb, struct net_device *dev)
{
	struct ip_options *opt = &(IPCB(skb)->opt);
	int srrspace, srrptr;
	__be32 nexthop;
	struct iphdr *iph = ip_hdr(skb);
	unsigned char *optptr = skb_network_header(skb) + opt->srr;
	struct rtable *rt = skb_rtable(skb);
	struct rtable *rt2;
	unsigned long orefdst;
	int err;

	if (!rt)
		return 0;

	if (skb->pkt_type != PACKET_HOST)
		return -EINVAL;
	if (rt->rt_type == RTN_UNICAST) {
		if (!opt->is_strictroute)
			return 0;
		icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl(16<<24));
		return -EINVAL;
	}
	if (rt->rt_type != RTN_LOCAL)
		return -EINVAL;

	for (srrptr = optptr[2], srrspace = optptr[1]; srrptr <= srrspace; srrptr += 4) {
		if (srrptr + 3 > srrspace) {
			icmp_send(skb, ICMP_PARAMETERPROB, 0, htonl((opt->srr+2)<<24));
			return -EINVAL;
		}
		memcpy(&nexthop, &optptr[srrptr-1], 4);

		orefdst = skb->_skb_refdst;
		skb_dst_set(skb, NULL);
		err = ip_route_input(skb, nexthop, iph->saddr, iph->tos, dev);
		rt2 = skb_rtable(skb);
		if (err || (rt2->rt_type != RTN_UNICAST && rt2->rt_type != RTN_LOCAL)) {
			skb_dst_drop(skb);
			skb->_skb_refdst = orefdst;
			return -EINVAL;
		}
		refdst_drop(orefdst);
		if (rt2->rt_type != RTN_LOCAL)
			break;
		/* Superfast 8) loopback forward */
		iph->daddr = nexthop;
		opt->is_changed = 1;
	}
	if (srrptr <= srrspace) {
		opt->srr_is_hit = 1;
		opt->nexthop = nexthop;
		opt->is_changed = 1;
	}
	return 0;
}
EXPORT_SYMBOL(ip_options_rcv_srr);

};

/*****************************************************************/

struct bluethooh_core

{
static bool compress_src = true;
static bool compress_dst = true;

static LIST_HEAD(bnep_session_list);
static DECLARE_RWSEM(bnep_session_sem);

static struct bnep_session *__bnep_get_session(u8 *dst)
{
	struct bnep_session *s;

	BT_DBG("");

	list_for_each_entry(s, &bnep_session_list, list)
		if (ether_addr_equal(dst, s->eh.h_source))
			return s;

	return NULL;
}

static void __bnep_link_session(struct bnep_session *s)
{
	list_add(&s->list, &bnep_session_list);
}

static void __bnep_unlink_session(struct bnep_session *s)
{
	list_del(&s->list);
}

static int bnep_send(struct bnep_session *s, void *data, size_t len)
{
	struct socket *sock = s->sock;
	struct kvec iv = { data, len };

	return kernel_sendmsg(sock, &s->msg, &iv, 1, len);
}

static int bnep_send_rsp(struct bnep_session *s, u8 ctrl, u16 resp)
{
	struct bnep_control_rsp rsp;
	rsp.type = BNEP_CONTROL;
	rsp.ctrl = ctrl;
	rsp.resp = htons(resp);
	return bnep_send(s, &rsp, sizeof(rsp));
}

#ifdef CONFIG_BT_BNEP_PROTO_FILTER
static inline void bnep_set_default_proto_filter(struct bnep_session *s)
{
	/* (IPv4, ARP)  */
	s->proto_filter[0].start = ETH_P_IP;
	s->proto_filter[0].end   = ETH_P_ARP;
	/* (RARP, AppleTalk) */
	s->proto_filter[1].start = ETH_P_RARP;
	s->proto_filter[1].end   = ETH_P_AARP;
	/* (IPX, IPv6) */
	s->proto_filter[2].start = ETH_P_IPX;
	s->proto_filter[2].end   = ETH_P_IPV6;
}
#endif

static int bnep_ctrl_set_netfilter(struct bnep_session *s, __be16 *data, int len)
{
	int n;

	if (len < 2)
		return -EILSEQ;

	n = get_unaligned_be16(data);
	data++;
	len -= 2;

	if (len < n)
		return -EILSEQ;

	BT_DBG("filter len %d", n);

#ifdef CONFIG_BT_BNEP_PROTO_FILTER
	n /= 4;
	if (n <= BNEP_MAX_PROTO_FILTERS) {
		struct bnep_proto_filter *f = s->proto_filter;
		int i;

		for (i = 0; i < n; i++) {
			f[i].start = get_unaligned_be16(data++);
			f[i].end   = get_unaligned_be16(data++);

			BT_DBG("proto filter start %d end %d",
				f[i].start, f[i].end);
		}

		if (i < BNEP_MAX_PROTO_FILTERS)
			memset(f + i, 0, sizeof(*f));

		if (n == 0)
			bnep_set_default_proto_filter(s);

		bnep_send_rsp(s, BNEP_FILTER_NET_TYPE_RSP, BNEP_SUCCESS);
	} else {
		bnep_send_rsp(s, BNEP_FILTER_NET_TYPE_RSP, BNEP_FILTER_LIMIT_REACHED);
	}
#else
	bnep_send_rsp(s, BNEP_FILTER_NET_TYPE_RSP, BNEP_FILTER_UNSUPPORTED_REQ);
#endif
	return 0;
}

static int bnep_ctrl_set_mcfilter(struct bnep_session *s, u8 *data, int len)
{
	int n;

	if (len < 2)
		return -EILSEQ;

	n = get_unaligned_be16(data);
	data += 2;
	len -= 2;

	if (len < n)
		return -EILSEQ;

	BT_DBG("filter len %d", n);

#ifdef CONFIG_BT_BNEP_MC_FILTER
	n /= (ETH_ALEN * 2);

	if (n > 0) {
		int i;

		s->mc_filter = 0;

		/* Always send broadcast */
		set_bit(bnep_mc_hash(s->dev->broadcast), (ulong *) &s->mc_filter);

		/* Add address ranges to the multicast hash */
		for (; n > 0; n--) {
			u8 a1[6], *a2;

			memcpy(a1, data, ETH_ALEN);
			data += ETH_ALEN;
			a2 = data;
			data += ETH_ALEN;

			BT_DBG("mc filter %pMR -> %pMR", a1, a2);

			/* Iterate from a1 to a2 */
			set_bit(bnep_mc_hash(a1), (ulong *) &s->mc_filter);
			while (memcmp(a1, a2, 6) < 0 && s->mc_filter != ~0LL) {
				/* Increment a1 */
				i = 5;
				while (i >= 0 && ++a1[i--] == 0)
					;

				set_bit(bnep_mc_hash(a1), (ulong *) &s->mc_filter);
			}
		}
	}

	BT_DBG("mc filter hash 0x%llx", s->mc_filter);

	bnep_send_rsp(s, BNEP_FILTER_MULTI_ADDR_RSP, BNEP_SUCCESS);
#else
	bnep_send_rsp(s, BNEP_FILTER_MULTI_ADDR_RSP, BNEP_FILTER_UNSUPPORTED_REQ);
#endif
	return 0;
}

static int bnep_rx_control(struct bnep_session *s, void *data, int len)
{
	u8  cmd = *(u8 *)data;
	int err = 0;

	data++;
	len--;

	switch (cmd) {
	case BNEP_CMD_NOT_UNDERSTOOD:
	case BNEP_SETUP_CONN_RSP:
	case BNEP_FILTER_NET_TYPE_RSP:
	case BNEP_FILTER_MULTI_ADDR_RSP:
		/* Ignore these for now */
		break;

	case BNEP_FILTER_NET_TYPE_SET:
		err = bnep_ctrl_set_netfilter(s, data, len);
		break;

	case BNEP_FILTER_MULTI_ADDR_SET:
		err = bnep_ctrl_set_mcfilter(s, data, len);
		break;

	case BNEP_SETUP_CONN_REQ:
		/* Successful response should be sent only once */
		if (test_bit(BNEP_SETUP_RESPONSE, &s->flags) &&
		    !test_and_set_bit(BNEP_SETUP_RSP_SENT, &s->flags))
			err = bnep_send_rsp(s, BNEP_SETUP_CONN_RSP,
					    BNEP_SUCCESS);
		else
			err = bnep_send_rsp(s, BNEP_SETUP_CONN_RSP,
					    BNEP_CONN_NOT_ALLOWED);
		break;

	default: {
			u8 pkt[3];
			pkt[0] = BNEP_CONTROL;
			pkt[1] = BNEP_CMD_NOT_UNDERSTOOD;
			pkt[2] = cmd;
			err = bnep_send(s, pkt, sizeof(pkt));
		}
		break;
	}

	return err;
}

static int bnep_rx_extension(struct bnep_session *s, struct sk_buff *skb)
{
	struct bnep_ext_hdr *h;
	int err = 0;

	do {
		h = (void *) skb->data;
		if (!skb_pull(skb, sizeof(*h))) {
			err = -EILSEQ;
			break;
		}

		BT_DBG("type 0x%x len %d", h->type, h->len);

		switch (h->type & BNEP_TYPE_MASK) {
		case BNEP_EXT_CONTROL:
			bnep_rx_control(s, skb->data, skb->len);
			break;

		default:
			/* Unknown extension, skip it. */
			break;
		}

		if (!skb_pull(skb, h->len)) {
			err = -EILSEQ;
			break;
		}
	} while (!err && (h->type & BNEP_EXT_HEADER));

	return err;
}

static u8 __bnep_rx_hlen[] = {
	ETH_HLEN,     /* BNEP_GENERAL */
	0,            /* BNEP_CONTROL */
	2,            /* BNEP_COMPRESSED */
	ETH_ALEN + 2, /* BNEP_COMPRESSED_SRC_ONLY */
	ETH_ALEN + 2  /* BNEP_COMPRESSED_DST_ONLY */
};

static int bnep_rx_frame(struct bnep_session *s, struct sk_buff *skb)
{
	struct net_device *dev = s->dev;
	struct sk_buff *nskb;
	u8 type, ctrl_type;

	dev->stats.rx_bytes += skb->len;

	type = *(u8 *) skb->data;
	skb_pull(skb, 1);
	ctrl_type = *(u8 *)skb->data;

	if ((type & BNEP_TYPE_MASK) >= sizeof(__bnep_rx_hlen))
		goto badframe;

	if ((type & BNEP_TYPE_MASK) == BNEP_CONTROL) {
		if (bnep_rx_control(s, skb->data, skb->len) < 0) {
			dev->stats.tx_errors++;
			kfree_skb(skb);
			return 0;
		}

		if (!(type & BNEP_EXT_HEADER)) {
			kfree_skb(skb);
			return 0;
		}

		/* Verify and pull ctrl message since it's already processed */
		switch (ctrl_type) {
		case BNEP_SETUP_CONN_REQ:
			/* Pull: ctrl type (1 b), len (1 b), data (len bytes) */
			if (!skb_pull(skb, 2 + *(u8 *)(skb->data + 1) * 2))
				goto badframe;
			break;
		case BNEP_FILTER_MULTI_ADDR_SET:
		case BNEP_FILTER_NET_TYPE_SET:
			/* Pull: ctrl type (1 b), len (2 b), data (len bytes) */
			if (!skb_pull(skb, 3 + *(u16 *)(skb->data + 1) * 2))
				goto badframe;
			break;
		default:
			kfree_skb(skb);
			return 0;
		}
	} else {
		skb_reset_mac_header(skb);

		/* Verify and pull out header */
		if (!skb_pull(skb, __bnep_rx_hlen[type & BNEP_TYPE_MASK]))
			goto badframe;

		s->eh.h_proto = get_unaligned((__be16 *) (skb->data - 2));
	}

	if (type & BNEP_EXT_HEADER) {
		if (bnep_rx_extension(s, skb) < 0)
			goto badframe;
	}

	/* Strip 802.1p header */
	if (ntohs(s->eh.h_proto) == ETH_P_8021Q) {
		if (!skb_pull(skb, 4))
			goto badframe;
		s->eh.h_proto = get_unaligned((__be16 *) (skb->data - 2));
	}

	/* We have to alloc new skb and copy data here :(. Because original skb
	 * may not be modified and because of the alignment requirements. */
	nskb = alloc_skb(2 + ETH_HLEN + skb->len, GFP_KERNEL);
	if (!nskb) {
		dev->stats.rx_dropped++;
		kfree_skb(skb);
		return -ENOMEM;
	}
	skb_reserve(nskb, 2);

	/* Decompress header and construct ether frame */
	switch (type & BNEP_TYPE_MASK) {
	case BNEP_COMPRESSED:
		__skb_put_data(nskb, &s->eh, ETH_HLEN);
		break;

	case BNEP_COMPRESSED_SRC_ONLY:
		__skb_put_data(nskb, s->eh.h_dest, ETH_ALEN);
		__skb_put_data(nskb, skb_mac_header(skb), ETH_ALEN);
		put_unaligned(s->eh.h_proto, (__be16 *) __skb_put(nskb, 2));
		break;

	case BNEP_COMPRESSED_DST_ONLY:
		__skb_put_data(nskb, skb_mac_header(skb), ETH_ALEN);
		__skb_put_data(nskb, s->eh.h_source, ETH_ALEN + 2);
		break;

	case BNEP_GENERAL:
		__skb_put_data(nskb, skb_mac_header(skb), ETH_ALEN * 2);
		put_unaligned(s->eh.h_proto, (__be16 *) __skb_put(nskb, 2));
		break;
	}

	skb_copy_from_linear_data(skb, __skb_put(nskb, skb->len), skb->len);
	kfree_skb(skb);

	dev->stats.rx_packets++;
	nskb->ip_summed = CHECKSUM_NONE;
	nskb->protocol  = eth_type_trans(nskb, dev);
	netif_rx_ni(nskb);
	return 0;

badframe:
	dev->stats.rx_errors++;
	kfree_skb(skb);
	return 0;
}

static u8 __bnep_tx_types[] = {
	BNEP_GENERAL,
	BNEP_COMPRESSED_SRC_ONLY,
	BNEP_COMPRESSED_DST_ONLY,
	BNEP_COMPRESSED
};

static int bnep_tx_frame(struct bnep_session *s, struct sk_buff *skb)
{
	struct ethhdr *eh = (void *) skb->data;
	struct socket *sock = s->sock;
	struct kvec iv[3];
	int len = 0, il = 0;
	u8 type = 0;

	BT_DBG("skb %p dev %p type %d", skb, skb->dev, skb->pkt_type);

	if (!skb->dev) {
		/* Control frame sent by us */
		goto send;
	}

	iv[il++] = (struct kvec) { &type, 1 };
	len++;

	if (compress_src && ether_addr_equal(eh->h_dest, s->eh.h_source))
		type |= 0x01;

	if (compress_dst && ether_addr_equal(eh->h_source, s->eh.h_dest))
		type |= 0x02;

	if (type)
		skb_pull(skb, ETH_ALEN * 2);

	type = __bnep_tx_types[type];
	switch (type) {
	case BNEP_COMPRESSED_SRC_ONLY:
		iv[il++] = (struct kvec) { eh->h_source, ETH_ALEN };
		len += ETH_ALEN;
		break;

	case BNEP_COMPRESSED_DST_ONLY:
		iv[il++] = (struct kvec) { eh->h_dest, ETH_ALEN };
		len += ETH_ALEN;
		break;
	}

send:
	iv[il++] = (struct kvec) { skb->data, skb->len };
	len += skb->len;

	/* FIXME: linearize skb */
	{
		len = kernel_sendmsg(sock, &s->msg, iv, il, len);
	}
	kfree_skb(skb);

	if (len > 0) {
		s->dev->stats.tx_bytes += len;
		s->dev->stats.tx_packets++;
		return 0;
	}

	return len;
}

static int bnep_session(void *arg)
{
	struct bnep_session *s = arg;
	struct net_device *dev = s->dev;
	struct sock *sk = s->sock->sk;
	struct sk_buff *skb;
	DEFINE_WAIT_FUNC(wait, woken_wake_function);

	BT_DBG("");

	set_user_nice(current, -15);

	add_wait_queue(sk_sleep(sk), &wait);
	while (1) {
		if (atomic_read(&s->terminate))
			break;
		/* RX */
		while ((skb = skb_dequeue(&sk->sk_receive_queue))) {
			skb_orphan(skb);
			if (!skb_linearize(skb))
				bnep_rx_frame(s, skb);
			else
				kfree_skb(skb);
		}

		if (sk->sk_state != BT_CONNECTED)
			break;

		/* TX */
		while ((skb = skb_dequeue(&sk->sk_write_queue)))
			if (bnep_tx_frame(s, skb))
				break;
		netif_wake_queue(dev);

		/*
		 * wait_woken() performs the necessary memory barriers
		 * for us; see the header comment for this primitive.
		 */
		wait_woken(&wait, TASK_INTERRUPTIBLE, MAX_SCHEDULE_TIMEOUT);
	}
	remove_wait_queue(sk_sleep(sk), &wait);

	/* Cleanup session */
	down_write(&bnep_session_sem);

	/* Delete network device */
	unregister_netdev(dev);

	/* Wakeup user-space polling for socket errors */
	s->sock->sk->sk_err = EUNATCH;

	wake_up_interruptible(sk_sleep(s->sock->sk));

	/* Release the socket */
	fput(s->sock->file);

	__bnep_unlink_session(s);

	up_write(&bnep_session_sem);
	free_netdev(dev);
	module_put_and_exit(0);
	return 0;
}

static struct device *bnep_get_device(struct bnep_session *session)
{
	struct l2cap_conn *conn = l2cap_pi(session->sock->sk)->chan->conn;

	if (!conn || !conn->hcon)
		return NULL;

	return &conn->hcon->dev;
}

static struct device_type bnep_type = {
	.name	= "bluetooth",
};

int bnep_add_connection(struct bnep_connadd_req *req, struct socket *sock)
{
	u32 valid_flags = BIT(BNEP_SETUP_RESPONSE);
	struct net_device *dev;
	struct bnep_session *s, *ss;
	u8 dst[ETH_ALEN], src[ETH_ALEN];
	int err;

	BT_DBG("");

	if (!l2cap_is_socket(sock))
		return -EBADFD;

	if (req->flags & ~valid_flags)
		return -EINVAL;

	baswap((void *) dst, &l2cap_pi(sock->sk)->chan->dst);
	baswap((void *) src, &l2cap_pi(sock->sk)->chan->src);

	/* session struct allocated as private part of net_device */
	dev = alloc_netdev(sizeof(struct bnep_session),
			   (*req->device) ? req->device : "bnep%d",
			   NET_NAME_UNKNOWN,
			   bnep_net_setup);
	if (!dev)
		return -ENOMEM;

	down_write(&bnep_session_sem);

	ss = __bnep_get_session(dst);
	if (ss && ss->state == BT_CONNECTED) {
		err = -EEXIST;
		goto failed;
	}

	s = netdev_priv(dev);

	/* This is rx header therefore addresses are swapped.
	 * ie. eh.h_dest is our local address. */
	memcpy(s->eh.h_dest,   &src, ETH_ALEN);
	memcpy(s->eh.h_source, &dst, ETH_ALEN);
	memcpy(dev->dev_addr, s->eh.h_dest, ETH_ALEN);

	s->dev   = dev;
	s->sock  = sock;
	s->role  = req->role;
	s->state = BT_CONNECTED;
	s->flags = req->flags;

	s->msg.msg_flags = MSG_NOSIGNAL;

#ifdef CONFIG_BT_BNEP_MC_FILTER
	/* Set default mc filter to not filter out any mc addresses
	 * as defined in the BNEP specification (revision 0.95a)
	 * http://grouper.ieee.org/groups/802/15/Bluetooth/BNEP.pdf
	 */
	s->mc_filter = ~0LL;
#endif

#ifdef CONFIG_BT_BNEP_PROTO_FILTER
	/* Set default protocol filter */
	bnep_set_default_proto_filter(s);
#endif

	SET_NETDEV_DEV(dev, bnep_get_device(s));
	SET_NETDEV_DEVTYPE(dev, &bnep_type);

	err = register_netdev(dev);
	if (err)
		goto failed;

	__bnep_link_session(s);

	__module_get(THIS_MODULE);
	s->task = kthread_run(bnep_session, s, "kbnepd %s", dev->name);
	if (IS_ERR(s->task)) {
		/* Session thread start failed, gotta cleanup. */
		module_put(THIS_MODULE);
		unregister_netdev(dev);
		__bnep_unlink_session(s);
		err = PTR_ERR(s->task);
		goto failed;
	}

	up_write(&bnep_session_sem);
	strcpy(req->device, dev->name);
	return 0;

failed:
	up_write(&bnep_session_sem);
	free_netdev(dev);
	return err;
}

int bnep_del_connection(struct bnep_conndel_req *req)
{
	u32 valid_flags = 0;
	struct bnep_session *s;
	int  err = 0;

	BT_DBG("");

	if (req->flags & ~valid_flags)
		return -EINVAL;

	down_read(&bnep_session_sem);

	s = __bnep_get_session(req->dst);
	if (s) {
		atomic_inc(&s->terminate);
		wake_up_interruptible(sk_sleep(s->sock->sk));
	} else
		err = -ENOENT;

	up_read(&bnep_session_sem);
	return err;
}

static void __bnep_copy_ci(struct bnep_conninfo *ci, struct bnep_session *s)
{
	u32 valid_flags = BIT(BNEP_SETUP_RESPONSE);

	memset(ci, 0, sizeof(*ci));
	memcpy(ci->dst, s->eh.h_source, ETH_ALEN);
	strcpy(ci->device, s->dev->name);
	ci->flags = s->flags & valid_flags;
	ci->state = s->state;
	ci->role  = s->role;
}

int bnep_get_connlist(struct bnep_connlist_req *req)
{
	struct bnep_session *s;
	int err = 0, n = 0;

	down_read(&bnep_session_sem);

	list_for_each_entry(s, &bnep_session_list, list) {
		struct bnep_conninfo ci;

		__bnep_copy_ci(&ci, s);

		if (copy_to_user(req->ci, &ci, sizeof(ci))) {
			err = -EFAULT;
			break;
		}

		if (++n >= req->cnum)
			break;

		req->ci++;
	}
	req->cnum = n;

	up_read(&bnep_session_sem);
	return err;
}

int bnep_get_conninfo(struct bnep_conninfo *ci)
{
	struct bnep_session *s;
	int err = 0;

	down_read(&bnep_session_sem);

	s = __bnep_get_session(ci->dst);
	if (s)
		__bnep_copy_ci(ci, s);
	else
		err = -ENOENT;

	up_read(&bnep_session_sem);
	return err;
}

static int __init bnep_init(void)
{
	char flt[50] = "";

#ifdef CONFIG_BT_BNEP_PROTO_FILTER
	strcat(flt, "protocol ");
#endif

#ifdef CONFIG_BT_BNEP_MC_FILTER
	strcat(flt, "multicast");
#endif

	BT_INFO("BNEP (Ethernet Emulation) ver %s", VERSION);
	if (flt[0])
		BT_INFO("BNEP filters: %s", flt);

	bnep_sock_init();
	return 0;
}

static void __exit bnep_exit(void)
{
	bnep_sock_cleanup();
}

module_init(bnep_init);
module_exit(bnep_exit);

module_param(compress_src, bool, 0644);
MODULE_PARM_DESC(compress_src, "Compress sources headers");

module_param(compress_dst, bool, 0644);
MODULE_PARM_DESC(compress_dst, "Compress destination headers");

MODULE_AUTHOR("Marcel Holtmann <marcel@holtmann.org>");
MODULE_DESCRIPTION("Bluetooth BNEP ver " VERSION);
MODULE_VERSION(VERSION);
MODULE_LICENSE("GPL");
MODULE_ALIAS("bt-proto-4");

};
/*********************************************/

struct Ethernet
{

__setup("ether=", netdev_boot_setup);

/**
 * eth_header - create the Ethernet header
 * @skb:	buffer to alter
 * @dev:	source device
 * @type:	Ethernet type field
 * @daddr: destination address (NULL leave destination address)
 * @saddr: source address (NULL use device source address)
 * @len:   packet length (<= skb->len)
 *
 *
 * Set the protocol type. For a packet of type ETH_P_802_3/2 we put the length
 * in here instead.
 */
int eth_header(struct sk_buff *skb, struct net_device *dev,
	       unsigned short type,
	       const void *daddr, const void *saddr, unsigned int len)
{
	struct ethhdr *eth = skb_push(skb, ETH_HLEN);

	if (type != ETH_P_802_3 && type != ETH_P_802_2)
		eth->h_proto = htons(type);
	else
		eth->h_proto = htons(len);

	/*
	 *      Set the source hardware address.
	 */

	if (!saddr)
		saddr = dev->dev_addr;
	memcpy(eth->h_source, saddr, ETH_ALEN);

	if (daddr) {
		memcpy(eth->h_dest, daddr, ETH_ALEN);
		return ETH_HLEN;
	}

	/*
	 *      Anyway, the loopback-device should never use this function...
	 */

	if (dev->flags & (IFF_LOOPBACK | IFF_NOARP)) {
		eth_zero_addr(eth->h_dest);
		return ETH_HLEN;
	}

	return -ETH_HLEN;
}
EXPORT_SYMBOL(eth_header);

/**
 * eth_get_headlen - determine the length of header for an ethernet frame
 * @dev: pointer to network device
 * @data: pointer to start of frame
 * @len: total length of frame
 *
 * Make a best effort attempt to pull the length for all of the headers for
 * a given frame in a linear buffer.
 */
u32 eth_get_headlen(const struct net_device *dev, void *data, unsigned int len)
{
	const unsigned int flags = FLOW_DISSECTOR_F_PARSE_1ST_FRAG;
	const struct ethhdr *eth = (const struct ethhdr *)data;
	struct flow_keys_basic keys;

	/* this should never happen, but better safe than sorry */
	if (unlikely(len < sizeof(*eth)))
		return len;

	/* parse any remaining L2/L3 headers, check for L4 */
	if (!skb_flow_dissect_flow_keys_basic(dev_net(dev), NULL, &keys, data,
					      eth->h_proto, sizeof(*eth),
					      len, flags))
		return max_t(u32, keys.control.thoff, sizeof(*eth));

	/* parse for any L4 headers */
	return min_t(u32, __skb_get_poff(NULL, data, &keys, len), len);
}
EXPORT_SYMBOL(eth_get_headlen);

/**
 * eth_type_trans - determine the packet's protocol ID.
 * @skb: received socket data
 * @dev: receiving network device
 *
 * The rule here is that we
 * assume 802.3 if the type field is short enough to be a length.
 * This is normal practice and works for any 'now in use' protocol.
 */
__be16 eth_type_trans(struct sk_buff *skb, struct net_device *dev)
{
	unsigned short _service_access_point;
	const unsigned short *sap;
	const struct ethhdr *eth;

	skb->dev = dev;
	skb_reset_mac_header(skb);

	eth = (struct ethhdr *)skb->data;
	skb_pull_inline(skb, ETH_HLEN);

	if (unlikely(!ether_addr_equal_64bits(eth->h_dest,
					      dev->dev_addr))) {
		if (unlikely(is_multicast_ether_addr_64bits(eth->h_dest))) {
			if (ether_addr_equal_64bits(eth->h_dest, dev->broadcast))
				skb->pkt_type = PACKET_BROADCAST;
			else
				skb->pkt_type = PACKET_MULTICAST;
		} else {
			skb->pkt_type = PACKET_OTHERHOST;
		}
	}

	/*
	 * Some variants of DSA tagging don't have an ethertype field
	 * at all, so we check here whether one of those tagging
	 * variants has been configured on the receiving interface,
	 * and if so, set skb->protocol without looking at the packet.
	 * The DSA tagging protocol may be able to decode some but not all
	 * traffic (for example only for management). In that case give it the
	 * option to filter the packets from which it can decode source port
	 * information.
	 */
	if (unlikely(netdev_uses_dsa(dev)) && dsa_can_decode(skb, dev))
		return htons(ETH_P_XDSA);

	if (likely(eth_proto_is_802_3(eth->h_proto)))
		return eth->h_proto;

	/*
	 *      This is a magic hack to spot IPX packets. Older Novell breaks
	 *      the protocol design and runs IPX over 802.3 without an 802.2 LLC
	 *      layer. We look for FFFF which isn't a used 802.2 SSAP/DSAP. This
	 *      won't work for fault tolerant netware but does for the rest.
	 */
	sap = skb_header_pointer(skb, 0, sizeof(*sap), &_service_access_point);
	if (sap && *sap == 0xFFFF)
		return htons(ETH_P_802_3);

	/*
	 *      Real 802.2 LLC
	 */
	return htons(ETH_P_802_2);
}
EXPORT_SYMBOL(eth_type_trans);

/**
 * eth_header_parse - extract hardware address from packet
 * @skb: packet to extract header from
 * @haddr: destination buffer
 */
int eth_header_parse(const struct sk_buff *skb, unsigned char *haddr)
{
	const struct ethhdr *eth = eth_hdr(skb);
	memcpy(haddr, eth->h_source, ETH_ALEN);
	return ETH_ALEN;
}
EXPORT_SYMBOL(eth_header_parse);

/**
 * eth_header_cache - fill cache entry from neighbour
 * @neigh: source neighbour
 * @hh: destination cache entry
 * @type: Ethernet type field
 *
 * Create an Ethernet header template from the neighbour.
 */
int eth_header_cache(const struct neighbour *neigh, struct hh_cache *hh, __be16 type)
{
	struct ethhdr *eth;
	const struct net_device *dev = neigh->dev;

	eth = (struct ethhdr *)
	    (((u8 *) hh->hh_data) + (HH_DATA_OFF(sizeof(*eth))));

	if (type == htons(ETH_P_802_3))
		return -1;

	eth->h_proto = type;
	memcpy(eth->h_source, dev->dev_addr, ETH_ALEN);
	memcpy(eth->h_dest, neigh->ha, ETH_ALEN);

	/* Pairs with READ_ONCE() in neigh_resolve_output(),
	 * neigh_hh_output() and neigh_update_hhs().
	 */
	smp_store_release(&hh->hh_len, ETH_HLEN);

	return 0;
}
EXPORT_SYMBOL(eth_header_cache);

/**
 * eth_header_cache_update - update cache entry
 * @hh: destination cache entry
 * @dev: network device
 * @haddr: new hardware address
 *
 * Called by Address Resolution module to notify changes in address.
 */
void eth_header_cache_update(struct hh_cache *hh,
			     const struct net_device *dev,
			     const unsigned char *haddr)
{
	memcpy(((u8 *) hh->hh_data) + HH_DATA_OFF(sizeof(struct ethhdr)),
	       haddr, ETH_ALEN);
}
EXPORT_SYMBOL(eth_header_cache_update);

/**
 * eth_header_parser_protocol - extract protocol from L2 header
 * @skb: packet to extract protocol from
 */
__be16 eth_header_parse_protocol(const struct sk_buff *skb)
{
	const struct ethhdr *eth = eth_hdr(skb);

	return eth->h_proto;
}
EXPORT_SYMBOL(eth_header_parse_protocol);

/**
 * eth_prepare_mac_addr_change - prepare for mac change
 * @dev: network device
 * @p: socket address
 */
int eth_prepare_mac_addr_change(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	if (!(dev->priv_flags & IFF_LIVE_ADDR_CHANGE) && netif_running(dev))
		return -EBUSY;
	if (!is_valid_ether_addr(addr->sa_data))
		return -EADDRNOTAVAIL;
	return 0;
}
EXPORT_SYMBOL(eth_prepare_mac_addr_change);

/**
 * eth_commit_mac_addr_change - commit mac change
 * @dev: network device
 * @p: socket address
 */
void eth_commit_mac_addr_change(struct net_device *dev, void *p)
{
	struct sockaddr *addr = p;

	memcpy(dev->dev_addr, addr->sa_data, ETH_ALEN);
}
EXPORT_SYMBOL(eth_commit_mac_addr_change);

/**
 * eth_mac_addr - set new Ethernet hardware address
 * @dev: network device
 * @p: socket address
 *
 * Change hardware address of device.
 *
 * This doesn't change hardware matching, so needs to be overridden
 * for most real devices.
 */
int eth_mac_addr(struct net_device *dev, void *p)
{
	int ret;

	ret = eth_prepare_mac_addr_change(dev, p);
	if (ret < 0)
		return ret;
	eth_commit_mac_addr_change(dev, p);
	return 0;
}
EXPORT_SYMBOL(eth_mac_addr);

int eth_validate_addr(struct net_device *dev)
{
	if (!is_valid_ether_addr(dev->dev_addr))
		return -EADDRNOTAVAIL;

	return 0;
}
EXPORT_SYMBOL(eth_validate_addr);

const struct header_ops eth_header_ops ____cacheline_aligned = {
	.create		= eth_header,
	.parse		= eth_header_parse,
	.cache		= eth_header_cache,
	.cache_update	= eth_header_cache_update,
	.parse_protocol	= eth_header_parse_protocol,
};

/**
 * ether_setup - setup Ethernet network device
 * @dev: network device
 *
 * Fill in the fields of the device structure with Ethernet-generic values.
 */
void ether_setup(struct net_device *dev)
{
	dev->header_ops		= &eth_header_ops;
	dev->type		= ARPHRD_ETHER;
	dev->hard_header_len 	= ETH_HLEN;
	dev->min_header_len	= ETH_HLEN;
	dev->mtu		= ETH_DATA_LEN;
	dev->min_mtu		= ETH_MIN_MTU;
	dev->max_mtu		= ETH_DATA_LEN;
	dev->addr_len		= ETH_ALEN;
	dev->tx_queue_len	= DEFAULT_TX_QUEUE_LEN;
	dev->flags		= IFF_BROADCAST|IFF_MULTICAST;
	dev->priv_flags		|= IFF_TX_SKB_SHARING;

	eth_broadcast_addr(dev->broadcast);

}
EXPORT_SYMBOL(ether_setup);

/**
 * alloc_etherdev_mqs - Allocates and sets up an Ethernet device
 * @sizeof_priv: Size of additional driver-private structure to be allocated
 *	for this Ethernet device
 * @txqs: The number of TX queues this device has.
 * @rxqs: The number of RX queues this device has.
 *
 * Fill in the fields of the device structure with Ethernet-generic
 * values. Basically does everything except registering the device.
 *
 * Constructs a new net device, complete with a private data area of
 * size (sizeof_priv).  A 32-byte (not bit) alignment is enforced for
 * this private data area.
 */

struct net_device *alloc_etherdev_mqs(int sizeof_priv, unsigned int txqs,
				      unsigned int rxqs)
{
	return alloc_netdev_mqs(sizeof_priv, "eth%d", NET_NAME_UNKNOWN,
				ether_setup, txqs, rxqs);
}
EXPORT_SYMBOL(alloc_etherdev_mqs);

static void devm_free_netdev(struct device *dev, void *res)
{
	free_netdev(*(struct net_device **)res);
}

struct net_device *devm_alloc_etherdev_mqs(struct device *dev, int sizeof_priv,
					   unsigned int txqs, unsigned int rxqs)
{
	struct net_device **dr;
	struct net_device *netdev;

	dr = devres_alloc(devm_free_netdev, sizeof(*dr), GFP_KERNEL);
	if (!dr)
		return NULL;

	netdev = alloc_etherdev_mqs(sizeof_priv, txqs, rxqs);
	if (!netdev) {
		devres_free(dr);
		return NULL;
	}

	*dr = netdev;
	devres_add(dev, dr);

	return netdev;
}
EXPORT_SYMBOL(devm_alloc_etherdev_mqs);

ssize_t sysfs_format_mac(char *buf, const unsigned char *addr, int len)
{
	return scnprintf(buf, PAGE_SIZE, "%*phC\n", len, addr);
}
EXPORT_SYMBOL(sysfs_format_mac);

struct sk_buff *eth_gro_receive(struct list_head *head, struct sk_buff *skb)
{
	const struct packet_offload *ptype;
	unsigned int hlen, off_eth;
	struct sk_buff *pp = NULL;
	struct ethhdr *eh, *eh2;
	struct sk_buff *p;
	__be16 type;
	int flush = 1;

	off_eth = skb_gro_offset(skb);
	hlen = off_eth + sizeof(*eh);
	eh = skb_gro_header_fast(skb, off_eth);
	if (skb_gro_header_hard(skb, hlen)) {
		eh = skb_gro_header_slow(skb, hlen, off_eth);
		if (unlikely(!eh))
			goto out;
	}

	flush = 0;

	list_for_each_entry(p, head, list) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		eh2 = (struct ethhdr *)(p->data + off_eth);
		if (compare_ether_header(eh, eh2)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}
	}

	type = eh->h_proto;

	rcu_read_lock();
	ptype = gro_find_receive_by_type(type);
	if (ptype == NULL) {
		flush = 1;
		goto out_unlock;
	}

	skb_gro_pull(skb, sizeof(*eh));
	skb_gro_postpull_rcsum(skb, eh, sizeof(*eh));
	pp = call_gro_receive(ptype->callbacks.gro_receive, head, skb);

out_unlock:
	rcu_read_unlock();
out:
	skb_gro_flush_final(skb, pp, flush);

	return pp;
}
EXPORT_SYMBOL(eth_gro_receive);

int eth_gro_complete(struct sk_buff *skb, int nhoff)
{
	struct ethhdr *eh = (struct ethhdr *)(skb->data + nhoff);
	__be16 type = eh->h_proto;
	struct packet_offload *ptype;
	int err = -ENOSYS;

	if (skb->encapsulation)
		skb_set_inner_mac_header(skb, nhoff);

	rcu_read_lock();
	ptype = gro_find_complete_by_type(type);
	if (ptype != NULL)
		err = ptype->callbacks.gro_complete(skb, nhoff +
						    sizeof(struct ethhdr));

	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(eth_gro_complete);

static struct packet_offload eth_packet_offload __read_mostly = {
	.type = cpu_to_be16(ETH_P_TEB),
	.priority = 10,
	.callbacks = {
		.gro_receive = eth_gro_receive,
		.gro_complete = eth_gro_complete,
	},
};

static int __init eth_offload_init(void)
{
	dev_add_offload(&eth_packet_offload);

	return 0;
}

fs_initcall(eth_offload_init);

unsigned char * __weak arch_get_platform_mac_address(void)
{
	return NULL;
}

int eth_platform_get_mac_address(struct device *dev, u8 *mac_addr)
{
	const unsigned char *addr = NULL;

	if (dev->of_node)
		addr = of_get_mac_address(dev->of_node);
	if (IS_ERR_OR_NULL(addr))
		addr = arch_get_platform_mac_address();

	if (!addr)
		return -ENODEV;

	ether_addr_copy(mac_addr, addr);

	return 0;
}
EXPORT_SYMBOL(eth_platform_get_mac_address);

/**
 * Obtain the MAC address from an nvmem cell named 'mac-address' associated
 * with given device.
 *
 * @dev:	Device with which the mac-address cell is associated.
 * @addrbuf:	Buffer to which the MAC address will be copied on success.
 *
 * Returns 0 on success or a negative error number on failure.
 */
int nvmem_get_mac_address(struct device *dev, void *addrbuf)
{
	struct nvmem_cell *cell;
	const void *mac;
	size_t len;

	cell = nvmem_cell_get(dev, "mac-address");
	if (IS_ERR(cell))
		return PTR_ERR(cell);

	mac = nvmem_cell_read(cell, &len);
	nvmem_cell_put(cell);

	if (IS_ERR(mac))
		return PTR_ERR(mac);

	if (len != ETH_ALEN || !is_valid_ether_addr(mac)) {
		kfree(mac);
		return -EINVAL;
	}

	ether_addr_copy(addrbuf, mac);
	kfree(mac);

	return 0;
}
EXPORT_SYMBOL(nvmem_get_mac_address);

};
/*********************************************************/

/*protocol  linux_protocol */

struct linux_protocol 
{
    HLIST_HEAD(atalk_sockets);
DEFINE_RWLOCK(atalk_sockets_lock);

static inline void __atalk_insert_socket(struct sock *sk)
{
	sk_add_node(sk, &atalk_sockets);
}

static inline void atalk_remove_socket(struct sock *sk)
{
	write_lock_bh(&atalk_sockets_lock);
	sk_del_node_init(sk);
	write_unlock_bh(&atalk_sockets_lock);
}

static struct sock *atalk_search_socket(struct sockaddr_at *to,
					struct atalk_iface *atif)
{
	struct sock *s;

	read_lock_bh(&atalk_sockets_lock);
	sk_for_each(s, &atalk_sockets) {
		struct atalk_sock *at = at_sk(s);

		if (to->sat_port != at->src_port)
			continue;

		if (to->sat_addr.s_net == ATADDR_ANYNET &&
		    to->sat_addr.s_node == ATADDR_BCAST)
			goto found;

		if (to->sat_addr.s_net == at->src_net &&
		    (to->sat_addr.s_node == at->src_node ||
		     to->sat_addr.s_node == ATADDR_BCAST ||
		     to->sat_addr.s_node == ATADDR_ANYNODE))
			goto found;

		/* XXXX.0 -- we got a request for this router. make sure
		 * that the node is appropriately set. */
		if (to->sat_addr.s_node == ATADDR_ANYNODE &&
		    to->sat_addr.s_net != ATADDR_ANYNET &&
		    atif->address.s_node == at->src_node) {
			to->sat_addr.s_node = atif->address.s_node;
			goto found;
		}
	}
	s = NULL;
found:
	read_unlock_bh(&atalk_sockets_lock);
	return s;
}

/**
 * atalk_find_or_insert_socket - Try to find a socket matching ADDR
 * @sk: socket to insert in the list if it is not there already
 * @sat: address to search for
 *
 * Try to find a socket matching ADDR in the socket list, if found then return
 * it. If not, insert SK into the socket list.
 *
 * This entire operation must execute atomically.
 */
static struct sock *atalk_find_or_insert_socket(struct sock *sk,
						struct sockaddr_at *sat)
{
	struct sock *s;
	struct atalk_sock *at;

	write_lock_bh(&atalk_sockets_lock);
	sk_for_each(s, &atalk_sockets) {
		at = at_sk(s);

		if (at->src_net == sat->sat_addr.s_net &&
		    at->src_node == sat->sat_addr.s_node &&
		    at->src_port == sat->sat_port)
			goto found;
	}
	s = NULL;
	__atalk_insert_socket(sk); /* Wheee, it's free, assign and insert. */
found:
	write_unlock_bh(&atalk_sockets_lock);
	return s;
}

static void atalk_destroy_timer(struct timer_list *t)
{
	struct sock *sk = from_timer(sk, t, sk_timer);

	if (sk_has_allocations(sk)) {
		sk->sk_timer.expires = jiffies + SOCK_DESTROY_TIME;
		add_timer(&sk->sk_timer);
	} else
		sock_put(sk);
}

static inline void atalk_destroy_socket(struct sock *sk)
{
	atalk_remove_socket(sk);
	skb_queue_purge(&sk->sk_receive_queue);

	if (sk_has_allocations(sk)) {
		timer_setup(&sk->sk_timer, atalk_destroy_timer, 0);
		sk->sk_timer.expires	= jiffies + SOCK_DESTROY_TIME;
		add_timer(&sk->sk_timer);
	} else
		sock_put(sk);
}

/**************************************************************************\
*                                                                          *
* Routing tables for the AppleTalk socket layer.                           *
*                                                                          *
\**************************************************************************/

/* Anti-deadlock ordering is atalk_routes_lock --> iface_lock -DaveM */
struct atalk_route *atalk_routes;
DEFINE_RWLOCK(atalk_routes_lock);

struct atalk_iface *atalk_interfaces;
DEFINE_RWLOCK(atalk_interfaces_lock);

/* For probing devices or in a routerless network */
struct atalk_route atrtr_default;

/* AppleTalk interface control */
/*
 * Drop a device. Doesn't drop any of its routes - that is the caller's
 * problem. Called when we down the interface or delete the address.
 */
static void atif_drop_device(struct net_device *dev)
{
	struct atalk_iface **iface = &atalk_interfaces;
	struct atalk_iface *tmp;

	write_lock_bh(&atalk_interfaces_lock);
	while ((tmp = *iface) != NULL) {
		if (tmp->dev == dev) {
			*iface = tmp->next;
			dev_put(dev);
			kfree(tmp);
			dev->atalk_ptr = NULL;
		} else
			iface = &tmp->next;
	}
	write_unlock_bh(&atalk_interfaces_lock);
}

static struct atalk_iface *atif_add_device(struct net_device *dev,
					   struct atalk_addr *sa)
{
	struct atalk_iface *iface = kzalloc(sizeof(*iface), GFP_KERNEL);

	if (!iface)
		goto out;

	dev_hold(dev);
	iface->dev = dev;
	dev->atalk_ptr = iface;
	iface->address = *sa;
	iface->status = 0;

	write_lock_bh(&atalk_interfaces_lock);
	iface->next = atalk_interfaces;
	atalk_interfaces = iface;
	write_unlock_bh(&atalk_interfaces_lock);
out:
	return iface;
}

/* Perform phase 2 AARP probing on our tentative address */
static int atif_probe_device(struct atalk_iface *atif)
{
	int netrange = ntohs(atif->nets.nr_lastnet) -
			ntohs(atif->nets.nr_firstnet) + 1;
	int probe_net = ntohs(atif->address.s_net);
	int probe_node = atif->address.s_node;
	int netct, nodect;

	/* Offset the network we start probing with */
	if (probe_net == ATADDR_ANYNET) {
		probe_net = ntohs(atif->nets.nr_firstnet);
		if (netrange)
			probe_net += jiffies % netrange;
	}
	if (probe_node == ATADDR_ANYNODE)
		probe_node = jiffies & 0xFF;

	/* Scan the networks */
	atif->status |= ATIF_PROBE;
	for (netct = 0; netct <= netrange; netct++) {
		/* Sweep the available nodes from a given start */
		atif->address.s_net = htons(probe_net);
		for (nodect = 0; nodect < 256; nodect++) {
			atif->address.s_node = (nodect + probe_node) & 0xFF;
			if (atif->address.s_node > 0 &&
			    atif->address.s_node < 254) {
				/* Probe a proposed address */
				aarp_probe_network(atif);

				if (!(atif->status & ATIF_PROBE_FAIL)) {
					atif->status &= ~ATIF_PROBE;
					return 0;
				}
			}
			atif->status &= ~ATIF_PROBE_FAIL;
		}
		probe_net++;
		if (probe_net > ntohs(atif->nets.nr_lastnet))
			probe_net = ntohs(atif->nets.nr_firstnet);
	}
	atif->status &= ~ATIF_PROBE;

	return -EADDRINUSE;	/* Network is full... */
}


/* Perform AARP probing for a proxy address */
static int atif_proxy_probe_device(struct atalk_iface *atif,
				   struct atalk_addr *proxy_addr)
{
	int netrange = ntohs(atif->nets.nr_lastnet) -
			ntohs(atif->nets.nr_firstnet) + 1;
	/* we probe the interface's network */
	int probe_net = ntohs(atif->address.s_net);
	int probe_node = ATADDR_ANYNODE;	    /* we'll take anything */
	int netct, nodect;

	/* Offset the network we start probing with */
	if (probe_net == ATADDR_ANYNET) {
		probe_net = ntohs(atif->nets.nr_firstnet);
		if (netrange)
			probe_net += jiffies % netrange;
	}

	if (probe_node == ATADDR_ANYNODE)
		probe_node = jiffies & 0xFF;

	/* Scan the networks */
	for (netct = 0; netct <= netrange; netct++) {
		/* Sweep the available nodes from a given start */
		proxy_addr->s_net = htons(probe_net);
		for (nodect = 0; nodect < 256; nodect++) {
			proxy_addr->s_node = (nodect + probe_node) & 0xFF;
			if (proxy_addr->s_node > 0 &&
			    proxy_addr->s_node < 254) {
				/* Tell AARP to probe a proposed address */
				int ret = aarp_proxy_probe_network(atif,
								    proxy_addr);

				if (ret != -EADDRINUSE)
					return ret;
			}
		}
		probe_net++;
		if (probe_net > ntohs(atif->nets.nr_lastnet))
			probe_net = ntohs(atif->nets.nr_firstnet);
	}

	return -EADDRINUSE;	/* Network is full... */
}


struct atalk_addr *atalk_find_dev_addr(struct net_device *dev)
{
	struct atalk_iface *iface = dev->atalk_ptr;
	return iface ? &iface->address : NULL;
}

static struct atalk_addr *atalk_find_primary(void)
{
	struct atalk_iface *fiface = NULL;
	struct atalk_addr *retval;
	struct atalk_iface *iface;

	/*
	 * Return a point-to-point interface only if
	 * there is no non-ptp interface available.
	 */
	read_lock_bh(&atalk_interfaces_lock);
	for (iface = atalk_interfaces; iface; iface = iface->next) {
		if (!fiface && !(iface->dev->flags & IFF_LOOPBACK))
			fiface = iface;
		if (!(iface->dev->flags & (IFF_LOOPBACK | IFF_POINTOPOINT))) {
			retval = &iface->address;
			goto out;
		}
	}

	if (fiface)
		retval = &fiface->address;
	else if (atalk_interfaces)
		retval = &atalk_interfaces->address;
	else
		retval = NULL;
out:
	read_unlock_bh(&atalk_interfaces_lock);
	return retval;
}

/*
 * Find a match for 'any network' - ie any of our interfaces with that
 * node number will do just nicely.
 */
static struct atalk_iface *atalk_find_anynet(int node, struct net_device *dev)
{
	struct atalk_iface *iface = dev->atalk_ptr;

	if (!iface || iface->status & ATIF_PROBE)
		goto out_err;

	if (node != ATADDR_BCAST &&
	    iface->address.s_node != node &&
	    node != ATADDR_ANYNODE)
		goto out_err;
out:
	return iface;
out_err:
	iface = NULL;
	goto out;
}

/* Find a match for a specific network:node pair */
static struct atalk_iface *atalk_find_interface(__be16 net, int node)
{
	struct atalk_iface *iface;

	read_lock_bh(&atalk_interfaces_lock);
	for (iface = atalk_interfaces; iface; iface = iface->next) {
		if ((node == ATADDR_BCAST ||
		     node == ATADDR_ANYNODE ||
		     iface->address.s_node == node) &&
		    iface->address.s_net == net &&
		    !(iface->status & ATIF_PROBE))
			break;

		/* XXXX.0 -- net.0 returns the iface associated with net */
		if (node == ATADDR_ANYNODE && net != ATADDR_ANYNET &&
		    ntohs(iface->nets.nr_firstnet) <= ntohs(net) &&
		    ntohs(net) <= ntohs(iface->nets.nr_lastnet))
			break;
	}
	read_unlock_bh(&atalk_interfaces_lock);
	return iface;
}


/*
 * Find a route for an AppleTalk packet. This ought to get cached in
 * the socket (later on...). We know about host routes and the fact
 * that a route must be direct to broadcast.
 */
static struct atalk_route *atrtr_find(struct atalk_addr *target)
{
	/*
	 * we must search through all routes unless we find a
	 * host route, because some host routes might overlap
	 * network routes
	 */
	struct atalk_route *net_route = NULL;
	struct atalk_route *r;

	read_lock_bh(&atalk_routes_lock);
	for (r = atalk_routes; r; r = r->next) {
		if (!(r->flags & RTF_UP))
			continue;

		if (r->target.s_net == target->s_net) {
			if (r->flags & RTF_HOST) {
				/*
				 * if this host route is for the target,
				 * the we're done
				 */
				if (r->target.s_node == target->s_node)
					goto out;
			} else
				/*
				 * this route will work if there isn't a
				 * direct host route, so cache it
				 */
				net_route = r;
		}
	}

	/*
	 * if we found a network route but not a direct host
	 * route, then return it
	 */
	if (net_route)
		r = net_route;
	else if (atrtr_default.dev)
		r = &atrtr_default;
	else /* No route can be found */
		r = NULL;
out:
	read_unlock_bh(&atalk_routes_lock);
	return r;
}


/*
 * Given an AppleTalk network, find the device to use. This can be
 * a simple lookup.
 */
struct net_device *atrtr_get_dev(struct atalk_addr *sa)
{
	struct atalk_route *atr = atrtr_find(sa);
	return atr ? atr->dev : NULL;
}

/* Set up a default router */
static void atrtr_set_default(struct net_device *dev)
{
	atrtr_default.dev	     = dev;
	atrtr_default.flags	     = RTF_UP;
	atrtr_default.gateway.s_net  = htons(0);
	atrtr_default.gateway.s_node = 0;
}

/*
 * Add a router. Basically make sure it looks valid and stuff the
 * entry in the list. While it uses netranges we always set them to one
 * entry to work like netatalk.
 */
static int atrtr_create(struct rtentry *r, struct net_device *devhint)
{
	struct sockaddr_at *ta = (struct sockaddr_at *)&r->rt_dst;
	struct sockaddr_at *ga = (struct sockaddr_at *)&r->rt_gateway;
	struct atalk_route *rt;
	struct atalk_iface *iface, *riface;
	int retval = -EINVAL;

	/*
	 * Fixme: Raise/Lower a routing change semaphore for these
	 * operations.
	 */

	/* Validate the request */
	if (ta->sat_family != AF_APPLETALK ||
	    (!devhint && ga->sat_family != AF_APPLETALK))
		goto out;

	/* Now walk the routing table and make our decisions */
	write_lock_bh(&atalk_routes_lock);
	for (rt = atalk_routes; rt; rt = rt->next) {
		if (r->rt_flags != rt->flags)
			continue;

		if (ta->sat_addr.s_net == rt->target.s_net) {
			if (!(rt->flags & RTF_HOST))
				break;
			if (ta->sat_addr.s_node == rt->target.s_node)
				break;
		}
	}

	if (!devhint) {
		riface = NULL;

		read_lock_bh(&atalk_interfaces_lock);
		for (iface = atalk_interfaces; iface; iface = iface->next) {
			if (!riface &&
			    ntohs(ga->sat_addr.s_net) >=
					ntohs(iface->nets.nr_firstnet) &&
			    ntohs(ga->sat_addr.s_net) <=
					ntohs(iface->nets.nr_lastnet))
				riface = iface;

			if (ga->sat_addr.s_net == iface->address.s_net &&
			    ga->sat_addr.s_node == iface->address.s_node)
				riface = iface;
		}
		read_unlock_bh(&atalk_interfaces_lock);

		retval = -ENETUNREACH;
		if (!riface)
			goto out_unlock;

		devhint = riface->dev;
	}

	if (!rt) {
		rt = kzalloc(sizeof(*rt), GFP_ATOMIC);

		retval = -ENOBUFS;
		if (!rt)
			goto out_unlock;

		rt->next = atalk_routes;
		atalk_routes = rt;
	}

	/* Fill in the routing entry */
	rt->target  = ta->sat_addr;
	dev_hold(devhint);
	rt->dev     = devhint;
	rt->flags   = r->rt_flags;
	rt->gateway = ga->sat_addr;

	retval = 0;
out_unlock:
	write_unlock_bh(&atalk_routes_lock);
out:
	return retval;
}

/* Delete a route. Find it and discard it */
static int atrtr_delete(struct atalk_addr *addr)
{
	struct atalk_route **r = &atalk_routes;
	int retval = 0;
	struct atalk_route *tmp;

	write_lock_bh(&atalk_routes_lock);
	while ((tmp = *r) != NULL) {
		if (tmp->target.s_net == addr->s_net &&
		    (!(tmp->flags&RTF_GATEWAY) ||
		     tmp->target.s_node == addr->s_node)) {
			*r = tmp->next;
			dev_put(tmp->dev);
			kfree(tmp);
			goto out;
		}
		r = &tmp->next;
	}
	retval = -ENOENT;
out:
	write_unlock_bh(&atalk_routes_lock);
	return retval;
}

/*
 * Called when a device is downed. Just throw away any routes
 * via it.
 */
static void atrtr_device_down(struct net_device *dev)
{
	struct atalk_route **r = &atalk_routes;
	struct atalk_route *tmp;

	write_lock_bh(&atalk_routes_lock);
	while ((tmp = *r) != NULL) {
		if (tmp->dev == dev) {
			*r = tmp->next;
			dev_put(dev);
			kfree(tmp);
		} else
			r = &tmp->next;
	}
	write_unlock_bh(&atalk_routes_lock);

	if (atrtr_default.dev == dev)
		atrtr_set_default(NULL);
}

/* Actually down the interface */
static inline void atalk_dev_down(struct net_device *dev)
{
	atrtr_device_down(dev);	/* Remove all routes for the device */
	aarp_device_down(dev);	/* Remove AARP entries for the device */
	atif_drop_device(dev);	/* Remove the device */
}

/*
 * A device event has occurred. Watch for devices going down and
 * delete our use of them (iface and route).
 */
static int ddp_device_event(struct notifier_block *this, unsigned long event,
			    void *ptr)
{
	struct net_device *dev = netdev_notifier_info_to_dev(ptr);

	if (!net_eq(dev_net(dev), &init_net))
		return NOTIFY_DONE;

	if (event == NETDEV_DOWN)
		/* Discard any use of this */
		atalk_dev_down(dev);

	return NOTIFY_DONE;
}

/* ioctl calls. Shouldn't even need touching */
/* Device configuration ioctl calls */
static int atif_ioctl(int cmd, void __user *arg)
{
	static char aarp_mcast[6] = { 0x09, 0x00, 0x00, 0xFF, 0xFF, 0xFF };
	struct ifreq atreq;
	struct atalk_netrange *nr;
	struct sockaddr_at *sa;
	struct net_device *dev;
	struct atalk_iface *atif;
	int ct;
	int limit;
	struct rtentry rtdef;
	int add_route;

	if (copy_from_user(&atreq, arg, sizeof(atreq)))
		return -EFAULT;

	dev = __dev_get_by_name(&init_net, atreq.ifr_name);
	if (!dev)
		return -ENODEV;

	sa = (struct sockaddr_at *)&atreq.ifr_addr;
	atif = atalk_find_dev(dev);

	switch (cmd) {
	case SIOCSIFADDR:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (sa->sat_family != AF_APPLETALK)
			return -EINVAL;
		if (dev->type != ARPHRD_ETHER &&
		    dev->type != ARPHRD_LOOPBACK &&
		    dev->type != ARPHRD_LOCALTLK &&
		    dev->type != ARPHRD_PPP)
			return -EPROTONOSUPPORT;

		nr = (struct atalk_netrange *)&sa->sat_zero[0];
		add_route = 1;

		/*
		 * if this is a point-to-point iface, and we already
		 * have an iface for this AppleTalk address, then we
		 * should not add a route
		 */
		if ((dev->flags & IFF_POINTOPOINT) &&
		    atalk_find_interface(sa->sat_addr.s_net,
					 sa->sat_addr.s_node)) {
			printk(KERN_DEBUG "AppleTalk: point-to-point "
			       "interface added with "
			       "existing address\n");
			add_route = 0;
		}

		/*
		 * Phase 1 is fine on LocalTalk but we don't do
		 * EtherTalk phase 1. Anyone wanting to add it go ahead.
		 */
		if (dev->type == ARPHRD_ETHER && nr->nr_phase != 2)
			return -EPROTONOSUPPORT;
		if (sa->sat_addr.s_node == ATADDR_BCAST ||
		    sa->sat_addr.s_node == 254)
			return -EINVAL;
		if (atif) {
			/* Already setting address */
			if (atif->status & ATIF_PROBE)
				return -EBUSY;

			atif->address.s_net  = sa->sat_addr.s_net;
			atif->address.s_node = sa->sat_addr.s_node;
			atrtr_device_down(dev);	/* Flush old routes */
		} else {
			atif = atif_add_device(dev, &sa->sat_addr);
			if (!atif)
				return -ENOMEM;
		}
		atif->nets = *nr;

		/*
		 * Check if the chosen address is used. If so we
		 * error and atalkd will try another.
		 */

		if (!(dev->flags & IFF_LOOPBACK) &&
		    !(dev->flags & IFF_POINTOPOINT) &&
		    atif_probe_device(atif) < 0) {
			atif_drop_device(dev);
			return -EADDRINUSE;
		}

		/* Hey it worked - add the direct routes */
		sa = (struct sockaddr_at *)&rtdef.rt_gateway;
		sa->sat_family = AF_APPLETALK;
		sa->sat_addr.s_net  = atif->address.s_net;
		sa->sat_addr.s_node = atif->address.s_node;
		sa = (struct sockaddr_at *)&rtdef.rt_dst;
		rtdef.rt_flags = RTF_UP;
		sa->sat_family = AF_APPLETALK;
		sa->sat_addr.s_node = ATADDR_ANYNODE;
		if (dev->flags & IFF_LOOPBACK ||
		    dev->flags & IFF_POINTOPOINT)
			rtdef.rt_flags |= RTF_HOST;

		/* Routerless initial state */
		if (nr->nr_firstnet == htons(0) &&
		    nr->nr_lastnet == htons(0xFFFE)) {
			sa->sat_addr.s_net = atif->address.s_net;
			atrtr_create(&rtdef, dev);
			atrtr_set_default(dev);
		} else {
			limit = ntohs(nr->nr_lastnet);
			if (limit - ntohs(nr->nr_firstnet) > 4096) {
				printk(KERN_WARNING "Too many routes/"
				       "iface.\n");
				return -EINVAL;
			}
			if (add_route)
				for (ct = ntohs(nr->nr_firstnet);
				     ct <= limit; ct++) {
					sa->sat_addr.s_net = htons(ct);
					atrtr_create(&rtdef, dev);
				}
		}
		dev_mc_add_global(dev, aarp_mcast);
		return 0;

	case SIOCGIFADDR:
		if (!atif)
			return -EADDRNOTAVAIL;

		sa->sat_family = AF_APPLETALK;
		sa->sat_addr = atif->address;
		break;

	case SIOCGIFBRDADDR:
		if (!atif)
			return -EADDRNOTAVAIL;

		sa->sat_family = AF_APPLETALK;
		sa->sat_addr.s_net = atif->address.s_net;
		sa->sat_addr.s_node = ATADDR_BCAST;
		break;

	case SIOCATALKDIFADDR:
	case SIOCDIFADDR:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (sa->sat_family != AF_APPLETALK)
			return -EINVAL;
		atalk_dev_down(dev);
		break;

	case SIOCSARP:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (sa->sat_family != AF_APPLETALK)
			return -EINVAL;
		/*
		 * for now, we only support proxy AARP on ELAP;
		 * we should be able to do it for LocalTalk, too.
		 */
		if (dev->type != ARPHRD_ETHER)
			return -EPROTONOSUPPORT;

		/*
		 * atif points to the current interface on this network;
		 * we aren't concerned about its current status (at
		 * least for now), but it has all the settings about
		 * the network we're going to probe. Consequently, it
		 * must exist.
		 */
		if (!atif)
			return -EADDRNOTAVAIL;

		nr = (struct atalk_netrange *)&(atif->nets);
		/*
		 * Phase 1 is fine on Localtalk but we don't do
		 * Ethertalk phase 1. Anyone wanting to add it go ahead.
		 */
		if (dev->type == ARPHRD_ETHER && nr->nr_phase != 2)
			return -EPROTONOSUPPORT;

		if (sa->sat_addr.s_node == ATADDR_BCAST ||
		    sa->sat_addr.s_node == 254)
			return -EINVAL;

		/*
		 * Check if the chosen address is used. If so we
		 * error and ATCP will try another.
		 */
		if (atif_proxy_probe_device(atif, &(sa->sat_addr)) < 0)
			return -EADDRINUSE;

		/*
		 * We now have an address on the local network, and
		 * the AARP code will defend it for us until we take it
		 * down. We don't set up any routes right now, because
		 * ATCP will install them manually via SIOCADDRT.
		 */
		break;

	case SIOCDARP:
		if (!capable(CAP_NET_ADMIN))
			return -EPERM;
		if (sa->sat_family != AF_APPLETALK)
			return -EINVAL;
		if (!atif)
			return -EADDRNOTAVAIL;

		/* give to aarp module to remove proxy entry */
		aarp_proxy_remove(atif->dev, &(sa->sat_addr));
		return 0;
	}

	return copy_to_user(arg, &atreq, sizeof(atreq)) ? -EFAULT : 0;
}

/* Routing ioctl() calls */
static int atrtr_ioctl(unsigned int cmd, void __user *arg)
{
	struct rtentry rt;

	if (copy_from_user(&rt, arg, sizeof(rt)))
		return -EFAULT;

	switch (cmd) {
	case SIOCDELRT:
		if (rt.rt_dst.sa_family != AF_APPLETALK)
			return -EINVAL;
		return atrtr_delete(&((struct sockaddr_at *)
				      &rt.rt_dst)->sat_addr);

	case SIOCADDRT: {
		struct net_device *dev = NULL;
		if (rt.rt_dev) {
			char name[IFNAMSIZ];
			if (copy_from_user(name, rt.rt_dev, IFNAMSIZ-1))
				return -EFAULT;
			name[IFNAMSIZ-1] = '\0';
			dev = __dev_get_by_name(&init_net, name);
			if (!dev)
				return -ENODEV;
		}
		return atrtr_create(&rt, dev);
	}
	}
	return -EINVAL;
}

/**************************************************************************\
*                                                                          *
* Handling for system calls applied via the various interfaces to an       *
* AppleTalk socket object.                                                 *
*                                                                          *
\**************************************************************************/

/*
 * Checksum: This is 'optional'. It's quite likely also a good
 * candidate for assembler hackery 8)
 */
static unsigned long atalk_sum_partial(const unsigned char *data,
				       int len, unsigned long sum)
{
	/* This ought to be unwrapped neatly. I'll trust gcc for now */
	while (len--) {
		sum += *data++;
		sum = rol16(sum, 1);
	}
	return sum;
}

/*  Checksum skb data --  similar to skb_checksum  */
static unsigned long atalk_sum_skb(const struct sk_buff *skb, int offset,
				   int len, unsigned long sum)
{
	int start = skb_headlen(skb);
	struct sk_buff *frag_iter;
	int i, copy;

	/* checksum stuff in header space */
	if ((copy = start - offset) > 0) {
		if (copy > len)
			copy = len;
		sum = atalk_sum_partial(skb->data + offset, copy, sum);
		if ((len -= copy) == 0)
			return sum;

		offset += copy;
	}

	/* checksum stuff in frags */
	for (i = 0; i < skb_shinfo(skb)->nr_frags; i++) {
		int end;
		const skb_frag_t *frag = &skb_shinfo(skb)->frags[i];
		WARN_ON(start > offset + len);

		end = start + skb_frag_size(frag);
		if ((copy = end - offset) > 0) {
			u8 *vaddr;

			if (copy > len)
				copy = len;
			vaddr = kmap_atomic(skb_frag_page(frag));
			sum = atalk_sum_partial(vaddr + skb_frag_off(frag) +
						offset - start, copy, sum);
			kunmap_atomic(vaddr);

			if (!(len -= copy))
				return sum;
			offset += copy;
		}
		start = end;
	}

	skb_walk_frags(skb, frag_iter) {
		int end;

		WARN_ON(start > offset + len);

		end = start + frag_iter->len;
		if ((copy = end - offset) > 0) {
			if (copy > len)
				copy = len;
			sum = atalk_sum_skb(frag_iter, offset - start,
					    copy, sum);
			if ((len -= copy) == 0)
				return sum;
			offset += copy;
		}
		start = end;
	}

	BUG_ON(len > 0);

	return sum;
}

static __be16 atalk_checksum(const struct sk_buff *skb, int len)
{
	unsigned long sum;

	/* skip header 4 bytes */
	sum = atalk_sum_skb(skb, 4, len-4, 0);

	/* Use 0xFFFF for 0. 0 itself means none */
	return sum ? htons((unsigned short)sum) : htons(0xFFFF);
}

static struct proto ddp_proto = {
	.name	  = "DDP",
	.owner	  = THIS_MODULE,
	.obj_size = sizeof(struct atalk_sock),
};

/*
 * Create a socket. Initialise the socket, blank the addresses
 * set the state.
 */
static int atalk_create(struct net *net, struct socket *sock, int protocol,
			int kern)
{
	struct sock *sk;
	int rc = -ESOCKTNOSUPPORT;

	if (!net_eq(net, &init_net))
		return -EAFNOSUPPORT;

	/*
	 * We permit SOCK_DGRAM and RAW is an extension. It is trivial to do
	 * and gives you the full ELAP frame. Should be handy for CAP 8)
	 */
	if (sock->type != SOCK_RAW && sock->type != SOCK_DGRAM)
		goto out;

	rc = -EPERM;
	if (sock->type == SOCK_RAW && !kern && !capable(CAP_NET_RAW))
		goto out;

	rc = -ENOMEM;
	sk = sk_alloc(net, PF_APPLETALK, GFP_KERNEL, &ddp_proto, kern);
	if (!sk)
		goto out;
	rc = 0;
	sock->ops = &atalk_dgram_ops;
	sock_init_data(sock, sk);

	/* Checksums on by default */
	sock_set_flag(sk, SOCK_ZAPPED);
out:
	return rc;
}

/* Free a socket. No work needed */
static int atalk_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (sk) {
		sock_hold(sk);
		lock_sock(sk);

		sock_orphan(sk);
		sock->sk = NULL;
		atalk_destroy_socket(sk);

		release_sock(sk);
		sock_put(sk);
	}
	return 0;
}

/**
 * atalk_pick_and_bind_port - Pick a source port when one is not given
 * @sk: socket to insert into the tables
 * @sat: address to search for
 *
 * Pick a source port when one is not given. If we can find a suitable free
 * one, we insert the socket into the tables using it.
 *
 * This whole operation must be atomic.
 */
static int atalk_pick_and_bind_port(struct sock *sk, struct sockaddr_at *sat)
{
	int retval;

	write_lock_bh(&atalk_sockets_lock);

	for (sat->sat_port = ATPORT_RESERVED;
	     sat->sat_port < ATPORT_LAST;
	     sat->sat_port++) {
		struct sock *s;

		sk_for_each(s, &atalk_sockets) {
			struct atalk_sock *at = at_sk(s);

			if (at->src_net == sat->sat_addr.s_net &&
			    at->src_node == sat->sat_addr.s_node &&
			    at->src_port == sat->sat_port)
				goto try_next_port;
		}

		/* Wheee, it's free, assign and insert. */
		__atalk_insert_socket(sk);
		at_sk(sk)->src_port = sat->sat_port;
		retval = 0;
		goto out;

try_next_port:;
	}

	retval = -EBUSY;
out:
	write_unlock_bh(&atalk_sockets_lock);
	return retval;
}

static int atalk_autobind(struct sock *sk)
{
	struct atalk_sock *at = at_sk(sk);
	struct sockaddr_at sat;
	struct atalk_addr *ap = atalk_find_primary();
	int n = -EADDRNOTAVAIL;

	if (!ap || ap->s_net == htons(ATADDR_ANYNET))
		goto out;

	at->src_net  = sat.sat_addr.s_net  = ap->s_net;
	at->src_node = sat.sat_addr.s_node = ap->s_node;

	n = atalk_pick_and_bind_port(sk, &sat);
	if (!n)
		sock_reset_flag(sk, SOCK_ZAPPED);
out:
	return n;
}

/* Set the address 'our end' of the connection */
static int atalk_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sockaddr_at *addr = (struct sockaddr_at *)uaddr;
	struct sock *sk = sock->sk;
	struct atalk_sock *at = at_sk(sk);
	int err;

	if (!sock_flag(sk, SOCK_ZAPPED) ||
	    addr_len != sizeof(struct sockaddr_at))
		return -EINVAL;

	if (addr->sat_family != AF_APPLETALK)
		return -EAFNOSUPPORT;

	lock_sock(sk);
	if (addr->sat_addr.s_net == htons(ATADDR_ANYNET)) {
		struct atalk_addr *ap = atalk_find_primary();

		err = -EADDRNOTAVAIL;
		if (!ap)
			goto out;

		at->src_net  = addr->sat_addr.s_net = ap->s_net;
		at->src_node = addr->sat_addr.s_node = ap->s_node;
	} else {
		err = -EADDRNOTAVAIL;
		if (!atalk_find_interface(addr->sat_addr.s_net,
					  addr->sat_addr.s_node))
			goto out;

		at->src_net  = addr->sat_addr.s_net;
		at->src_node = addr->sat_addr.s_node;
	}

	if (addr->sat_port == ATADDR_ANYPORT) {
		err = atalk_pick_and_bind_port(sk, addr);

		if (err < 0)
			goto out;
	} else {
		at->src_port = addr->sat_port;

		err = -EADDRINUSE;
		if (atalk_find_or_insert_socket(sk, addr))
			goto out;
	}

	sock_reset_flag(sk, SOCK_ZAPPED);
	err = 0;
out:
	release_sock(sk);
	return err;
}

/* Set the address we talk to */
static int atalk_connect(struct socket *sock, struct sockaddr *uaddr,
			 int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	struct atalk_sock *at = at_sk(sk);
	struct sockaddr_at *addr;
	int err;

	sk->sk_state   = TCP_CLOSE;
	sock->state = SS_UNCONNECTED;

	if (addr_len != sizeof(*addr))
		return -EINVAL;

	addr = (struct sockaddr_at *)uaddr;

	if (addr->sat_family != AF_APPLETALK)
		return -EAFNOSUPPORT;

	if (addr->sat_addr.s_node == ATADDR_BCAST &&
	    !sock_flag(sk, SOCK_BROADCAST)) {
#if 1
		pr_warn("atalk_connect: %s is broken and did not set SO_BROADCAST.\n",
			current->comm);
#else
		return -EACCES;
#endif
	}

	lock_sock(sk);
	err = -EBUSY;
	if (sock_flag(sk, SOCK_ZAPPED))
		if (atalk_autobind(sk) < 0)
			goto out;

	err = -ENETUNREACH;
	if (!atrtr_get_dev(&addr->sat_addr))
		goto out;

	at->dest_port = addr->sat_port;
	at->dest_net  = addr->sat_addr.s_net;
	at->dest_node = addr->sat_addr.s_node;

	sock->state  = SS_CONNECTED;
	sk->sk_state = TCP_ESTABLISHED;
	err = 0;
out:
	release_sock(sk);
	return err;
}

/*
 * Find the name of an AppleTalk socket. Just copy the right
 * fields into the sockaddr.
 */
static int atalk_getname(struct socket *sock, struct sockaddr *uaddr,
			 int peer)
{
	struct sockaddr_at sat;
	struct sock *sk = sock->sk;
	struct atalk_sock *at = at_sk(sk);
	int err;

	lock_sock(sk);
	err = -ENOBUFS;
	if (sock_flag(sk, SOCK_ZAPPED))
		if (atalk_autobind(sk) < 0)
			goto out;

	memset(&sat, 0, sizeof(sat));

	if (peer) {
		err = -ENOTCONN;
		if (sk->sk_state != TCP_ESTABLISHED)
			goto out;

		sat.sat_addr.s_net  = at->dest_net;
		sat.sat_addr.s_node = at->dest_node;
		sat.sat_port	    = at->dest_port;
	} else {
		sat.sat_addr.s_net  = at->src_net;
		sat.sat_addr.s_node = at->src_node;
		sat.sat_port	    = at->src_port;
	}

	sat.sat_family = AF_APPLETALK;
	memcpy(uaddr, &sat, sizeof(sat));
	err = sizeof(struct sockaddr_at);

out:
	release_sock(sk);
	return err;
}

#if IS_ENABLED(CONFIG_IPDDP)
static __inline__ int is_ip_over_ddp(struct sk_buff *skb)
{
	return skb->data[12] == 22;
}

static int handle_ip_over_ddp(struct sk_buff *skb)
{
	struct net_device *dev = __dev_get_by_name(&init_net, "ipddp0");
	struct net_device_stats *stats;

	/* This needs to be able to handle ipddp"N" devices */
	if (!dev) {
		kfree_skb(skb);
		return NET_RX_DROP;
	}

	skb->protocol = htons(ETH_P_IP);
	skb_pull(skb, 13);
	skb->dev   = dev;
	skb_reset_transport_header(skb);

	stats = netdev_priv(dev);
	stats->rx_packets++;
	stats->rx_bytes += skb->len + 13;
	return netif_rx(skb);  /* Send the SKB up to a higher place. */
}
#else
/* make it easy for gcc to optimize this test out, i.e. kill the code */
#define is_ip_over_ddp(skb) 0
#define handle_ip_over_ddp(skb) 0
#endif

static int atalk_route_packet(struct sk_buff *skb, struct net_device *dev,
			      struct ddpehdr *ddp, __u16 len_hops, int origlen)
{
	struct atalk_route *rt;
	struct atalk_addr ta;

	/*
	 * Don't route multicast, etc., packets, or packets sent to "this
	 * network"
	 */
	if (skb->pkt_type != PACKET_HOST || !ddp->deh_dnet) {
		/*
		 * FIXME:
		 *
		 * Can it ever happen that a packet is from a PPP iface and
		 * needs to be broadcast onto the default network?
		 */
		if (dev->type == ARPHRD_PPP)
			printk(KERN_DEBUG "AppleTalk: didn't forward broadcast "
					  "packet received from PPP iface\n");
		goto free_it;
	}

	ta.s_net  = ddp->deh_dnet;
	ta.s_node = ddp->deh_dnode;

	/* Route the packet */
	rt = atrtr_find(&ta);
	/* increment hops count */
	len_hops += 1 << 10;
	if (!rt || !(len_hops & (15 << 10)))
		goto free_it;

	/* FIXME: use skb->cb to be able to use shared skbs */

	/*
	 * Route goes through another gateway, so set the target to the
	 * gateway instead.
	 */

	if (rt->flags & RTF_GATEWAY) {
		ta.s_net  = rt->gateway.s_net;
		ta.s_node = rt->gateway.s_node;
	}

	/* Fix up skb->len field */
	skb_trim(skb, min_t(unsigned int, origlen,
			    (rt->dev->hard_header_len +
			     ddp_dl->header_length + (len_hops & 1023))));

	/* FIXME: use skb->cb to be able to use shared skbs */
	ddp->deh_len_hops = htons(len_hops);

	/*
	 * Send the buffer onwards
	 *
	 * Now we must always be careful. If it's come from LocalTalk to
	 * EtherTalk it might not fit
	 *
	 * Order matters here: If a packet has to be copied to make a new
	 * headroom (rare hopefully) then it won't need unsharing.
	 *
	 * Note. ddp-> becomes invalid at the realloc.
	 */
	if (skb_headroom(skb) < 22) {
		/* 22 bytes - 12 ether, 2 len, 3 802.2 5 snap */
		struct sk_buff *nskb = skb_realloc_headroom(skb, 32);
		kfree_skb(skb);
		skb = nskb;
	} else
		skb = skb_unshare(skb, GFP_ATOMIC);

	/*
	 * If the buffer didn't vanish into the lack of space bitbucket we can
	 * send it.
	 */
	if (skb == NULL)
		goto drop;

	if (aarp_send_ddp(rt->dev, skb, &ta, NULL) == NET_XMIT_DROP)
		return NET_RX_DROP;
	return NET_RX_SUCCESS;
free_it:
	kfree_skb(skb);
drop:
	return NET_RX_DROP;
}

/**
 *	atalk_rcv - Receive a packet (in skb) from device dev
 *	@skb - packet received
 *	@dev - network device where the packet comes from
 *	@pt - packet type
 *
 *	Receive a packet (in skb) from device dev. This has come from the SNAP
 *	decoder, and on entry skb->transport_header is the DDP header, skb->len
 *	is the DDP header, skb->len is the DDP length. The physical headers
 *	have been extracted. PPP should probably pass frames marked as for this
 *	layer.  [ie ARPHRD_ETHERTALK]
 */
static int atalk_rcv(struct sk_buff *skb, struct net_device *dev,
		     struct packet_type *pt, struct net_device *orig_dev)
{
	struct ddpehdr *ddp;
	struct sock *sock;
	struct atalk_iface *atif;
	struct sockaddr_at tosat;
	int origlen;
	__u16 len_hops;

	if (!net_eq(dev_net(dev), &init_net))
		goto drop;

	/* Don't mangle buffer if shared */
	if (!(skb = skb_share_check(skb, GFP_ATOMIC)))
		goto out;

	/* Size check and make sure header is contiguous */
	if (!pskb_may_pull(skb, sizeof(*ddp)))
		goto drop;

	ddp = ddp_hdr(skb);

	len_hops = ntohs(ddp->deh_len_hops);

	/* Trim buffer in case of stray trailing data */
	origlen = skb->len;
	skb_trim(skb, min_t(unsigned int, skb->len, len_hops & 1023));

	/*
	 * Size check to see if ddp->deh_len was crap
	 * (Otherwise we'll detonate most spectacularly
	 * in the middle of atalk_checksum() or recvmsg()).
	 */
	if (skb->len < sizeof(*ddp) || skb->len < (len_hops & 1023)) {
		pr_debug("AppleTalk: dropping corrupted frame (deh_len=%u, "
			 "skb->len=%u)\n", len_hops & 1023, skb->len);
		goto drop;
	}

	/*
	 * Any checksums. Note we don't do htons() on this == is assumed to be
	 * valid for net byte orders all over the networking code...
	 */
	if (ddp->deh_sum &&
	    atalk_checksum(skb, len_hops & 1023) != ddp->deh_sum)
		/* Not a valid AppleTalk frame - dustbin time */
		goto drop;

	/* Check the packet is aimed at us */
	if (!ddp->deh_dnet)	/* Net 0 is 'this network' */
		atif = atalk_find_anynet(ddp->deh_dnode, dev);
	else
		atif = atalk_find_interface(ddp->deh_dnet, ddp->deh_dnode);

	if (!atif) {
		/* Not ours, so we route the packet via the correct
		 * AppleTalk iface
		 */
		return atalk_route_packet(skb, dev, ddp, len_hops, origlen);
	}

	/* if IP over DDP is not selected this code will be optimized out */
	if (is_ip_over_ddp(skb))
		return handle_ip_over_ddp(skb);
	/*
	 * Which socket - atalk_search_socket() looks for a *full match*
	 * of the <net, node, port> tuple.
	 */
	tosat.sat_addr.s_net  = ddp->deh_dnet;
	tosat.sat_addr.s_node = ddp->deh_dnode;
	tosat.sat_port	      = ddp->deh_dport;

	sock = atalk_search_socket(&tosat, atif);
	if (!sock) /* But not one of our sockets */
		goto drop;

	/* Queue packet (standard) */
	if (sock_queue_rcv_skb(sock, skb) < 0)
		goto drop;

	return NET_RX_SUCCESS;

drop:
	kfree_skb(skb);
out:
	return NET_RX_DROP;

}

/*
 * Receive a LocalTalk frame. We make some demands on the caller here.
 * Caller must provide enough headroom on the packet to pull the short
 * header and append a long one.
 */
static int ltalk_rcv(struct sk_buff *skb, struct net_device *dev,
		     struct packet_type *pt, struct net_device *orig_dev)
{
	if (!net_eq(dev_net(dev), &init_net))
		goto freeit;

	/* Expand any short form frames */
	if (skb_mac_header(skb)[2] == 1) {
		struct ddpehdr *ddp;
		/* Find our address */
		struct atalk_addr *ap = atalk_find_dev_addr(dev);

		if (!ap || skb->len < sizeof(__be16) || skb->len > 1023)
			goto freeit;

		/* Don't mangle buffer if shared */
		if (!(skb = skb_share_check(skb, GFP_ATOMIC)))
			return 0;

		/*
		 * The push leaves us with a ddephdr not an shdr, and
		 * handily the port bytes in the right place preset.
		 */
		ddp = skb_push(skb, sizeof(*ddp) - 4);

		/* Now fill in the long header */

		/*
		 * These two first. The mac overlays the new source/dest
		 * network information so we MUST copy these before
		 * we write the network numbers !
		 */

		ddp->deh_dnode = skb_mac_header(skb)[0];     /* From physical header */
		ddp->deh_snode = skb_mac_header(skb)[1];     /* From physical header */

		ddp->deh_dnet  = ap->s_net;	/* Network number */
		ddp->deh_snet  = ap->s_net;
		ddp->deh_sum   = 0;		/* No checksum */
		/*
		 * Not sure about this bit...
		 */
		/* Non routable, so force a drop if we slip up later */
		ddp->deh_len_hops = htons(skb->len + (DDP_MAXHOPS << 10));
	}
	skb_reset_transport_header(skb);

	return atalk_rcv(skb, dev, pt, orig_dev);
freeit:
	kfree_skb(skb);
	return 0;
}

static int atalk_sendmsg(struct socket *sock, struct msghdr *msg, size_t len)
{
	struct sock *sk = sock->sk;
	struct atalk_sock *at = at_sk(sk);
	DECLARE_SOCKADDR(struct sockaddr_at *, usat, msg->msg_name);
	int flags = msg->msg_flags;
	int loopback = 0;
	struct sockaddr_at local_satalk, gsat;
	struct sk_buff *skb;
	struct net_device *dev;
	struct ddpehdr *ddp;
	int size;
	struct atalk_route *rt;
	int err;

	if (flags & ~(MSG_DONTWAIT|MSG_CMSG_COMPAT))
		return -EINVAL;

	if (len > DDP_MAXSZ)
		return -EMSGSIZE;

	lock_sock(sk);
	if (usat) {
		err = -EBUSY;
		if (sock_flag(sk, SOCK_ZAPPED))
			if (atalk_autobind(sk) < 0)
				goto out;

		err = -EINVAL;
		if (msg->msg_namelen < sizeof(*usat) ||
		    usat->sat_family != AF_APPLETALK)
			goto out;

		err = -EPERM;
		/* netatalk didn't implement this check */
		if (usat->sat_addr.s_node == ATADDR_BCAST &&
		    !sock_flag(sk, SOCK_BROADCAST)) {
			goto out;
		}
	} else {
		err = -ENOTCONN;
		if (sk->sk_state != TCP_ESTABLISHED)
			goto out;
		usat = &local_satalk;
		usat->sat_family      = AF_APPLETALK;
		usat->sat_port	      = at->dest_port;
		usat->sat_addr.s_node = at->dest_node;
		usat->sat_addr.s_net  = at->dest_net;
	}

	/* Build a packet */
	SOCK_DEBUG(sk, "SK %p: Got address.\n", sk);

	/* For headers */
	size = sizeof(struct ddpehdr) + len + ddp_dl->header_length;

	if (usat->sat_addr.s_net || usat->sat_addr.s_node == ATADDR_ANYNODE) {
		rt = atrtr_find(&usat->sat_addr);
	} else {
		struct atalk_addr at_hint;

		at_hint.s_node = 0;
		at_hint.s_net  = at->src_net;

		rt = atrtr_find(&at_hint);
	}
	err = -ENETUNREACH;
	if (!rt)
		goto out;

	dev = rt->dev;

	SOCK_DEBUG(sk, "SK %p: Size needed %d, device %s\n",
			sk, size, dev->name);

	size += dev->hard_header_len;
	release_sock(sk);
	skb = sock_alloc_send_skb(sk, size, (flags & MSG_DONTWAIT), &err);
	lock_sock(sk);
	if (!skb)
		goto out;

	skb_reserve(skb, ddp_dl->header_length);
	skb_reserve(skb, dev->hard_header_len);
	skb->dev = dev;

	SOCK_DEBUG(sk, "SK %p: Begin build.\n", sk);

	ddp = skb_put(skb, sizeof(struct ddpehdr));
	ddp->deh_len_hops  = htons(len + sizeof(*ddp));
	ddp->deh_dnet  = usat->sat_addr.s_net;
	ddp->deh_snet  = at->src_net;
	ddp->deh_dnode = usat->sat_addr.s_node;
	ddp->deh_snode = at->src_node;
	ddp->deh_dport = usat->sat_port;
	ddp->deh_sport = at->src_port;

	SOCK_DEBUG(sk, "SK %p: Copy user data (%zd bytes).\n", sk, len);

	err = memcpy_from_msg(skb_put(skb, len), msg, len);
	if (err) {
		kfree_skb(skb);
		err = -EFAULT;
		goto out;
	}

	if (sk->sk_no_check_tx)
		ddp->deh_sum = 0;
	else
		ddp->deh_sum = atalk_checksum(skb, len + sizeof(*ddp));

	/*
	 * Loopback broadcast packets to non gateway targets (ie routes
	 * to group we are in)
	 */
	if (ddp->deh_dnode == ATADDR_BCAST &&
	    !(rt->flags & RTF_GATEWAY) && !(dev->flags & IFF_LOOPBACK)) {
		struct sk_buff *skb2 = skb_copy(skb, GFP_KERNEL);

		if (skb2) {
			loopback = 1;
			SOCK_DEBUG(sk, "SK %p: send out(copy).\n", sk);
			/*
			 * If it fails it is queued/sent above in the aarp queue
			 */
			aarp_send_ddp(dev, skb2, &usat->sat_addr, NULL);
		}
	}

	if (dev->flags & IFF_LOOPBACK || loopback) {
		SOCK_DEBUG(sk, "SK %p: Loop back.\n", sk);
		/* loop back */
		skb_orphan(skb);
		if (ddp->deh_dnode == ATADDR_BCAST) {
			struct atalk_addr at_lo;

			at_lo.s_node = 0;
			at_lo.s_net  = 0;

			rt = atrtr_find(&at_lo);
			if (!rt) {
				kfree_skb(skb);
				err = -ENETUNREACH;
				goto out;
			}
			dev = rt->dev;
			skb->dev = dev;
		}
		ddp_dl->request(ddp_dl, skb, dev->dev_addr);
	} else {
		SOCK_DEBUG(sk, "SK %p: send out.\n", sk);
		if (rt->flags & RTF_GATEWAY) {
		    gsat.sat_addr = rt->gateway;
		    usat = &gsat;
		}

		/*
		 * If it fails it is queued/sent above in the aarp queue
		 */
		aarp_send_ddp(dev, skb, &usat->sat_addr, NULL);
	}
	SOCK_DEBUG(sk, "SK %p: Done write (%zd).\n", sk, len);

out:
	release_sock(sk);
	return err ? : len;
}

static int atalk_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
			 int flags)
{
	struct sock *sk = sock->sk;
	struct ddpehdr *ddp;
	int copied = 0;
	int offset = 0;
	int err = 0;
	struct sk_buff *skb;

	skb = skb_recv_datagram(sk, flags & ~MSG_DONTWAIT,
						flags & MSG_DONTWAIT, &err);
	lock_sock(sk);

	if (!skb)
		goto out;

	/* FIXME: use skb->cb to be able to use shared skbs */
	ddp = ddp_hdr(skb);
	copied = ntohs(ddp->deh_len_hops) & 1023;

	if (sk->sk_type != SOCK_RAW) {
		offset = sizeof(*ddp);
		copied -= offset;
	}

	if (copied > size) {
		copied = size;
		msg->msg_flags |= MSG_TRUNC;
	}
	err = skb_copy_datagram_msg(skb, offset, msg, copied);

	if (!err && msg->msg_name) {
		DECLARE_SOCKADDR(struct sockaddr_at *, sat, msg->msg_name);
		sat->sat_family      = AF_APPLETALK;
		sat->sat_port        = ddp->deh_sport;
		sat->sat_addr.s_node = ddp->deh_snode;
		sat->sat_addr.s_net  = ddp->deh_snet;
		msg->msg_namelen     = sizeof(*sat);
	}

	skb_free_datagram(sk, skb);	/* Free the datagram. */

out:
	release_sock(sk);
	return err ? : copied;
}


/*
 * AppleTalk ioctl calls.
 */
static int atalk_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	int rc = -ENOIOCTLCMD;
	struct sock *sk = sock->sk;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	/* Protocol layer */
	case TIOCOUTQ: {
		long amount = sk->sk_sndbuf - sk_wmem_alloc_get(sk);

		if (amount < 0)
			amount = 0;
		rc = put_user(amount, (int __user *)argp);
		break;
	}
	case TIOCINQ: {
		/*
		 * These two are safe on a single CPU system as only
		 * user tasks fiddle here
		 */
		struct sk_buff *skb = skb_peek(&sk->sk_receive_queue);
		long amount = 0;

		if (skb)
			amount = skb->len - sizeof(struct ddpehdr);
		rc = put_user(amount, (int __user *)argp);
		break;
	}
	/* Routing */
	case SIOCADDRT:
	case SIOCDELRT:
		rc = -EPERM;
		if (capable(CAP_NET_ADMIN))
			rc = atrtr_ioctl(cmd, argp);
		break;
	/* Interface */
	case SIOCGIFADDR:
	case SIOCSIFADDR:
	case SIOCGIFBRDADDR:
	case SIOCATALKDIFADDR:
	case SIOCDIFADDR:
	case SIOCSARP:		/* proxy AARP */
	case SIOCDARP:		/* proxy AARP */
		rtnl_lock();
		rc = atif_ioctl(cmd, argp);
		rtnl_unlock();
		break;
	}

	return rc;
}


#ifdef CONFIG_COMPAT
static int atalk_compat_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	/*
	 * SIOCATALKDIFADDR is a SIOCPROTOPRIVATE ioctl number, so we
	 * cannot handle it in common code. The data we access if ifreq
	 * here is compatible, so we can simply call the native
	 * handler.
	 */
	if (cmd == SIOCATALKDIFADDR)
		return atalk_ioctl(sock, cmd, (unsigned long)compat_ptr(arg));

	return -ENOIOCTLCMD;
}
#endif


static const struct net_proto_family atalk_family_ops = {
	.family		= PF_APPLETALK,
	.create		= atalk_create,
	.owner		= THIS_MODULE,
};

static const struct proto_ops atalk_dgram_ops = {
	.family		= PF_APPLETALK,
	.owner		= THIS_MODULE,
	.release	= atalk_release,
	.bind		= atalk_bind,
	.connect	= atalk_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= sock_no_accept,
	.getname	= atalk_getname,
	.poll		= datagram_poll,
	.ioctl		= atalk_ioctl,
	.gettstamp	= sock_gettstamp,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= atalk_compat_ioctl,
#endif
	.listen		= sock_no_listen,
	.shutdown	= sock_no_shutdown,
	.setsockopt	= sock_no_setsockopt,
	.getsockopt	= sock_no_getsockopt,
	.sendmsg	= atalk_sendmsg,
	.recvmsg	= atalk_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage,
};

static struct notifier_block ddp_notifier = {
	.notifier_call	= ddp_device_event,
};

static struct packet_type ltalk_packet_type __read_mostly = {
	.type		= cpu_to_be16(ETH_P_LOCALTALK),
	.func		= ltalk_rcv,
};

static struct packet_type ppptalk_packet_type __read_mostly = {
	.type		= cpu_to_be16(ETH_P_PPPTALK),
	.func		= atalk_rcv,
};

static unsigned char ddp_snap_id[] = { 0x08, 0x00, 0x07, 0x80, 0x9B };

/* Export symbols for use by drivers when AppleTalk is a module */
EXPORT_SYMBOL(atrtr_get_dev);
EXPORT_SYMBOL(atalk_find_dev_addr);

/* Called by proto.c on kernel start up */
static int __init atalk_init(void)
{
	int rc;

	rc = proto_register(&ddp_proto, 0);
	if (rc)
		goto out;

	rc = sock_register(&atalk_family_ops);
	if (rc)
		goto out_proto;

	ddp_dl = register_snap_client(ddp_snap_id, atalk_rcv);
	if (!ddp_dl) {
		pr_crit("Unable to register DDP with SNAP.\n");
		rc = -ENOMEM;
		goto out_sock;
	}

	dev_add_pack(&ltalk_packet_type);
	dev_add_pack(&ppptalk_packet_type);

	rc = register_netdevice_notifier(&ddp_notifier);
	if (rc)
		goto out_snap;

	rc = aarp_proto_init();
	if (rc)
		goto out_dev;

	rc = atalk_proc_init();
	if (rc)
		goto out_aarp;

	rc = atalk_register_sysctl();
	if (rc)
		goto out_proc;
out:
	return rc;
out_proc:
	atalk_proc_exit();
out_aarp:
	aarp_cleanup_module();
out_dev:
	unregister_netdevice_notifier(&ddp_notifier);
out_snap:
	dev_remove_pack(&ppptalk_packet_type);
	dev_remove_pack(&ltalk_packet_type);
	unregister_snap_client(ddp_dl);
out_sock:
	sock_unregister(PF_APPLETALK);
out_proto:
	proto_unregister(&ddp_proto);
	goto out;
}
module_init(atalk_init);

/*
 * No explicit module reference count manipulation is needed in the
 * protocol. Socket layer sets module reference count for us
 * and interfaces reference counting is done
 * by the network device layer.
 *
 * Ergo, before the AppleTalk module can be removed, all AppleTalk
 * sockets be closed from user space.
 */
static void __exit atalk_exit(void)
{
#ifdef CONFIG_SYSCTL
	atalk_unregister_sysctl();
#endif /* CONFIG_SYSCTL */
	atalk_proc_exit();
	aarp_cleanup_module();	/* General aarp clean-up. */
	unregister_netdevice_notifier(&ddp_notifier);
	dev_remove_pack(&ltalk_packet_type);
	dev_remove_pack(&ppptalk_packet_type);
	unregister_snap_client(ddp_dl);
	sock_unregister(PF_APPLETALK);
	proto_unregister(&ddp_proto);
}
module_exit(atalk_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alan Cox <alan@lxorguk.ukuu.org.uk>");
MODULE_DESCRIPTION("AppleTalk 0.20\n");
MODULE_ALIAS_NETPROTO(PF_APPLETALK);
};

/******************************************************************/

struct channel 
{


static const struct nla_policy
channels_get_policy[ETHTOOL_A_CHANNELS_MAX + 1] = {
	[ETHTOOL_A_CHANNELS_UNSPEC]		= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_HEADER]		= { .type = NLA_NESTED },
	[ETHTOOL_A_CHANNELS_RX_MAX]		= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_TX_MAX]		= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_OTHER_MAX]		= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_COMBINED_MAX]	= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_RX_COUNT]		= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_TX_COUNT]		= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_OTHER_COUNT]	= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_COMBINED_COUNT]	= { .type = NLA_REJECT },
};

 static int channels_prepare_data(const struct ethnl_req_info *req_base,
				 struct ethnl_reply_data *reply_base,
				 struct genl_info *info)
{
	struct channels_reply_data *data = CHANNELS_REPDATA(reply_base);
	struct net_device *dev = reply_base->dev;
	int ret;

	if (!dev->ethtool_ops->get_channels)
		return -EOPNOTSUPP;
	ret = ethnl_ops_begin(dev);
	if (ret < 0)
		return ret;
	dev->ethtool_ops->get_channels(dev, &data->channels);
	ethnl_ops_complete(dev);

	return 0;
}

static int channels_reply_size(const struct ethnl_req_info *req_base,
			       const struct ethnl_reply_data *reply_base)
{
	return nla_total_size(sizeof(u32)) +	/* _CHANNELS_RX_MAX */
	       nla_total_size(sizeof(u32)) +	/* _CHANNELS_TX_MAX */
	       nla_total_size(sizeof(u32)) +	/* _CHANNELS_OTHER_MAX */
	       nla_total_size(sizeof(u32)) +	/* _CHANNELS_COMBINED_MAX */
	       nla_total_size(sizeof(u32)) +	/* _CHANNELS_RX_COUNT */
	       nla_total_size(sizeof(u32)) +	/* _CHANNELS_TX_COUNT */
	       nla_total_size(sizeof(u32)) +	/* _CHANNELS_OTHER_COUNT */
	       nla_total_size(sizeof(u32));	/* _CHANNELS_COMBINED_COUNT */
}

static int channels_fill_reply(struct sk_buff *skb,
			       const struct ethnl_req_info *req_base,
			       const struct ethnl_reply_data *reply_base)
{
	const struct channels_reply_data *data = CHANNELS_REPDATA(reply_base);
	const struct ethtool_channels *channels = &data->channels;

	if ((channels->max_rx &&
	     (nla_put_u32(skb, ETHTOOL_A_CHANNELS_RX_MAX,
			  channels->max_rx) ||
	      nla_put_u32(skb, ETHTOOL_A_CHANNELS_RX_COUNT,
			  channels->rx_count))) ||
	    (channels->max_tx &&
	     (nla_put_u32(skb, ETHTOOL_A_CHANNELS_TX_MAX,
			  channels->max_tx) ||
	      nla_put_u32(skb, ETHTOOL_A_CHANNELS_TX_COUNT,
			  channels->tx_count))) ||
	    (channels->max_other &&
	     (nla_put_u32(skb, ETHTOOL_A_CHANNELS_OTHER_MAX,
			  channels->max_other) ||
	      nla_put_u32(skb, ETHTOOL_A_CHANNELS_OTHER_COUNT,
			  channels->other_count))) ||
	    (channels->max_combined &&
	     (nla_put_u32(skb, ETHTOOL_A_CHANNELS_COMBINED_MAX,
			  channels->max_combined) ||
	      nla_put_u32(skb, ETHTOOL_A_CHANNELS_COMBINED_COUNT,
			  channels->combined_count))))
		return -EMSGSIZE;

	return 0;
}

const struct ethnl_request_ops ethnl_channels_request_ops = {
	.request_cmd		= ETHTOOL_MSG_CHANNELS_GET,
	.reply_cmd		= ETHTOOL_MSG_CHANNELS_GET_REPLY,
	.hdr_attr		= ETHTOOL_A_CHANNELS_HEADER,
	.max_attr		= ETHTOOL_A_CHANNELS_MAX,
	.req_info_size		= sizeof(struct channels_req_info),
	.reply_data_size	= sizeof(struct channels_reply_data),
	.request_policy		= channels_get_policy,

	.prepare_data		= channels_prepare_data,
	.reply_size		= channels_reply_size,
	.fill_reply		= channels_fill_reply,
};

/* CHANNELS_SET */

static const struct nla_policy
channels_set_policy[ETHTOOL_A_CHANNELS_MAX + 1] = {
	[ETHTOOL_A_CHANNELS_UNSPEC]		= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_HEADER]		= { .type = NLA_NESTED },
	[ETHTOOL_A_CHANNELS_RX_MAX]		= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_TX_MAX]		= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_OTHER_MAX]		= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_COMBINED_MAX]	= { .type = NLA_REJECT },
	[ETHTOOL_A_CHANNELS_RX_COUNT]		= { .type = NLA_U32 },
	[ETHTOOL_A_CHANNELS_TX_COUNT]		= { .type = NLA_U32 },
	[ETHTOOL_A_CHANNELS_OTHER_COUNT]	= { .type = NLA_U32 },
	[ETHTOOL_A_CHANNELS_COMBINED_COUNT]	= { .type = NLA_U32 },
};

int ethnl_set_channels(struct sk_buff *skb, struct genl_info *info)
{
	struct nlattr *tb[ETHTOOL_A_CHANNELS_MAX + 1];
	unsigned int from_channel, old_total, i;
	struct ethtool_channels channels = {};
	struct ethnl_req_info req_info = {};
	const struct nlattr *err_attr;
	const struct ethtool_ops *ops;
	struct net_device *dev;
	u32 max_rx_in_use = 0;
	bool mod = false;
	int ret;

	ret = nlmsg_parse(info->nlhdr, GENL_HDRLEN, tb,
			  ETHTOOL_A_CHANNELS_MAX, channels_set_policy,
			  info->extack);
	if (ret < 0)
		return ret;
	ret = ethnl_parse_header_dev_get(&req_info,
					 tb[ETHTOOL_A_CHANNELS_HEADER],
					 genl_info_net(info), info->extack,
					 true);
	if (ret < 0)
		return ret;
	dev = req_info.dev;
	ops = dev->ethtool_ops;
	ret = -EOPNOTSUPP;
	if (!ops->get_channels || !ops->set_channels)
		goto out_dev;

	rtnl_lock();
	ret = ethnl_ops_begin(dev);
	if (ret < 0)
		goto out_rtnl;
	ops->get_channels(dev, &channels);
	old_total = channels.combined_count +
		    max(channels.rx_count, channels.tx_count);

	ethnl_update_u32(&channels.rx_count, tb[ETHTOOL_A_CHANNELS_RX_COUNT],
			 &mod);
	ethnl_update_u32(&channels.tx_count, tb[ETHTOOL_A_CHANNELS_TX_COUNT],
			 &mod);
	ethnl_update_u32(&channels.other_count,
			 tb[ETHTOOL_A_CHANNELS_OTHER_COUNT], &mod);
	ethnl_update_u32(&channels.combined_count,
			 tb[ETHTOOL_A_CHANNELS_COMBINED_COUNT], &mod);
	ret = 0;
	if (!mod)
		goto out_ops;

	/* ensure new channel counts are within limits */
	if (channels.rx_count > channels.max_rx)
		err_attr = tb[ETHTOOL_A_CHANNELS_RX_COUNT];
	else if (channels.tx_count > channels.max_tx)
		err_attr = tb[ETHTOOL_A_CHANNELS_TX_COUNT];
	else if (channels.other_count > channels.max_other)
		err_attr = tb[ETHTOOL_A_CHANNELS_OTHER_COUNT];
	else if (channels.combined_count > channels.max_combined)
		err_attr = tb[ETHTOOL_A_CHANNELS_COMBINED_COUNT];
	else
		err_attr = NULL;
	if (err_attr) {
		ret = -EINVAL;
		NL_SET_ERR_MSG_ATTR(info->extack, err_attr,
				    "requested channel count exceeds maximum");
		goto out_ops;
	}

	/* ensure the new Rx count fits within the configured Rx flow
	 * indirection table settings
	 */
	if (netif_is_rxfh_configured(dev) &&
	    !ethtool_get_max_rxfh_channel(dev, &max_rx_in_use) &&
	    (channels.combined_count + channels.rx_count) <= max_rx_in_use) {
		GENL_SET_ERR_MSG(info, "requested channel counts are too low for existing indirection table settings");
		return -EINVAL;
	}

	/* Disabling channels, query zero-copy AF_XDP sockets */
	from_channel = channels.combined_count +
		       min(channels.rx_count, channels.tx_count);
	for (i = from_channel; i < old_total; i++)
		if (xdp_get_umem_from_qid(dev, i)) {
			GENL_SET_ERR_MSG(info, "requested channel counts are too low for existing zerocopy AF_XDP sockets");
			return -EINVAL;
		}

	ret = dev->ethtool_ops->set_channels(dev, &channels);
	if (ret < 0)
		goto out_ops;
	ethtool_notify(dev, ETHTOOL_MSG_CHANNELS_NTF, NULL);

out_ops:
	ethnl_ops_complete(dev);
out_rtnl:
	rtnl_unlock();
out_dev:
	dev_put(dev);
	return ret;
}



};

/**************************************************************************************/

struct IPv6 
{
    static const struct inet_connection_sock_af_ops dccp_ipv6_mapped;
static const struct inet_connection_sock_af_ops dccp_ipv6_af_ops;

/* add pseudo-header to DCCP checksum stored in skb->csum */
static inline __sum16 dccp_v6_csum_finish(struct sk_buff *skb,
				      const struct in6_addr *saddr,
				      const struct in6_addr *daddr)
{
	return csum_ipv6_magic(saddr, daddr, skb->len, IPPROTO_DCCP, skb->csum);
}

static inline void dccp_v6_send_check(struct sock *sk, struct sk_buff *skb)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct dccp_hdr *dh = dccp_hdr(skb);

	dccp_csum_outgoing(skb);
	dh->dccph_checksum = dccp_v6_csum_finish(skb, &np->saddr, &sk->sk_v6_daddr);
}

static inline __u64 dccp_v6_init_sequence(struct sk_buff *skb)
{
	return secure_dccpv6_sequence_number(ipv6_hdr(skb)->daddr.s6_addr32,
					     ipv6_hdr(skb)->saddr.s6_addr32,
					     dccp_hdr(skb)->dccph_dport,
					     dccp_hdr(skb)->dccph_sport     );

}

static int dccp_v6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
			u8 type, u8 code, int offset, __be32 info)
{
	const struct ipv6hdr *hdr = (const struct ipv6hdr *)skb->data;
	const struct dccp_hdr *dh;
	struct dccp_sock *dp;
	struct ipv6_pinfo *np;
	struct sock *sk;
	int err;
	__u64 seq;
	struct net *net = dev_net(skb->dev);

	/* Only need dccph_dport & dccph_sport which are the first
	 * 4 bytes in dccp header.
	 * Our caller (icmpv6_notify()) already pulled 8 bytes for us.
	 */
	BUILD_BUG_ON(offsetofend(struct dccp_hdr, dccph_sport) > 8);
	BUILD_BUG_ON(offsetofend(struct dccp_hdr, dccph_dport) > 8);
	dh = (struct dccp_hdr *)(skb->data + offset);

	sk = __inet6_lookup_established(net, &dccp_hashinfo,
					&hdr->daddr, dh->dccph_dport,
					&hdr->saddr, ntohs(dh->dccph_sport),
					inet6_iif(skb), 0);

	if (!sk) {
		__ICMP6_INC_STATS(net, __in6_dev_get(skb->dev),
				  ICMP6_MIB_INERRORS);
		return -ENOENT;
	}

	if (sk->sk_state == DCCP_TIME_WAIT) {
		inet_twsk_put(inet_twsk(sk));
		return 0;
	}
	seq = dccp_hdr_seq(dh);
	if (sk->sk_state == DCCP_NEW_SYN_RECV) {
		dccp_req_err(sk, seq);
		return 0;
	}

	bh_lock_sock(sk);
	if (sock_owned_by_user(sk))
		__NET_INC_STATS(net, LINUX_MIB_LOCKDROPPEDICMPS);

	if (sk->sk_state == DCCP_CLOSED)
		goto out;

	dp = dccp_sk(sk);
	if ((1 << sk->sk_state) & ~(DCCPF_REQUESTING | DCCPF_LISTEN) &&
	    !between48(seq, dp->dccps_awl, dp->dccps_awh)) {
		__NET_INC_STATS(net, LINUX_MIB_OUTOFWINDOWICMPS);
		goto out;
	}

	np = inet6_sk(sk);

	if (type == NDISC_REDIRECT) {
		if (!sock_owned_by_user(sk)) {
			struct dst_entry *dst = __sk_dst_check(sk, np->dst_cookie);

			if (dst)
				dst->ops->redirect(dst, sk, skb);
		}
		goto out;
	}

	if (type == ICMPV6_PKT_TOOBIG) {
		struct dst_entry *dst = NULL;

		if (!ip6_sk_accept_pmtu(sk))
			goto out;

		if (sock_owned_by_user(sk))
			goto out;
		if ((1 << sk->sk_state) & (DCCPF_LISTEN | DCCPF_CLOSED))
			goto out;

		dst = inet6_csk_update_pmtu(sk, ntohl(info));
		if (!dst)
			goto out;

		if (inet_csk(sk)->icsk_pmtu_cookie > dst_mtu(dst))
			dccp_sync_mss(sk, dst_mtu(dst));
		goto out;
	}

	icmpv6_err_convert(type, code, &err);

	/* Might be for an request_sock */
	switch (sk->sk_state) {
	case DCCP_REQUESTING:
	case DCCP_RESPOND:  /* Cannot happen.
			       It can, it SYNs are crossed. --ANK */
		if (!sock_owned_by_user(sk)) {
			__DCCP_INC_STATS(DCCP_MIB_ATTEMPTFAILS);
			sk->sk_err = err;
			/*
			 * Wake people up to see the error
			 * (see connect in sock.c)
			 */
			sk->sk_error_report(sk);
			dccp_done(sk);
		} else
			sk->sk_err_soft = err;
		goto out;
	}

	if (!sock_owned_by_user(sk) && np->recverr) {
		sk->sk_err = err;
		sk->sk_error_report(sk);
	} else
		sk->sk_err_soft = err;

out:
	bh_unlock_sock(sk);
	sock_put(sk);
	return 0;
}


static int dccp_v6_send_response(const struct sock *sk, struct request_sock *req)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sk_buff *skb;
	struct in6_addr *final_p, final;
	struct flowi6 fl6;
	int err = -1;
	struct dst_entry *dst;

	memset(&fl6, 0, sizeof(fl6));
	fl6.flowi6_proto = IPPROTO_DCCP;
	fl6.daddr = ireq->ir_v6_rmt_addr;
	fl6.saddr = ireq->ir_v6_loc_addr;
	fl6.flowlabel = 0;
	fl6.flowi6_oif = ireq->ir_iif;
	fl6.fl6_dport = ireq->ir_rmt_port;
	fl6.fl6_sport = htons(ireq->ir_num);
	security_req_classify_flow(req, flowi6_to_flowi(&fl6));


	rcu_read_lock();
	final_p = fl6_update_dst(&fl6, rcu_dereference(np->opt), &final);
	rcu_read_unlock();

	dst = ip6_dst_lookup_flow(sock_net(sk), sk, &fl6, final_p);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		dst = NULL;
		goto done;
	}

	skb = dccp_make_response(sk, dst, req);
	if (skb != NULL) {
		struct dccp_hdr *dh = dccp_hdr(skb);
		struct ipv6_txoptions *opt;

		dh->dccph_checksum = dccp_v6_csum_finish(skb,
							 &ireq->ir_v6_loc_addr,
							 &ireq->ir_v6_rmt_addr);
		fl6.daddr = ireq->ir_v6_rmt_addr;
		rcu_read_lock();
		opt = ireq->ipv6_opt;
		if (!opt)
			opt = rcu_dereference(np->opt);
		err = ip6_xmit(sk, skb, &fl6, sk->sk_mark, opt, np->tclass,
			       sk->sk_priority);
		rcu_read_unlock();
		err = net_xmit_eval(err);
	}

done:
	dst_release(dst);
	return err;
}

static void dccp_v6_reqsk_destructor(struct request_sock *req)
{
	dccp_feat_list_purge(&dccp_rsk(req)->dreq_featneg);
	kfree(inet_rsk(req)->ipv6_opt);
	kfree_skb(inet_rsk(req)->pktopts);
}

static void dccp_v6_ctl_send_reset(const struct sock *sk, struct sk_buff *rxskb)
{
	const struct ipv6hdr *rxip6h;
	struct sk_buff *skb;
	struct flowi6 fl6;
	struct net *net = dev_net(skb_dst(rxskb)->dev);
	struct sock *ctl_sk = net->dccp.v6_ctl_sk;
	struct dst_entry *dst;

	if (dccp_hdr(rxskb)->dccph_type == DCCP_PKT_RESET)
		return;

	if (!ipv6_unicast_destination(rxskb))
		return;

	skb = dccp_ctl_make_reset(ctl_sk, rxskb);
	if (skb == NULL)
		return;

	rxip6h = ipv6_hdr(rxskb);
	dccp_hdr(skb)->dccph_checksum = dccp_v6_csum_finish(skb, &rxip6h->saddr,
							    &rxip6h->daddr);

	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = rxip6h->saddr;
	fl6.saddr = rxip6h->daddr;

	fl6.flowi6_proto = IPPROTO_DCCP;
	fl6.flowi6_oif = inet6_iif(rxskb);
	fl6.fl6_dport = dccp_hdr(skb)->dccph_dport;
	fl6.fl6_sport = dccp_hdr(skb)->dccph_sport;
	security_skb_classify_flow(rxskb, flowi6_to_flowi(&fl6));

	/* sk = NULL, but it is safe for now. RST socket required. */
	dst = ip6_dst_lookup_flow(sock_net(ctl_sk), ctl_sk, &fl6, NULL);
	if (!IS_ERR(dst)) {
		skb_dst_set(skb, dst);
		ip6_xmit(ctl_sk, skb, &fl6, 0, NULL, 0, 0);
		DCCP_INC_STATS(DCCP_MIB_OUTSEGS);
		DCCP_INC_STATS(DCCP_MIB_OUTRSTS);
		return;
	}

	kfree_skb(skb);
}

static struct request_sock_ops dccp6_request_sock_ops = {
	.family		= AF_INET6,
	.obj_size	= sizeof(struct dccp6_request_sock),
	.rtx_syn_ack	= dccp_v6_send_response,
	.send_ack	= dccp_reqsk_send_ack,
	.destructor	= dccp_v6_reqsk_destructor,
	.send_reset	= dccp_v6_ctl_send_reset,
	.syn_ack_timeout = dccp_syn_ack_timeout,
};

static int dccp_v6_conn_request(struct sock *sk, struct sk_buff *skb)
{
	struct request_sock *req;
	struct dccp_request_sock *dreq;
	struct inet_request_sock *ireq;
	struct ipv6_pinfo *np = inet6_sk(sk);
	const __be32 service = dccp_hdr_request(skb)->dccph_req_service;
	struct dccp_skb_cb *dcb = DCCP_SKB_CB(skb);

	if (skb->protocol == htons(ETH_P_IP))
		return dccp_v4_conn_request(sk, skb);

	if (!ipv6_unicast_destination(skb))
		return 0;	/* discard, don't send a reset here */

	if (dccp_bad_service_code(sk, service)) {
		dcb->dccpd_reset_code = DCCP_RESET_CODE_BAD_SERVICE_CODE;
		goto drop;
	}
	/*
	 * There are no SYN attacks on IPv6, yet...
	 */
	dcb->dccpd_reset_code = DCCP_RESET_CODE_TOO_BUSY;
	if (inet_csk_reqsk_queue_is_full(sk))
		goto drop;

	if (sk_acceptq_is_full(sk))
		goto drop;

	req = inet_reqsk_alloc(&dccp6_request_sock_ops, sk, true);
	if (req == NULL)
		goto drop;

	if (dccp_reqsk_init(req, dccp_sk(sk), skb))
		goto drop_and_free;

	dreq = dccp_rsk(req);
	if (dccp_parse_options(sk, dreq, skb))
		goto drop_and_free;

	if (security_inet_conn_request(sk, skb, req))
		goto drop_and_free;

	ireq = inet_rsk(req);
	ireq->ir_v6_rmt_addr = ipv6_hdr(skb)->saddr;
	ireq->ir_v6_loc_addr = ipv6_hdr(skb)->daddr;
	ireq->ireq_family = AF_INET6;
	ireq->ir_mark = inet_request_mark(sk, skb);

	if (ipv6_opt_accepted(sk, skb, IP6CB(skb)) ||
	    np->rxopt.bits.rxinfo || np->rxopt.bits.rxoinfo ||
	    np->rxopt.bits.rxhlim || np->rxopt.bits.rxohlim) {
		refcount_inc(&skb->users);
		ireq->pktopts = skb;
	}
	ireq->ir_iif = sk->sk_bound_dev_if;

	/* So that link locals have meaning */
	if (!sk->sk_bound_dev_if &&
	    ipv6_addr_type(&ireq->ir_v6_rmt_addr) & IPV6_ADDR_LINKLOCAL)
		ireq->ir_iif = inet6_iif(skb);

	/*
	 * Step 3: Process LISTEN state
	 *
	 *   Set S.ISR, S.GSR, S.SWL, S.SWH from packet or Init Cookie
	 *
	 * Setting S.SWL/S.SWH to is deferred to dccp_create_openreq_child().
	 */
	dreq->dreq_isr	   = dcb->dccpd_seq;
	dreq->dreq_gsr     = dreq->dreq_isr;
	dreq->dreq_iss	   = dccp_v6_init_sequence(skb);
	dreq->dreq_gss     = dreq->dreq_iss;
	dreq->dreq_service = service;

	if (dccp_v6_send_response(sk, req))
		goto drop_and_free;

	inet_csk_reqsk_queue_hash_add(sk, req, DCCP_TIMEOUT_INIT);
	reqsk_put(req);
	return 0;

drop_and_free:
	reqsk_free(req);
drop:
	__DCCP_INC_STATS(DCCP_MIB_ATTEMPTFAILS);
	return -1;
}

static struct sock *dccp_v6_request_recv_sock(const struct sock *sk,
					      struct sk_buff *skb,
					      struct request_sock *req,
					      struct dst_entry *dst,
					      struct request_sock *req_unhash,
					      bool *own_req)
{
	struct inet_request_sock *ireq = inet_rsk(req);
	struct ipv6_pinfo *newnp;
	const struct ipv6_pinfo *np = inet6_sk(sk);
	struct ipv6_txoptions *opt;
	struct inet_sock *newinet;
	struct dccp6_sock *newdp6;
	struct sock *newsk;

	if (skb->protocol == htons(ETH_P_IP)) {
		/*
		 *	v6 mapped
		 */
		newsk = dccp_v4_request_recv_sock(sk, skb, req, dst,
						  req_unhash, own_req);
		if (newsk == NULL)
			return NULL;

		newdp6 = (struct dccp6_sock *)newsk;
		newinet = inet_sk(newsk);
		newinet->pinet6 = &newdp6->inet6;
		newnp = inet6_sk(newsk);

		memcpy(newnp, np, sizeof(struct ipv6_pinfo));

		newnp->saddr = newsk->sk_v6_rcv_saddr;

		inet_csk(newsk)->icsk_af_ops = &dccp_ipv6_mapped;
		newsk->sk_backlog_rcv = dccp_v4_do_rcv;
		newnp->pktoptions  = NULL;
		newnp->opt	   = NULL;
		newnp->ipv6_mc_list = NULL;
		newnp->ipv6_ac_list = NULL;
		newnp->ipv6_fl_list = NULL;
		newnp->mcast_oif   = inet_iif(skb);
		newnp->mcast_hops  = ip_hdr(skb)->ttl;

		/*
		 * No need to charge this sock to the relevant IPv6 refcnt debug socks count
		 * here, dccp_create_openreq_child now does this for us, see the comment in
		 * that function for the gory details. -acme
		 */

		/* It is tricky place. Until this moment IPv4 tcp
		   worked with IPv6 icsk.icsk_af_ops.
		   Sync it now.
		 */
		dccp_sync_mss(newsk, inet_csk(newsk)->icsk_pmtu_cookie);

		return newsk;
	}


	if (sk_acceptq_is_full(sk))
		goto out_overflow;

	if (!dst) {
		struct flowi6 fl6;

		dst = inet6_csk_route_req(sk, &fl6, req, IPPROTO_DCCP);
		if (!dst)
			goto out;
	}

	newsk = dccp_create_openreq_child(sk, req, skb);
	if (newsk == NULL)
		goto out_nonewsk;

	/*
	 * No need to charge this sock to the relevant IPv6 refcnt debug socks
	 * count here, dccp_create_openreq_child now does this for us, see the
	 * comment in that function for the gory details. -acme
	 */

	ip6_dst_store(newsk, dst, NULL, NULL);
	newsk->sk_route_caps = dst->dev->features & ~(NETIF_F_IP_CSUM |
						      NETIF_F_TSO);
	newdp6 = (struct dccp6_sock *)newsk;
	newinet = inet_sk(newsk);
	newinet->pinet6 = &newdp6->inet6;
	newnp = inet6_sk(newsk);

	memcpy(newnp, np, sizeof(struct ipv6_pinfo));

	newsk->sk_v6_daddr	= ireq->ir_v6_rmt_addr;
	newnp->saddr		= ireq->ir_v6_loc_addr;
	newsk->sk_v6_rcv_saddr	= ireq->ir_v6_loc_addr;
	newsk->sk_bound_dev_if	= ireq->ir_iif;

	/* Now IPv6 options...
	   First: no IPv4 options.
	 */
	newinet->inet_opt = NULL;

	/* Clone RX bits */
	newnp->rxopt.all = np->rxopt.all;

	newnp->ipv6_mc_list = NULL;
	newnp->ipv6_ac_list = NULL;
	newnp->ipv6_fl_list = NULL;
	newnp->pktoptions = NULL;
	newnp->opt	  = NULL;
	newnp->mcast_oif  = inet6_iif(skb);
	newnp->mcast_hops = ipv6_hdr(skb)->hop_limit;

	/*
	 * Clone native IPv6 options from listening socket (if any)
	 *
	 * Yes, keeping reference count would be much more clever, but we make
	 * one more one thing there: reattach optmem to newsk.
	 */
	opt = ireq->ipv6_opt;
	if (!opt)
		opt = rcu_dereference(np->opt);
	if (opt) {
		opt = ipv6_dup_options(newsk, opt);
		RCU_INIT_POINTER(newnp->opt, opt);
	}
	inet_csk(newsk)->icsk_ext_hdr_len = 0;
	if (opt)
		inet_csk(newsk)->icsk_ext_hdr_len = opt->opt_nflen +
						    opt->opt_flen;

	dccp_sync_mss(newsk, dst_mtu(dst));

	newinet->inet_daddr = newinet->inet_saddr = LOOPBACK4_IPV6;
	newinet->inet_rcv_saddr = LOOPBACK4_IPV6;

	if (__inet_inherit_port(sk, newsk) < 0) {
		inet_csk_prepare_forced_close(newsk);
		dccp_done(newsk);
		goto out;
	}
	*own_req = inet_ehash_nolisten(newsk, req_to_sk(req_unhash));
	/* Clone pktoptions received with SYN, if we own the req */
	if (*own_req && ireq->pktopts) {
		newnp->pktoptions = skb_clone(ireq->pktopts, GFP_ATOMIC);
		consume_skb(ireq->pktopts);
		ireq->pktopts = NULL;
		if (newnp->pktoptions)
			skb_set_owner_r(newnp->pktoptions, newsk);
	}

	return newsk;

out_overflow:
	__NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENOVERFLOWS);
out_nonewsk:
	dst_release(dst);
out:
	__NET_INC_STATS(sock_net(sk), LINUX_MIB_LISTENDROPS);
	return NULL;
}

/* The socket must have it's spinlock held when we get
 * here.
 *
 * We have a potential double-lock case here, so even when
 * doing backlog processing we use the BH locking scheme.
 * This is because we cannot sleep with the original spinlock
 * held.
 */
static int dccp_v6_do_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct sk_buff *opt_skb = NULL;

	/* Imagine: socket is IPv6. IPv4 packet arrives,
	   goes to IPv4 receive handler and backlogged.
	   From backlog it always goes here. Kerboom...
	   Fortunately, dccp_rcv_established and rcv_established
	   handle them correctly, but it is not case with
	   dccp_v6_hnd_req and dccp_v6_ctl_send_reset().   --ANK
	 */

	if (skb->protocol == htons(ETH_P_IP))
		return dccp_v4_do_rcv(sk, skb);

	if (sk_filter(sk, skb))
		goto discard;

	/*
	 * socket locking is here for SMP purposes as backlog rcv is currently
	 * called with bh processing disabled.
	 */

	/* Do Stevens' IPV6_PKTOPTIONS.
	   Yes, guys, it is the only place in our code, where we
	   may make it not affecting IPv4.
	   The rest of code is protocol independent,
	   and I do not like idea to uglify IPv4.
	   Actually, all the idea behind IPV6_PKTOPTIONS
	   looks not very well thought. For now we latch
	   options, received in the last packet, enqueued
	   by tcp. Feel free to propose better solution.
					       --ANK (980728)
	 */
	if (np->rxopt.all)
		opt_skb = skb_clone(skb, GFP_ATOMIC);

	if (sk->sk_state == DCCP_OPEN) { /* Fast path */
		if (dccp_rcv_established(sk, skb, dccp_hdr(skb), skb->len))
			goto reset;
		if (opt_skb)
			goto ipv6_pktoptions;
		return 0;
	}

	/*
	 *  Step 3: Process LISTEN state
	 *     If S.state == LISTEN,
	 *	 If P.type == Request or P contains a valid Init Cookie option,
	 *	      (* Must scan the packet's options to check for Init
	 *		 Cookies.  Only Init Cookies are processed here,
	 *		 however; other options are processed in Step 8.  This
	 *		 scan need only be performed if the endpoint uses Init
	 *		 Cookies *)
	 *	      (* Generate a new socket and switch to that socket *)
	 *	      Set S := new socket for this port pair
	 *	      S.state = RESPOND
	 *	      Choose S.ISS (initial seqno) or set from Init Cookies
	 *	      Initialize S.GAR := S.ISS
	 *	      Set S.ISR, S.GSR, S.SWL, S.SWH from packet or Init Cookies
	 *	      Continue with S.state == RESPOND
	 *	      (* A Response packet will be generated in Step 11 *)
	 *	 Otherwise,
	 *	      Generate Reset(No Connection) unless P.type == Reset
	 *	      Drop packet and return
	 *
	 * NOTE: the check for the packet types is done in
	 *	 dccp_rcv_state_process
	 */

	if (dccp_rcv_state_process(sk, skb, dccp_hdr(skb), skb->len))
		goto reset;
	if (opt_skb)
		goto ipv6_pktoptions;
	return 0;

reset:
	dccp_v6_ctl_send_reset(sk, skb);
discard:
	if (opt_skb != NULL)
		__kfree_skb(opt_skb);
	kfree_skb(skb);
	return 0;

/* Handling IPV6_PKTOPTIONS skb the similar
 * way it's done for net/ipv6/tcp_ipv6.c
 */
ipv6_pktoptions:
	if (!((1 << sk->sk_state) & (DCCPF_CLOSED | DCCPF_LISTEN))) {
		if (np->rxopt.bits.rxinfo || np->rxopt.bits.rxoinfo)
			np->mcast_oif = inet6_iif(opt_skb);
		if (np->rxopt.bits.rxhlim || np->rxopt.bits.rxohlim)
			np->mcast_hops = ipv6_hdr(opt_skb)->hop_limit;
		if (np->rxopt.bits.rxflow || np->rxopt.bits.rxtclass)
			np->rcv_flowinfo = ip6_flowinfo(ipv6_hdr(opt_skb));
		if (np->repflow)
			np->flow_label = ip6_flowlabel(ipv6_hdr(opt_skb));
		if (ipv6_opt_accepted(sk, opt_skb,
				      &DCCP_SKB_CB(opt_skb)->header.h6)) {
			skb_set_owner_r(opt_skb, sk);
			memmove(IP6CB(opt_skb),
				&DCCP_SKB_CB(opt_skb)->header.h6,
				sizeof(struct inet6_skb_parm));
			opt_skb = xchg(&np->pktoptions, opt_skb);
		} else {
			__kfree_skb(opt_skb);
			opt_skb = xchg(&np->pktoptions, NULL);
		}
	}

	kfree_skb(opt_skb);
	return 0;
}

static int dccp_v6_rcv(struct sk_buff *skb)
{
	const struct dccp_hdr *dh;
	bool refcounted;
	struct sock *sk;
	int min_cov;

	/* Step 1: Check header basics */

	if (dccp_invalid_packet(skb))
		goto discard_it;

	/* Step 1: If header checksum is incorrect, drop packet and return. */
	if (dccp_v6_csum_finish(skb, &ipv6_hdr(skb)->saddr,
				     &ipv6_hdr(skb)->daddr)) {
		DCCP_WARN("dropped packet with invalid checksum\n");
		goto discard_it;
	}

	dh = dccp_hdr(skb);

	DCCP_SKB_CB(skb)->dccpd_seq  = dccp_hdr_seq(dh);
	DCCP_SKB_CB(skb)->dccpd_type = dh->dccph_type;

	if (dccp_packet_without_ack(skb))
		DCCP_SKB_CB(skb)->dccpd_ack_seq = DCCP_PKT_WITHOUT_ACK_SEQ;
	else
		DCCP_SKB_CB(skb)->dccpd_ack_seq = dccp_hdr_ack_seq(skb);

lookup:
	sk = __inet6_lookup_skb(&dccp_hashinfo, skb, __dccp_hdr_len(dh),
			        dh->dccph_sport, dh->dccph_dport,
				inet6_iif(skb), 0, &refcounted);
	if (!sk) {
		dccp_pr_debug("failed to look up flow ID in table and "
			      "get corresponding socket\n");
		goto no_dccp_socket;
	}

	/*
	 * Step 2:
	 *	... or S.state == TIMEWAIT,
	 *		Generate Reset(No Connection) unless P.type == Reset
	 *		Drop packet and return
	 */
	if (sk->sk_state == DCCP_TIME_WAIT) {
		dccp_pr_debug("sk->sk_state == DCCP_TIME_WAIT: do_time_wait\n");
		inet_twsk_put(inet_twsk(sk));
		goto no_dccp_socket;
	}

	if (sk->sk_state == DCCP_NEW_SYN_RECV) {
		struct request_sock *req = inet_reqsk(sk);
		struct sock *nsk;

		sk = req->rsk_listener;
		if (unlikely(sk->sk_state != DCCP_LISTEN)) {
			inet_csk_reqsk_queue_drop_and_put(sk, req);
			goto lookup;
		}
		sock_hold(sk);
		refcounted = true;
		nsk = dccp_check_req(sk, skb, req);
		if (!nsk) {
			reqsk_put(req);
			goto discard_and_relse;
		}
		if (nsk == sk) {
			reqsk_put(req);
		} else if (dccp_child_process(sk, nsk, skb)) {
			dccp_v6_ctl_send_reset(sk, skb);
			goto discard_and_relse;
		} else {
			sock_put(sk);
			return 0;
		}
	}
	/*
	 * RFC 4340, sec. 9.2.1: Minimum Checksum Coverage
	 *	o if MinCsCov = 0, only packets with CsCov = 0 are accepted
	 *	o if MinCsCov > 0, also accept packets with CsCov >= MinCsCov
	 */
	min_cov = dccp_sk(sk)->dccps_pcrlen;
	if (dh->dccph_cscov  &&  (min_cov == 0 || dh->dccph_cscov < min_cov))  {
		dccp_pr_debug("Packet CsCov %d does not satisfy MinCsCov %d\n",
			      dh->dccph_cscov, min_cov);
		/* FIXME: send Data Dropped option (see also dccp_v4_rcv) */
		goto discard_and_relse;
	}

	if (!xfrm6_policy_check(sk, XFRM_POLICY_IN, skb))
		goto discard_and_relse;

	return __sk_receive_skb(sk, skb, 1, dh->dccph_doff * 4,
				refcounted) ? -1 : 0;

no_dccp_socket:
	if (!xfrm6_policy_check(NULL, XFRM_POLICY_IN, skb))
		goto discard_it;
	/*
	 * Step 2:
	 *	If no socket ...
	 *		Generate Reset(No Connection) unless P.type == Reset
	 *		Drop packet and return
	 */
	if (dh->dccph_type != DCCP_PKT_RESET) {
		DCCP_SKB_CB(skb)->dccpd_reset_code =
					DCCP_RESET_CODE_NO_CONNECTION;
		dccp_v6_ctl_send_reset(sk, skb);
	}

discard_it:
	kfree_skb(skb);
	return 0;

discard_and_relse:
	if (refcounted)
		sock_put(sk);
	goto discard_it;
}

static int dccp_v6_connect(struct sock *sk, struct sockaddr *uaddr,
			   int addr_len)
{
	struct sockaddr_in6 *usin = (struct sockaddr_in6 *)uaddr;
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct inet_sock *inet = inet_sk(sk);
	struct ipv6_pinfo *np = inet6_sk(sk);
	struct dccp_sock *dp = dccp_sk(sk);
	struct in6_addr *saddr = NULL, *final_p, final;
	struct ipv6_txoptions *opt;
	struct flowi6 fl6;
	struct dst_entry *dst;
	int addr_type;
	int err;

	dp->dccps_role = DCCP_ROLE_CLIENT;

	if (addr_len < SIN6_LEN_RFC2133)
		return -EINVAL;

	if (usin->sin6_family != AF_INET6)
		return -EAFNOSUPPORT;

	memset(&fl6, 0, sizeof(fl6));

	if (np->sndflow) {
		fl6.flowlabel = usin->sin6_flowinfo & IPV6_FLOWINFO_MASK;
		IP6_ECN_flow_init(fl6.flowlabel);
		if (fl6.flowlabel & IPV6_FLOWLABEL_MASK) {
			struct ip6_flowlabel *flowlabel;
			flowlabel = fl6_sock_lookup(sk, fl6.flowlabel);
			if (IS_ERR(flowlabel))
				return -EINVAL;
			fl6_sock_release(flowlabel);
		}
	}
	/*
	 * connect() to INADDR_ANY means loopback (BSD'ism).
	 */
	if (ipv6_addr_any(&usin->sin6_addr))
		usin->sin6_addr.s6_addr[15] = 1;

	addr_type = ipv6_addr_type(&usin->sin6_addr);

	if (addr_type & IPV6_ADDR_MULTICAST)
		return -ENETUNREACH;

	if (addr_type & IPV6_ADDR_LINKLOCAL) {
		if (addr_len >= sizeof(struct sockaddr_in6) &&
		    usin->sin6_scope_id) {
			/* If interface is set while binding, indices
			 * must coincide.
			 */
			if (sk->sk_bound_dev_if &&
			    sk->sk_bound_dev_if != usin->sin6_scope_id)
				return -EINVAL;

			sk->sk_bound_dev_if = usin->sin6_scope_id;
		}

		/* Connect to link-local address requires an interface */
		if (!sk->sk_bound_dev_if)
			return -EINVAL;
	}

	sk->sk_v6_daddr = usin->sin6_addr;
	np->flow_label = fl6.flowlabel;

	/*
	 * DCCP over IPv4
	 */
	if (addr_type == IPV6_ADDR_MAPPED) {
		u32 exthdrlen = icsk->icsk_ext_hdr_len;
		struct sockaddr_in sin;

		SOCK_DEBUG(sk, "connect: ipv4 mapped\n");

		if (__ipv6_only_sock(sk))
			return -ENETUNREACH;

		sin.sin_family = AF_INET;
		sin.sin_port = usin->sin6_port;
		sin.sin_addr.s_addr = usin->sin6_addr.s6_addr32[3];

		icsk->icsk_af_ops = &dccp_ipv6_mapped;
		sk->sk_backlog_rcv = dccp_v4_do_rcv;

		err = dccp_v4_connect(sk, (struct sockaddr *)&sin, sizeof(sin));
		if (err) {
			icsk->icsk_ext_hdr_len = exthdrlen;
			icsk->icsk_af_ops = &dccp_ipv6_af_ops;
			sk->sk_backlog_rcv = dccp_v6_do_rcv;
			goto failure;
		}
		np->saddr = sk->sk_v6_rcv_saddr;
		return err;
	}

	if (!ipv6_addr_any(&sk->sk_v6_rcv_saddr))
		saddr = &sk->sk_v6_rcv_saddr;

	fl6.flowi6_proto = IPPROTO_DCCP;
	fl6.daddr = sk->sk_v6_daddr;
	fl6.saddr = saddr ? *saddr : np->saddr;
	fl6.flowi6_oif = sk->sk_bound_dev_if;
	fl6.fl6_dport = usin->sin6_port;
	fl6.fl6_sport = inet->inet_sport;
	security_sk_classify_flow(sk, flowi6_to_flowi(&fl6));

	opt = rcu_dereference_protected(np->opt, lockdep_sock_is_held(sk));
	final_p = fl6_update_dst(&fl6, opt, &final);

	dst = ip6_dst_lookup_flow(sock_net(sk), sk, &fl6, final_p);
	if (IS_ERR(dst)) {
		err = PTR_ERR(dst);
		goto failure;
	}

	if (saddr == NULL) {
		saddr = &fl6.saddr;
		sk->sk_v6_rcv_saddr = *saddr;
	}

	/* set the source address */
	np->saddr = *saddr;
	inet->inet_rcv_saddr = LOOPBACK4_IPV6;

	ip6_dst_store(sk, dst, NULL, NULL);

	icsk->icsk_ext_hdr_len = 0;
	if (opt)
		icsk->icsk_ext_hdr_len = opt->opt_flen + opt->opt_nflen;

	inet->inet_dport = usin->sin6_port;

	dccp_set_state(sk, DCCP_REQUESTING);
	err = inet6_hash_connect(&dccp_death_row, sk);
	if (err)
		goto late_failure;

	dp->dccps_iss = secure_dccpv6_sequence_number(np->saddr.s6_addr32,
						      sk->sk_v6_daddr.s6_addr32,
						      inet->inet_sport,
						      inet->inet_dport);
	err = dccp_connect(sk);
	if (err)
		goto late_failure;

	return 0;

late_failure:
	dccp_set_state(sk, DCCP_CLOSED);
	__sk_dst_reset(sk);
failure:
	inet->inet_dport = 0;
	sk->sk_route_caps = 0;
	return err;
}

static const struct inet_connection_sock_af_ops dccp_ipv6_af_ops = {
	.queue_xmit	   = inet6_csk_xmit,
	.send_check	   = dccp_v6_send_check,
	.rebuild_header	   = inet6_sk_rebuild_header,
	.conn_request	   = dccp_v6_conn_request,
	.syn_recv_sock	   = dccp_v6_request_recv_sock,
	.net_header_len	   = sizeof(struct ipv6hdr),
	.setsockopt	   = ipv6_setsockopt,
	.getsockopt	   = ipv6_getsockopt,
	.addr2sockaddr	   = inet6_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in6),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ipv6_setsockopt,
	.compat_getsockopt = compat_ipv6_getsockopt,
#endif
};

/*
 *	DCCP over IPv4 via INET6 API
 */
static const struct inet_connection_sock_af_ops dccp_ipv6_mapped = {
	.queue_xmit	   = ip_queue_xmit,
	.send_check	   = dccp_v4_send_check,
	.rebuild_header	   = inet_sk_rebuild_header,
	.conn_request	   = dccp_v6_conn_request,
	.syn_recv_sock	   = dccp_v6_request_recv_sock,
	.net_header_len	   = sizeof(struct iphdr),
	.setsockopt	   = ipv6_setsockopt,
	.getsockopt	   = ipv6_getsockopt,
	.addr2sockaddr	   = inet6_csk_addr2sockaddr,
	.sockaddr_len	   = sizeof(struct sockaddr_in6),
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_ipv6_setsockopt,
	.compat_getsockopt = compat_ipv6_getsockopt,
#endif
};

/* NOTE: A lot of things set to zero explicitly by call to
 *       sk_alloc() so need not be done here.
 */
static int dccp_v6_init_sock(struct sock *sk)
{
	static __u8 dccp_v6_ctl_sock_initialized;
	int err = dccp_init_sock(sk, dccp_v6_ctl_sock_initialized);

	if (err == 0) {
		if (unlikely(!dccp_v6_ctl_sock_initialized))
			dccp_v6_ctl_sock_initialized = 1;
		inet_csk(sk)->icsk_af_ops = &dccp_ipv6_af_ops;
	}

	return err;
}

static void dccp_v6_destroy_sock(struct sock *sk)
{
	dccp_destroy_sock(sk);
	inet6_destroy_sock(sk);
}

static struct timewait_sock_ops dccp6_timewait_sock_ops = {
	.twsk_obj_size	= sizeof(struct dccp6_timewait_sock),
};

static struct proto dccp_v6_prot = {
	.name		   = "DCCPv6",
	.owner		   = THIS_MODULE,
	.close		   = dccp_close,
	.connect	   = dccp_v6_connect,
	.disconnect	   = dccp_disconnect,
	.ioctl		   = dccp_ioctl,
	.init		   = dccp_v6_init_sock,
	.setsockopt	   = dccp_setsockopt,
	.getsockopt	   = dccp_getsockopt,
	.sendmsg	   = dccp_sendmsg,
	.recvmsg	   = dccp_recvmsg,
	.backlog_rcv	   = dccp_v6_do_rcv,
	.hash		   = inet6_hash,
	.unhash		   = inet_unhash,
	.accept		   = inet_csk_accept,
	.get_port	   = inet_csk_get_port,
	.shutdown	   = dccp_shutdown,
	.destroy	   = dccp_v6_destroy_sock,
	.orphan_count	   = &dccp_orphan_count,
	.max_header	   = MAX_DCCP_HEADER,
	.obj_size	   = sizeof(struct dccp6_sock),
	.slab_flags	   = SLAB_TYPESAFE_BY_RCU,
	.rsk_prot	   = &dccp6_request_sock_ops,
	.twsk_prot	   = &dccp6_timewait_sock_ops,
	.h.hashinfo	   = &dccp_hashinfo,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_dccp_setsockopt,
	.compat_getsockopt = compat_dccp_getsockopt,
#endif
};

static const struct inet6_protocol dccp_v6_protocol = {
	.handler	= dccp_v6_rcv,
	.err_handler	= dccp_v6_err,
	.flags		= INET6_PROTO_NOPOLICY | INET6_PROTO_FINAL,
};

static const struct proto_ops inet6_dccp_ops = {
	.family		   = PF_INET6,
	.owner		   = THIS_MODULE,
	.release	   = inet6_release,
	.bind		   = inet6_bind,
	.connect	   = inet_stream_connect,
	.socketpair	   = sock_no_socketpair,
	.accept		   = inet_accept,
	.getname	   = inet6_getname,
	.poll		   = dccp_poll,
	.ioctl		   = inet6_ioctl,
	.gettstamp	   = sock_gettstamp,
	.listen		   = inet_dccp_listen,
	.shutdown	   = inet_shutdown,
	.setsockopt	   = sock_common_setsockopt,
	.getsockopt	   = sock_common_getsockopt,
	.sendmsg	   = inet_sendmsg,
	.recvmsg	   = sock_common_recvmsg,
	.mmap		   = sock_no_mmap,
	.sendpage	   = sock_no_sendpage,
#ifdef CONFIG_COMPAT
	.compat_setsockopt = compat_sock_common_setsockopt,
	.compat_getsockopt = compat_sock_common_getsockopt,
#endif
};

static struct inet_protosw dccp_v6_protosw = {
	.type		= SOCK_DCCP,
	.protocol	= IPPROTO_DCCP,
	.prot		= &dccp_v6_prot,
	.ops		= &inet6_dccp_ops,
	.flags		= INET_PROTOSW_ICSK,
};

static int __net_init dccp_v6_init_net(struct net *net)
{
	if (dccp_hashinfo.bhash == NULL)
		return -ESOCKTNOSUPPORT;

	return inet_ctl_sock_create(&net->dccp.v6_ctl_sk, PF_INET6,
				    SOCK_DCCP, IPPROTO_DCCP, net);
}

static void __net_exit dccp_v6_exit_net(struct net *net)
{
	inet_ctl_sock_destroy(net->dccp.v6_ctl_sk);
}

static void __net_exit dccp_v6_exit_batch(struct list_head *net_exit_list)
{
	inet_twsk_purge(&dccp_hashinfo, AF_INET6);
}

static struct pernet_operations dccp_v6_ops = {
	.init   = dccp_v6_init_net,
	.exit   = dccp_v6_exit_net,
	.exit_batch = dccp_v6_exit_batch,
};

static int __init dccp_v6_init(void)
{
	int err = proto_register(&dccp_v6_prot, 1);

	if (err)
		goto out;

	inet6_register_protosw(&dccp_v6_protosw);

	err = register_pernet_subsys(&dccp_v6_ops);
	if (err)
		goto out_destroy_ctl_sock;

	err = inet6_add_protocol(&dccp_v6_protocol, IPPROTO_DCCP);
	if (err)
		goto out_unregister_proto;

out:
	return err;
out_unregister_proto:
	unregister_pernet_subsys(&dccp_v6_ops);
out_destroy_ctl_sock:
	inet6_unregister_protosw(&dccp_v6_protosw);
	proto_unregister(&dccp_v6_prot);
	goto out;
}

static void __exit dccp_v6_exit(void)
{
	inet6_del_protocol(&dccp_v6_protocol, IPPROTO_DCCP);
	unregister_pernet_subsys(&dccp_v6_ops);
	inet6_unregister_protosw(&dccp_v6_protosw);
	proto_unregister(&dccp_v6_prot);
}

module_init(dccp_v6_init);
module_exit(dccp_v6_exit);

/*
 * __stringify doesn't likes enums, so use SOCK_DCCP (6) and IPPROTO_DCCP (33)
 * values directly, Also cover the case where the protocol is not specified,
 * i.e. net-pf-PF_INET6-proto-0-type-SOCK_DCCP
 */
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_INET6, 33, 6);
MODULE_ALIAS_NET_PF_PROTO_TYPE(PF_INET6, 0, 6);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Arnaldo Carvalho de Melo <acme@mandriva.com>");
MODULE_DESCRIPTION("DCCPv6 - Datagram Congestion Controlled Protocol");
};

/****************************************************************************/


struct Cpumap 
{
   enum {
	CPUINFO_LVL_ROOT = 0,
	CPUINFO_LVL_NODE,
	CPUINFO_LVL_CORE,
	CPUINFO_LVL_PROC,
	CPUINFO_LVL_MAX,
};

enum {
	ROVER_NO_OP              = 0,
	/* Increment rover every time level is visited */
	ROVER_INC_ON_VISIT       = 1 << 0,
	/* Increment parent's rover every time rover wraps around */
	ROVER_INC_PARENT_ON_LOOP = 1 << 1,
};

struct cpuinfo_node {
	int id;
	int level;
	int num_cpus;    /* Number of CPUs in this hierarchy */
	int parent_index;
	int child_start; /* Array index of the first child node */
	int child_end;   /* Array index of the last child node */
	int rover;       /* Child node iterator */
};

struct cpuinfo_level {
	int start_index; /* Index of first node of a level in a cpuinfo tree */
	int end_index;   /* Index of last node of a level in a cpuinfo tree */
	int num_nodes;   /* Number of nodes in a level in a cpuinfo tree */
};

struct cpuinfo_tree {
	int total_nodes;

	/* Offsets into nodes[] for each level of the tree */
	struct cpuinfo_level level[CPUINFO_LVL_MAX];
	struct cpuinfo_node  nodes[0];
};


static struct cpuinfo_tree *cpuinfo_tree;

static u16 cpu_distribution_map[NR_CPUS];
static DEFINE_SPINLOCK(cpu_map_lock);


/* Niagara optimized cpuinfo tree traversal. */
static const int niagara_iterate_method[] = {
	[CPUINFO_LVL_ROOT] = ROVER_NO_OP,

	/* Strands (or virtual CPUs) within a core may not run concurrently
	 * on the Niagara, as instruction pipeline(s) are shared.  Distribute
	 * work to strands in different cores first for better concurrency.
	 * Go to next NUMA node when all cores are used.
	 */
	[CPUINFO_LVL_NODE] = ROVER_INC_ON_VISIT|ROVER_INC_PARENT_ON_LOOP,

	/* Strands are grouped together by proc_id in cpuinfo_sparc, i.e.
	 * a proc_id represents an instruction pipeline.  Distribute work to
	 * strands in different proc_id groups if the core has multiple
	 * instruction pipelines (e.g. the Niagara 2/2+ has two).
	 */
	[CPUINFO_LVL_CORE] = ROVER_INC_ON_VISIT,

	/* Pick the next strand in the proc_id group. */
	[CPUINFO_LVL_PROC] = ROVER_INC_ON_VISIT,
};

/* Generic cpuinfo tree traversal.  Distribute work round robin across NUMA
 * nodes.
 */
static const int generic_iterate_method[] = {
	[CPUINFO_LVL_ROOT] = ROVER_INC_ON_VISIT,
	[CPUINFO_LVL_NODE] = ROVER_NO_OP,
	[CPUINFO_LVL_CORE] = ROVER_INC_PARENT_ON_LOOP,
	[CPUINFO_LVL_PROC] = ROVER_INC_ON_VISIT|ROVER_INC_PARENT_ON_LOOP,
};


static int cpuinfo_id(int cpu, int level)
{
	int id;

	switch (level) {
	case CPUINFO_LVL_ROOT:
		id = 0;
		break;
	case CPUINFO_LVL_NODE:
		id = cpu_to_node(cpu);
		break;
	case CPUINFO_LVL_CORE:
		id = cpu_data(cpu).core_id;
		break;
	case CPUINFO_LVL_PROC:
		id = cpu_data(cpu).proc_id;
		break;
	default:
		id = -EINVAL;
	}
	return id;
}

/*
 * Enumerate the CPU information in __cpu_data to determine the start index,
 * end index, and number of nodes for each level in the cpuinfo tree.  The
 * total number of cpuinfo nodes required to build the tree is returned.
 */
static int enumerate_cpuinfo_nodes(struct cpuinfo_level *tree_level)
{
	int prev_id[CPUINFO_LVL_MAX];
	int i, n, num_nodes;

	for (i = CPUINFO_LVL_ROOT; i < CPUINFO_LVL_MAX; i++) {
		struct cpuinfo_level *lv = &tree_level[i];

		prev_id[i] = -1;
		lv->start_index = lv->end_index = lv->num_nodes = 0;
	}

	num_nodes = 1; /* Include the root node */

	for (i = 0; i < num_possible_cpus(); i++) {
		if (!cpu_online(i))
			continue;

		n = cpuinfo_id(i, CPUINFO_LVL_NODE);
		if (n > prev_id[CPUINFO_LVL_NODE]) {
			tree_level[CPUINFO_LVL_NODE].num_nodes++;
			prev_id[CPUINFO_LVL_NODE] = n;
			num_nodes++;
		}
		n = cpuinfo_id(i, CPUINFO_LVL_CORE);
		if (n > prev_id[CPUINFO_LVL_CORE]) {
			tree_level[CPUINFO_LVL_CORE].num_nodes++;
			prev_id[CPUINFO_LVL_CORE] = n;
			num_nodes++;
		}
		n = cpuinfo_id(i, CPUINFO_LVL_PROC);
		if (n > prev_id[CPUINFO_LVL_PROC]) {
			tree_level[CPUINFO_LVL_PROC].num_nodes++;
			prev_id[CPUINFO_LVL_PROC] = n;
			num_nodes++;
		}
	}

	tree_level[CPUINFO_LVL_ROOT].num_nodes = 1;

	n = tree_level[CPUINFO_LVL_NODE].num_nodes;
	tree_level[CPUINFO_LVL_NODE].start_index = 1;
	tree_level[CPUINFO_LVL_NODE].end_index   = n;

	n++;
	tree_level[CPUINFO_LVL_CORE].start_index = n;
	n += tree_level[CPUINFO_LVL_CORE].num_nodes;
	tree_level[CPUINFO_LVL_CORE].end_index   = n - 1;

	tree_level[CPUINFO_LVL_PROC].start_index = n;
	n += tree_level[CPUINFO_LVL_PROC].num_nodes;
	tree_level[CPUINFO_LVL_PROC].end_index   = n - 1;

	return num_nodes;
}

/* Build a tree representation of the CPU hierarchy using the per CPU
 * information in __cpu_data.  Entries in __cpu_data[0..NR_CPUS] are
 * assumed to be sorted in ascending order based on node, core_id, and
 * proc_id (in order of significance).
 */
static struct cpuinfo_tree *build_cpuinfo_tree(void)
{
	struct cpuinfo_tree *new_tree;
	struct cpuinfo_node *node;
	struct cpuinfo_level tmp_level[CPUINFO_LVL_MAX];
	int num_cpus[CPUINFO_LVL_MAX];
	int level_rover[CPUINFO_LVL_MAX];
	int prev_id[CPUINFO_LVL_MAX];
	int n, id, cpu, prev_cpu, last_cpu, level;

	n = enumerate_cpuinfo_nodes(tmp_level);

	new_tree = kzalloc(struct_size(new_tree, nodes, n), GFP_ATOMIC);
	if (!new_tree)
		return NULL;

	new_tree->total_nodes = n;
	memcpy(&new_tree->level, tmp_level, sizeof(tmp_level));

	prev_cpu = cpu = cpumask_first(cpu_online_mask);

	/* Initialize all levels in the tree with the first CPU */
	for (level = CPUINFO_LVL_PROC; level >= CPUINFO_LVL_ROOT; level--) {
		n = new_tree->level[level].start_index;

		level_rover[level] = n;
		node = &new_tree->nodes[n];

		id = cpuinfo_id(cpu, level);
		if (unlikely(id < 0)) {
			kfree(new_tree);
			return NULL;
		}
		node->id = id;
		node->level = level;
		node->num_cpus = 1;

		node->parent_index = (level > CPUINFO_LVL_ROOT)
		    ? new_tree->level[level - 1].start_index : -1;

		node->child_start = node->child_end = node->rover =
		    (level == CPUINFO_LVL_PROC)
		    ? cpu : new_tree->level[level + 1].start_index;

		prev_id[level] = node->id;
		num_cpus[level] = 1;
	}

	for (last_cpu = (num_possible_cpus() - 1); last_cpu >= 0; last_cpu--) {
		if (cpu_online(last_cpu))
			break;
	}

	while (++cpu <= last_cpu) {
		if (!cpu_online(cpu))
			continue;

		for (level = CPUINFO_LVL_PROC; level >= CPUINFO_LVL_ROOT;
		     level--) {
			id = cpuinfo_id(cpu, level);
			if (unlikely(id < 0)) {
				kfree(new_tree);
				return NULL;
			}

			if ((id != prev_id[level]) || (cpu == last_cpu)) {
				prev_id[level] = id;
				node = &new_tree->nodes[level_rover[level]];
				node->num_cpus = num_cpus[level];
				num_cpus[level] = 1;

				if (cpu == last_cpu)
					node->num_cpus++;

				/* Connect tree node to parent */
				if (level == CPUINFO_LVL_ROOT)
					node->parent_index = -1;
				else
					node->parent_index =
					    level_rover[level - 1];

				if (level == CPUINFO_LVL_PROC) {
					node->child_end =
					    (cpu == last_cpu) ? cpu : prev_cpu;
				} else {
					node->child_end =
					    level_rover[level + 1] - 1;
				}

				/* Initialize the next node in the same level */
				n = ++level_rover[level];
				if (n <= new_tree->level[level].end_index) {
					node = &new_tree->nodes[n];
					node->id = id;
					node->level = level;

					/* Connect node to child */
					node->child_start = node->child_end =
					node->rover =
					    (level == CPUINFO_LVL_PROC)
					    ? cpu : level_rover[level + 1];
				}
			} else
				num_cpus[level]++;
		}
		prev_cpu = cpu;
	}

	return new_tree;
}

static void increment_rover(struct cpuinfo_tree *t, int node_index,
                            int root_index, const int *rover_inc_table)
{
	struct cpuinfo_node *node = &t->nodes[node_index];
	int top_level, level;

	top_level = t->nodes[root_index].level;
	for (level = node->level; level >= top_level; level--) {
		node->rover++;
		if (node->rover <= node->child_end)
			return;

		node->rover = node->child_start;
		/* If parent's rover does not need to be adjusted, stop here. */
		if ((level == top_level) ||
		    !(rover_inc_table[level] & ROVER_INC_PARENT_ON_LOOP))
			return;

		node = &t->nodes[node->parent_index];
	}
}

static int iterate_cpu(struct cpuinfo_tree *t, unsigned int root_index)
{
	const int *rover_inc_table;
	int level, new_index, index = root_index;

	switch (sun4v_chip_type) {
	case SUN4V_CHIP_NIAGARA1:
	case SUN4V_CHIP_NIAGARA2:
	case SUN4V_CHIP_NIAGARA3:
	case SUN4V_CHIP_NIAGARA4:
	case SUN4V_CHIP_NIAGARA5:
	case SUN4V_CHIP_SPARC_M6:
	case SUN4V_CHIP_SPARC_M7:
	case SUN4V_CHIP_SPARC_M8:
	case SUN4V_CHIP_SPARC_SN:
	case SUN4V_CHIP_SPARC64X:
		rover_inc_table = niagara_iterate_method;
		break;
	default:
		rover_inc_table = generic_iterate_method;
	}

	for (level = t->nodes[root_index].level; level < CPUINFO_LVL_MAX;
	     level++) {
		new_index = t->nodes[index].rover;
		if (rover_inc_table[level] & ROVER_INC_ON_VISIT)
			increment_rover(t, index, root_index, rover_inc_table);

		index = new_index;
	}
	return index;
}

static void _cpu_map_rebuild(void)
{
	int i;

	if (cpuinfo_tree) {
		kfree(cpuinfo_tree);
		cpuinfo_tree = NULL;
	}

	cpuinfo_tree = build_cpuinfo_tree();
	if (!cpuinfo_tree)
		return;

	/* Build CPU distribution map that spans all online CPUs.  No need
	 * to check if the CPU is online, as that is done when the cpuinfo
	 * tree is being built.
	 */
	for (i = 0; i < cpuinfo_tree->nodes[0].num_cpus; i++)
		cpu_distribution_map[i] = iterate_cpu(cpuinfo_tree, 0);
}

/* Fallback if the cpuinfo tree could not be built.  CPU mapping is linear
 * round robin.
 */
static int simple_map_to_cpu(unsigned int index)
{
	int i, end, cpu_rover;

	cpu_rover = 0;
	end = index % num_online_cpus();
	for (i = 0; i < num_possible_cpus(); i++) {
		if (cpu_online(cpu_rover)) {
			if (cpu_rover >= end)
				return cpu_rover;

			cpu_rover++;
		}
	}

	/* Impossible, since num_online_cpus() <= num_possible_cpus() */
	return cpumask_first(cpu_online_mask);
}

static int _map_to_cpu(unsigned int index)
{
	struct cpuinfo_node *root_node;

	if (unlikely(!cpuinfo_tree)) {
		_cpu_map_rebuild();
		if (!cpuinfo_tree)
			return simple_map_to_cpu(index);
	}

	root_node = &cpuinfo_tree->nodes[0];
#ifdef CONFIG_HOTPLUG_CPU
	if (unlikely(root_node->num_cpus != num_online_cpus())) {
		_cpu_map_rebuild();
		if (!cpuinfo_tree)
			return simple_map_to_cpu(index);
	}
#endif
	return cpu_distribution_map[index % root_node->num_cpus];
}

int map_to_cpu(unsigned int index)
{
	int mapped_cpu;
	unsigned long flag;

	spin_lock_irqsave(&cpu_map_lock, flag);
	mapped_cpu = _map_to_cpu(index);

#ifdef CONFIG_HOTPLUG_CPU
	while (unlikely(!cpu_online(mapped_cpu)))
		mapped_cpu = _map_to_cpu(index);
#endif
	spin_unlock_irqrestore(&cpu_map_lock, flag);
	return mapped_cpu;
}
EXPORT_SYMBOL(map_to_cpu);

void cpu_map_rebuild(void)
{
	unsigned long flag;

	spin_lock_irqsave(&cpu_map_lock, flag);
	_cpu_map_rebuild();
	spin_unlock_irqrestore(&cpu_map_lock, flag);
}



};

/***************************************************************************/

/* Probe and map in the Auxiliary I/O register */

/* auxio_register is not static because it is referenced 
 * in entry.S::floppy_tdone
 */
void __iomem *auxio_register = NULL;
static DEFINE_SPINLOCK(auxio_lock);

void __init auxio_probe(void)
{
	phandle node, auxio_nd;
	struct linux_prom_registers auxregs[1];
	struct resource r;

	switch (sparc_cpu_model) {
	case sparc_leon:
	case sun4d:
		return;
	default:
		break;
	}
	node = prom_getchild(prom_root_node);
	auxio_nd = prom_searchsiblings(node, "auxiliary-io");
	if(!auxio_nd) {
		node = prom_searchsiblings(node, "obio");
		node = prom_getchild(node);
		auxio_nd = prom_searchsiblings(node, "auxio");
		if(!auxio_nd) {
#ifdef CONFIG_PCI
			/* There may be auxio on Ebus */
			return;
#else
			if(prom_searchsiblings(node, "leds")) {
				/* VME chassis sun4m machine, no auxio exists. */
				return;
			}
			prom_printf("Cannot find auxio node, cannot continue...\n");
			prom_halt();
#endif
		}
	}
	if(prom_getproperty(auxio_nd, "reg", (char *) auxregs, sizeof(auxregs)) <= 0)
		return;
	prom_apply_obio_ranges(auxregs, 0x1);
	/* Map the register both read and write */
	r.flags = auxregs[0].which_io & 0xF;
	r.start = auxregs[0].phys_addr;
	r.end = auxregs[0].phys_addr + auxregs[0].reg_size - 1;
	auxio_register = of_ioremap(&r, 0, auxregs[0].reg_size, "auxio");
	/* Fix the address on sun4m. */
	if ((((unsigned long) auxregs[0].phys_addr) & 3) == 3)
		auxio_register += (3 - ((unsigned long)auxio_register & 3));

	set_auxio(AUXIO_LED, 0);
}

unsigned char get_auxio(void)
{
	if(auxio_register) 
		return sbus_readb(auxio_register);
	return 0;
}
EXPORT_SYMBOL(get_auxio);

void set_auxio(unsigned char bits_on, unsigned char bits_off)
{
	unsigned char regval;
	unsigned long flags;
	spin_lock_irqsave(&auxio_lock, flags);
	switch (sparc_cpu_model) {
	case sun4m:
		if(!auxio_register)
			break;     /* VME chassis sun4m, no auxio. */
		regval = sbus_readb(auxio_register);
		sbus_writeb(((regval | bits_on) & ~bits_off) | AUXIO_ORMEIN4M,
			auxio_register);
		break;
	case sun4d:
		break;
	default:
		panic("Can't set AUXIO register on this machine.");
	}
	spin_unlock_irqrestore(&auxio_lock, flags);
}
EXPORT_SYMBOL(set_auxio);

/* sun4m power control register (AUXIO2) */

volatile u8 __iomem *auxio_power_register = NULL;

void __init auxio_power_probe(void)
{
	struct linux_prom_registers regs;
	phandle node;
	struct resource r;

	/* Attempt to find the sun4m power control node. */
	node = prom_getchild(prom_root_node);
	node = prom_searchsiblings(node, "obio");
	node = prom_getchild(node);
	node = prom_searchsiblings(node, "power");
	if (node == 0 || (s32)node == -1)
		return;

	/* Map the power control register. */
	if (prom_getproperty(node, "reg", (char *)&regs, sizeof(regs)) <= 0)
		return;
	prom_apply_obio_ranges(&regs, 1);
	memset(&r, 0, sizeof(r));
	r.flags = regs.which_io & 0xF;
	r.start = regs.phys_addr;
	r.end = regs.phys_addr + regs.reg_size - 1;
	auxio_power_register =
		(u8 __iomem *)of_ioremap(&r, 0, regs.reg_size, "auxpower");

	/* Display a quick message on the console. */
	if (auxio_power_register)
		printk(KERN_INFO "Power off control detected.\n");
}

/***********************************************************************************/

struct utls 
{
	/* must be called with ids->rwsem acquired for writing */
int ipc_addid(struct ipc_ids *, struct kern_ipc_perm *, int);

/* must be called with both locks acquired. */
void ipc_rmid(struct ipc_ids *, struct kern_ipc_perm *);

/* must be called with both locks acquired. */
void ipc_set_key_private(struct ipc_ids *, struct kern_ipc_perm *);

/* must be called with ipcp locked */
int ipcperms(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp, short flg);

/**
 * ipc_get_maxidx - get the highest assigned index
 * @ids: ipc identifier set
 *
 * Called with ipc_ids.rwsem held for reading.
 */
static inline int ipc_get_maxidx(struct ipc_ids *ids)
{
	if (ids->in_use == 0)
		return -1;

	if (ids->in_use == ipc_mni)
		return ipc_mni - 1;

	return ids->max_idx;
}

/*
 * For allocation that need to be freed by RCU.
 * Objects are reference counted, they start with reference count 1.
 * getref increases the refcount, the putref call that reduces the recount
 * to 0 schedules the rcu destruction. Caller must guarantee locking.
 *
 * refcount is initialized by ipc_addid(), before that point call_rcu()
 * must be used.
 */
bool ipc_rcu_getref(struct kern_ipc_perm *ptr);
void ipc_rcu_putref(struct kern_ipc_perm *ptr,
			void (*func)(struct rcu_head *head));

struct kern_ipc_perm *ipc_obtain_object_idr(struct ipc_ids *ids, int id);

void kernel_to_ipc64_perm(struct kern_ipc_perm *in, struct ipc64_perm *out);
void ipc64_perm_to_ipc_perm(struct ipc64_perm *in, struct ipc_perm *out);
int ipc_update_perm(struct ipc64_perm *in, struct kern_ipc_perm *out);
struct kern_ipc_perm *ipcctl_obtain_check(struct ipc_namespace *ns,
					     struct ipc_ids *ids, int id, int cmd,
					     struct ipc64_perm *perm, int extra_perm);

static inline void ipc_update_pid(struct pid **pos, struct pid *pid)
{
	struct pid *old = *pos;
	if (old != pid) {
		*pos = get_pid(pid);
		put_pid(old);
	}
}

#ifdef CONFIG_ARCH_WANT_IPC_PARSE_VERSION
int ipc_parse_version(int *cmd);
#endif

extern void free_msg(struct msg_msg *msg);
extern struct msg_msg *load_msg(const void __user *src, size_t len);
extern struct msg_msg *copy_msg(struct msg_msg *src, struct msg_msg *dst);
extern int store_msg(void __user *dest, struct msg_msg *msg, size_t len);

static inline int ipc_checkid(struct kern_ipc_perm *ipcp, int id)
{
	return ipcid_to_seqx(id) != ipcp->seq;
}

static inline void ipc_lock_object(struct kern_ipc_perm *perm)
{
	spin_lock(&perm->lock);
}

static inline void ipc_unlock_object(struct kern_ipc_perm *perm)
{
	spin_unlock(&perm->lock);
}

static inline void ipc_assert_locked_object(struct kern_ipc_perm *perm)
{
	assert_spin_locked(&perm->lock);
}

static inline void ipc_unlock(struct kern_ipc_perm *perm)
{
	ipc_unlock_object(perm);
	rcu_read_unlock();
}

/*
 * ipc_valid_object() - helper to sort out IPC_RMID races for codepaths
 * where the respective ipc_ids.rwsem is not being held down.
 * Checks whether the ipc object is still around or if it's gone already, as
 * ipc_rmid() may have already freed the ID while the ipc lock was spinning.
 * Needs to be called with kern_ipc_perm.lock held -- exception made for one
 * checkpoint case at sys_semtimedop() as noted in code commentary.
 */
static inline bool ipc_valid_object(struct kern_ipc_perm *perm)
{
	return !perm->deleted;
}

struct kern_ipc_perm *ipc_obtain_object_check(struct ipc_ids *ids, int id);
int ipcget(struct ipc_namespace *ns, struct ipc_ids *ids,
			const struct ipc_ops *ops, struct ipc_params *params);
void free_ipcs(struct ipc_namespace *ns, struct ipc_ids *ids,
		void (*free)(struct ipc_namespace *, struct kern_ipc_perm *));

static inline int sem_check_semmni(struct ipc_namespace *ns) {
	/*
	 * Check semmni range [0, ipc_mni]
	 * semmni is the last element of sem_ctls[4] array
	 */
	return ((ns->sem_ctls[3] < 0) || (ns->sem_ctls[3] > ipc_mni))
		? -ERANGE : 0;
}

#ifdef CONFIG_COMPAT

struct compat_ipc_perm {
	key_t key;
	__compat_uid_t uid;
	__compat_gid_t gid;
	__compat_uid_t cuid;
	__compat_gid_t cgid;
	compat_mode_t mode;
	unsigned short seq;
};

void to_compat_ipc_perm(struct compat_ipc_perm *, struct ipc64_perm *);
void to_compat_ipc64_perm(struct compat_ipc64_perm *, struct ipc64_perm *);
int get_compat_ipc_perm(struct ipc64_perm *, struct compat_ipc_perm __user *);
int get_compat_ipc64_perm(struct ipc64_perm *,
			  struct compat_ipc64_perm __user *);

static inline int compat_ipc_parse_version(int *cmd)
{
	int version = *cmd & IPC_64;
	*cmd &= ~IPC_64;
	return version;
}

long compat_ksys_old_semctl(int semid, int semnum, int cmd, int arg);
long compat_ksys_old_msgctl(int msqid, int cmd, void __user *uptr);
long compat_ksys_msgrcv(int msqid, compat_uptr_t msgp, compat_ssize_t msgsz,
			compat_long_t msgtyp, int msgflg);
long compat_ksys_msgsnd(int msqid, compat_uptr_t msgp,
		       compat_ssize_t msgsz, int msgflg);
long compat_ksys_old_shmctl(int shmid, int cmd, void __user *uptr);


struct ipc_proc_iface {
	const char *path;
	const char *header;
	int ids;
	int (*show)(struct seq_file *, void *);
};

/**
 * ipc_init - initialise ipc subsystem
 *
 * The various sysv ipc resources (semaphores, messages and shared
 * memory) are initialised.
 *
 * A callback routine is registered into the memory hotplug notifier
 * chain: since msgmni scales to lowmem this callback routine will be
 * called upon successful memory add / remove to recompute msmgni.
 */
static int __init ipc_init(void)
{
	proc_mkdir("sysvipc", NULL);
	sem_init();
	msg_init();
	shm_init();

	return 0;
}
device_initcall(ipc_init);

static const struct rhashtable_params ipc_kht_params = {
	.head_offset		= offsetof(struct kern_ipc_perm, khtnode),
	.key_offset		= offsetof(struct kern_ipc_perm, key),
	.key_len		= sizeof_field(struct kern_ipc_perm, key),
	.automatic_shrinking	= true,
};

/**
 * ipc_init_ids	- initialise ipc identifiers
 * @ids: ipc identifier set
 *
 * Set up the sequence range to use for the ipc identifier range (limited
 * below ipc_mni) then initialise the keys hashtable and ids idr.
 */
void ipc_init_ids(struct ipc_ids *ids)
{
	ids->in_use = 0;
	ids->seq = 0;
	init_rwsem(&ids->rwsem);
	rhashtable_init(&ids->key_ht, &ipc_kht_params);
	idr_init(&ids->ipcs_idr);
	ids->max_idx = -1;
	ids->last_idx = -1;
#ifdef CONFIG_CHECKPOINT_RESTORE
	ids->next_id = -1;
#endif
}

#ifdef CONFIG_PROC_FS
static const struct proc_ops sysvipc_proc_ops;
/**
 * ipc_init_proc_interface -  create a proc interface for sysipc types using a seq_file interface.
 * @path: Path in procfs
 * @header: Banner to be printed at the beginning of the file.
 * @ids: ipc id table to iterate.
 * @show: show routine.
 */
void __init ipc_init_proc_interface(const char *path, const char *header,
		int ids, int (*show)(struct seq_file *, void *))
{
	struct proc_dir_entry *pde;
	struct ipc_proc_iface *iface;

	iface = kmalloc(sizeof(*iface), GFP_KERNEL);
	if (!iface)
		return;
	iface->path	= path;
	iface->header	= header;
	iface->ids	= ids;
	iface->show	= show;

	pde = proc_create_data(path,
			       S_IRUGO,        /* world readable */
			       NULL,           /* parent dir */
			       &sysvipc_proc_ops,
			       iface);
	if (!pde)
		kfree(iface);
}
#endif

/**
 * ipc_findkey	- find a key in an ipc identifier set
 * @ids: ipc identifier set
 * @key: key to find
 *
 * Returns the locked pointer to the ipc structure if found or NULL
 * otherwise. If key is found ipc points to the owning ipc structure
 *
 * Called with writer ipc_ids.rwsem held.
 */
static struct kern_ipc_perm *ipc_findkey(struct ipc_ids *ids, key_t key)
{
	struct kern_ipc_perm *ipcp;

	ipcp = rhashtable_lookup_fast(&ids->key_ht, &key,
					      ipc_kht_params);
	if (!ipcp)
		return NULL;

	rcu_read_lock();
	ipc_lock_object(ipcp);
	return ipcp;
}

/*
 * Insert new IPC object into idr tree, and set sequence number and id
 * in the correct order.
 * Especially:
 * - the sequence number must be set before inserting the object into the idr,
 *   because the sequence number is accessed without a lock.
 * - the id can/must be set after inserting the object into the idr.
 *   All accesses must be done after getting kern_ipc_perm.lock.
 *
 * The caller must own kern_ipc_perm.lock.of the new object.
 * On error, the function returns a (negative) error code.
 *
 * To conserve sequence number space, especially with extended ipc_mni,
 * the sequence number is incremented only when the returned ID is less than
 * the last one.
 */
static inline int ipc_idr_alloc(struct ipc_ids *ids, struct kern_ipc_perm *new)
{
	int idx, next_id = -1;

#ifdef CONFIG_CHECKPOINT_RESTORE
	next_id = ids->next_id;
	ids->next_id = -1;
#endif

	/*
	 * As soon as a new object is inserted into the idr,
	 * ipc_obtain_object_idr() or ipc_obtain_object_check() can find it,
	 * and the lockless preparations for ipc operations can start.
	 * This means especially: permission checks, audit calls, allocation
	 * of undo structures, ...
	 *
	 * Thus the object must be fully initialized, and if something fails,
	 * then the full tear-down sequence must be followed.
	 * (i.e.: set new->deleted, reduce refcount, call_rcu())
	 */

	if (next_id < 0) { /* !CHECKPOINT_RESTORE or next_id is unset */
		int max_idx;

		max_idx = max(ids->in_use*3/2, ipc_min_cycle);
		max_idx = min(max_idx, ipc_mni);

		/* allocate the idx, with a NULL struct kern_ipc_perm */
		idx = idr_alloc_cyclic(&ids->ipcs_idr, NULL, 0, max_idx,
					GFP_NOWAIT);

		if (idx >= 0) {
			/*
			 * idx got allocated successfully.
			 * Now calculate the sequence number and set the
			 * pointer for real.
			 */
			if (idx <= ids->last_idx) {
				ids->seq++;
				if (ids->seq >= ipcid_seq_max())
					ids->seq = 0;
			}
			ids->last_idx = idx;

			new->seq = ids->seq;
			/* no need for smp_wmb(), this is done
			 * inside idr_replace, as part of
			 * rcu_assign_pointer
			 */
			idr_replace(&ids->ipcs_idr, new, idx);
		}
	} else {
		new->seq = ipcid_to_seqx(next_id);
		idx = idr_alloc(&ids->ipcs_idr, new, ipcid_to_idx(next_id),
				0, GFP_NOWAIT);
	}
	if (idx >= 0)
		new->id = (new->seq << ipcmni_seq_shift()) + idx;
	return idx;
}

/**
 * ipc_addid - add an ipc identifier
 * @ids: ipc identifier set
 * @new: new ipc permission set
 * @limit: limit for the number of used ids
 *
 * Add an entry 'new' to the ipc ids idr. The permissions object is
 * initialised and the first free entry is set up and the index assigned
 * is returned. The 'new' entry is returned in a locked state on success.
 *
 * On failure the entry is not locked and a negative err-code is returned.
 * The caller must use ipc_rcu_putref() to free the identifier.
 *
 * Called with writer ipc_ids.rwsem held.
 */
int ipc_addid(struct ipc_ids *ids, struct kern_ipc_perm *new, int limit)
{
	kuid_t euid;
	kgid_t egid;
	int idx, err;

	/* 1) Initialize the refcount so that ipc_rcu_putref works */
	refcount_set(&new->refcount, 1);

	if (limit > ipc_mni)
		limit = ipc_mni;

	if (ids->in_use >= limit)
		return -ENOSPC;

	idr_preload(GFP_KERNEL);

	spin_lock_init(&new->lock);
	rcu_read_lock();
	spin_lock(&new->lock);

	current_euid_egid(&euid, &egid);
	new->cuid = new->uid = euid;
	new->gid = new->cgid = egid;

	new->deleted = false;

	idx = ipc_idr_alloc(ids, new);
	idr_preload_end();

	if (idx >= 0 && new->key != IPC_PRIVATE) {
		err = rhashtable_insert_fast(&ids->key_ht, &new->khtnode,
					     ipc_kht_params);
		if (err < 0) {
			idr_remove(&ids->ipcs_idr, idx);
			idx = err;
		}
	}
	if (idx < 0) {
		new->deleted = true;
		spin_unlock(&new->lock);
		rcu_read_unlock();
		return idx;
	}

	ids->in_use++;
	if (idx > ids->max_idx)
		ids->max_idx = idx;
	return idx;
}

/**
 * ipcget_new -	create a new ipc object
 * @ns: ipc namespace
 * @ids: ipc identifier set
 * @ops: the actual creation routine to call
 * @params: its parameters
 *
 * This routine is called by sys_msgget, sys_semget() and sys_shmget()
 * when the key is IPC_PRIVATE.
 */
static int ipcget_new(struct ipc_namespace *ns, struct ipc_ids *ids,
		const struct ipc_ops *ops, struct ipc_params *params)
{
	int err;

	down_write(&ids->rwsem);
	err = ops->getnew(ns, params);
	up_write(&ids->rwsem);
	return err;
}

/**
 * ipc_check_perms - check security and permissions for an ipc object
 * @ns: ipc namespace
 * @ipcp: ipc permission set
 * @ops: the actual security routine to call
 * @params: its parameters
 *
 * This routine is called by sys_msgget(), sys_semget() and sys_shmget()
 * when the key is not IPC_PRIVATE and that key already exists in the
 * ds IDR.
 *
 * On success, the ipc id is returned.
 *
 * It is called with ipc_ids.rwsem and ipcp->lock held.
 */
static int ipc_check_perms(struct ipc_namespace *ns,
			   struct kern_ipc_perm *ipcp,
			   const struct ipc_ops *ops,
			   struct ipc_params *params)
{
	int err;

	if (ipcperms(ns, ipcp, params->flg))
		err = -EACCES;
	else {
		err = ops->associate(ipcp, params->flg);
		if (!err)
			err = ipcp->id;
	}

	return err;
}

/**
 * ipcget_public - get an ipc object or create a new one
 * @ns: ipc namespace
 * @ids: ipc identifier set
 * @ops: the actual creation routine to call
 * @params: its parameters
 *
 * This routine is called by sys_msgget, sys_semget() and sys_shmget()
 * when the key is not IPC_PRIVATE.
 * It adds a new entry if the key is not found and does some permission
 * / security checkings if the key is found.
 *
 * On success, the ipc id is returned.
 */
static int ipcget_public(struct ipc_namespace *ns, struct ipc_ids *ids,
		const struct ipc_ops *ops, struct ipc_params *params)
{
	struct kern_ipc_perm *ipcp;
	int flg = params->flg;
	int err;

	/*
	 * Take the lock as a writer since we are potentially going to add
	 * a new entry + read locks are not "upgradable"
	 */
	down_write(&ids->rwsem);
	ipcp = ipc_findkey(ids, params->key);
	if (ipcp == NULL) {
		/* key not used */
		if (!(flg & IPC_CREAT))
			err = -ENOENT;
		else
			err = ops->getnew(ns, params);
	} else {
		/* ipc object has been locked by ipc_findkey() */

		if (flg & IPC_CREAT && flg & IPC_EXCL)
			err = -EEXIST;
		else {
			err = 0;
			if (ops->more_checks)
				err = ops->more_checks(ipcp, params);
			if (!err)
				/*
				 * ipc_check_perms returns the IPC id on
				 * success
				 */
				err = ipc_check_perms(ns, ipcp, ops, params);
		}
		ipc_unlock(ipcp);
	}
	up_write(&ids->rwsem);

	return err;
}

/**
 * ipc_kht_remove - remove an ipc from the key hashtable
 * @ids: ipc identifier set
 * @ipcp: ipc perm structure containing the key to remove
 *
 * ipc_ids.rwsem (as a writer) and the spinlock for this ID are held
 * before this function is called, and remain locked on the exit.
 */
static void ipc_kht_remove(struct ipc_ids *ids, struct kern_ipc_perm *ipcp)
{
	if (ipcp->key != IPC_PRIVATE)
		rhashtable_remove_fast(&ids->key_ht, &ipcp->khtnode,
				       ipc_kht_params);
}

/**
 * ipc_rmid - remove an ipc identifier
 * @ids: ipc identifier set
 * @ipcp: ipc perm structure containing the identifier to remove
 *
 * ipc_ids.rwsem (as a writer) and the spinlock for this ID are held
 * before this function is called, and remain locked on the exit.
 */
void ipc_rmid(struct ipc_ids *ids, struct kern_ipc_perm *ipcp)
{
	int idx = ipcid_to_idx(ipcp->id);

	idr_remove(&ids->ipcs_idr, idx);
	ipc_kht_remove(ids, ipcp);
	ids->in_use--;
	ipcp->deleted = true;

	if (unlikely(idx == ids->max_idx)) {
		do {
			idx--;
			if (idx == -1)
				break;
		} while (!idr_find(&ids->ipcs_idr, idx));
		ids->max_idx = idx;
	}
}

/**
 * ipc_set_key_private - switch the key of an existing ipc to IPC_PRIVATE
 * @ids: ipc identifier set
 * @ipcp: ipc perm structure containing the key to modify
 *
 * ipc_ids.rwsem (as a writer) and the spinlock for this ID are held
 * before this function is called, and remain locked on the exit.
 */
void ipc_set_key_private(struct ipc_ids *ids, struct kern_ipc_perm *ipcp)
{
	ipc_kht_remove(ids, ipcp);
	ipcp->key = IPC_PRIVATE;
}

bool ipc_rcu_getref(struct kern_ipc_perm *ptr)
{
	return refcount_inc_not_zero(&ptr->refcount);
}

void ipc_rcu_putref(struct kern_ipc_perm *ptr,
			void (*func)(struct rcu_head *head))
{
	if (!refcount_dec_and_test(&ptr->refcount))
		return;

	call_rcu(&ptr->rcu, func);
}

/**
 * ipcperms - check ipc permissions
 * @ns: ipc namespace
 * @ipcp: ipc permission set
 * @flag: desired permission set
 *
 * Check user, group, other permissions for access
 * to ipc resources. return 0 if allowed
 *
 * @flag will most probably be 0 or ``S_...UGO`` from <linux/stat.h>
 */
int ipcperms(struct ipc_namespace *ns, struct kern_ipc_perm *ipcp, short flag)
{
	kuid_t euid = current_euid();
	int requested_mode, granted_mode;

	audit_ipc_obj(ipcp);
	requested_mode = (flag >> 6) | (flag >> 3) | flag;
	granted_mode = ipcp->mode;
	if (uid_eq(euid, ipcp->cuid) ||
	    uid_eq(euid, ipcp->uid))
		granted_mode >>= 6;
	else if (in_group_p(ipcp->cgid) || in_group_p(ipcp->gid))
		granted_mode >>= 3;
	/* is there some bit set in requested_mode but not in granted_mode? */
	if ((requested_mode & ~granted_mode & 0007) &&
	    !ns_capable(ns->user_ns, CAP_IPC_OWNER))
		return -1;

	return security_ipc_permission(ipcp, flag);
}

/*
 * Functions to convert between the kern_ipc_perm structure and the
 * old/new ipc_perm structures
 */

/**
 * kernel_to_ipc64_perm	- convert kernel ipc permissions to user
 * @in: kernel permissions
 * @out: new style ipc permissions
 *
 * Turn the kernel object @in into a set of permissions descriptions
 * for returning to userspace (@out).
 */
void kernel_to_ipc64_perm(struct kern_ipc_perm *in, struct ipc64_perm *out)
{
	out->key	= in->key;
	out->uid	= from_kuid_munged(current_user_ns(), in->uid);
	out->gid	= from_kgid_munged(current_user_ns(), in->gid);
	out->cuid	= from_kuid_munged(current_user_ns(), in->cuid);
	out->cgid	= from_kgid_munged(current_user_ns(), in->cgid);
	out->mode	= in->mode;
	out->seq	= in->seq;
}

/**
 * ipc64_perm_to_ipc_perm - convert new ipc permissions to old
 * @in: new style ipc permissions
 * @out: old style ipc permissions
 *
 * Turn the new style permissions object @in into a compatibility
 * object and store it into the @out pointer.
 */
void ipc64_perm_to_ipc_perm(struct ipc64_perm *in, struct ipc_perm *out)
{
	out->key	= in->key;
	SET_UID(out->uid, in->uid);
	SET_GID(out->gid, in->gid);
	SET_UID(out->cuid, in->cuid);
	SET_GID(out->cgid, in->cgid);
	out->mode	= in->mode;
	out->seq	= in->seq;
}

/**
 * ipc_obtain_object_idr
 * @ids: ipc identifier set
 * @id: ipc id to look for
 *
 * Look for an id in the ipc ids idr and return associated ipc object.
 *
 * Call inside the RCU critical section.
 * The ipc object is *not* locked on exit.
 */
struct kern_ipc_perm *ipc_obtain_object_idr(struct ipc_ids *ids, int id)
{
	struct kern_ipc_perm *out;
	int idx = ipcid_to_idx(id);

	out = idr_find(&ids->ipcs_idr, idx);
	if (!out)
		return ERR_PTR(-EINVAL);

	return out;
}

/**
 * ipc_obtain_object_check
 * @ids: ipc identifier set
 * @id: ipc id to look for
 *
 * Similar to ipc_obtain_object_idr() but also checks the ipc object
 * sequence number.
 *
 * Call inside the RCU critical section.
 * The ipc object is *not* locked on exit.
 */
struct kern_ipc_perm *ipc_obtain_object_check(struct ipc_ids *ids, int id)
{
	struct kern_ipc_perm *out = ipc_obtain_object_idr(ids, id);

	if (IS_ERR(out))
		goto out;

	if (ipc_checkid(out, id))
		return ERR_PTR(-EINVAL);
out:
	return out;
}

/**
 * ipcget - Common sys_*get() code
 * @ns: namespace
 * @ids: ipc identifier set
 * @ops: operations to be called on ipc object creation, permission checks
 *       and further checks
 * @params: the parameters needed by the previous operations.
 *
 * Common routine called by sys_msgget(), sys_semget() and sys_shmget().
 */
int ipcget(struct ipc_namespace *ns, struct ipc_ids *ids,
			const struct ipc_ops *ops, struct ipc_params *params)
{
	if (params->key == IPC_PRIVATE)
		return ipcget_new(ns, ids, ops, params);
	else
		return ipcget_public(ns, ids, ops, params);
}

/**
 * ipc_update_perm - update the permissions of an ipc object
 * @in:  the permission given as input.
 * @out: the permission of the ipc to set.
 */
int ipc_update_perm(struct ipc64_perm *in, struct kern_ipc_perm *out)
{
	kuid_t uid = make_kuid(current_user_ns(), in->uid);
	kgid_t gid = make_kgid(current_user_ns(), in->gid);
	if (!uid_valid(uid) || !gid_valid(gid))
		return -EINVAL;

	out->uid = uid;
	out->gid = gid;
	out->mode = (out->mode & ~S_IRWXUGO)
		| (in->mode & S_IRWXUGO);

	return 0;
}

/**
 * ipcctl_obtain_check - retrieve an ipc object and check permissions
 * @ns:  ipc namespace
 * @ids:  the table of ids where to look for the ipc
 * @id:   the id of the ipc to retrieve
 * @cmd:  the cmd to check
 * @perm: the permission to set
 * @extra_perm: one extra permission parameter used by msq
 *
 * This function does some common audit and permissions check for some IPC_XXX
 * cmd and is called from semctl_down, shmctl_down and msgctl_down.
 *
 * It:
 *   - retrieves the ipc object with the given id in the given table.
 *   - performs some audit and permission check, depending on the given cmd
 *   - returns a pointer to the ipc object or otherwise, the corresponding
 *     error.
 *
 * Call holding the both the rwsem and the rcu read lock.
 */
struct kern_ipc_perm *ipcctl_obtain_check(struct ipc_namespace *ns,
					struct ipc_ids *ids, int id, int cmd,
					struct ipc64_perm *perm, int extra_perm)
{
	kuid_t euid;
	int err = -EPERM;
	struct kern_ipc_perm *ipcp;

	ipcp = ipc_obtain_object_check(ids, id);
	if (IS_ERR(ipcp)) {
		err = PTR_ERR(ipcp);
		goto err;
	}

	audit_ipc_obj(ipcp);
	if (cmd == IPC_SET)
		audit_ipc_set_perm(extra_perm, perm->uid,
				   perm->gid, perm->mode);

	euid = current_euid();
	if (uid_eq(euid, ipcp->cuid) || uid_eq(euid, ipcp->uid)  ||
	    ns_capable(ns->user_ns, CAP_SYS_ADMIN))
		return ipcp; /* successful lookup */
err:
	return ERR_PTR(err);
}

#ifdef CONFIG_ARCH_WANT_IPC_PARSE_VERSION


/**
 * ipc_parse_version - ipc call version
 * @cmd: pointer to command
 *
 * Return IPC_64 for new style IPC and IPC_OLD for old style IPC.
 * The @cmd value is turned from an encoding command and version into
 * just the command code.
 */
int ipc_parse_version(int *cmd)
{
	if (*cmd & IPC_64) {
		*cmd ^= IPC_64;
		return IPC_64;
	} else {
		return IPC_OLD;
	}
}

#endif /* CONFIG_ARCH_WANT_IPC_PARSE_VERSION */

#ifdef CONFIG_PROC_FS
struct ipc_proc_iter {
	struct ipc_namespace *ns;
	struct pid_namespace *pid_ns;
	struct ipc_proc_iface *iface;
};

struct pid_namespace *ipc_seq_pid_ns(struct seq_file *s)
{
	struct ipc_proc_iter *iter = s->private;
	return iter->pid_ns;
}

/*
 * This routine locks the ipc structure found at least at position pos.
 */
static struct kern_ipc_perm *sysvipc_find_ipc(struct ipc_ids *ids, loff_t pos,
					      loff_t *new_pos)
{
	struct kern_ipc_perm *ipc;
	int total, id;

	total = 0;
	for (id = 0; id < pos && total < ids->in_use; id++) {
		ipc = idr_find(&ids->ipcs_idr, id);
		if (ipc != NULL)
			total++;
	}

	if (total >= ids->in_use)
		return NULL;

	for (; pos < ipc_mni; pos++) {
		ipc = idr_find(&ids->ipcs_idr, pos);
		if (ipc != NULL) {
			*new_pos = pos + 1;
			rcu_read_lock();
			ipc_lock_object(ipc);
			return ipc;
		}
	}

	/* Out of range - return NULL to terminate iteration */
	return NULL;
}

static void *sysvipc_proc_next(struct seq_file *s, void *it, loff_t *pos)
{
	struct ipc_proc_iter *iter = s->private;
	struct ipc_proc_iface *iface = iter->iface;
	struct kern_ipc_perm *ipc = it;

	/* If we had an ipc id locked before, unlock it */
	if (ipc && ipc != SEQ_START_TOKEN)
		ipc_unlock(ipc);

	return sysvipc_find_ipc(&iter->ns->ids[iface->ids], *pos, pos);
}

/*
 * File positions: pos 0 -> header, pos n -> ipc id = n - 1.
 * SeqFile iterator: iterator value locked ipc pointer or SEQ_TOKEN_START.
 */
static void *sysvipc_proc_start(struct seq_file *s, loff_t *pos)
{
	struct ipc_proc_iter *iter = s->private;
	struct ipc_proc_iface *iface = iter->iface;
	struct ipc_ids *ids;

	ids = &iter->ns->ids[iface->ids];

	/*
	 * Take the lock - this will be released by the corresponding
	 * call to stop().
	 */
	down_read(&ids->rwsem);

	/* pos < 0 is invalid */
	if (*pos < 0)
		return NULL;

	/* pos == 0 means header */
	if (*pos == 0)
		return SEQ_START_TOKEN;

	/* Find the (pos-1)th ipc */
	return sysvipc_find_ipc(ids, *pos - 1, pos);
}

static void sysvipc_proc_stop(struct seq_file *s, void *it)
{
	struct kern_ipc_perm *ipc = it;
	struct ipc_proc_iter *iter = s->private;
	struct ipc_proc_iface *iface = iter->iface;
	struct ipc_ids *ids;

	/* If we had a locked structure, release it */
	if (ipc && ipc != SEQ_START_TOKEN)
		ipc_unlock(ipc);

	ids = &iter->ns->ids[iface->ids];
	/* Release the lock we took in start() */
	up_read(&ids->rwsem);
}

static int sysvipc_proc_show(struct seq_file *s, void *it)
{
	struct ipc_proc_iter *iter = s->private;
	struct ipc_proc_iface *iface = iter->iface;

	if (it == SEQ_START_TOKEN) {
		seq_puts(s, iface->header);
		return 0;
	}

	return iface->show(s, it);
}

static const struct seq_operations sysvipc_proc_seqops = {
	.start = sysvipc_proc_start,
	.stop  = sysvipc_proc_stop,
	.next  = sysvipc_proc_next,
	.show  = sysvipc_proc_show,
};

static int sysvipc_proc_open(struct inode *inode, struct file *file)
{
	struct ipc_proc_iter *iter;

	iter = __seq_open_private(file, &sysvipc_proc_seqops, sizeof(*iter));
	if (!iter)
		return -ENOMEM;

	iter->iface = PDE_DATA(inode);
	iter->ns    = get_ipc_ns(current->nsproxy->ipc_ns);
	iter->pid_ns = get_pid_ns(task_active_pid_ns(current));

	return 0;
}

static int sysvipc_proc_release(struct inode *inode, struct file *file)
{
	struct seq_file *seq = file->private_data;
	struct ipc_proc_iter *iter = seq->private;
	put_ipc_ns(iter->ns);
	put_pid_ns(iter->pid_ns);
	return seq_release_private(inode, file);
}

static const struct proc_ops sysvipc_proc_ops = {
	.proc_flags	= PROC_ENTRY_PERMANENT,
	.proc_open	= sysvipc_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= sysvipc_proc_release,
};
#endif /* CONFIG_PROC_FS */
};


/****************************************************************************************************/

struct request_key
{
	#define key_negative_timeout	60	/* default timeout on a negative key's existence */

static struct key *check_cached_key(struct keyring_search_context *ctx)
{
#ifdef CONFIG_KEYS_REQUEST_CACHE
	struct key *key = current->cached_requested_key;

	if (key &&
	    ctx->match_data.cmp(key, &ctx->match_data) &&
	    !(key->flags & ((1 << KEY_FLAG_INVALIDATED) |
			    (1 << KEY_FLAG_REVOKED))))
		return key_get(key);
#endif
	return NULL;
}

static void cache_requested_key(struct key *key)
{
#ifdef CONFIG_KEYS_REQUEST_CACHE
	struct task_struct *t = current;

	key_put(t->cached_requested_key);
	t->cached_requested_key = key_get(key);
	set_tsk_thread_flag(t, TIF_NOTIFY_RESUME);
#endif
}

/**
 * complete_request_key - Complete the construction of a key.
 * @authkey: The authorisation key.
 * @error: The success or failute of the construction.
 *
 * Complete the attempt to construct a key.  The key will be negated
 * if an error is indicated.  The authorisation key will be revoked
 * unconditionally.
 */
void complete_request_key(struct key *authkey, int error)
{
	struct request_key_auth *rka = get_request_key_auth(authkey);
	struct key *key = rka->target_key;

	kenter("%d{%d},%d", authkey->serial, key->serial, error);

	if (error < 0)
		key_negate_and_link(key, key_negative_timeout, NULL, authkey);
	else
		key_revoke(authkey);
}
EXPORT_SYMBOL(complete_request_key);

/*
 * Initialise a usermode helper that is going to have a specific session
 * keyring.
 *
 * This is called in context of freshly forked kthread before kernel_execve(),
 * so we can simply install the desired session_keyring at this point.
 */
static int umh_keys_init(struct subprocess_info *info, struct cred *cred)
{
	struct key *keyring = info->data;

	return install_session_keyring_to_cred(cred, keyring);
}

/*
 * Clean up a usermode helper with session keyring.
 */
static void umh_keys_cleanup(struct subprocess_info *info)
{
	struct key *keyring = info->data;
	key_put(keyring);
}

/*
 * Call a usermode helper with a specific session keyring.
 */
static int call_usermodehelper_keys(const char *path, char **argv, char **envp,
					struct key *session_keyring, int wait)
{
	struct subprocess_info *info;

	info = call_usermodehelper_setup(path, argv, envp, GFP_KERNEL,
					  umh_keys_init, umh_keys_cleanup,
					  session_keyring);
	if (!info)
		return -ENOMEM;

	key_get(session_keyring);
	return call_usermodehelper_exec(info, wait);
}

/*
 * Request userspace finish the construction of a key
 * - execute "/sbin/request-key <op> <key> <uid> <gid> <keyring> <keyring> <keyring>"
 */
static int call_sbin_request_key(struct key *authkey, void *aux)
{
	static char const request_key[] = "/sbin/request-key";
	struct request_key_auth *rka = get_request_key_auth(authkey);
	const struct cred *cred = current_cred();
	key_serial_t prkey, sskey;
	struct key *key = rka->target_key, *keyring, *session, *user_session;
	char *argv[9], *envp[3], uid_str[12], gid_str[12];
	char key_str[12], keyring_str[3][12];
	char desc[20];
	int ret, i;

	kenter("{%d},{%d},%s", key->serial, authkey->serial, rka->op);

	ret = look_up_user_keyrings(NULL, &user_session);
	if (ret < 0)
		goto error_us;

	/* allocate a new session keyring */
	sprintf(desc, "_req.%u", key->serial);

	cred = get_current_cred();
	keyring = keyring_alloc(desc, cred->fsuid, cred->fsgid, cred,
				KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ,
				KEY_ALLOC_QUOTA_OVERRUN, NULL, NULL);
	put_cred(cred);
	if (IS_ERR(keyring)) {
		ret = PTR_ERR(keyring);
		goto error_alloc;
	}

	/* attach the auth key to the session keyring */
	ret = key_link(keyring, authkey);
	if (ret < 0)
		goto error_link;

	/* record the UID and GID */
	sprintf(uid_str, "%d", from_kuid(&init_user_ns, cred->fsuid));
	sprintf(gid_str, "%d", from_kgid(&init_user_ns, cred->fsgid));

	/* we say which key is under construction */
	sprintf(key_str, "%d", key->serial);

	/* we specify the process's default keyrings */
	sprintf(keyring_str[0], "%d",
		cred->thread_keyring ? cred->thread_keyring->serial : 0);

	prkey = 0;
	if (cred->process_keyring)
		prkey = cred->process_keyring->serial;
	sprintf(keyring_str[1], "%d", prkey);

	session = cred->session_keyring;
	if (!session)
		session = user_session;
	sskey = session->serial;

	sprintf(keyring_str[2], "%d", sskey);

	/* set up a minimal environment */
	i = 0;
	envp[i++] = "HOME=/";
	envp[i++] = "PATH=/sbin:/bin:/usr/sbin:/usr/bin";
	envp[i] = NULL;

	/* set up the argument list */
	i = 0;
	argv[i++] = (char *)request_key;
	argv[i++] = (char *)rka->op;
	argv[i++] = key_str;
	argv[i++] = uid_str;
	argv[i++] = gid_str;
	argv[i++] = keyring_str[0];
	argv[i++] = keyring_str[1];
	argv[i++] = keyring_str[2];
	argv[i] = NULL;

	/* do it */
	ret = call_usermodehelper_keys(request_key, argv, envp, keyring,
				       UMH_WAIT_PROC);
	kdebug("usermode -> 0x%x", ret);
	if (ret >= 0) {
		/* ret is the exit/wait code */
		if (test_bit(KEY_FLAG_USER_CONSTRUCT, &key->flags) ||
		    key_validate(key) < 0)
			ret = -ENOKEY;
		else
			/* ignore any errors from userspace if the key was
			 * instantiated */
			ret = 0;
	}

error_link:
	key_put(keyring);

error_alloc:
	key_put(user_session);
error_us:
	complete_request_key(authkey, ret);
	kleave(" = %d", ret);
	return ret;
}

/*
 * Call out to userspace for key construction.
 *
 * Program failure is ignored in favour of key status.
 */
static int construct_key(struct key *key, const void *callout_info,
			 size_t callout_len, void *aux,
			 struct key *dest_keyring)
{
	request_key_actor_t actor;
	struct key *authkey;
	int ret;

	kenter("%d,%p,%zu,%p", key->serial, callout_info, callout_len, aux);

	/* allocate an authorisation key */
	authkey = request_key_auth_new(key, "create", callout_info, callout_len,
				       dest_keyring);
	if (IS_ERR(authkey))
		return PTR_ERR(authkey);

	/* Make the call */
	actor = call_sbin_request_key;
	if (key->type->request_key)
		actor = key->type->request_key;

	ret = actor(authkey, aux);

	/* check that the actor called complete_request_key() prior to
	 * returning an error */
	WARN_ON(ret < 0 &&
		!test_bit(KEY_FLAG_INVALIDATED, &authkey->flags));

	key_put(authkey);
	kleave(" = %d", ret);
	return ret;
}

/*
 * Get the appropriate destination keyring for the request.
 *
 * The keyring selected is returned with an extra reference upon it which the
 * caller must release.
 */
static int construct_get_dest_keyring(struct key **_dest_keyring)
{
	struct request_key_auth *rka;
	const struct cred *cred = current_cred();
	struct key *dest_keyring = *_dest_keyring, *authkey;
	int ret;

	kenter("%p", dest_keyring);

	/* find the appropriate keyring */
	if (dest_keyring) {
		/* the caller supplied one */
		key_get(dest_keyring);
	} else {
		bool do_perm_check = true;

		/* use a default keyring; falling through the cases until we
		 * find one that we actually have */
		switch (cred->jit_keyring) {
		case KEY_REQKEY_DEFL_DEFAULT:
		case KEY_REQKEY_DEFL_REQUESTOR_KEYRING:
			if (cred->request_key_auth) {
				authkey = cred->request_key_auth;
				down_read(&authkey->sem);
				rka = get_request_key_auth(authkey);
				if (!test_bit(KEY_FLAG_REVOKED,
					      &authkey->flags))
					dest_keyring =
						key_get(rka->dest_keyring);
				up_read(&authkey->sem);
				if (dest_keyring) {
					do_perm_check = false;
					break;
				}
			}

			/* fall through */
		case KEY_REQKEY_DEFL_THREAD_KEYRING:
			dest_keyring = key_get(cred->thread_keyring);
			if (dest_keyring)
				break;

			/* fall through */
		case KEY_REQKEY_DEFL_PROCESS_KEYRING:
			dest_keyring = key_get(cred->process_keyring);
			if (dest_keyring)
				break;

			/* fall through */
		case KEY_REQKEY_DEFL_SESSION_KEYRING:
			dest_keyring = key_get(cred->session_keyring);

			if (dest_keyring)
				break;

			/* fall through */
		case KEY_REQKEY_DEFL_USER_SESSION_KEYRING:
			ret = look_up_user_keyrings(NULL, &dest_keyring);
			if (ret < 0)
				return ret;
			break;

		case KEY_REQKEY_DEFL_USER_KEYRING:
			ret = look_up_user_keyrings(&dest_keyring, NULL);
			if (ret < 0)
				return ret;
			break;

		case KEY_REQKEY_DEFL_GROUP_KEYRING:
		default:
			BUG();
		}

		/*
		 * Require Write permission on the keyring.  This is essential
		 * because the default keyring may be the session keyring, and
		 * joining a keyring only requires Search permission.
		 *
		 * However, this check is skipped for the "requestor keyring" so
		 * that /sbin/request-key can itself use request_key() to add
		 * keys to the original requestor's destination keyring.
		 */
		if (dest_keyring && do_perm_check) {
			ret = key_permission(make_key_ref(dest_keyring, 1),
					     KEY_NEED_WRITE);
			if (ret) {
				key_put(dest_keyring);
				return ret;
			}
		}
	}

	*_dest_keyring = dest_keyring;
	kleave(" [dk %d]", key_serial(dest_keyring));
	return 0;
}

/*
 * Allocate a new key in under-construction state and attempt to link it in to
 * the requested keyring.
 *
 * May return a key that's already under construction instead if there was a
 * race between two thread calling request_key().
 */
static int construct_alloc_key(struct keyring_search_context *ctx,
			       struct key *dest_keyring,
			       unsigned long flags,
			       struct key_user *user,
			       struct key **_key)
{
	struct assoc_array_edit *edit = NULL;
	struct key *key;
	key_perm_t perm;
	key_ref_t key_ref;
	int ret;

	kenter("%s,%s,,,",
	       ctx->index_key.type->name, ctx->index_key.description);

	*_key = NULL;
	mutex_lock(&user->cons_lock);

	perm = KEY_POS_VIEW | KEY_POS_SEARCH | KEY_POS_LINK | KEY_POS_SETATTR;
	perm |= KEY_USR_VIEW;
	if (ctx->index_key.type->read)
		perm |= KEY_POS_READ;
	if (ctx->index_key.type == &key_type_keyring ||
	    ctx->index_key.type->update)
		perm |= KEY_POS_WRITE;

	key = key_alloc(ctx->index_key.type, ctx->index_key.description,
			ctx->cred->fsuid, ctx->cred->fsgid, ctx->cred,
			perm, flags, NULL);
	if (IS_ERR(key))
		goto alloc_failed;

	set_bit(KEY_FLAG_USER_CONSTRUCT, &key->flags);

	if (dest_keyring) {
		ret = __key_link_lock(dest_keyring, &ctx->index_key);
		if (ret < 0)
			goto link_lock_failed;
		ret = __key_link_begin(dest_keyring, &ctx->index_key, &edit);
		if (ret < 0)
			goto link_prealloc_failed;
	}

	/* attach the key to the destination keyring under lock, but we do need
	 * to do another check just in case someone beat us to it whilst we
	 * waited for locks */
	mutex_lock(&key_construction_mutex);

	rcu_read_lock();
	key_ref = search_process_keyrings_rcu(ctx);
	rcu_read_unlock();
	if (!IS_ERR(key_ref))
		goto key_already_present;

	if (dest_keyring)
		__key_link(key, &edit);

	mutex_unlock(&key_construction_mutex);
	if (dest_keyring)
		__key_link_end(dest_keyring, &ctx->index_key, edit);
	mutex_unlock(&user->cons_lock);
	*_key = key;
	kleave(" = 0 [%d]", key_serial(key));
	return 0;

	/* the key is now present - we tell the caller that we found it by
	 * returning -EINPROGRESS  */
key_already_present:
	key_put(key);
	mutex_unlock(&key_construction_mutex);
	key = key_ref_to_ptr(key_ref);
	if (dest_keyring) {
		ret = __key_link_check_live_key(dest_keyring, key);
		if (ret == 0)
			__key_link(key, &edit);
		__key_link_end(dest_keyring, &ctx->index_key, edit);
		if (ret < 0)
			goto link_check_failed;
	}
	mutex_unlock(&user->cons_lock);
	*_key = key;
	kleave(" = -EINPROGRESS [%d]", key_serial(key));
	return -EINPROGRESS;

link_check_failed:
	mutex_unlock(&user->cons_lock);
	key_put(key);
	kleave(" = %d [linkcheck]", ret);
	return ret;

link_prealloc_failed:
	__key_link_end(dest_keyring, &ctx->index_key, edit);
link_lock_failed:
	mutex_unlock(&user->cons_lock);
	key_put(key);
	kleave(" = %d [prelink]", ret);
	return ret;

alloc_failed:
	mutex_unlock(&user->cons_lock);
	kleave(" = %ld", PTR_ERR(key));
	return PTR_ERR(key);
}

/*
 * Commence key construction.
 */
static struct key *construct_key_and_link(struct keyring_search_context *ctx,
					  const char *callout_info,
					  size_t callout_len,
					  void *aux,
					  struct key *dest_keyring,
					  unsigned long flags)
{
	struct key_user *user;
	struct key *key;
	int ret;

	kenter("");

	if (ctx->index_key.type == &key_type_keyring)
		return ERR_PTR(-EPERM);

	ret = construct_get_dest_keyring(&dest_keyring);
	if (ret)
		goto error;

	user = key_user_lookup(current_fsuid());
	if (!user) {
		ret = -ENOMEM;
		goto error_put_dest_keyring;
	}

	ret = construct_alloc_key(ctx, dest_keyring, flags, user, &key);
	key_user_put(user);

	if (ret == 0) {
		ret = construct_key(key, callout_info, callout_len, aux,
				    dest_keyring);
		if (ret < 0) {
			kdebug("cons failed");
			goto construction_failed;
		}
	} else if (ret == -EINPROGRESS) {
		ret = 0;
	} else {
		goto error_put_dest_keyring;
	}

	key_put(dest_keyring);
	kleave(" = key %d", key_serial(key));
	return key;

construction_failed:
	key_negate_and_link(key, key_negative_timeout, NULL, NULL);
	key_put(key);
error_put_dest_keyring:
	key_put(dest_keyring);
error:
	kleave(" = %d", ret);
	return ERR_PTR(ret);
}

/**
 * request_key_and_link - Request a key and cache it in a keyring.
 * @type: The type of key we want.
 * @description: The searchable description of the key.
 * @domain_tag: The domain in which the key operates.
 * @callout_info: The data to pass to the instantiation upcall (or NULL).
 * @callout_len: The length of callout_info.
 * @aux: Auxiliary data for the upcall.
 * @dest_keyring: Where to cache the key.
 * @flags: Flags to key_alloc().
 *
 * A key matching the specified criteria (type, description, domain_tag) is
 * searched for in the process's keyrings and returned with its usage count
 * incremented if found.  Otherwise, if callout_info is not NULL, a key will be
 * allocated and some service (probably in userspace) will be asked to
 * instantiate it.
 *
 * If successfully found or created, the key will be linked to the destination
 * keyring if one is provided.
 *
 * Returns a pointer to the key if successful; -EACCES, -ENOKEY, -EKEYREVOKED
 * or -EKEYEXPIRED if an inaccessible, negative, revoked or expired key was
 * found; -ENOKEY if no key was found and no @callout_info was given; -EDQUOT
 * if insufficient key quota was available to create a new key; or -ENOMEM if
 * insufficient memory was available.
 *
 * If the returned key was created, then it may still be under construction,
 * and wait_for_key_construction() should be used to wait for that to complete.
 */
struct key *request_key_and_link(struct key_type *type,
				 const char *description,
				 struct key_tag *domain_tag,
				 const void *callout_info,
				 size_t callout_len,
				 void *aux,
				 struct key *dest_keyring,
				 unsigned long flags)
{
	struct keyring_search_context ctx = {
		.index_key.type		= type,
		.index_key.domain_tag	= domain_tag,
		.index_key.description	= description,
		.index_key.desc_len	= strlen(description),
		.cred			= current_cred(),
		.match_data.cmp		= key_default_cmp,
		.match_data.raw_data	= description,
		.match_data.lookup_type	= KEYRING_SEARCH_LOOKUP_DIRECT,
		.flags			= (KEYRING_SEARCH_DO_STATE_CHECK |
					   KEYRING_SEARCH_SKIP_EXPIRED |
					   KEYRING_SEARCH_RECURSE),
	};
	struct key *key;
	key_ref_t key_ref;
	int ret;

	kenter("%s,%s,%p,%zu,%p,%p,%lx",
	       ctx.index_key.type->name, ctx.index_key.description,
	       callout_info, callout_len, aux, dest_keyring, flags);

	if (type->match_preparse) {
		ret = type->match_preparse(&ctx.match_data);
		if (ret < 0) {
			key = ERR_PTR(ret);
			goto error;
		}
	}

	key = check_cached_key(&ctx);
	if (key)
		goto error_free;

	/* search all the process keyrings for a key */
	rcu_read_lock();
	key_ref = search_process_keyrings_rcu(&ctx);
	rcu_read_unlock();

	if (!IS_ERR(key_ref)) {
		if (dest_keyring) {
			ret = key_task_permission(key_ref, current_cred(),
						  KEY_NEED_LINK);
			if (ret < 0) {
				key_ref_put(key_ref);
				key = ERR_PTR(ret);
				goto error_free;
			}
		}

		key = key_ref_to_ptr(key_ref);
		if (dest_keyring) {
			ret = key_link(dest_keyring, key);
			if (ret < 0) {
				key_put(key);
				key = ERR_PTR(ret);
				goto error_free;
			}
		}

		/* Only cache the key on immediate success */
		cache_requested_key(key);
	} else if (PTR_ERR(key_ref) != -EAGAIN) {
		key = ERR_CAST(key_ref);
	} else  {
		/* the search failed, but the keyrings were searchable, so we
		 * should consult userspace if we can */
		key = ERR_PTR(-ENOKEY);
		if (!callout_info)
			goto error_free;

		key = construct_key_and_link(&ctx, callout_info, callout_len,
					     aux, dest_keyring, flags);
	}

error_free:
	if (type->match_free)
		type->match_free(&ctx.match_data);
error:
	kleave(" = %p", key);
	return key;
}

/**
 * wait_for_key_construction - Wait for construction of a key to complete
 * @key: The key being waited for.
 * @intr: Whether to wait interruptibly.
 *
 * Wait for a key to finish being constructed.
 *
 * Returns 0 if successful; -ERESTARTSYS if the wait was interrupted; -ENOKEY
 * if the key was negated; or -EKEYREVOKED or -EKEYEXPIRED if the key was
 * revoked or expired.
 */
int wait_for_key_construction(struct key *key, bool intr)
{
	int ret;

	ret = wait_on_bit(&key->flags, KEY_FLAG_USER_CONSTRUCT,
			  intr ? TASK_INTERRUPTIBLE : TASK_UNINTERRUPTIBLE);
	if (ret)
		return -ERESTARTSYS;
	ret = key_read_state(key);
	if (ret < 0)
		return ret;
	return key_validate(key);
}
EXPORT_SYMBOL(wait_for_key_construction);

/**
 * request_key_tag - Request a key and wait for construction
 * @type: Type of key.
 * @description: The searchable description of the key.
 * @domain_tag: The domain in which the key operates.
 * @callout_info: The data to pass to the instantiation upcall (or NULL).
 *
 * As for request_key_and_link() except that it does not add the returned key
 * to a keyring if found, new keys are always allocated in the user's quota,
 * the callout_info must be a NUL-terminated string and no auxiliary data can
 * be passed.
 *
 * Furthermore, it then works as wait_for_key_construction() to wait for the
 * completion of keys undergoing construction with a non-interruptible wait.
 */
struct key *request_key_tag(struct key_type *type,
			    const char *description,
			    struct key_tag *domain_tag,
			    const char *callout_info)
{
	struct key *key;
	size_t callout_len = 0;
	int ret;

	if (callout_info)
		callout_len = strlen(callout_info);
	key = request_key_and_link(type, description, domain_tag,
				   callout_info, callout_len,
				   NULL, NULL, KEY_ALLOC_IN_QUOTA);
	if (!IS_ERR(key)) {
		ret = wait_for_key_construction(key, false);
		if (ret < 0) {
			key_put(key);
			return ERR_PTR(ret);
		}
	}
	return key;
}
EXPORT_SYMBOL(request_key_tag);

/**
 * request_key_with_auxdata - Request a key with auxiliary data for the upcaller
 * @type: The type of key we want.
 * @description: The searchable description of the key.
 * @domain_tag: The domain in which the key operates.
 * @callout_info: The data to pass to the instantiation upcall (or NULL).
 * @callout_len: The length of callout_info.
 * @aux: Auxiliary data for the upcall.
 *
 * As for request_key_and_link() except that it does not add the returned key
 * to a keyring if found and new keys are always allocated in the user's quota.
 *
 * Furthermore, it then works as wait_for_key_construction() to wait for the
 * completion of keys undergoing construction with a non-interruptible wait.
 */
struct key *request_key_with_auxdata(struct key_type *type,
				     const char *description,
				     struct key_tag *domain_tag,
				     const void *callout_info,
				     size_t callout_len,
				     void *aux)
{
	struct key *key;
	int ret;

	key = request_key_and_link(type, description, domain_tag,
				   callout_info, callout_len,
				   aux, NULL, KEY_ALLOC_IN_QUOTA);
	if (!IS_ERR(key)) {
		ret = wait_for_key_construction(key, false);
		if (ret < 0) {
			key_put(key);
			return ERR_PTR(ret);
		}
	}
	return key;
}
EXPORT_SYMBOL(request_key_with_auxdata);

/**
 * request_key_rcu - Request key from RCU-read-locked context
 * @type: The type of key we want.
 * @description: The name of the key we want.
 * @domain_tag: The domain in which the key operates.
 *
 * Request a key from a context that we may not sleep in (such as RCU-mode
 * pathwalk).  Keys under construction are ignored.
 *
 * Return a pointer to the found key if successful, -ENOKEY if we couldn't find
 * a key or some other error if the key found was unsuitable or inaccessible.
 */
struct key *request_key_rcu(struct key_type *type,
			    const char *description,
			    struct key_tag *domain_tag)
{
	struct keyring_search_context ctx = {
		.index_key.type		= type,
		.index_key.domain_tag	= domain_tag,
		.index_key.description	= description,
		.index_key.desc_len	= strlen(description),
		.cred			= current_cred(),
		.match_data.cmp		= key_default_cmp,
		.match_data.raw_data	= description,
		.match_data.lookup_type	= KEYRING_SEARCH_LOOKUP_DIRECT,
		.flags			= (KEYRING_SEARCH_DO_STATE_CHECK |
					   KEYRING_SEARCH_SKIP_EXPIRED),
	};
	struct key *key;
	key_ref_t key_ref;

	kenter("%s,%s", type->name, description);

	key = check_cached_key(&ctx);
	if (key)
		return key;

	/* search all the process keyrings for a key */
	key_ref = search_process_keyrings_rcu(&ctx);
	if (IS_ERR(key_ref)) {
		key = ERR_CAST(key_ref);
		if (PTR_ERR(key_ref) == -EAGAIN)
			key = ERR_PTR(-ENOKEY);
	} else {
		key = key_ref_to_ptr(key_ref);
		cache_requested_key(key);
	}

	kleave(" = %p", key);
	return key;
}
EXPORT_SYMBOL(request_key_rcu);

}

/****************************************************************************************************/

struct  process_key
{
	/* Session keyring create vs join semaphore */
static DEFINE_MUTEX(key_session_mutex);

/* The root user's tracking struct */
struct key_user root_key_user = {
	.usage		= REFCOUNT_INIT(3),
	.cons_lock	= __MUTEX_INITIALIZER(root_key_user.cons_lock),
	.lock		= __SPIN_LOCK_UNLOCKED(root_key_user.lock),
	.nkeys		= ATOMIC_INIT(2),
	.nikeys		= ATOMIC_INIT(2),
	.uid		= GLOBAL_ROOT_UID,
};

/*
 * Get or create a user register keyring.
 */
static struct key *get_user_register(struct user_namespace *user_ns)
{
	struct key *reg_keyring = READ_ONCE(user_ns->user_keyring_register);

	if (reg_keyring)
		return reg_keyring;

	down_write(&user_ns->keyring_sem);

	/* Make sure there's a register keyring.  It gets owned by the
	 * user_namespace's owner.
	 */
	reg_keyring = user_ns->user_keyring_register;
	if (!reg_keyring) {
		reg_keyring = keyring_alloc(".user_reg",
					    user_ns->owner, INVALID_GID,
					    &init_cred,
					    KEY_POS_WRITE | KEY_POS_SEARCH |
					    KEY_USR_VIEW | KEY_USR_READ,
					    0,
					    NULL, NULL);
		if (!IS_ERR(reg_keyring))
			smp_store_release(&user_ns->user_keyring_register,
					  reg_keyring);
	}

	up_write(&user_ns->keyring_sem);

	/* We don't return a ref since the keyring is pinned by the user_ns */
	return reg_keyring;
}

/*
 * Look up the user and user session keyrings for the current process's UID,
 * creating them if they don't exist.
 */
int look_up_user_keyrings(struct key **_user_keyring,
			  struct key **_user_session_keyring)
{
	const struct cred *cred = current_cred();
	struct user_namespace *user_ns = current_user_ns();
	struct key *reg_keyring, *uid_keyring, *session_keyring;
	key_perm_t user_keyring_perm;
	key_ref_t uid_keyring_r, session_keyring_r;
	uid_t uid = from_kuid(user_ns, cred->user->uid);
	char buf[20];
	int ret;

	user_keyring_perm = (KEY_POS_ALL & ~KEY_POS_SETATTR) | KEY_USR_ALL;

	kenter("%u", uid);

	reg_keyring = get_user_register(user_ns);
	if (IS_ERR(reg_keyring))
		return PTR_ERR(reg_keyring);

	down_write(&user_ns->keyring_sem);
	ret = 0;

	/* Get the user keyring.  Note that there may be one in existence
	 * already as it may have been pinned by a session, but the user_struct
	 * pointing to it may have been destroyed by setuid.
	 */
	snprintf(buf, sizeof(buf), "_uid.%u", uid);
	uid_keyring_r = keyring_search(make_key_ref(reg_keyring, true),
				       &key_type_keyring, buf, false);
	kdebug("_uid %p", uid_keyring_r);
	if (uid_keyring_r == ERR_PTR(-EAGAIN)) {
		uid_keyring = keyring_alloc(buf, cred->user->uid, INVALID_GID,
					    cred, user_keyring_perm,
					    KEY_ALLOC_UID_KEYRING |
					    KEY_ALLOC_IN_QUOTA,
					    NULL, reg_keyring);
		if (IS_ERR(uid_keyring)) {
			ret = PTR_ERR(uid_keyring);
			goto error;
		}
	} else if (IS_ERR(uid_keyring_r)) {
		ret = PTR_ERR(uid_keyring_r);
		goto error;
	} else {
		uid_keyring = key_ref_to_ptr(uid_keyring_r);
	}

	/* Get a default session keyring (which might also exist already) */
	snprintf(buf, sizeof(buf), "_uid_ses.%u", uid);
	session_keyring_r = keyring_search(make_key_ref(reg_keyring, true),
					   &key_type_keyring, buf, false);
	kdebug("_uid_ses %p", session_keyring_r);
	if (session_keyring_r == ERR_PTR(-EAGAIN)) {
		session_keyring = keyring_alloc(buf, cred->user->uid, INVALID_GID,
						cred, user_keyring_perm,
						KEY_ALLOC_UID_KEYRING |
						KEY_ALLOC_IN_QUOTA,
						NULL, NULL);
		if (IS_ERR(session_keyring)) {
			ret = PTR_ERR(session_keyring);
			goto error_release;
		}

		/* We install a link from the user session keyring to
		 * the user keyring.
		 */
		ret = key_link(session_keyring, uid_keyring);
		if (ret < 0)
			goto error_release_session;

		/* And only then link the user-session keyring to the
		 * register.
		 */
		ret = key_link(reg_keyring, session_keyring);
		if (ret < 0)
			goto error_release_session;
	} else if (IS_ERR(session_keyring_r)) {
		ret = PTR_ERR(session_keyring_r);
		goto error_release;
	} else {
		session_keyring = key_ref_to_ptr(session_keyring_r);
	}

	up_write(&user_ns->keyring_sem);

	if (_user_session_keyring)
		*_user_session_keyring = session_keyring;
	else
		key_put(session_keyring);
	if (_user_keyring)
		*_user_keyring = uid_keyring;
	else
		key_put(uid_keyring);
	kleave(" = 0");
	return 0;

error_release_session:
	key_put(session_keyring);
error_release:
	key_put(uid_keyring);
error:
	up_write(&user_ns->keyring_sem);
	kleave(" = %d", ret);
	return ret;
}

/*
 * Get the user session keyring if it exists, but don't create it if it
 * doesn't.
 */
struct key *get_user_session_keyring_rcu(const struct cred *cred)
{
	struct key *reg_keyring = READ_ONCE(cred->user_ns->user_keyring_register);
	key_ref_t session_keyring_r;
	char buf[20];

	struct keyring_search_context ctx = {
		.index_key.type		= &key_type_keyring,
		.index_key.description	= buf,
		.cred			= cred,
		.match_data.cmp		= key_default_cmp,
		.match_data.raw_data	= buf,
		.match_data.lookup_type	= KEYRING_SEARCH_LOOKUP_DIRECT,
		.flags			= KEYRING_SEARCH_DO_STATE_CHECK,
	};

	if (!reg_keyring)
		return NULL;

	ctx.index_key.desc_len = snprintf(buf, sizeof(buf), "_uid_ses.%u",
					  from_kuid(cred->user_ns,
						    cred->user->uid));

	session_keyring_r = keyring_search_rcu(make_key_ref(reg_keyring, true),
					       &ctx);
	if (IS_ERR(session_keyring_r))
		return NULL;
	return key_ref_to_ptr(session_keyring_r);
}

/*
 * Install a thread keyring to the given credentials struct if it didn't have
 * one already.  This is allowed to overrun the quota.
 *
 * Return: 0 if a thread keyring is now present; -errno on failure.
 */
int install_thread_keyring_to_cred(struct cred *new)
{
	struct key *keyring;

	if (new->thread_keyring)
		return 0;

	keyring = keyring_alloc("_tid", new->uid, new->gid, new,
				KEY_POS_ALL | KEY_USR_VIEW,
				KEY_ALLOC_QUOTA_OVERRUN,
				NULL, NULL);
	if (IS_ERR(keyring))
		return PTR_ERR(keyring);

	new->thread_keyring = keyring;
	return 0;
}

/*
 * Install a thread keyring to the current task if it didn't have one already.
 *
 * Return: 0 if a thread keyring is now present; -errno on failure.
 */
static int install_thread_keyring(void)
{
	struct cred *new;
	int ret;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	ret = install_thread_keyring_to_cred(new);
	if (ret < 0) {
		abort_creds(new);
		return ret;
	}

	return commit_creds(new);
}

/*
 * Install a process keyring to the given credentials struct if it didn't have
 * one already.  This is allowed to overrun the quota.
 *
 * Return: 0 if a process keyring is now present; -errno on failure.
 */
int install_process_keyring_to_cred(struct cred *new)
{
	struct key *keyring;

	if (new->process_keyring)
		return 0;

	keyring = keyring_alloc("_pid", new->uid, new->gid, new,
				KEY_POS_ALL | KEY_USR_VIEW,
				KEY_ALLOC_QUOTA_OVERRUN,
				NULL, NULL);
	if (IS_ERR(keyring))
		return PTR_ERR(keyring);

	new->process_keyring = keyring;
	return 0;
}

/*
 * Install a process keyring to the current task if it didn't have one already.
 *
 * Return: 0 if a process keyring is now present; -errno on failure.
 */
static int install_process_keyring(void)
{
	struct cred *new;
	int ret;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	ret = install_process_keyring_to_cred(new);
	if (ret < 0) {
		abort_creds(new);
		return ret;
	}

	return commit_creds(new);
}

/*
 * Install the given keyring as the session keyring of the given credentials
 * struct, replacing the existing one if any.  If the given keyring is NULL,
 * then install a new anonymous session keyring.
 * @cred can not be in use by any task yet.
 *
 * Return: 0 on success; -errno on failure.
 */
int install_session_keyring_to_cred(struct cred *cred, struct key *keyring)
{
	unsigned long flags;
	struct key *old;

	might_sleep();

	/* create an empty session keyring */
	if (!keyring) {
		flags = KEY_ALLOC_QUOTA_OVERRUN;
		if (cred->session_keyring)
			flags = KEY_ALLOC_IN_QUOTA;

		keyring = keyring_alloc("_ses", cred->uid, cred->gid, cred,
					KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ,
					flags, NULL, NULL);
		if (IS_ERR(keyring))
			return PTR_ERR(keyring);
	} else {
		__key_get(keyring);
	}

	/* install the keyring */
	old = cred->session_keyring;
	cred->session_keyring = keyring;

	if (old)
		key_put(old);

	return 0;
}

/*
 * Install the given keyring as the session keyring of the current task,
 * replacing the existing one if any.  If the given keyring is NULL, then
 * install a new anonymous session keyring.
 *
 * Return: 0 on success; -errno on failure.
 */
static int install_session_keyring(struct key *keyring)
{
	struct cred *new;
	int ret;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;

	ret = install_session_keyring_to_cred(new, keyring);
	if (ret < 0) {
		abort_creds(new);
		return ret;
	}

	return commit_creds(new);
}

/*
 * Handle the fsuid changing.
 */
void key_fsuid_changed(struct cred *new_cred)
{
	/* update the ownership of the thread keyring */
	if (new_cred->thread_keyring) {
		down_write(&new_cred->thread_keyring->sem);
		new_cred->thread_keyring->uid = new_cred->fsuid;
		up_write(&new_cred->thread_keyring->sem);
	}
}

/*
 * Handle the fsgid changing.
 */
void key_fsgid_changed(struct cred *new_cred)
{
	/* update the ownership of the thread keyring */
	if (new_cred->thread_keyring) {
		down_write(&new_cred->thread_keyring->sem);
		new_cred->thread_keyring->gid = new_cred->fsgid;
		up_write(&new_cred->thread_keyring->sem);
	}
}

/*
 * Search the process keyrings attached to the supplied cred for the first
 * matching key under RCU conditions (the caller must be holding the RCU read
 * lock).
 *
 * The search criteria are the type and the match function.  The description is
 * given to the match function as a parameter, but doesn't otherwise influence
 * the search.  Typically the match function will compare the description
 * parameter to the key's description.
 *
 * This can only search keyrings that grant Search permission to the supplied
 * credentials.  Keyrings linked to searched keyrings will also be searched if
 * they grant Search permission too.  Keys can only be found if they grant
 * Search permission to the credentials.
 *
 * Returns a pointer to the key with the key usage count incremented if
 * successful, -EAGAIN if we didn't find any matching key or -ENOKEY if we only
 * matched negative keys.
 *
 * In the case of a successful return, the possession attribute is set on the
 * returned key reference.
 */
key_ref_t search_cred_keyrings_rcu(struct keyring_search_context *ctx)
{
	struct key *user_session;
	key_ref_t key_ref, ret, err;
	const struct cred *cred = ctx->cred;

	/* we want to return -EAGAIN or -ENOKEY if any of the keyrings were
	 * searchable, but we failed to find a key or we found a negative key;
	 * otherwise we want to return a sample error (probably -EACCES) if
	 * none of the keyrings were searchable
	 *
	 * in terms of priority: success > -ENOKEY > -EAGAIN > other error
	 */
	key_ref = NULL;
	ret = NULL;
	err = ERR_PTR(-EAGAIN);

	/* search the thread keyring first */
	if (cred->thread_keyring) {
		key_ref = keyring_search_rcu(
			make_key_ref(cred->thread_keyring, 1), ctx);
		if (!IS_ERR(key_ref))
			goto found;

		switch (PTR_ERR(key_ref)) {
		case -EAGAIN: /* no key */
		case -ENOKEY: /* negative key */
			ret = key_ref;
			break;
		default:
			err = key_ref;
			break;
		}
	}

	/* search the process keyring second */
	if (cred->process_keyring) {
		key_ref = keyring_search_rcu(
			make_key_ref(cred->process_keyring, 1), ctx);
		if (!IS_ERR(key_ref))
			goto found;

		switch (PTR_ERR(key_ref)) {
		case -EAGAIN: /* no key */
			if (ret)
				break;
			/* fall through */
		case -ENOKEY: /* negative key */
			ret = key_ref;
			break;
		default:
			err = key_ref;
			break;
		}
	}

	/* search the session keyring */
	if (cred->session_keyring) {
		key_ref = keyring_search_rcu(
			make_key_ref(cred->session_keyring, 1), ctx);

		if (!IS_ERR(key_ref))
			goto found;

		switch (PTR_ERR(key_ref)) {
		case -EAGAIN: /* no key */
			if (ret)
				break;
			/* fall through */
		case -ENOKEY: /* negative key */
			ret = key_ref;
			break;
		default:
			err = key_ref;
			break;
		}
	}
	/* or search the user-session keyring */
	else if ((user_session = get_user_session_keyring_rcu(cred))) {
		key_ref = keyring_search_rcu(make_key_ref(user_session, 1),
					     ctx);
		key_put(user_session);

		if (!IS_ERR(key_ref))
			goto found;

		switch (PTR_ERR(key_ref)) {
		case -EAGAIN: /* no key */
			if (ret)
				break;
			/* fall through */
		case -ENOKEY: /* negative key */
			ret = key_ref;
			break;
		default:
			err = key_ref;
			break;
		}
	}

	/* no key - decide on the error we're going to go for */
	key_ref = ret ? ret : err;

found:
	return key_ref;
}

/*
 * Search the process keyrings attached to the supplied cred for the first
 * matching key in the manner of search_my_process_keyrings(), but also search
 * the keys attached to the assumed authorisation key using its credentials if
 * one is available.
 *
 * The caller must be holding the RCU read lock.
 *
 * Return same as search_cred_keyrings_rcu().
 */
key_ref_t search_process_keyrings_rcu(struct keyring_search_context *ctx)
{
	struct request_key_auth *rka;
	key_ref_t key_ref, ret = ERR_PTR(-EACCES), err;

	key_ref = search_cred_keyrings_rcu(ctx);
	if (!IS_ERR(key_ref))
		goto found;
	err = key_ref;

	/* if this process has an instantiation authorisation key, then we also
	 * search the keyrings of the process mentioned there
	 * - we don't permit access to request_key auth keys via this method
	 */
	if (ctx->cred->request_key_auth &&
	    ctx->cred == current_cred() &&
	    ctx->index_key.type != &key_type_request_key_auth
	    ) {
		const struct cred *cred = ctx->cred;

		if (key_validate(cred->request_key_auth) == 0) {
			rka = ctx->cred->request_key_auth->payload.data[0];

			//// was search_process_keyrings() [ie. recursive]
			ctx->cred = rka->cred;
			key_ref = search_cred_keyrings_rcu(ctx);
			ctx->cred = cred;

			if (!IS_ERR(key_ref))
				goto found;
			ret = key_ref;
		}
	}

	/* no key - decide on the error we're going to go for */
	if (err == ERR_PTR(-ENOKEY) || ret == ERR_PTR(-ENOKEY))
		key_ref = ERR_PTR(-ENOKEY);
	else if (err == ERR_PTR(-EACCES))
		key_ref = ret;
	else
		key_ref = err;

found:
	return key_ref;
}
/*
 * See if the key we're looking at is the target key.
 */
bool lookup_user_key_possessed(const struct key *key,
			       const struct key_match_data *match_data)
{
	return key == match_data->raw_data;
}

/*
 * Look up a key ID given us by userspace with a given permissions mask to get
 * the key it refers to.
 *
 * Flags can be passed to request that special keyrings be created if referred
 * to directly, to permit partially constructed keys to be found and to skip
 * validity and permission checks on the found key.
 *
 * Returns a pointer to the key with an incremented usage count if successful;
 * -EINVAL if the key ID is invalid; -ENOKEY if the key ID does not correspond
 * to a key or the best found key was a negative key; -EKEYREVOKED or
 * -EKEYEXPIRED if the best found key was revoked or expired; -EACCES if the
 * found key doesn't grant the requested permit or the LSM denied access to it;
 * or -ENOMEM if a special keyring couldn't be created.
 *
 * In the case of a successful return, the possession attribute is set on the
 * returned key reference.
 */
key_ref_t lookup_user_key(key_serial_t id, unsigned long lflags,
			  key_perm_t perm)
{
	struct keyring_search_context ctx = {
		.match_data.cmp		= lookup_user_key_possessed,
		.match_data.lookup_type	= KEYRING_SEARCH_LOOKUP_DIRECT,
		.flags			= (KEYRING_SEARCH_NO_STATE_CHECK |
					   KEYRING_SEARCH_RECURSE),
	};
	struct request_key_auth *rka;
	struct key *key, *user_session;
	key_ref_t key_ref, skey_ref;
	int ret;

try_again:
	ctx.cred = get_current_cred();
	key_ref = ERR_PTR(-ENOKEY);

	switch (id) {
	case KEY_SPEC_THREAD_KEYRING:
		if (!ctx.cred->thread_keyring) {
			if (!(lflags & KEY_LOOKUP_CREATE))
				goto error;

			ret = install_thread_keyring();
			if (ret < 0) {
				key_ref = ERR_PTR(ret);
				goto error;
			}
			goto reget_creds;
		}

		key = ctx.cred->thread_keyring;
		__key_get(key);
		key_ref = make_key_ref(key, 1);
		break;

	case KEY_SPEC_PROCESS_KEYRING:
		if (!ctx.cred->process_keyring) {
			if (!(lflags & KEY_LOOKUP_CREATE))
				goto error;

			ret = install_process_keyring();
			if (ret < 0) {
				key_ref = ERR_PTR(ret);
				goto error;
			}
			goto reget_creds;
		}

		key = ctx.cred->process_keyring;
		__key_get(key);
		key_ref = make_key_ref(key, 1);
		break;

	case KEY_SPEC_SESSION_KEYRING:
		if (!ctx.cred->session_keyring) {
			/* always install a session keyring upon access if one
			 * doesn't exist yet */
			ret = look_up_user_keyrings(NULL, &user_session);
			if (ret < 0)
				goto error;
			if (lflags & KEY_LOOKUP_CREATE)
				ret = join_session_keyring(NULL);
			else
				ret = install_session_keyring(user_session);

			key_put(user_session);
			if (ret < 0)
				goto error;
			goto reget_creds;
		} else if (test_bit(KEY_FLAG_UID_KEYRING,
				    &ctx.cred->session_keyring->flags) &&
			   lflags & KEY_LOOKUP_CREATE) {
			ret = join_session_keyring(NULL);
			if (ret < 0)
				goto error;
			goto reget_creds;
		}

		key = ctx.cred->session_keyring;
		__key_get(key);
		key_ref = make_key_ref(key, 1);
		break;

	case KEY_SPEC_USER_KEYRING:
		ret = look_up_user_keyrings(&key, NULL);
		if (ret < 0)
			goto error;
		key_ref = make_key_ref(key, 1);
		break;

	case KEY_SPEC_USER_SESSION_KEYRING:
		ret = look_up_user_keyrings(NULL, &key);
		if (ret < 0)
			goto error;
		key_ref = make_key_ref(key, 1);
		break;

	case KEY_SPEC_GROUP_KEYRING:
		/* group keyrings are not yet supported */
		key_ref = ERR_PTR(-EINVAL);
		goto error;

	case KEY_SPEC_REQKEY_AUTH_KEY:
		key = ctx.cred->request_key_auth;
		if (!key)
			goto error;

		__key_get(key);
		key_ref = make_key_ref(key, 1);
		break;

	case KEY_SPEC_REQUESTOR_KEYRING:
		if (!ctx.cred->request_key_auth)
			goto error;

		down_read(&ctx.cred->request_key_auth->sem);
		if (test_bit(KEY_FLAG_REVOKED,
			     &ctx.cred->request_key_auth->flags)) {
			key_ref = ERR_PTR(-EKEYREVOKED);
			key = NULL;
		} else {
			rka = ctx.cred->request_key_auth->payload.data[0];
			key = rka->dest_keyring;
			__key_get(key);
		}
		up_read(&ctx.cred->request_key_auth->sem);
		if (!key)
			goto error;
		key_ref = make_key_ref(key, 1);
		break;

	default:
		key_ref = ERR_PTR(-EINVAL);
		if (id < 1)
			goto error;

		key = key_lookup(id);
		if (IS_ERR(key)) {
			key_ref = ERR_CAST(key);
			goto error;
		}

		key_ref = make_key_ref(key, 0);

		/* check to see if we possess the key */
		ctx.index_key			= key->index_key;
		ctx.match_data.raw_data		= key;
		kdebug("check possessed");
		rcu_read_lock();
		skey_ref = search_process_keyrings_rcu(&ctx);
		rcu_read_unlock();
		kdebug("possessed=%p", skey_ref);

		if (!IS_ERR(skey_ref)) {
			key_put(key);
			key_ref = skey_ref;
		}

		break;
	}

	/* unlink does not use the nominated key in any way, so can skip all
	 * the permission checks as it is only concerned with the keyring */
	if (lflags & KEY_LOOKUP_FOR_UNLINK) {
		ret = 0;
		goto error;
	}

	if (!(lflags & KEY_LOOKUP_PARTIAL)) {
		ret = wait_for_key_construction(key, true);
		switch (ret) {
		case -ERESTARTSYS:
			goto invalid_key;
		default:
			if (perm)
				goto invalid_key;
		case 0:
			break;
		}
	} else if (perm) {
		ret = key_validate(key);
		if (ret < 0)
			goto invalid_key;
	}

	ret = -EIO;
	if (!(lflags & KEY_LOOKUP_PARTIAL) &&
	    key_read_state(key) == KEY_IS_UNINSTANTIATED)
		goto invalid_key;

	/* check the permissions */
	ret = key_task_permission(key_ref, ctx.cred, perm);
	if (ret < 0)
		goto invalid_key;

	key->last_used_at = ktime_get_real_seconds();

error:
	put_cred(ctx.cred);
	return key_ref;

invalid_key:
	key_ref_put(key_ref);
	key_ref = ERR_PTR(ret);
	goto error;

	/* if we attempted to install a keyring, then it may have caused new
	 * creds to be installed */
reget_creds:
	put_cred(ctx.cred);
	goto try_again;
}
EXPORT_SYMBOL(lookup_user_key);

/*
 * Join the named keyring as the session keyring if possible else attempt to
 * create a new one of that name and join that.
 *
 * If the name is NULL, an empty anonymous keyring will be installed as the
 * session keyring.
 *
 * Named session keyrings are joined with a semaphore held to prevent the
 * keyrings from going away whilst the attempt is made to going them and also
 * to prevent a race in creating compatible session keyrings.
 */
long join_session_keyring(const char *name)
{
	const struct cred *old;
	struct cred *new;
	struct key *keyring;
	long ret, serial;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	old = current_cred();

	/* if no name is provided, install an anonymous keyring */
	if (!name) {
		ret = install_session_keyring_to_cred(new, NULL);
		if (ret < 0)
			goto error;

		serial = new->session_keyring->serial;
		ret = commit_creds(new);
		if (ret == 0)
			ret = serial;
		goto okay;
	}

	/* allow the user to join or create a named keyring */
	mutex_lock(&key_session_mutex);

	/* look for an existing keyring of this name */
	keyring = find_keyring_by_name(name, false);
	if (PTR_ERR(keyring) == -ENOKEY) {
		/* not found - try and create a new one */
		keyring = keyring_alloc(
			name, old->uid, old->gid, old,
			KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ | KEY_USR_LINK,
			KEY_ALLOC_IN_QUOTA, NULL, NULL);
		if (IS_ERR(keyring)) {
			ret = PTR_ERR(keyring);
			goto error2;
		}
	} else if (IS_ERR(keyring)) {
		ret = PTR_ERR(keyring);
		goto error2;
	} else if (keyring == new->session_keyring) {
		ret = 0;
		goto error3;
	}

	/* we've got a keyring - now to install it */
	ret = install_session_keyring_to_cred(new, keyring);
	if (ret < 0)
		goto error3;

	commit_creds(new);
	mutex_unlock(&key_session_mutex);

	ret = keyring->serial;
	key_put(keyring);
okay:
	return ret;

error3:
	key_put(keyring);
error2:
	mutex_unlock(&key_session_mutex);
error:
	abort_creds(new);
	return ret;
}

/*
 * Replace a process's session keyring on behalf of one of its children when
 * the target  process is about to resume userspace execution.
 */
void key_change_session_keyring(struct callback_head *twork)
{
	const struct cred *old = current_cred();
	struct cred *new = container_of(twork, struct cred, rcu);

	if (unlikely(current->flags & PF_EXITING)) {
		put_cred(new);
		return;
	}

	new->  uid	= old->  uid;
	new-> euid	= old-> euid;
	new-> suid	= old-> suid;
	new->fsuid	= old->fsuid;
	new->  gid	= old->  gid;
	new-> egid	= old-> egid;
	new-> sgid	= old-> sgid;
	new->fsgid	= old->fsgid;
	new->user	= get_uid(old->user);
	new->user_ns	= get_user_ns(old->user_ns);
	new->group_info	= get_group_info(old->group_info);

	new->securebits	= old->securebits;
	new->cap_inheritable	= old->cap_inheritable;
	new->cap_permitted	= old->cap_permitted;
	new->cap_effective	= old->cap_effective;
	new->cap_ambient	= old->cap_ambient;
	new->cap_bset		= old->cap_bset;

	new->jit_keyring	= old->jit_keyring;
	new->thread_keyring	= key_get(old->thread_keyring);
	new->process_keyring	= key_get(old->process_keyring);

	security_transfer_creds(new, old);

	commit_creds(new);
}

/*
 * Make sure that root's user and user-session keyrings exist.
 */
static int __init init_root_keyring(void)
{
	return look_up_user_keyrings(NULL, NULL);
}

late_initcall(init_root_keyring);
};




/**************************************************************************************/

struct TABLE 
{
   int *a;
   int *head ; 
   int a = &head;  
   int array_simple [5] = {0,1,2,3,4,5};

};

struct CHAIR 
{  
  int *back;
  int head = &back;
  int array_simple [5] = {0,1,2,3,4,5};
};

struct DOOR
{
  int *c;
  int  back = null;
  int array_simple [5] = {0,1,2,3,4,5};
};


int main ()
{  
  
 
 return 0;

}

