/*
   Netfilter target which handle string replacing
*/
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <linux/string.h>
#include <net/tcp.h>
#include <net/checksum.h>
//#include <linux/netfilter/xt_POLIMI.h>
#include "xt_POLIMI.h"
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_string.h>


MODULE_DESCRIPTION("Xtables: Polimi Project");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_POLIMI");
MODULE_AUTHOR("Daniele Rossetti");
MODULE_AUTHOR("Antonio Verlotta");
MODULE_AUTHOR("Marco Scoppetta");

/*Replace all occurences of substr with replacement and return the new string*/
char *str_replace ( const char *string, const char *substr, const char *replacement ){
  char *tok = NULL;
  char *newstr = NULL;
  char *oldstr = NULL;
  if ( substr == NULL || replacement == NULL ) return kstrdup (string,GFP_ATOMIC);
  newstr = kstrdup (string,GFP_ATOMIC);
  while ( (tok = strstr ( newstr, substr ))){
    oldstr = newstr;
    newstr = kmalloc ( strlen ( oldstr ) - strlen ( substr ) + strlen ( replacement ) + 1 ,GFP_ATOMIC);
    if ( newstr == NULL ){
      kfree (oldstr);
      return NULL;
    }
    memcpy ( newstr, oldstr, tok - oldstr );
    memcpy ( newstr + (tok - oldstr), replacement, strlen ( replacement ) );
    memcpy ( newstr + (tok - oldstr) + strlen( replacement ), tok + strlen ( substr ), strlen ( oldstr ) - strlen ( substr ) - ( tok - oldstr ) );
    memset ( newstr + strlen ( oldstr ) - strlen ( substr ) + strlen ( replacement ) , 0, 1 );
    kfree (oldstr);
  }
  return newstr;
}


static unsigned int
polimi_tg(struct sk_buff *skb, const struct xt_action_param *par)
{

	/*TCP Header*/
	struct tcphdr *tcph;
	/*IP Header*/
	struct iphdr *iph;
	/*UDP Header*/
	struct udphdr *udph;
	/*Parameters from user-space*/	
	const struct xt_polimi_info *info = par->targinfo;
	/*Packet Payload*/
	char * payload;
	/*Payload size*/
	int payload_size;
	/*Packet Size*/
	int len = skb->len;
	


	/*IF STRING IS NOT FOUND, PACKET IS ACCEPTED*/
	struct ts_state state;
	memset(&state, 0, sizeof(struct ts_state));
	
	struct ts_config *conf = textsearch_prepare("bm", info->findString, info->find_len, GFP_ATOMIC, TS_AUTOLOAD);
	
	int pos = skb_find_text(skb,0, skb->len, conf, &state);
	textsearch_destroy(conf);
	if(pos==UINT_MAX){
		printk("[POLIMI] String Not found \n");
		return XT_CONTINUE;
	}
	printk("[POLIMI] String found \n");
		
	if(skb_linearize(skb)<0){
		printk("[POLIMI] Not Linearizable \n");
		return NF_DROP;	
	}
	
	/*Get Ip Header*/
	iph = ip_hdr(skb);	


	/*Get payload*/
	switch (iph->protocol) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
			/*TCP header size*/
			int tcph_len = tcph->doff*4;
			/*get tcp payload */ 
			payload = (char *)tcph + tcph_len;
			payload_size = ntohs(iph->tot_len)-ip_hdrlen(skb)-tcph_len;			
		break;
		
		case IPPROTO_UDP:
			udph = (struct udphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
			/*UDP header size*/
			int udph_len = sizeof(struct udphdr);
			/*get udp payload*/			
			payload = (char *) udph + udph_len;
			payload_size = ntohs(udph->len) - udph_len;
			
		break;
	}
	
	
	/*Create new payload, replacing all occurrences of wanted string*/
	char *payload_temp = kmalloc(sizeof(char)*payload_size,GFP_ATOMIC);
	memcpy(payload_temp,payload,payload_size*sizeof(char));
	char *newpayload = str_replace(payload_temp,info->findString,info->replString);
	int newpayload_size = strlen(newpayload);
	kfree(payload_temp);
	
	
	/*Resize data space in buffer*/
	if(newpayload_size<payload_size){
		/*Make it smaller*/
		skb_trim(skb,skb->len-payload_size+newpayload_size);

	}else if(newpayload_size>payload_size){
		int delta = newpayload_size - payload_size;
		if (delta > skb_tailroom(skb)){
			printk("[POLIMI] Socket Buffer too small");
			return NF_DROP;
		}
		/*Make it bigger*/
		skb_put(skb,delta);
	}
	/*Copy the new payload*/
	memcpy(payload,newpayload,newpayload_size);
		
	/*fix ip tot length*/
	iph->tot_len=htons(ntohs(iph->tot_len)-payload_size+newpayload_size);

	/*fix checksum*/
	switch (iph->protocol) {
		case IPPROTO_TCP:
			
			tcph = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
			tcph->check = 0;	
			/*fix tcp checksum*/	
			tcph->check = tcp_v4_check(skb->len - 4*iph->ihl,iph->saddr, iph->daddr,csum_partial((char *)tcph, skb->len-4*iph->ihl,0));			
		break;
		
		case IPPROTO_UDP:
			udph = (struct udphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
			int udplen = ntohs(udph->len)-payload_size+newpayload_size;
			/*fix udp length*/
			udph->len = htons(udplen);
			/*fix udp checksum*/	
			udph->check = 0;
			udph->check = csum_tcpudp_magic(iph->saddr,iph->daddr,udplen, IPPROTO_UDP,csum_partial((char *)udph, udplen, 0));
			
			
		break;
	}
	/*IP Checksum*/
	iph->check = htons(0);
	iph->check = ip_fast_csum((unsigned char *) iph,iph->ihl);
	
	return XT_CONTINUE;
}



static struct xt_target polimi_tg_reg __read_mostly = {
	.name     = "POLIMI",
	.revision = 0,
	.family   = NFPROTO_UNSPEC,
	.target   = polimi_tg,
	.targetsize = sizeof(struct xt_polimi_info),
	.table    = "mangle",
	.me       = THIS_MODULE,
};

static int __init polimi_tg_init(void)
{
	return xt_register_target(&polimi_tg_reg);
}

static void __exit polimi_tg_exit(void)
{
	xt_unregister_target(&polimi_tg_reg);
}

module_init(polimi_tg_init);
module_exit(polimi_tg_exit);
