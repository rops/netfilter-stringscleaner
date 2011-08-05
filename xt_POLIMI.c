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

	struct tcphdr *tcph;
	struct iphdr *iph;
	struct udphdr *udph;
	const struct xt_polimi_info *info = par->targinfo;
	char * payload;
	int payload_size;
	int len = skb->len;
	int thlen;
	iph = ip_hdr(skb);	



	/*IF NOTFOUND*/
	struct ts_state state;
	memset(&state, 0, sizeof(struct ts_state));
	
	struct ts_config *conf = textsearch_prepare("bm", info->findString, info->find_len, GFP_ATOMIC, TS_AUTOLOAD);
	
	int pos = skb_find_text(skb,0, skb->len, conf, &state);
	if(pos==UINT_MAX){
		printk("[POLIMI] String Not found");
		return XT_CONTINUE;
	}

		
	if(skb_linearize(skb)<0){
		printk("[POLIMI] Not Linearizable \n");
		return NF_DROP;	
	}
	


	/*get payload*/
	switch (iph->protocol) {
		case IPPROTO_TCP:
			tcph = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
			int tcph_len = tcph->doff*4;
			thlen = tcph_len;
			payload = (char *)tcph + tcph_len;
			payload_size = ntohs(iph->tot_len)-ip_hdrlen(skb)-tcph_len;			
		break;
		
		case IPPROTO_UDP:
			/*get udp payload*/
			udph = (struct udphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
			int udph_len = sizeof(struct udphdr);
			thlen = udph_len;
			payload = (char *) udph + udph_len;
			payload_size = ntohs(udph->len) - udph_len;
			return XT_CONTINUE;/*UDP NOT YET SUPPORTED*/
			
		break;
	}
	
	
	/*replace string in payload*/
	char *payload_temp = kmalloc(sizeof(char)*payload_size,GFP_ATOMIC);
	memcpy(payload_temp,payload,payload_size*sizeof(char));
	char *newpayload = str_replace(payload_temp,info->findString,info->replString);
	int newpayload_size = strlen(newpayload);
	kfree(payload_temp);
	
	/*REPLACE SKBUFF DATA*/
	
	/*Get the header (L3 + L4)*/
	int header_len = payload - (char *) skb->data;
	char *header = kmalloc(sizeof(char)*header_len,GFP_KERNEL);
	memcpy(header,skb->data,header_len);
	
	/*Remove all data from skbuff*/
	skb_pull(skb,skb->len);
	/*Create new space in skbuff, with the right dimension*/
	char *data = skb_push(skb,newpayload_size+header_len);
	/*Copy the old header*/
	memcpy(data,header,header_len);
	/*Copy the new payload*/
	memcpy(data+header_len,newpayload,newpayload_size);
	
	
	/*fix ip tot length*/
	iph=ip_hdr(skb);
	iph->tot_len=htons(ip_hdrlen(skb)+thlen+newpayload_size);


	
	

	/*fix tcp/udp checksum*/
	switch (iph->protocol) {
		case IPPROTO_TCP:
			
			tcph = (struct tcphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
			tcph->check = 0;		
			tcph->check = tcp_v4_check(skb->len - 4*iph->ihl,iph->saddr, iph->daddr,csum_partial((char *)tcph, skb->len-4*iph->ihl,0));			
		break;
		
		case IPPROTO_UDP:
			udph = (struct udphdr *)(skb_network_header(skb) + ip_hdrlen(skb));
			udph->check = 0;
			/*udp checksum - NOT YET IMPLEMENTED*/
			
		break;
	}
	/* IP Checksum - not necessary
	iph->check = ip_fast_csum((unsigned char *) iph,iph->ihl);
	*/
	
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
