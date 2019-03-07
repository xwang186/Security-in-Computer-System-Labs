/**********************************************
 * Listing 14.3: Simple netfilter module (telnetFilter.c)
 **********************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_bridge.h>  
#include <linux/init.h>
#include <linux/ip.h>
#include <linux/inet.h>
#include <linux/tcp.h>

static struct nf_hook_ops telnetFilterHook;

/* The implementation of the telnetFilter function is omitted here; 
   it was shown earlier in (*@Listing~\ref{firewall:code:telnetFilter}@*). */
unsigned int telnetFilter(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct iphdr *iph;
	struct tcphdr *tcph;

	iph = ip_hdr(skb);
	tcph = (void *)iph + iph->ihl * 4;
	//Rule1 not allow this PC to do telnet to 10.0.2.15. 
	bool rule1 = iph->protocol == IPPROTO_TCP && iph->daddr == in_aton("10.0.2.15") && tcph->dest == htons(23);
	//Rule2 not allow this PC to be done telnet by 10.0.2.15.
	bool rule2 = iph->protocol == IPPROTO_TCP && iph->daddr == in_aton("10.0.2.15") && tcph->source == htons(23);
	//Rule3 not allow this PC to visit SU websites.
	bool rule3 = iph->daddr == in_aton("128.230.18.198");
	/*Rule4 not allow this PC to ping PC 10,0.2.15 or any PC to ping this PC
	*telnetFilterHook.hooknum should be changed to NF_INET_PRE_ROUTING;
	*/
	bool rule4 = iph->protocol == IPPROTO_ICMP;
	/*Rule5 not allow the port 22.
	 *Port 22 is used as my ssh connection, so when the program works, the ssh client should be disconnected.
	 */
	bool rule5 = tcph->source == htons(22);

	bool task3_1 = iph->protocol == IPPROTO_TCP && tcph->dest == htons(23);
	bool task3_2 = iph->daddr == in_aton("128.230.18.198");
	if (task3_1 || task3_2) {
		printk(KERN_INFO "Dropping packets from %d.%d.%d.%d to %d.%d.%d.%d\n",
			((unsigned char *)&iph->saddr)[0],
			((unsigned char *)&iph->saddr)[1],
			((unsigned char *)&iph->saddr)[2],
			((unsigned char *)&iph->saddr)[3],
			((unsigned char *)&iph->daddr)[0],
			((unsigned char *)&iph->daddr)[1],
			((unsigned char *)&iph->daddr)[2],
			((unsigned char *)&iph->daddr)[3]);
		return NF_DROP;
	}
	else {
		return NF_ACCEPT;
	}
}
int setUpFilter(void) {
	printk(KERN_INFO "Registering a Telnet filter.\n");
	telnetFilterHook.hook = telnetFilter; //(*@\label{firewall:line:telnetHookfn}@*)
	telnetFilterHook.hooknum = NF_INET_POST_ROUTING; 
	telnetFilterHook.pf = PF_INET;
	telnetFilterHook.priority = NF_IP_PRI_FIRST;

	// Register the hook.
	nf_register_net_hook(&init_net, &telnetFilterHook);
	return 0;
}
void removeFilter(void) {
	printk(KERN_INFO "Telnet filter is being removed.\n");
	nf_unregister_net_hook(&init_net, &telnetFilterHook);
}

module_init(setUpFilter);
module_exit(removeFilter);