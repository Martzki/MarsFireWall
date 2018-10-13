#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/string.h>
#include <linux/kmod.h>
#include <linux/vmalloc.h>
#include <linux/workqueue.h>
#include <linux/spinlock.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/icmp.h>
#include <net/sock.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <linux/if_arp.h>
#include <linux/cdev.h>
#include <linux/fs.h>
#include <linux/time.h>
#include <linux/timex.h>
#include <linux/rtc.h>
#include <linux/if_ether.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/proc_fs.h>
#include <linux/netfilter_bridge.h>
#include <linux/ioctl.h>
#include <linux/unistd.h>
#include <linux/fcntl.h>
#include <net/ip.h>


// const variables  define
#define CDEV_NAME "MarsFireWall"
#define CLASS_NAME "fp"
#ifndef __FW_INCLUDE__
#define __FW_INCLUDE__

// actions defined
#define FW_ADD_RULE               0
#define FW_REMOVE_RULE            1
#define FW_CLEAR_RULE             2
#define FW_GET_NAT_LEN            3
#define FW_REFRESH_NAT_RULE       4
#define FW_START_NAT_TRANSFORM    5
#define FW_STOP_NAT_TRANSFORM     6
#define FW_GET_ACTIVELINK_LEN     7
#define FW_REFRESH_ACTIVELINK     8
#define FW_GET_LOG_LEN            9
#define FW_WRITE_LOG              10



// active link hash table size
#define ACTIVE_LINK_HASH_TABLE_SIZE 128

// NAT port range set
#define NAT_PORT_START   6655
#define NAT_PORT_END     7655


// filter rules struct define
typedef struct Rule{
  unsigned int sip;
  unsigned int dip;
  unsigned short sport;
  unsigned short dport;
  unsigned short protocol;
  unsigned short sMask;
  unsigned short dMask;
  bool accept;
  bool log;
  struct Rule *next;          //单链表的指针域
}Rule;

typedef struct HostInfo{
    __be32 ip;
    __be16 mask;
}HostInfo;

typedef struct NATRule {
        unsigned int ip;
	unsigned int natip;
        unsigned short port;
	unsigned short natport;
	struct NATRule *next;
}NATRule;

typedef struct mtime{
    int year;
    int month;
    int day;
    int hour;
    int min;
    int sec;
}mtime;

typedef struct ActiveLink {
    __be32 sip;
    __be32 dip;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    mtime createtime;
    __u8 lifetime;
    bool log;
    struct ActiveLink *next;
}ActiveLink;

typedef struct Log{
    __be32 sip;
    __be32 dip;
    __be16 sport;
    __be16 dport;
    __u8 protocol;
    mtime time;
    bool accept;
    struct Log *next;
}Log;
#endif

// module message
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mars");
MODULE_DESCRIPTION("MarsFireWall communication driver");
MODULE_VERSION("1.0.0");

// file_operations options, device operation
static long netfilter_cdev_ioctl( struct file *file, unsigned int cmd, unsigned long arg);
static int netfilter_cdev_open(struct inode *inode, struct file *file);
static int netfilter_cdev_release(struct inode *inode, struct file *file);

// define rules control funcitons
int initRuleList(void);
int addRule(const Rule *rule);
int removeRule(const Rule *rule);
int clearRuleList(void);
Rule *findRule(const Rule *rule);
bool compareRule(const Rule *a,const Rule *b);
Rule *matchRule(const unsigned int sip,const unsigned short sport,
               const unsigned int dip,const unsigned short dport,
               const unsigned short protocol);

//NAT rules control functions
int addNATRule(const NATRule *NATrule);
int removeNATRule(const NATRule *NATrule);
int clearNATRule(void);
int initNATList(void);
bool compareNATRule(const NATRule *a, const NATRule *b);
NATRule *findNATRule(const __be32 ip, const __be16 port);
int NATCore(__be32 *ip, __be16 *port);
__be16 getNATPort();


//Active Links functions
int initActiveLink(void);
int addActiveLink(const ActiveLink *link);
int removeActiveLink(const ActiveLink *link);
int clearActiveLink(void);
ActiveLink *findActiveLink(const ActiveLink *link);
bool compareActiveLink(const ActiveLink *a,const ActiveLink *b);
unsigned int hashLink(const ActiveLink *link);

//Log List functions
int initLogList(void);
int addLog(const Log *log);
int clearLogList(void);

/* variable define */
static int major_number,fd;
static Rule *RuleList,*RuleTail;
static HostInfo hostInfo;
static bool NATFlag = false;
static NATRule *NATList,*NATtail;
static int NATPort = NAT_PORT_START;
static ActiveLink *ActiveLinkList;
static Log *LogList,*LogTail;
static struct cdev netfilter_cdev;
static struct timer_list ktimer;
struct timeval oldtv;

// hook function
unsigned int FilterHookFunc(unsigned int hooknum,
               struct sk_buff *skb,
               const struct net_device *in,
               const struct net_device *out,
               int (*okfn)(struct sk_buff *));

unsigned int srcNATHookFunc(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int(*okfn)(struct sk_buff *));

unsigned int dstNATHookFunc(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int(*okfn)(struct sk_buff *));


// 字符设备选项拿出需要的字段并且绑定相应的操作函数
struct file_operations netfilter_cdev_fops = {
  .owner = THIS_MODULE,
  .unlocked_ioctl = netfilter_cdev_ioctl, // before 2.6 is .ioctl
  .open = netfilter_cdev_open,
  .release = netfilter_cdev_release
};

// hook函数
//handle packages would deliver to host
struct nf_hook_ops FilterHookIn = {
  .hook = FilterHookFunc,
  .hooknum = NF_INET_LOCAL_IN,
  .owner = THIS_MODULE,
  .pf = PF_INET,
  .priority = NF_IP_PRI_FILTER
};

//handle packages would be transmitted
struct nf_hook_ops FilterHookForward = {
  .hook = FilterHookFunc,
  .hooknum = NF_INET_FORWARD,
  .owner = THIS_MODULE,
  .pf = PF_INET,
  .priority = NF_IP_PRI_FILTER
};

//handle packages from host
struct nf_hook_ops FilterHookOut = {
  .hook = FilterHookFunc,
  .hooknum = NF_INET_LOCAL_OUT,
  .owner = THIS_MODULE,
  .pf = PF_INET,
  .priority = NF_IP_PRI_FILTER
};

//do NAT transform when packages in
struct nf_hook_ops NATHookIn = {
  .hook = dstNATHookFunc,
  .hooknum = NF_INET_PRE_ROUTING ,
  .owner = THIS_MODULE,
  .pf = PF_INET,
  .priority = NF_IP_PRI_NAT_DST
};


//do NAT transform when packages out
struct nf_hook_ops NATHookOut = {
  .hook = srcNATHookFunc,
  .hooknum = NF_INET_POST_ROUTING ,
  .owner = THIS_MODULE,
  .pf = PF_INET,
  .priority = NF_IP_PRI_NAT_SRC
};

/* 字符设备操作函数,cmd is a number */

// 打开设备0
static int netfilter_cdev_open(struct inode *inode, struct file *file)  {
  printk(KERN_INFO "prompt: Device has been opened!");
  return 0;
}

// 设备释放
static int netfilter_cdev_release(struct inode *inode, struct file *file)  {
  printk(KERN_INFO "prompt: Closed!\n");
  return 0;
}

// ioctrl
static long netfilter_cdev_ioctl(struct file *file, unsigned int cmd, unsigned long arg)  {
    long ret = 0;
  Rule rule;
  NATRule *NATNode;
  ActiveLink *linkNode;
  Log *logNode;
  int linkLen = 0,logLen = 0,NATLen = 0,move = 0;
  switch(cmd) {
    case FW_ADD_RULE:
      //printk("\nFW_ADD_RULE!\n");
      copy_from_user(&rule,(struct Rule *)arg, sizeof(struct Rule));
      addRule(&rule);
      break;
    case FW_REMOVE_RULE:
      //printk("\nFW_DEL_RULE\n");
      copy_from_user(&rule,(struct Rule *)arg, sizeof(struct Rule));
      removeRule(&rule);
      break;
    case FW_CLEAR_RULE:
      //printk("\nFW_CLEAR_RULE\n");
      clearRuleList();
      break;
    case FW_GET_NAT_LEN:
      //printk("\nFW_GET_NAT_LEN!\n");
      NATLen = NATList->ip;
      copy_to_user((int *)arg,&NATLen,sizeof(NATLen));
      break;
    case FW_REFRESH_NAT_RULE:
      //printk("\nFW_REFRESH_NAT_RULE!\n");
      NATNode = NATList->next;
      while(NATNode){
          copy_to_user((struct NATRule*)arg + move++,NATNode,sizeof(struct NATRule));
          NATNode = NATNode->next;
      }
      break;
    case FW_START_NAT_TRANSFORM:
      //printk("\nFW_START_NAT_TRANSFORM!\n");
      NATFlag = true;
      copy_from_user(&hostInfo,(struct HostInfo *)arg, sizeof(struct HostInfo));
      break;
    case FW_STOP_NAT_TRANSFORM:
      //printk("\nFW_STOP_NAT_TRANSFORM!\n");
      NATFlag = false;
      clearNATRule();
      NATPort = NAT_PORT_START;
      break;
    case FW_GET_ACTIVELINK_LEN:
      //printk("\nFW_GET_ACTIVELINK_LEN!\n");
      for(int i = 0;i < ACTIVE_LINK_HASH_TABLE_SIZE;i++){
          linkLen += ActiveLinkList[i].sip;
      }
      copy_to_user((int *)arg,&linkLen,sizeof(linkLen));
      break;
    case FW_REFRESH_ACTIVELINK:
      //printk("\nFW_REFRESH_ACTIVELINK!\n");
      for(int i = 0;i < ACTIVE_LINK_HASH_TABLE_SIZE;i++){
          linkNode = ActiveLinkList[i].next;
          while(linkNode){
              copy_to_user((struct ActiveLink *)arg + move++,linkNode,sizeof(struct ActiveLink));
              linkNode = linkNode->next;
          }
      }
      break;
    case FW_GET_LOG_LEN:
        //printk("\nFW_GET_LOG_LEN!\n");
        logLen = LogList->sip;
        copy_to_user((int *)arg,&logLen,sizeof(logLen));
      break;
    case FW_WRITE_LOG:
        //printk("\nFW_WRITE_LOG!\n");
        logNode = LogList->next;
        while(logNode){
            copy_to_user((struct Log*)arg + move++,logNode,sizeof(struct Log));
            logNode = logNode->next;
        }
        clearLogList();
      break;
    default:
      //printk("\nUnknown cmd!\n");
      break;
  }
  return ret;
}

 
/**********************
 * filter hook function
 */
unsigned int FilterHookFunc(unsigned int hooknum,
               struct sk_buff *skb,
               const struct net_device *in,
               const struct net_device *out,
               int (*okfn)(struct sk_buff *)) {
    //printk("\nIn filter hook function.");

    unsigned int ret = NF_ACCEPT;
    unsigned int sip,dip;
    unsigned short sport,dport,protocol;
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph;
    struct udphdr *udph;
    sip = iph->saddr;
    dip = iph->daddr;
    protocol = iph->protocol;
    switch(protocol){
        case IPPROTO_TCP:
            tcph = (struct tcphdr*)((__u8 *)iph + (iph->ihl << 2));
            sport = ntohs(tcph->source);
            dport = ntohs(tcph->dest);
            break;
        case IPPROTO_UDP:
            udph = (struct udphdr*)((__u8 *)iph + (iph->ihl << 2));
            sport = ntohs(udph->source);
            dport = ntohs(udph->dest);
            break;
        default:
            sport = 0;
            dport = 0;
            break;
    }
    bool logflag = false;
    ActiveLink *rsLink,link;
    link.sip = sip;
    link.dip = dip;
    link.sport = sport;
    link.dport = dport;
    link.protocol = protocol;
    link.createtime.year = 0;
    link.createtime.month = 0;
    link.createtime.day = 0;
    link.createtime.hour = 0;
    link.createtime.min = 0;
    link.createtime.sec = 0;
    link.lifetime = 0;
    link.log = false;
    rsLink = findActiveLink(&link);
    //link established
    if(rsLink){
        printk("link established!\n");
        if(protocol == IPPROTO_TCP){
            if(tcph->fin){
                removeActiveLink(&link);
            }
        }
        logflag = rsLink->log;
    }
    else{
        Rule *rule;
        rule = matchRule(sip,sport,dip,dport,protocol);
        if(rule){
            printk("rule exists!\n");
            if(rule->accept){
                if(protocol == IPPROTO_TCP){
                    if(tcph->syn){
                        addActiveLink(&link);
                    }
                    else{
                        ret = NF_DROP;
                    }
                }
                else{
                    addActiveLink(&link);
                }
            }
            else{
                ret = NF_DROP;
            }
            logflag = rule->log;
        }
        else{
            ret = NF_DROP;
        }
    }
    if(logflag){
        if(LogList->sip >= 1000){
            clearLogList();
            LogList->sip = 0;
            LogTail = LogList;
        }
        Log log;
        log.sip = sip;
        log.dip = dip;
        log.sport = sport;
        log.dport = dport;
        log.protocol = protocol;
        struct timex  nowtime;
        struct rtc_time nowtm;
        do_gettimeofday(&(nowtime.time));
        rtc_time_to_tm(nowtime.time.tv_sec,&nowtm);
        log.time.year = nowtm.tm_year + 1900;
        log.time.month = nowtm.tm_mon + 1;
        log.time.day = nowtm.tm_mday;
        log.time.hour = nowtm.tm_hour;
        log.time.min = nowtm.tm_min;
        log.time.sec = nowtm.tm_sec;
        if(ret == NF_ACCEPT){
            log.accept = true;
        }
        else{
            log.accept = false;
        }
        addLog(&log);
    }
    return ret;
}


/*******************************
 * Hook func to do src NAT transform
 */
unsigned int srcNATHookFunc(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int(*okfn)(struct sk_buff *)) {
	unsigned int ret = NF_ACCEPT; // default policy
        if(NATFlag){
            __be32 *sip,*dip;
            __be16 *sport,*dport;
            struct iphdr *iph = ip_hdr(skb);
            struct tcphdr *tcph;
            struct udphdr *udph;
            NATRule *NATNode,NATrule;
            sip = &(iph->saddr);
            dip = &(iph->daddr);
            switch(iph->protocol){
                case IPPROTO_TCP:
                    tcph = (struct tcphdr*)((__u8 *)iph + (iph->ihl << 2));
                    sport = &(tcph->source);
                    dport = &(tcph->dest);
                    break;
                case IPPROTO_UDP:
                    udph = (struct udphdr*)((__u8 *)iph + (iph->ihl << 2));
                    sport = &(udph->source);
                    dport = &(udph->dest);
                    break;
                default:
                    return NF_ACCEPT;
            }
            if(((htonl(*sip) >> (32 - hostInfo.mask)) == (htonl(hostInfo.ip) >> (32 - hostInfo.mask))) &&
                 *sip != hostInfo.ip){
                NATNode = findNATRule(*sip,ntohs(*sport));
                //NAT rule not exists
                if(!NATNode){
                    NATrule.ip = *sip;
                    NATrule.port = ntohs(*sport);
                    NATrule.natip = hostInfo.ip;
                    NATrule.natport = getNATPort();
                    addNATRule(&NATrule);
                }
                printk("\n=======================\nSRC NAT HOOK FUNC:\n");
                printk("Host IP = %u Mask = %u\n",hostInfo.ip,hostInfo.mask);
                printk("\nbefore NAT sip = %u sport = %u\n",*sip,ntohs(*sport));
                NATCore(sip,sport);
                printk("\nafter NAT sip = %u sport = %u\n",*sip,ntohs(*sport));
                //change check sum
                int tot_len;
                int iph_len;
                iph_len = ip_hdrlen(skb);
                tot_len = ntohs(iph->tot_len);
                if(iph->protocol == IPPROTO_TCP){
                    tcph->check = 0;
                    skb->csum = csum_partial((unsigned char *)tcph, tot_len - iph_len,0);
                    tcph->check = csum_tcpudp_magic(iph->saddr,
                                                    iph->daddr,
                                                    ntohs(iph->tot_len) - iph_len,iph->protocol,
                                                    skb->csum);
                    iph->check = 0;
                    iph->check = ip_fast_csum(iph,iph->ihl);
                }
                else{
                    iph->check = 0;
                }
            }
            else if(dip == hostInfo.ip){
                NATCore(dip,dport);
                //change check sum
                int tot_len;
                int iph_len;
                iph_len = ip_hdrlen(skb);
                tot_len = ntohs(iph->tot_len);
                if(iph->protocol == IPPROTO_TCP){
                    tcph->check = 0;
                    skb->csum = csum_partial((unsigned char *)tcph, tot_len - iph_len,0);
                    tcph->check = csum_tcpudp_magic(iph->saddr,
                                                    iph->daddr,
                                                    ntohs(iph->tot_len) - iph_len,iph->protocol,
                                                    skb->csum);
                    iph->check = 0;
                    iph->check = ip_fast_csum(iph,iph->ihl);
                }
                else{
                    iph->check = 0;
                }
            }

        }
        return NF_ACCEPT;
}

/***********************************
 * Hook func to do dst NAT transform
 */
unsigned int dstNATHookFunc(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int(*okfn)(struct sk_buff *)) {
    //printk("\nIn NAT hook function.");
    unsigned int ret = NF_ACCEPT; // default policy
    if(NATFlag){
        __be32 *sip,*dip;
        __be16 *sport,*dport;
        struct iphdr *iph = ip_hdr(skb);
        struct tcphdr *tcph;
        struct udphdr *udph;
        NATRule *NATNode,NATrule;
        sip = &(iph->saddr);
        dip = &(iph->daddr);
        switch(iph->protocol){
            case IPPROTO_TCP:
                tcph = (struct tcphdr*)((__u8 *)iph + (iph->ihl << 2));
                sport = &(tcph->source);
                dport = &(tcph->dest);
                break;
            case IPPROTO_UDP:
                udph = (struct udphdr*)((__u8 *)iph + (iph->ihl << 2));
                sport = &(udph->source);
                dport = &(udph->dest);
                break;
            default:
                return NF_ACCEPT;
        }
        if(*dip == hostInfo.ip){
            printk("\n=======================\nSRC NAT HOOK FUNC:\n");
            printk("Host IP = %u Mask = %u\n",hostInfo.ip,hostInfo.mask);
            printk("\nbefore NAT sip = %u sport = %u\n",*sip,ntohs(*sport));
            printk("\nbefore NAT dip = %u dport = %u\n",*dip,ntohs(*dport));
            //did NAT Transform or not
            if(!NATCore(dip,dport)){
                printk("\nafter NAT sip = %u sport = %u\n",*sip,ntohs(*sport));
                printk("\nafter NAT dip = %u dport = %u\n",*dip,ntohs(*dport));
                //change check sum
                int tot_len;
                int iph_len;
                iph_len = ip_hdrlen(skb);
                tot_len = ntohs(iph->tot_len);
                if(iph->protocol == IPPROTO_TCP){
                    tcph->check = 0;
                    skb->csum = csum_partial((unsigned char *)tcph, tot_len - iph_len,0);
                    tcph->check = csum_tcpudp_magic(iph->saddr,
                                                    iph->daddr,
                                                    ntohs(iph->tot_len) - iph_len,iph->protocol,
                                                    skb->csum);
                    iph->check = 0;
                    iph->check = ip_fast_csum(iph,iph->ihl);
                }
                else{
                    iph->check = 0;
                }
            }
        }
    }
    return NF_ACCEPT;
}


/***********************
 * init filter rule list
 */
int initRuleList(void){
    RuleList = (Rule *)kmalloc(sizeof(Rule),0);
    if(!RuleList){
        return -1;
    }
    RuleList->sip = 0xFFFF;
    RuleList->dip = 0xFFFF;
    RuleList->sport = 0xFF;
    RuleList->dport = 0xFF;
    RuleList->protocol = 0xFF;
    RuleList->sMask = 0xFF;
    RuleList->dMask = 0xFF;
    RuleList->accept = false;
    RuleList->log = false;
    RuleList->next = NULL;
    RuleTail = RuleList;
    return 0;
}

/**********************************
 * add filter rule to the rule list
 */
int addRule(const Rule *rule){
    Rule *ruleNode = (Rule *)kmalloc(sizeof(Rule),0);
    if(!ruleNode){
        return -1;
    }
    if(findRule(rule)){
        return -2;
    }
    ruleNode->sip = rule->sip;
    ruleNode->dip = rule->dip;
    ruleNode->sport = rule->sport;
    ruleNode->dport = rule->dport;
    ruleNode->protocol = rule->protocol;
    ruleNode->sMask = rule->sMask;
    ruleNode->dMask = rule->dMask;
    ruleNode->accept = rule->accept;
    ruleNode->log = rule->log;
    ruleNode->next = NULL;
    RuleTail->next = ruleNode;
    RuleTail = ruleNode;
    return 0;
}

/***************************************
 * remove filter rule from the rule list
 */
int removeRule(const Rule *rule){
    if(!rule){
        return -1;
    }
    if(!RuleList->next){
        return -2;
    }
    Rule *pre = RuleList,*after;
    while(pre){
        if(compareRule(rule,pre->next)){
            after = pre->next->next;
            kfree(pre->next);
            pre->next = after;
            if(!after){
                RuleTail = pre;
            }
            return 0;
        }
        else{
            pre = pre->next;
        }
    }
    return -3;
}

/************************
 * clear filter rule list
 */
int clearRuleList(void){
    Rule *node = RuleList->next,*next;
    while(node){
        next = node->next;
        kfree(node);
        node = next;
    }
    RuleList->next = NULL;
    RuleTail = RuleList;
    return 0;
}

/************************
 * find rule in rule list
 */
Rule *findRule(const Rule *rule){
    if(!rule){
        return NULL;
    }
    Rule *ruleNode = RuleList->next;
    while(ruleNode){
        if(compareRule(rule,ruleNode)){
            return ruleNode;
        }
        ruleNode = ruleNode->next;
    }
    return NULL;
}

/**********************
 * compare filter rules
 */
bool compareRule(const Rule *a,const Rule *b){
    if(!a || !b){
        return false;
    }
    return (a->sip == b->sip &&
            a->dip == b->dip &&
            a->sport == b->sport &&
            a->dport == b->dport &&
            a->protocol == b->protocol &&
            a->sMask == b->sMask &&
            a->dMask == b->dMask &&
            a->accept == b->accept &&
            a->log == b->log);
}

/*****************************************
 * judge if package match one of the rules
 */
Rule *matchRule(const unsigned int sip,const unsigned short sport,
               const unsigned int dip,const unsigned short dport,
               const unsigned short protocol){
    Rule *ruleNode = RuleList->next;
    while(ruleNode){
        if(ruleNode->protocol == 0 || protocol == ruleNode->protocol){
            if(ruleNode->sip == 0 || (htonl(sip) >> (32 - ruleNode->sMask)) == (htonl(ruleNode->sip) >> (32 - ruleNode->sMask))){
                if(ruleNode->sport == 0 || sport == ruleNode->sport){
                    if(ruleNode->dip == 0 || (htonl(dip) >> (32 - ruleNode->dMask)) == (htonl(ruleNode->dip) >> (32 - ruleNode->dMask))){
                        if(ruleNode->dport == 0 || dport == ruleNode->dport){
                            return ruleNode;
                        }
                    }
                }
            }
        }
        ruleNode = ruleNode->next;
    }
    return NULL;
}



/******************
 * init NAT list
 */
int initNATList(void) {
	NATList = (NATRule *)kmalloc(sizeof(NATRule), 0);
        if(!NATList){
            return -1;
        }
        NATList->ip = 0;//count of NAT rules
	NATList->port = 0xFF;
	NATList->natip = 0XFFFF;
	NATList->natport = 0xFF;
	NATList->next = NULL;
        NATtail = NATList;
        return 0;
}

/****************
 * add  NAT rule
 */
int addNATRule(const NATRule *NATrule) {
	NATRule *NATnode = (NATRule *)kmalloc(sizeof(NATRule), 0);
        if(!NATnode){
            return -1;
        }
        NATnode->ip = NATrule->ip;
        NATnode->port = NATrule->port;
        NATnode->natip = NATrule->natip;
        NATnode->natport = NATrule->natport;
	NATnode->next = NULL;
	NATtail->next = NATnode;
	NATtail = NATnode;
        ++NATList->ip;
        return 0;
}

/*****************
 * remove NAT rule
 */
int removeNATRule(const NATRule *NATrule) {
	if (!NATrule){ 
                return -1;
	}	
        if (!NATList->next) {
                return -2;
	}
        NATRule *pre = NATList,*after;
	while (pre) {
                if (compareNATRule(NATrule, pre->next)) {
			after = pre->next->next;
			kfree(pre->next);
			pre->next = after;
			if (!after) {
                                NATtail = pre;
			}
                        --NATList->ip;
                        return 0;
		}
		else {
			pre = pre->next;
		}
	}
        return -3;
}

/******************
 * clear NAT rule
 */
int clearNATRule(void) {
        NATList->ip = 0;//reset counter
	NATRule *NATnode, *NATnext;
	NATnode = NATList->next;
        while(NATnode){
            NATnext = NATnode->next;
            kfree(NATnode);
            NATnode = NATnext;
        }
        NATtail = NATList;
        return 0;
}

/***************
 * find NAT rule
 */
NATRule *findNATRule(const __be32 ip,const __be16 port) {
        NATRule *NATNode = NATList->next;
        while(NATNode){
            if(NATNode->ip == ip && NATNode->port == port){
                return NATNode;
            }
            if(NATNode->natip == ip && NATNode->natport == port){
                return NATNode;
            }
            NATNode = NATNode->next;
        }
	return NULL;
}

/*******************
 * compare NAT rules
 */
bool compareNATRule(const NATRule *a, const NATRule *b) {
	if (!a || !b) {
		return false;
	}
        return (a->ip == b->ip&&
                        a->port == b->port&&
                        a->natip == b->natip&&
                        a->natport == b->natport);
}

/*********************************
 * core functiion of NAT transform
 */
int NATCore(__be32 *ip, __be16 *port) {
    NATRule *NATNode = NATList->next;
    while(NATNode){
        if(*ip == NATNode->ip && ntohs(*port) == NATNode->port){
            *ip = NATNode->natip;
            *port = htons(NATNode->natport);
            return 0;
        }
        if(*ip == NATNode->natip && ntohs(*port) == NATNode->natport){
            *ip = NATNode->ip;
            *port = htons(NATNode->port);
            return 0;
        }
        NATNode = NATNode->next;
    }
    return -1;
}

/**************
 * get NAT port
 */
__be16 getNATPort(){
    if(NATPort < NAT_PORT_END){
        return NATPort++;
    }
    else{
        NATFlag = false;
        return NAT_PORT_END;
    }
}

/***********************
 * init Active Link List
 */
int initActiveLink(void){
    ActiveLinkList = (ActiveLink *)kmalloc(sizeof(ActiveLink)*ACTIVE_LINK_HASH_TABLE_SIZE,0);
    if(!ActiveLinkList){
        return -1;
    }
    for(int i = 0; i < ACTIVE_LINK_HASH_TABLE_SIZE; i++){
        ActiveLinkList[i].sip = 0;       //the head node sip of the list is the count of the list
        ActiveLinkList[i].dip = 0xFFFF;
        ActiveLinkList[i].sport = 0xFF;
        ActiveLinkList[i].dport = 0xFF;
        ActiveLinkList[i].protocol = 0xF;
        ActiveLinkList[i].createtime.year = 0;
        ActiveLinkList[i].createtime.month = 0;
        ActiveLinkList[i].createtime.day = 0;
        ActiveLinkList[i].createtime.hour = 0;
        ActiveLinkList[i].createtime.min = 0;
        ActiveLinkList[i].createtime.sec = 0;
        ActiveLinkList[i].lifetime = 0xFFFF;
        ActiveLinkList[i].log = false;
        ActiveLinkList[i].next = NULL;
    }
    return 0;
}

/******************************
 * add link to Active Link List
 */
int addActiveLink(const ActiveLink *link){
    ActiveLink *linkNode,*tailNode;
    linkNode = (ActiveLink *)kmalloc(sizeof(ActiveLink),0);
    if(!linkNode){
        return -1;
    }
    linkNode->sip = link->sip;
    linkNode->dip = link->dip;
    linkNode->sport = link->sport;
    linkNode->dport = link->dport;
    linkNode->protocol = link->protocol;
    struct timex  nowtime;
    struct rtc_time nowtm;
    do_gettimeofday(&(nowtime.time));
    rtc_time_to_tm(nowtime.time.tv_sec,&nowtm);
    linkNode->createtime.year = nowtm.tm_year + 1900;
    linkNode->createtime.month = nowtm.tm_mon + 1;
    linkNode->createtime.day = nowtm.tm_mday;
    linkNode->createtime.hour = nowtm.tm_hour;
    linkNode->createtime.min = nowtm.tm_min;
    linkNode->createtime.sec = nowtm.tm_sec;
    if(linkNode->protocol == IPPROTO_TCP){
        linkNode->lifetime = 60;
    }
    else{
        linkNode->lifetime = 20;
    }
    linkNode->next = NULL;
    tailNode = &ActiveLinkList[hashLink(linkNode)];
    ++tailNode->sip;//count of nodes + 1
    while(tailNode->next){
        tailNode = tailNode->next;
    }
    tailNode->next = linkNode;
    return 0;
}

/***********************************
 * remove link from Active Link List
 */
int removeActiveLink(const ActiveLink *link){
    if(!link){
        return -1;
    }
    ActiveLink *node = &ActiveLinkList[hashLink(link)];
    ActiveLink *pre = node,*after;
    while(pre->next){
        if(compareActiveLink(link,pre->next)){
            after = pre->next->next;
            kfree(pre->next);
            pre->next = after;
            --node->sip;//count of nodes - 1
            return 0;
        }
        else{
            pre = pre->next;
        }
    }
    return -3;
}

/************************
 * clear Active Link List
 */
int clearActiveLink(void){
    for(int i = 0;i < ACTIVE_LINK_HASH_TABLE_SIZE;i++){
        ActiveLink *node,*next;
        node = ActiveLinkList[i].next;
        ActiveLinkList[i].sip = 0;//set count of nodes = 0
        if(!node){
            continue;
        }
        next = node->next;
        do{
            kfree(node);
            node = next;
            if(next){
                next = next->next;
            }
        }while(next);
    }
    return 0;
}

/*********************************
 * find link from Active Link List
 */
ActiveLink *findActiveLink(const ActiveLink *link){
    if(!link){
        return NULL;
    }
    ActiveLink *node = ActiveLinkList[hashLink(link)].next;
    while(node){
        if(compareActiveLink(link,node)){
            if(node->lifetime > 0){
                //reset lifetime
                if(node->protocol == IPPROTO_TCP){
                    node->lifetime = 60;
                }
                else{
                    node->lifetime = 20;
                }
                return node;
            }
            else{
                removeActiveLink(link);
                return NULL;
            }
        }
        node = node->next;
    }
    return NULL;
}

/**********************
 * compare Active Links
 */
bool compareActiveLink(const ActiveLink *a,const ActiveLink *b){
    if(!a || !b){
        return false;
    }
    //createtime and lifetime are not needed when comparing
    bool original,changed;
    original = (a->sip == b->sip &&
                a->dip == b->dip &&
                a->sport == b->sport &&
                a->dport == b->dport &&
                a->protocol == b->protocol);
    changed = (a->sip == b->dip &&
               a->dip == b->sip &&
               a->sport == b->dport &&
               a->dport == b->sport &&
               a->protocol == b->protocol);
    return original || changed;
}

/*********************
 * get Hash for a link
 */
unsigned int hashLink(const ActiveLink *link){
    unsigned long long hash = 7;
    hash += 13 * link->sip;
    hash += 13 * link->dip;
    hash += 19 * link->sport;
    hash += 19 * link->dport;
    hash += 29 * link->protocol;
    return hash % ACTIVE_LINK_HASH_TABLE_SIZE;
}

/******************************************
 * callback function for timer
 * refresh the lifetime of active link list
 */
void timerCallBack(unsigned long arg){
    ActiveLink *pre,*next,*node;
    for(int i = 0;i < ACTIVE_LINK_HASH_TABLE_SIZE;i++){
        pre = &ActiveLinkList[i];
        node = pre->next;
        while(node){
            next = node->next;
            if(node->lifetime > 1){
                --node->lifetime;
                pre = node;
            }
            else{
                kfree(node);
                --ActiveLinkList[i].sip;
                pre->next = next;
            }
            node = next;
        }
    }
    struct timeval tv;
    do_gettimeofday(&tv);
    oldtv = tv;
    ktimer.expires = jiffies+1*HZ;
    add_timer(&ktimer);
}

/***************
 * init Log List
 */
int initLogList(void){
    LogList = (Log *)kmalloc(sizeof(Log),0);
    if(!LogList){
        printk("Log List init failed!\n");
        return -1;
    }
    LogList->sip = 0;//count of logs
    LogList->dip = 0xFFFF;
    LogList->sport = 0xFF;
    LogList->dport = 0xFF;
    LogList->protocol = 0xF;
    LogList->time.year = 0xFFFF;
    LogList->time.month = 0xFFFF;
    LogList->time.day = 0xFFFF;
    LogList->time.hour = 0xFFFF;
    LogList->time.min = 0xFFFF;
    LogList->time.sec = 0xFFFF;
    LogList->accept = false;
    LogList->next = NULL;
    LogTail = LogList;
    return 0;
}

/*********************
 * add log to Log List
 */
int addLog(const Log *log){
    Log *logNode = (Log *)kmalloc(sizeof(Log),0);
    if(!logNode){
        printk("Add log failed!\n");
        return -1;
    }
    ++LogList->sip;
    logNode->sip = log->sip;
    logNode->dip = log->dip;
    logNode->sport = log->sport;
    logNode->dport = log->dport;
    logNode->protocol = log->protocol;
    logNode->time.year = log->time.year;
    logNode->time.month = log->time.month;
    logNode->time.day = log->time.day;
    logNode->time.hour = log->time.hour;
    logNode->time.min = log->time.min;
    logNode->time.sec = log->time.sec;
    logNode->accept = log->accept;
    logNode->next = NULL;
    LogTail->next = logNode;
    LogTail = logNode;
    return 0;
}

/****************
 * clear Log List
 */
int clearLogList(void){
    LogList->sip = 0;
    Log *logNode = LogList->next,*logNext;
    while(logNode){
        logNext = logNode->next;
        kfree(logNode);
        logNode = logNext;
        if(logNext){
            logNext = logNext->next;
        }
    }
    LogTail = LogList;
    return 0;
}

/*
 * dev init, 
 */
static int __init my_netfilter_init(void) {

  int ret,err;
  dev_t devno,devno_m;

  ret = alloc_chrdev_region(&devno,0,1,"MarsFireWall");
  if(ret < 0) {
    return ret;
  }
  fd = ret;
  major_number = MAJOR(devno);

  devno_m = MKDEV(major_number,0);
  cdev_init(&netfilter_cdev,&netfilter_cdev_fops);
  // netfilter_cdev.ops = &netfilter_cdev_fops;

  err = cdev_add(&netfilter_cdev,devno_m,1);
  if(err != 0) {
    printk("Error in cdev_add.");
  }

  nf_register_hook(&FilterHookIn);
  nf_register_hook(&FilterHookForward);
  nf_register_hook(&FilterHookOut);
  nf_register_hook(&NATHookIn);
  nf_register_hook(&NATHookOut);

    initRuleList();
    initNATList();
    initActiveLink();
    initLogList();
    init_timer(&ktimer);
    do_gettimeofday(&oldtv);
    ktimer.function= timerCallBack;
    ktimer.expires = jiffies+1*HZ;
    add_timer(&ktimer);

  //printk(KERN_INFO "prompt: Aha! Register successful! \nMain Device Number is %d\n", major_number);
  return 0;
}


/*
 * dev clear.
 */
static void __exit my_netfilter_exit(void) {

  nf_unregister_hook(&FilterHookIn);
  nf_unregister_hook(&FilterHookForward);
  nf_unregister_hook(&FilterHookOut);
  nf_unregister_hook(&NATHookIn);
  nf_unregister_hook(&NATHookOut);
  clearRuleList();
  clearNATRule();
  clearActiveLink();
  clearLogList();
  kfree(RuleList);
  kfree(NATList);
  kfree(ActiveLinkList);
  kfree(LogList);
  del_timer(&ktimer);
  cdev_del(&netfilter_cdev);
  unregister_chrdev_region(MKDEV(major_number,0),1);
  printk(KERN_INFO "prompt: WOW! exit!\n");
}

module_init(my_netfilter_init); // insmod module
module_exit(my_netfilter_exit); // rmmod module
