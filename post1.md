一. Linux系统内核接收以太帧的处理程序

1. 前言:
以太头中除了6字节目的MAC地址、6字节源MAC地址外，还有两字节的以太帧类型值

，如IPv4为0x0800，ARP为0x0806等，网卡驱动收到以太帧后通过接口函数

netif_receive_skb()(netif_rx实际最后也是调用netif_receive_skb)交到上层，

而这个接口函数就完成对以太帧类型的区分，交到不同的协议处理程序。如果想自

己编写某一以太类型帧的处理程序，需要自己添加相应的代码。以下为Linux内核

2.6代码。

2. 数据结构:
每种协议都要定义一个packet_type结构，引导进入相关的协议数据处理函数，所

有节点组成一个链表(HASH链表)。

/* include/linux/netdevice.h */
struct packet_type {
__be16 type; /* This is really htons(ether_type). */
struct net_device *dev; /* NULL is wildcarded here */
int (*func) (struct sk_buff *, struct net_device *, struct packet_type 

*);
void *af_packet_priv;
struct list_head list;
};

参数说明：
type：以太帧类型，16位。
dev：所附着的网卡设备，如果为NULL则匹配全部网卡。
func：协议入口接收处理函数。
af_packet_priv：协议私有数据。
list：链表扣。

一般各协议的packet_type结构都是静态存在，初始化时只提供type和func两个参

数就可以了，每个协议在初始化时都要把此结构加入到系统类型链表中。

3. 处理函数:
3.1 添加节点
/* net/core/dev.c */
void dev_add_pack(struct packet_type *pt) {}
3.2 删除节点
/* net/core/dev.c */
void dev_remove_pack(struct packet_type *pt) {}

4. 网络接收:
网卡驱动收到数据包构造出skb后，通过接口函数netif_receive_skb()传递到上层

进行协议处理分配。

/* net/core/dev.c */
int netif_receive_skb(struct sk_buff *skb) {}

5. 结论:
通过链表挂接方式，Linux内核可以很容易的添加各种协议的接收处理函数。
数据流程:
网卡驱动--->netif_rx()--->netif_receive_skb()->deliver_skb()-

>packet_type.func 

二. 在内核中执行一个用户态应用程序:
用call_usermodehelper()或exec_usermodehelper函数，定义在

include/linux/kmode.h. (note: call_usermodehelper最终也会调用

exec_usermodehelper)
/**
* call_usermodehelper - start a usermode application
* @path: pathname for the application
* @argv: null-terminated argument list
* @envp: null-terminated environment list
*
* Runs a user-space application. The application is started 

asynchronously. It
* runs as a child of keventd. It runs with full root capabilities. 

keventd silently
* reaps the child when it exits.
*
* Must be called from process context. Returns zero on success, else a 

negative
* error code.
*/
int call_usermodehelper(char *path, char **argv, char **envp) {}

三. struct net_device和struct in_device的区别与联系：
net_device是链路层结构，in_device是网络层结构，net_device->ip_ptr指向

in_device
in_device在设置该接口的ip地址时分配，具体见net/ipv4/devinet.c中的

inet_rtm_newaddr函数

struct net_device
{
    ...
    unsigned short hard_header_len; /* hardware hdr length */
/*
在数据包中硬件头的大小.RFC中规定以太网硬件头长度为14个字节(6字节目标得知

+6字节源地址+2字节数据长度).不过在IP头前应该是16字节.
*/
    ...
    void *ip_ptr;    /* IPv4 specific data    */  
    ...
}

struct in_device
{
    struct net_device       *dev;
    atomic_t                refcnt;
    int                     dead;
    struct in_ifaddr        *ifa_list;   /* IP ifaddr chain */
    rwlock_t                mc_list_lock;
    struct ip_mc_list       *mc_list;    /* IP multicast filter chain */
    spinlock_t              mc_tomb_lock;
    struct ip_mc_list       *mc_tomb;
    unsigned long           mr_v1_seen;
    unsigned long           mr_v2_seen;
    unsigned long           mr_maxdelay;
    unsigned char           mr_qrv;
    unsigned char           mr_gq_running;
    unsigned char           mr_ifc_count;
    struct timer_list       mr_gq_timer;    /* general query timer */
    struct timer_list       mr_ifc_timer;   /* interface change timer */
    struct neigh_parms      *arp_parms;
    struct ipv4_devconf     cnf;
};
struct in_ifaddr
{
    struct in_ifaddr    *ifa_next;
    struct in_device    *ifa_dev;
    u32            ifa_local; /* 设备地址 */
    u32            ifa_address; /* 点对点设备的对端地址 */
    u32            ifa_mask; /* 网络地址掩码 */
    u32            ifa_broadcast; /* 设备的广播地址 */
    u32            ifa_anycast; 
    unsigned char    ifa_scope; /* 设备地址的寻址范围 */
    unsigned char    ifa_flags; /* 地址标志
    unsigned char    ifa_prefixlen; /* 设备网络地址长度 */
    char        ifa_label[IFNAMSIZ]; /* 设备IP地址标签 */
};

dev_get_by_name函数：
根据名字找设备
struct net_device * dev_get_by_name (const char * name)
name为要查找的名字
根据名字找到一个接口。这个函数可以在任何上下文中调用并持有自己的锁。返回

句柄的引用计数增加，调用者必须在其不使用时调用dev_put释放它，如果没有匹

配的名字，则返回NULL。

in_dev_get()函数：
返回net_device中的指向in_device的指针ip_ptr,调用者必须在其不使用时调用

in_dev_put释放它

函数原型:
static __inline__ struct in_device *
in_dev_get(const struct net_device *dev)
{
    struct in_device *in_dev;

    read_lock(&inetdev_lock);
    in_dev = dev->ip_ptr;
    if (in_dev)
        atomic_inc(&in_dev->refcnt);
    read_unlock(&inetdev_lock);
    return in_dev;
}

四. 内核线程:
我们知道Linux内核使用内核线程来将内核分成几个功能模块,像kswapd,kflushd等

,系统中的init进程也是由idle进程调用kernel_thread()来实现产生的.

int kernel_thread(int(*fn)(void*arg),void *arg,int flags) {}

它的伪C码实现为:
int kernel_thread()
{
    pid = clone(flags);
    if(child) {
        fn(arg);
        exit(0);
    }
    return pid;
}

内核线程有以下性质:
1. 内核线程是通过系统调用clone()来实现的,使用CLONE_VM标志(用户还可以提供

其他标志,CLONE_PID,CLONE_FS,CLONE_FILES等),因此内核线程与调用的进程

(current)具有相同的进程空间.
2. 由于调用进程是在内核里调用kernel_thread(),因此当系统调用返回时,子进程

也处于内核态中,而子进程随后调用fn,当fn退出时,子进程调用exit()退出,所以子

进程是在内核态运行的.
3. 由于内核线程是在内核态运行的,因此内核线程可以访问内核中数据,调用内核

函数.运行过程中不能被抢占等等. 
4. kernel_thread创建的进程是不能转到用户态运行的.

五. struct iphdr结构：
IPv4数据报格式：
struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8    ihl:4,    // 报头长度
            version:4;  // IP版本，4表示IPV4  
#elif defined (__BIG_ENDIAN_BITFIELD)
    __u8    version:4,
            ihl:4;
#else
#error  "Please fix <asm/byteorder.h>"
#endif
    __u8    tos;     // 服務類型TOS 
    __be16  tot_len; // 總長度（位元組） 
    __be16  id;      //元標識 
    __be16  frag_off; //标志
/*
IP数据的分片涉及到IP首部中的两个字段，即结构体struct iphdr的成员frag_off，其高三位是三个标志位，第二位是不允许分片标志，置该位，表示该IP数据报不允许被分片，如果发送这样的数据报，并且数据报本身长度已经超出MTU的很制，则向发送方发一个icmp出错报文，报文类型为目的不可达(3)，代码为需要进行分片但被设置了不允许分片的位 (4)；第三位如果置1，表示后面还有分片，置0表示本分片是一个完整的IP数据报的最后一个分片。frag_off的低13位表示本分片的第一个字节在整个IP数据报中的偏移量，单位是字节数除以8，所以需要把这13位左移3位，才是真正的偏移字节数。
frag_off，其高三位是三个标志位，第二位是不允许分片标志:
IP_DF//设置不可分片的指示位
IP_MF//设置分片的指示位
*/
    __u8    ttl;     //生存時間 TTL
    __u8    protocol;// 上层協定 (TCP, UDP 或其他)  
    __sum16 check;   // IP首部校驗和  
/*
ip_send_check(skb->nh.iph); // 计算IP头校验和
*/
    __be32  saddr;   // 源IP地址 
    __be32  daddr;   // 目的IP地址  
    /*The options start here. */
};
 
六. 路由緩衝表的基本結構
1) 在Linux內核中, 將IP包的路由稱為"目的入口"(dst_entry), 目的入口反映了相鄰的外部主機在主機
內部的一種"映像", IP包首先注入到目的入口中, 經過一系列IP包過濾器, 最後注入到目的入口的幀頭緩
衝入口或鄰居入口, 通過ARP緩衝創建硬件幀頭後發送到設備驅動程序上.

2) 路由緩衝表就是IP路由入口表, 它是轉發表路由規則的實例化. 在查詢IP路由時, 系統先在路由緩衝表
中查詢, 當路由入口已存在時, 將輸出包直接綁定到該路由入口, 如果未找到匹配的入口, 則通過轉發表
查詢路由規則, 當匹配成功後, 要在路由緩衝表中創建相應的目的入口.

3) 路由緩衝表是用散列索引的路由結構(rtable), 路由結構的開始即為目的入口結構, 它們在頭部形成聯
合.ip_route_output(&rt,daddr,saddr,oif)查詢輸出設備為oif, 目的地址為daddr, 源地址為saddr的路
由入口. ip_route_input(skb,daddr,saddr,tos,dev)將接收包skb綁定到輸入設備為dev, 目的地址為
daddr, 源地址為saddr, 服務類型為tos的目的入口.

1. struct dst_entry:
最终生成的IP数据报的路由称为目的入口(dst_entry)，目的入口反映了相邻的外部主机在主机内部的一种“映象”.
    __refcnt是目的入口的引用计数，创建成功后即设为1。__use是一个统计数值，该目的入口被使用一次(发送一个IP数据报)，__use就加1

。
    dev是该路由的输出网络设备接口，flags是标志位，其取值可以是DST_HOST，DST_NOXFRM，DST_NOPOLICY，DST_NOHASH，DST_BALANCED(用

在路由有多路径的情况下)。
    lastuse是一个时间值，每次目的入口被用于发送IP数据报，就将该值设置为当前系统时间值。该值被用于几个地方，路由缓存表 

myrt_hash_table是一个很大的数组(依据系统的内存大小而定)，每一项都是一个struct rtable的链表，当要往缓存表的某一个链表中插入一

个新的struct rtable时，如果这个链表的长度已经超出ip_rt_gc_elasticity(值为8)，则需要删掉一个当前使用价值最低的，已保持链表长度

的平衡。函数rt_score就是用于为每个struct rtable计算价值分数，分数是一个32位值，最高位表示非常有价值，当struct rtable的成员

rt_flags上有标志RTCF_REDIRECTED或RTCF_NOTIFY，或者目的入口的超时时间未到时，置该位，次高位价值次之，余下的30位由lastuse决定，

该目的入口距上次使用时间越长，价值越低。另外，用于在rt_may_expire函数中判断一个 struct rtable是否超时。
    expires是一个超时时间值，定时器rt_periodic_timer定期扫描路由缓存表rt_hash_table，如果发现expires值为0，或者小于当前系统时

间值，并符合其它超时条件，则把该路由从缓存表中删除。
    neighbour是为该路由绑定的邻居节点，详细分析见arp部分。
    hh是硬件头缓存，ARP解析得到的邻居的mac地址缓存在这里，再次发送IP数据报的时候，就不需要再到ARP缓存中去取硬件头。
    input和output分别是该目的入口的输入和输出函数。
    前面讲到通过在一张路由表(struct fib_table)中，根据查询路由的目的IP地址(key)在其路由哈希表(struct fn_hash)中找到一个路由域

(struct fn_zone)，并在路由域中匹配到一个key相等的路由节点(struct fib_node)，取其路由别名(struct fib_alias)和路由信息(struct 

fib_info)，生成一个路由查询结果(struct fib_result)。
struct dst_entry
{
    struct dst_entry        *next;
    atomic_t        __refcnt;    /* client references    */
    int            __use;
    struct net_device       *dev;
    int            obsolete;
    int            flags;
#define DST_HOST        1
    unsigned long        lastuse;
    unsigned long        expires;

    unsigned        mxlock;
    unsigned        pmtu;
    unsigned        window;
    unsigned        rtt; 
    unsigned        rttvar;
    unsigned        ssthresh;
    unsigned        cwnd;
    unsigned        advmss;
    unsigned        reordering;

    unsigned long        rate_last;    /* rate limiting for ICMP */
    unsigned long        rate_tokens;

    int            error;

    struct neighbour    *neighbour;
    struct hh_cache        *hh;

    int            (*input)(struct sk_buff*);
    int            (*output)(struct sk_buff*);

#ifdef CONFIG_NET_CLS_ROUTE
    __u32            tclassid;
#endif

    struct  dst_ops            *ops;
        
    char            info[0];
};

2. struct rtable:
路由查询结果还不能直接供发送IP数据报使用，接下来，还必须根据这个查询结果生成一个路由目的入口(dst_entry)，根据目的入口才可以发

送IP 数据报，目的入口用结构体struct dst_entry表示，在实际使用时，还在它的外面包装了一层，形成一个结构体struct rtable。
struct rtable 
{
    union
    {
        struct dst_entry    dst;
        struct rtable        *rt_next;
    } u;

    unsigned        rt_flags;
    unsigned        rt_type;

    __u32            rt_dst;    /* Path destination    */
    __u32            rt_src;    /* Path source        */
    int            rt_iif;

    /* Info on neighbour */
    __u32            rt_gateway;

    /* Cache lookup keys */
    struct rt_key        key;

    /* Miscellaneous cached information */
    __u32            rt_spec_dst; /* RFC1122 specific destination */
    struct inet_peer    *peer; /* long-living peer info */

#ifdef CONFIG_IP_ROUTE_NAT
    __u32            rt_src_map;
    __u32            rt_dst_map;
#endif
};
struct dst_ops
{
    unsigned short        family;
    unsigned short        protocol;
    unsigned        gc_thresh;

    int            (*gc)(void);
    struct dst_entry *    (*check)(struct dst_entry *, __u32 cookie);
    struct dst_entry *    (*reroute)(struct dst_entry *,
                       struct sk_buff *);
    void            (*destroy)(struct dst_entry *);
    struct dst_entry *    (*negative_advice)(struct dst_entry *);
    void            (*link_failure)(struct sk_buff *);
    int            entry_size;

    atomic_t        entries;
    kmem_cache_t         *kmem_cachep;
};
struct rt_key
{
    __u32            dst; 
    __u32            src;
    int            iif;
    int            oif;
#ifdef CONFIG_IP_ROUTE_FWMARK
    __u32            fwmark;
#endif
    __u8            tos;
    __u8            scope;
};

struct rt_hash_bucket {
    struct rtable    *chain;
    rwlock_t    lock;
} __attribute__((__aligned__(8)));

; net/ipv4/route.c

static struct rt_hash_bucket     *rt_hash_table;
static unsigned            rt_hash_mask;
static int            rt_hash_log;

static __inline__ unsigned rt_hash_code(u32 daddr, u32 saddr, u8 tos)
{
    unsigned hash = ((daddr&0xF0F0F0F0)>>4)|((daddr&0x0F0F0F0F)<<4);
    hash ^= saddr^tos;
    hash ^= (hash>>16);
    return (hash^(hash>>8)) & rt_hash_mask;
}
static inline int ip_route_output(struct rtable **rp,
                      u32 daddr, u32 saddr, u32 tos, int oif)
{ 
    struct rt_key key = { dst:daddr, src:saddr, oif:oif, tos:tos };

    return ip_route_output_key(rp, &key);
}
int ip_route_output_key(struct rtable **rp, const struct rt_key *key)
{
    unsigned hash;
    struct rtable *rth;

    hash = rt_hash_code(key->dst, key->src^(key->oif<<5), key->tos); 

    read_lock_bh(&rt_hash_table[hash].lock);
    for (rth=rt_hash_table[hash].chain; rth; rth=rth->u.rt_next) { 
        if (rth->key.dst == key->dst &&
            rth->key.src == key->src &&
            rth->key.iif == 0 &&
            rth->key.oif == key->oif &&
#ifdef CONFIG_IP_ROUTE_FWMARK
            rth->key.fwmark == key->fwmark &&
#endif
            !((rth->key.tos^key->tos)&(IPTOS_RT_MASK|RTO_ONLINK)) &&
            ((key->tos&RTO_TPROXY) || !(rth->rt_flags&RTCF_TPROXY))
        ) {
            rth->u.dst.lastuse = jiffies;
            dst_hold(&rth->u.dst);
            rth->u.dst.__use++;
            read_unlock_bh(&rt_hash_table[hash].lock);
            *rp = rth;
            return 0;
        }
    }
    read_unlock_bh(&rt_hash_table[hash].lock);

    return ip_route_output_slow(rp, key);
}    
int ip_route_input(struct sk_buff *skb, u32 daddr, u32 saddr,
           u8 tos, struct net_device *dev) 將從設備dev上的輸入IP包綁定到目的入口
{
    struct rtable * rth;
    unsigned    hash;
    int iif = dev->ifindex;

    tos &= IPTOS_RT_MASK;
    hash = rt_hash_code(daddr, saddr^(iif<<5), tos);

    read_lock(&rt_hash_table[hash].lock);
    for (rth=rt_hash_table[hash].chain; rth; rth=rth->u.rt_next) {
        if (rth->key.dst == daddr &&
            rth->key.src == saddr &&
            rth->key.iif == iif &&
            rth->key.oif == 0 &&
#ifdef CONFIG_IP_ROUTE_FWMARK
            rth->key.fwmark == skb->nfmark &&
#endif
            rth->key.tos == tos) {
            rth->u.dst.lastuse = jiffies;
            dst_hold(&rth->u.dst);
            rth->u.dst.__use++;
            read_unlock(&rt_hash_table[hash].lock);
            skb->dst = (struct dst_entry*)rth;
            return 0;
        }
    }
    read_unlock(&rt_hash_table[hash].lock);

    /* Multicast recognition logic is moved from route cache to here.
       The problem was that too many Ethernet cards have broken/missing
       hardware multicast filters :-( As result the host on multicasting
       network acquires a lot of useless route cache entries, sort of
       SDR messages from all the world. Now we try to get rid of them.
       Really, provided software IP multicast filter is organized
       reasonably (at least, hashed), it does not result in a slowdown
       comparing with route cache reject entries.
       Note, that multicast routers are not affected, because
       route cache entry is created eventually.
     */
    if (MULTICAST(daddr)) {
        struct in_device *in_dev;

        read_lock(&inetdev_lock);
        if ((in_dev = __in_dev_get(dev)) != NULL) {
            int our = ip_check_mc(in_dev, daddr);
            if (our
#ifdef CONFIG_IP_MROUTE
                || (!LOCAL_MCAST(daddr) && IN_DEV_MFORWARD(in_dev))
#endif
                ) {
                read_unlock(&inetdev_lock);
                return ip_route_input_mc(skb, daddr, saddr, tos, dev, our);
            }
        }
        read_unlock(&inetdev_lock);
        return -EINVAL;
    }
    return ip_route_input_slow(skb, daddr, saddr, tos, dev);
}
