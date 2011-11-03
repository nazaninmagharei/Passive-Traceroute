/*#ifndef lint
static char *rcsid =
	"@(#)$Header: traceroute.c,v 1.17 89/02/28 21:01:13 van Exp $ (LBL)";
#endif
*/
/*
 * traceroute host  - trace the route ip packets follow going to "host".
 *
 * Attempt to trace the route an ip packet would follow to some
 * internet host.  We find out intermediate hops by launching probe
 * packets with a small ttl (time to live) then listening for an
 * icmp "time exceeded" reply from a gateway.  We start our probes
 * with a ttl of one and increase by one until we get an icmp "port
 * unreachable" (which means we got to "host") or hit a max (which
 * defaults to 30 hops & can be changed with the -m flag).  Three
 * probes (change with -q flag) are sent at each ttl setting and a
 * line is printed showing the ttl, address of the gateway and
 * round trip time of each probe.  If the probe answers come from
 * different gateways, the address of each responding system will
 * be printed.  If there is no response within a 5 sec. timeout
 * interval (changed with the -w flag), a "*" is printed for that
 * probe.
 *
 * Probe packets are UDP format.  We don't want the destination 
 * host to process them so the destination port is set to an
 * unlikely value (if some clod on the destination is using that
 * value, it can be changed with the -p flag).
 *
 * A sample use might be:
 *
 *     [yak 71]% traceroute nis.nsf.net.
 *     traceroute to nis.nsf.net (35.1.1.48), 30 hops max, 56 byte packet
 *      1  helios.ee.lbl.gov (128.3.112.1)  19 ms  19 ms  0 ms
 *      2  lilac-dmc.Berkeley.EDU (128.32.216.1)  39 ms  39 ms  19 ms
 *      3  lilac-dmc.Berkeley.EDU (128.32.216.1)  39 ms  39 ms  19 ms
 *      4  ccngw-ner-cc.Berkeley.EDU (128.32.136.23)  39 ms  40 ms  39 ms
 *      5  ccn-nerif22.Berkeley.EDU (128.32.168.22)  39 ms  39 ms  39 ms 
 *      6  128.32.197.4 (128.32.197.4)  40 ms  59 ms  59 ms
 *      7  131.119.2.5 (131.119.2.5)  59 ms  59 ms  59 ms
 *      8  129.140.70.13 (129.140.70.13)  99 ms  99 ms  80 ms
 *      9  129.140.71.6 (129.140.71.6)  139 ms  239 ms  319 ms
 *     10  129.140.81.7 (129.140.81.7)  220 ms  199 ms  199 ms
 *     11  nic.merit.edu (35.1.1.48)  239 ms  239 ms  239 ms
 *
 * Note that lines 2 & 3 are the same.  This is due to a buggy
 * kernel on the 2nd hop system -- lbl-csam.arpa -- that forwards
 * packets with a zero ttl.
 *
 * A more interesting example is:
 *
 *     [yak 72]% traceroute allspice.lcs.mit.edu.
 *     traceroute to allspice.lcs.mit.edu (18.26.0.115), 30 hops max
 *      1  helios.ee.lbl.gov (128.3.112.1)  0 ms  0 ms  0 ms
 *      2  lilac-dmc.Berkeley.EDU (128.32.216.1)  19 ms  19 ms  19 ms
 *      3  lilac-dmc.Berkeley.EDU (128.32.216.1)  39 ms  19 ms  19 ms
 *      4  ccngw-ner-cc.Berkeley.EDU (128.32.136.23)  19 ms  39 ms  39 ms
 *      5  ccn-nerif22.Berkeley.EDU (128.32.168.22)  20 ms  39 ms  39 ms
 *      6  128.32.197.4 (128.32.197.4)  59 ms  119 ms  39 ms
 *      7  131.119.2.5 (131.119.2.5)  59 ms  59 ms  39 ms
 *      8  129.140.70.13 (129.140.70.13)  80 ms  79 ms  99 ms
 *      9  129.140.71.6 (129.140.71.6)  139 ms  139 ms  159 ms
 *     10  129.140.81.7 (129.140.81.7)  199 ms  180 ms  300 ms
 *     11  129.140.72.17 (129.140.72.17)  300 ms  239 ms  239 ms
 *     12  * * *
 *     13  128.121.54.72 (128.121.54.72)  259 ms  499 ms  279 ms
 *     14  * * *
 *     15  * * *
 *     16  * * *
 *     17  * * *
 *     18  ALLSPICE.LCS.MIT.EDU (18.26.0.115)  339 ms  279 ms  279 ms
 *
 * (I start to see why I'm having so much trouble with mail to
 * MIT.)  Note that the gateways 12, 14, 15, 16 & 17 hops away
 * either don't send ICMP "time exceeded" messages or send them
 * with a ttl too small to reach us.  14 - 17 are running the
 * MIT C Gateway code that doesn't send "time exceeded"s.  God
 * only knows what's going on with 12.
 *
 * The silent gateway 12 in the above may be the result of a bug in
 * the 4.[23]BSD network code (and its derivatives):  4.x (x <= 3)
 * sends an unreachable message using whatever ttl remains in the
 * original datagram.  Since, for gateways, the remaining ttl is
 * zero, the icmp "time exceeded" is guaranteed to not make it back
 * to us.  The behavior of this bug is slightly more interesting
 * when it appears on the destination system:
 *
 *      1  helios.ee.lbl.gov (128.3.112.1)  0 ms  0 ms  0 ms
 *      2  lilac-dmc.Berkeley.EDU (128.32.216.1)  39 ms  19 ms  39 ms
 *      3  lilac-dmc.Berkeley.EDU (128.32.216.1)  19 ms  39 ms  19 ms
 *      4  ccngw-ner-cc.Berkeley.EDU (128.32.136.23)  39 ms  40 ms  19 ms
 *      5  ccn-nerif35.Berkeley.EDU (128.32.168.35)  39 ms  39 ms  39 ms
 *      6  csgw.Berkeley.EDU (128.32.133.254)  39 ms  59 ms  39 ms
 *      7  * * *
 *      8  * * *
 *      9  * * *
 *     10  * * *
 *     11  * * *
 *     12  * * *
 *     13  rip.Berkeley.EDU (128.32.131.22)  59 ms !  39 ms !  39 ms !
 *
 * Notice that there are 12 "gateways" (13 is the final
 * destination) and exactly the last half of them are "missing".
 * What's really happening is that rip (a Sun-3 running Sun OS3.5)
 * is using the ttl from our arriving datagram as the ttl in its
 * icmp reply.  So, the reply will time out on the return path
 * (with no notice sent to anyone since icmp's aren't sent for
 * icmp's) until we probe with a ttl that's at least twice the path
 * length.  I.e., rip is really only 7 hops away.  A reply that
 * returns with a ttl of 1 is a clue this problem exists.
 * Traceroute prints a "!" after the time if the ttl is <= 1.
 * Since vendors ship a lot of obsolete (DEC's Ultrix, Sun 3.x) or
 * non-standard (HPUX) software, expect to see this problem
 * frequently and/or take care picking the target host of your
 * probes.
 *
 * Other possible annotations after the time are !H, !N, !P (got a host,
 * network or protocol unreachable, respectively), !S or !F (source
 * route failed or fragmentation needed -- neither of these should
 * ever occur and the associated gateway is busted if you see one).  If
 * almost all the probes result in some kind of unreachable, traceroute
 * will give up and exit.
 *
 * Notes
 * -----
 * This program must be run by root or be setuid.  (I suggest that
 * you *don't* make it setuid -- casual use could result in a lot
 * of unnecessary traffic on our poor, congested nets.)
 *
 * This program requires a kernel mod that does not appear in any
 * system available from Berkeley:  A raw ip socket using proto
 * IPPROTO_RAW must interpret the data sent as an ip datagram (as
 * opposed to data to be wrapped in a ip datagram).  See the README
 * file that came with the source to this program for a description
 * of the mods I made to /sys/netinet/raw_ip.c.  Your mileage may
 * vary.  But, again, ANY 4.x (x < 4) BSD KERNEL WILL HAVE TO BE
 * MODIFIED TO RUN THIS PROGRAM.
 *
 * The udp port usage may appear bizarre (well, ok, it is bizarre).
 * The problem is that an icmp message only contains 8 bytes of
 * data from the original datagram.  8 bytes is the size of a udp
 * header so, if we want to associate replies with the original
 * datagram, the necessary information must be encoded into the
 * udp header (the ip id could be used but there's no way to
 * interlock with the kernel's assignment of ip id's and, anyway,
 * it would have taken a lot more kernel hacking to allow this
 * code to set the ip id).  So, to allow two or more users to
 * use traceroute simultaneously, we use this task's pid as the
 * source port (the high bit is set to move the port number out
 * of the "likely" range).  To keep track of which probe is being
 * replied to (so times and/or hop counts don't get confused by a
 * reply that was delayed in transit), we increment the destination
 * port number before each probe.
 *
 * Tim Seaver, Ken Adelman and C. Philip Wood provided bug fixes and/or
 * enhancements to the original distribution.
 *
 * I've hacked up a round-trip-route version of this that works by
 * sending a loose-source-routed udp datagram through the destination
 * back to yourself.  Unfortunately, SO many gateways botch source
 * routing, the thing is almost worthless.  Maybe one day...
 *
 *  -- Van Jacobson (van@helios.ee.lbl.gov)
 *     Tue Dec 20 03:50:13 PST 1988
 *
 * Copyright (c) 1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that the above copyright notice and this paragraph are
 * duplicated in all such forms and that any documentation,
 * advertising materials, and other materials related to such
 * distribution and use acknowledge that the software was developed
 * by the University of California, Berkeley.  The name of the
 * University may not be used to endorse or promote products derived
 * from this software without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED
 * WARRANTIES OF MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/stat.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
//#include </home/nazanin/trace/ip_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <ctype.h>
#include <inttypes.h>
#include <sys/inotify.h>

#define	MAXPACKET	65535	/* max ip packet size */
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	64
#endif

#define TRACE_FILENAME "/tmp/passive-trace-files/bismark-trace.gz"
#define LOG_FILENAME "/tmp/bismark-passive-flowlog"

#ifndef FD_SET
#define NFDBITS         (8*sizeof(fd_set))
#define FD_SETSIZE      NFDBITS
//#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)      bzero((char *)(p), sizeof(*(p)))
#endif

#define Fprintf (void)fprintf
#define Sprintf (void)sprintf
#define Printf (void)printf
#define TRACE_TABLE_ENTRIES 6553

#define IP_QUAD(ip)  (ip)>>24,((ip)&0x00ff0000)>>16,((ip)&0x0000ff00)>>8,((ip)&0x000000ff)
#define MAX_TH 10

/* size of the event structure, not counting name */
#define EVENT_SIZE  (sizeof (struct inotify_event))

/* reasonable guess as to size of 1024 events */
#define BUF_LEN        (1024 * (EVENT_SIZE + 16))

extern	int errno;
int inotify_init(void);
//void *  StartTrace (u_char * , u_char *, int *);
void * StartTrace(void *);
//extern int inotify_add_watch(int fd, const char* path, int mask);
/*
*format of an icmp probe packet
*/

struct icpacket{
        struct ip ip;
        struct icmphdr icp;
        u_char seq; // sequence number of this packet
        u_char ttl; // ttl packet left with
        struct timeval tv; //time packet left
};

/*
 * format of a (udp) probe packet.
 */
struct opacket {
	struct ip ip;
	struct udphdr udp;
	u_char seq;		/* sequence number of this packet */
	u_char ttl;		/* ttl packet left with */
	struct timeval tv;	/* time packet left */
};

u_char	packet[512];		/* last inbound (icmp) packet */
struct opacket	*outpacket[MAX_TH];	/* last output (udp) packet */
struct icpacket *outicpacket[MAX_TH]; //last icmp output packet
//u_char outicpacket[MAXPACKET];
char *inetname();

int rcvsock[MAX_TH];				/* receive (icmp) socket file descriptor */
int sndsock[MAX_TH];			/* send (udp) socket file descriptor */
struct timezone tz[MAX_TH];		/* leftover */

struct sockaddr whereto[MAX_TH];	/* Who to try to reach */
struct sockaddr_in wherefrom;
int datalen[MAX_TH];			/* How much data */

char *source = 0;

int nprobes = 3;
int max_ttl = 30;
u_short ident[MAX_TH];
u_short port[MAX_TH];	/* start udp dest port # for probe packets */
int stport= 32768+666;

int options;			/* socket options */
int verbose=0;
int waittime = 5;		/* time to wait for response (in seconds) */
int nflag;			/* print addresses numerically */
uint32_t src[MAX_TH][TRACE_TABLE_ENTRIES];
int flowid[MAX_TH][TRACE_TABLE_ENTRIES];
uint64_t sessionid[MAX_TH];

u_short in_cksum(u_short *, int ); 
/* From Stevens, UNP2ev1 */ 
/*unsigned short in_cksum(unsigned short *addr, int len) 
{ 	int nleft = len; int sum = 0; unsigned short *w = addr; 
        unsigned short answer = 0; while (nleft > 1) { sum += *w++; nleft -= 2; } 
        if (nleft == 1) { *(unsigned char *)(&answer) = *(unsigned char *)w; sum += answer; } 
        sum = (sum >> 16) + (sum & 0xffff); sum += (sum >> 16); answer = ~sum; return (answer);
}*/

/*
 * Convert an ICMP "type" field to a printable string.
 */
char *
pr_type(t)
	u_char t;
{
	static char *ttab[] = {
	"Echo Reply",	"ICMP 1",	"ICMP 2",	"Dest Unreachable",
	"Source Quench", "Redirect",	"ICMP 6",	"ICMP 7",
	"Echo",		"ICMP 9",	"ICMP 10",	"Time Exceeded",
	"Param Problem", "Timestamp",	"Timestamp Reply", "Info Request",
	"Info Reply"
	};

	if(t > 16)
		return("OUT-OF-RANGE");

	return(ttab[t]);
}

char localh[10][NI_MAXHOST]; //can malloc for a better memory allocation in getsrcip instead!
                                //this stores the local ip addresses of interfaces
int locind=0;
                                 
unsigned long getsrcip ()
{
   bzero(localh,sizeof(localh));
   struct ifaddrs *ifaddr, *ifa;
   int family, s;
   char host[NI_MAXHOST];
   FILE * f = fopen("/proc/net/route","r");
   /* Find the appropriate interface */
   int i, n = 0;
   int mask = 0;
   uint32_t dest, tmask;
   char buf[256], tdevice[256], device[256];
   device[0] = '\0';
   struct hostent *hp;
   char * a;
   a="www.google.com";
   bzero(buf,sizeof(buf));
   bzero(tdevice,sizeof(tdevice));
   bzero(device,sizeof(device));
   hp = gethostbyname(a);
   struct sockaddr_in to;
   printf("%s %d\n",hp->h_addr, hp->h_length);                                                                                       
      
   bcopy(hp->h_addr, (caddr_t)&to.sin_addr, hp->h_length);
   while (fgets(buf, sizeof(buf), f) != NULL) {
                    ++n;
                    if (n == 1 && strncmp(buf, "Iface", 5) == 0)
                           continue;
                    i = sscanf(buf, "%255s %x %*s %*s %*s %*s %*s %x",tdevice, &dest, &tmask);
                    printf("%s %d %d\n",tdevice, dest, mask);
//                    if (i != 3)
//                           bb_error_msg_and_die("junk in buffer");
                    if ((to.sin_addr.s_addr & tmask) == dest
                                 && (tmask > mask || mask == 0)){
                           mask = tmask;
                           strcpy(device, tdevice);
                    }
     }
   fclose(f);
     if (device[0] == '\0')
        printf("can't find interface\n");
                                                                                                                                                                                                                                                                                                                                                    
   printf("%d\n",NI_MAXHOST);   
   if (getifaddrs(&ifaddr) == -1) {
                perror("getifaddrs");
                exit(EXIT_FAILURE);
               }
        printf("ifaddr %s\n",ifaddr->ifa_name);                            
   for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
   {if (ifa->ifa_addr == NULL)
      continue;
                      
    family = ifa->ifa_addr->sa_family;
    if (family == AF_INET) {
         s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in),
                                      host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                if (s != 0) {
                             printf("getnameinfo() failed: %s\n", gai_strerror(s));                                                                                      
                             exit(EXIT_FAILURE);
                            }
                if (strcmp(device, ifa->ifa_name) == 0)
                       { inet_aton(host, &to.sin_addr);
//                         to.sin_addr.s_addr=(in_addr_t)(ifa->ifa_addr->sa_data);
                          printf("%d %s\n",to.sin_addr.s_addr, inet_ntoa(to.sin_addr));
                       }       
                strcpy(localh[locind],host);
                locind++;
                printf("<Interface>: %s \t <Address> %s\n", ifa->ifa_name, host);
                if(locind>=10) {printf("More local addresses than allocated, skip the rest\n");
                                return to.sin_addr.s_addr;
                               } 
    }
   }
  return to.sin_addr.s_addr;
                                                                                                                                                                                                                            
}

int is_valid_ip(const char *ip_str)
{
        unsigned int n1,n2,n3,n4;
        int i;        
        if(sscanf(ip_str,"%u.%u.%u.%u", &n1, &n2, &n3, &n4) != 4) return 0;
        printf("addr to validate %s\n",ip_str);
        if(n1==127) return 0; //127/8
        
        if(n1==10) return 0;//10/8
        if(n1==172 && (n2>=16 && n2<=31)) return 0; //172.16/12
        if(n1==169 && n2==254) return 0; //169.254/16
        if(n1==192)
         {if(n2==0 && n3==0) return 0;//192.0.0/24
          else if(n2==0 && n3==2) return 0; //192.0.2/24
          else if(n2==88 && n3==99) return 0;//192.88.99/24
          else if(n2==168) return 0; //192.168/16
         }
        if(n1==198) 
        {if(n2==19 || n2==18) return 0; //198.18/15
         else if(n2==51 && n3==100) return 0; //198.51.100/24 
        }                 
        if(n1==203 && n2==0 && n3==113) return 0; //203.0.113/24
        if(n1>=224) return 0;//224/3
        if(n1==0) return 0;//0/8
        for(i=0;i<locind; i++)
          if(!strcmp(ip_str,localh[i])) return 0;
                 
        if((n1 < 224) && (n2 <= 255) && (n3 <= 255) && (n4 <= 255) && (n4!=0)) {
                                char buf[64];
                                sprintf(buf,"%u.%u.%u.%u",n1,n2,n3,n4);
                                if(strcmp(buf,ip_str)) return 0;
                                return 1;
                           }
         
        return 0;
}

int send_probe(seq, ttl,to,id)
int seq;
int ttl;
char * to;
int id;
{
	struct opacket *op = outpacket[id];
	struct ip *ip = &op->ip;
	struct udphdr *up = &op->udp;
	int i;

	ip->ip_off = 0;
	ip->ip_p = IPPROTO_UDP;
	ip->ip_len = datalen[id];
	ip->ip_ttl = ttl;
	ip->ip_hl = 5;
	ip->ip_v = 4;
	ip->ip_len = sizeof(struct ip);
	up->source = htons(ident[id]);
	up->dest = htons(port[id]+seq);
	up->len = htons((u_short)(datalen[id] - sizeof(struct ip)));
	up->check = 0;

	op->seq = seq;
	op->ttl = ttl;
	(void) gettimeofday(&op->tv, &tz[id]);

	i = sendto(sndsock[id], (char *)outpacket[id], datalen[id], 0, &whereto[id],
		   sizeof(struct sockaddr));
	if (i < 0 || i != datalen[id])  {
		if (i<0)
			perror("sendto");
		Printf("traceroute to %s: wrote %d chars, ret=%d\n",to,datalen[id], i);
		(void) fflush(stdout);
	}
	return 0;
}
#if defined(__GLIBC__) && (__GLIBC__ >= 2)
#define icmphdr			icmp
#endif

#if !defined(__GLIBC__) || (__GLIBC__ < 2)
#define icmp_id un.echo.id
#define icmp_seq un.echo.sequence
#endif /* __GLIBC__ */

int send_probe_ic(seq, ttl,to,id) 
int seq;
int ttl;
char * to;
int id;
{//first construct the IP header
//	register struct icmphdr * up;
 //       up=(struct icmphdr *) outicpacket;
	struct icpacket *op = outicpacket[id];
	struct ip *ip = &op->ip;
	ip->ip_v=4;
	ip->ip_len=sizeof(struct ip);
	ip->ip_p=IPPROTO_ICMP;
/*	ip->tos //set before
	ip->dest //set before
	ip->src //set before*/
	ip->ip_off=0;
	ip->ip_hl=5;
        ip->ip_ttl = ttl;
        ip->ip_id = htons(ident[id]);//?
        
        //now construct the protocol header (icmp)
                	
	struct icmp *up = (struct icmp *) &op->icp;
	int i;

	up->icmp_type = ICMP_ECHO;
	up->icmp_code=0;
	up->icmp_cksum=0;
	up->icmp_id=htons(ident[id]);
	up->icmp_seq=htons(seq);
	
	op->seq = seq;
	op->ttl = ttl;
	
	//this may not be correct?
	(void) gettimeofday(&op->tv, &tz[id]);
	//icmp packet length = icmp header len + data len
	 int icmp_hdr_n_data_len       = sizeof(*up);
	//may not be correct?
	 ip->ip_len= sizeof(struct ip)+icmp_hdr_n_data_len;
	 
	up->icmp_cksum = in_cksum((u_short *)up,icmp_hdr_n_data_len);
	printf("ttl %d checksum %d\n",ttl,up->icmp_cksum);
        if (up->icmp_cksum == 0)
           up->icmp_cksum = 0xffff;
	                                                            
        
	i = sendto(sndsock[id], (char *)outicpacket[id], datalen[id], 0, &whereto[id],
		   sizeof(struct sockaddr));
	if (i < 0 || i != datalen[id])  {
	        printf("i %d %d\n",i,up->icmp_cksum);
		if (i<0)
			perror("sendto");
		Printf("ICMP traceroute to %s: wrote %d chars, ret=%d\n",to,datalen[id], i);
		(void) fflush(stdout);
	}
	 if (verbose) {
	                 Printf("\n%d bytes ", datalen[id]);  
                         Printf(": icmp type %d (%s) code %d id %d seq %d\n", up->icmp_type, pr_type(up->icmp_type),up->icmp_code,up->icmp_id,up->icmp_seq);
                      }  	                                                                                                                                                                
	return 0;
}


/*
 * Subtract 2 timeval structs:  out = out - in.
 * Out is assumed to be >= in.
 */
int tvsub(out, in)
register struct timeval *out, *in;
{
	if ((out->tv_usec -= in->tv_usec) < 0)   {
		out->tv_sec--;
		out->tv_usec += 1000000;
	}
	out->tv_sec -= in->tv_sec;
	return 0;
}

double deltaT(tp,id)
	struct timeval *tp;
{
	struct timeval tv;

	(void) gettimeofday(&tv, &tz[id]);
	tvsub(&tv, tp);
	return (tv.tv_sec*1000.00 + (tv.tv_usec + 500.00)/1000.00);
}


int wait_for_reply(sock, from)
	int sock;
	struct sockaddr_in *from;
{
	fd_set fds;
	struct timeval wait;
	int cc = 0;
	int fromlen = sizeof (*from);

	FD_ZERO(&fds);
	FD_SET(sock, &fds);
	wait.tv_sec = waittime; wait.tv_usec = 0;

	if (select(sock+1, &fds, (fd_set *)0, (fd_set *)0, &wait) > 0)
		cc=recvfrom(sock, (char *)packet, sizeof(packet), 0,
			    (struct sockaddr *)from, (socklen_t *)&fromlen);

	return(cc);
}

int packet_ok(buf, cc, from, seq, id)
	u_char *buf;
	int cc;
	struct sockaddr_in *from;
	int seq;
	int id;
{
	register struct icmp *icp;
	u_char type, code;
	int hlen;
	struct ip *ip;
	
        ip = (struct ip *) buf;
        hlen = ip->ip_hl << 2;
	                
#ifndef ARCHAIC
//	struct ip *ip;

//	ip = (struct ip *) buf;
//	hlen = ip->ip_hl << 2;
	if (cc < hlen + ICMP_MINLEN) {
		if (verbose)
			Printf("packet too short (%d bytes) from %s\n", cc,
				inet_ntoa(from->sin_addr));
		return (0);
	}
	cc -= hlen;
	icp = (struct icmp *)(buf + hlen);
#else
	icp = (struct icmp *)buf;
#endif 
	type = icp->icmp_type; code = icp->icmp_code;
	if ((type == ICMP_TIMXCEED && code == ICMP_TIMXCEED_INTRANS) ||
	    type == ICMP_UNREACH || type == ICMP_ECHOREPLY) {
		struct ip *hip;
		struct udphdr *up;
		
		hip = &icp->icmp_ip;
		hlen = hip->ip_hl << 2;
		up = (struct udphdr *)((u_char *)hip + hlen);
		struct icmp * hicmp = (struct icmp *)((unsigned char *)hip + hlen);
	if(verbose){
		printf("receive %d bytes from %s to %s %s %s \n",cc, inet_ntoa(from->sin_addr), inet_ntoa(ip->ip_dst),inet_ntoa(ip->ip_src),pr_type(type));
		
		printf("id %d %d seq %d %d code %d type %d\n",hicmp->icmp_id,htons(ident[id]),hicmp->icmp_seq,htons(seq),code,type);}
		if (type == ICMP_ECHOREPLY && icp->icmp_id == htons(ident[id]) && icp->icmp_seq == htons(seq))
                  return -2;
		                                                                                        
		if(hip->ip_p == IPPROTO_UDP)
		{ if (hlen + 12 <= cc &&
		    up->source == htons(ident[id]) &&
		    up->dest == htons(port[id]+seq))
			return (type == ICMP_TIMXCEED? -1 : code+1);
		}
		else if(hip->ip_p == IPPROTO_ICMP)
		{ if (hlen + 12 <= cc  &&
	                hicmp->icmp_id == htons(ident[id]) &&
                        hicmp->icmp_seq == htons(seq))
		        return (type == ICMP_TIMXCEED? -1 : code+1);
		}                                        	
	}
#ifndef ARCHAIC
	if (verbose) {
		int i;
		u_long *lp = (u_long *)&icp->icmp_ip;

		Printf("\n%d bytes from %s to %s", cc,
			inet_ntoa(from->sin_addr), inet_ntoa(ip->ip_dst));
		Printf(": icmp type %d (%s) code %d\n", type, pr_type(type),
		       icp->icmp_code);
		for (i = 4; i < cc ; i += sizeof(long))
			Printf("%2d: x%8.8lx\n", i, *lp++);
	}
#endif 
	return(0);
}


int print(buf, cc, from, hd)
	u_char *buf;
	int cc;
	struct sockaddr_in *from;
	gzFile hd;
{
	struct ip *ip;
	int hlen;

	ip = (struct ip *) buf;
	hlen = ip->ip_hl << 2;
	cc -= hlen;

	if (nflag)
	        gzprintf(hd," %s", inet_ntoa(from->sin_addr));
//		Printf(" %s", inet_ntoa(from->sin_addr));
	else
		gzprintf(hd," %s", inet_ntoa(from->sin_addr));

	if (verbose)
		Printf (" %d bytes to %s", cc, inet_ntoa (ip->ip_dst));
	return 0;
}

void checkfile(char * logfile,int id)
{ 
 char line[500];
 struct stat st;
 if(stat("/tmp/passive-trace-files",&st) != 0)
  { strcpy(line,"mkdir /tmp/passive-trace-files");
    system(line);
    return; //nothing here yet
  }     
// char log[200]; 
// sprintf(log,"%s%d",TRACE_FILENAME,id);
 printf("%s\n",logfile);
 if(stat(logfile,&st) ==0 ) //update file exists
  {if(st.st_size==0) 
   {printf("%s size is zero\n",logfile);
    return;//size is zero
   }
  }  
 else {printf("%s does not exist\n",logfile);
       return;//does not exist
      } 
 time_t tim=time(NULL);
 struct tm * now=localtime(&tim);
 printf("Date is %d/%02d/%02d\n", now->tm_year+1900, now->tm_mon+1, now->tm_mday);
 printf("Time is %02d:%02d\n", now->tm_hour, now->tm_min);
 bzero(line,sizeof(line));
 char log[200];
 sprintf(log,"/tmp/passive-trace-files/`cat /etc/bismark/ID`_th%d_date%d_%02d-%02d-%02d_%02d_%02d.tar",id,now->tm_year+1900,now->tm_mon+1,now->tm_mday,now->tm_hour, now->tm_min,now->tm_sec);
// sprintf(line,"tar cvfP /tmp/passive-trace-files/`cat /etc/bismark/ID`_`date%d_%02d-%02d-%02d_%02d_%02d`.tar %s",now->tm_year+1900,now->tm_mon+1,now->tm_mday,now->tm_hour, now->tm_min,now->tm_sec,logfile);
 sprintf(line,"tar cvf %s %s",log,logfile);
 printf("%s\n",line);
 system(line);
// char key[50]="/etc/bismark/bismark_key";
// char user[10]="bismark";
 char key[50]="/etc/dropbear/dropbear_rsa_host_key";
 char user[10]="nazanin";
 char server[50]="prober.projectbismark.net";
 sprintf(line,"scp -S \"/tmp/bismark/ssh\" -i %s %s %s@%s:var/data/passive/trace && (rm %s; rm %s)",key,log,user,server,log,logfile);  
 printf("line %s\n",line);
 system(line);
// #. /etc/bismark/bismark.conf
 
//       (cd $STAGING_DIR && tar cvf $MANIFEST_FILE *.gz)
// sprintf(line,"scp -S \"/usr/bin/ssh\" -i $SSH_KEY %s $USER@$SERVER:var/data/passive && (rm %s;)",log,log);
//       fi
       
// sprintf(line,"sh passive-submit.sh %s",logfile);
// printf("%s\n",line);
// system(line);
 
 /*FILE * fp = fopen(logfile, "r");
 if (fp == NULL) {
   fprintf(stderr, "Can't open output file %s!\n", logfile);
             return;
             }
            
 char line[65536];
 int sind=0; 
 while (fgets(line, sizeof line, fp) !=NULL){
         sind++;
         break;
 }
 if(sind>0)                                                                                          
  //call scp
  */
}

int whois(char * dest,int id)
{ 

 char line[500];
 bzero(line,sizeof(line)); 
 char regex []= "\"\\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b\"";
   
 //sprintf(line,"whois -h whois.cymru.com \" -p -o %s\" | cut -d '|' -f 3 | egrep %s | tr / ' ' > sub%d",dest,regex,id);
 sprintf(line,"echo \"-p -o %s\" | netcat whois.cymru.com 43 | cut -d '|' -f 3 | egrep %s | tr / ' ' > sub%d",dest,regex,id);                   
 system(line);
 return 0;
}

int checkid(uint32_t * src, uint32_t adr, int ind){

int i;
 for(i=0;i<ind;i++)
 {if(src[i]==adr) //identical
   {printf("found already %d %d src %u\n",ind,i,src[i]);
    return 0;
   } 
 }
 return 1;
}
    
int Extract(id)
{	char FlowlogFile[] = "/tmp/bismark-passive-flowlog";
        FILE * fp = fopen(FlowlogFile, "r");
	if (fp == NULL) {
	  fprintf(stderr, "Can't open output file %s!\n",
	            FlowlogFile);
	              exit(1);
	             }
//	int sind=0,
	int ind=0;
        char line[65536];
        char *lpt;
             
/*	while (fgets(line, sizeof line, fp) !=NULL){
	sind++;
	}*/
//	printf("number of flows %d\n",sind);                
	rewind(fp);
        bzero(line,sizeof(line));

        while (fgets(lpt = line, sizeof line, fp)!=NULL){
         if(ind >= TRACE_TABLE_ENTRIES) {printf("Larger than allocated memory of %d %d\n",TRACE_TABLE_ENTRIES,ind); break;}
         char * pch=strpbrk(line," ");
 	 char pt[50];
 	 bzero(pt,sizeof(pt));
   	 int nw=0;
         struct in_addr checkad_s,checkad_d;
         uint32_t tmp;
         
	 while(pch !=NULL){
          nw++;
          pch=strpbrk(pch+1," ");    
         }
         if(nw==1) //first line of session id
          {sscanf(lpt,"%" PRIu64,&sessionid[id]);
                            
          }
         if(nw==3)                            	                             
         {int fl,k,l;
          sscanf(lpt,"%d",&fl);
          sprintf(pt,"%d",fl);
        //  printf("lpt %s\n",lpt);
          lpt++;
          lpt=lpt+strlen(pt);
                   
          sscanf(lpt,"%" PRIx32,&tmp);
          sprintf(pt,"%" PRIx32,tmp);
//          printf("lpt %s\n",lpt);
          lpt++;
          lpt=lpt+strlen(pt);
       //   printf("%s %u\n",lpt,tmp);
                    
          checkad_s.s_addr=htonl(tmp);
        //  printf("%u %u\n",tmp,checkad_s.s_addr);
                  
          sscanf(lpt,"%" PRIx32,&tmp);
          sprintf(pt,"%" PRIx32 ,tmp); 
      //    printf("%s %u\n",lpt,tmp);
          
          checkad_d.s_addr =htonl(tmp);
        //  printf("%u %u\n",tmp,checkad_d.s_addr);
          
          k=is_valid_ip(inet_ntoa((struct in_addr)checkad_d));
          l=is_valid_ip(inet_ntoa((struct in_addr)checkad_s));          
          if(!k && !l)
           {printf("invalid %s %s\n",inet_ntoa(checkad_d),inet_ntoa(checkad_s));
            continue;
           }
           
          flowid[id][ind]=fl;
	  if(k==1) {if(checkid(src[id],checkad_d.s_addr,ind))
	            {src[id][ind]=checkad_d.s_addr;
	             printf("%d.%d.%d.%d\n",IP_QUAD(src[id][ind]));
	             ind++;
	            }  
	           }          
	  if(l==1) {if(checkid(src[id],checkad_s.s_addr,ind)) 
	            {src[id][ind]=checkad_s.s_addr;
               	     printf("%d.%d.%d.%d\n",IP_QUAD(src[id][ind]));
          	     ind++;
          	    }
          	   }  
/*	  lpt++;
	  lpt=lpt+strlen(pt);
	  sscanf(lpt,"%" PRIx32,&dest[ind]);  
          sprintf(pt,"%" PRIx32,dest[ind++]);  */
          bzero(line,sizeof(line));
         } 
	}
	printf("number of flows %d\n",ind);
return ind;
}

/*const char *byte_to_binary(int x) {
        static char b[9];
        b[0] = '\0';
            
        int z;
        for (z = 256; z > 0; z >>= 1)
         strcat(b, ((x & z) == z) ? "1" : "0");                                    
         return b;
}*/
                                        
int is_ip_in_net(struct in_addr from,char * netmask,unsigned long mask)
{	
        printf("in is_ip\n");
        if(mask<=0 || mask>32) {printf("wrong mask %lu\n",mask); return 0;}
        unsigned long nm2;
        nm2 = ~((1 << (32 - mask)) - 1);
        printf("%lu %lx\n",nm2,nm2);
        struct sockaddr_in nw;
        inet_aton((char *)netmask,&nw.sin_addr);
        unsigned long ip=ntohl(from.s_addr);
        unsigned long net=ntohl(nw.sin_addr.s_addr);
        printf("broadcast %s %s %lu\n",inet_ntoa(from),netmask, nm2);
        printf("broadcast %lu %lu %lx %lx\n",(long unsigned)from.s_addr,(long unsigned)nw.sin_addr.s_addr,(long unsigned)from.s_addr,(long unsigned)nw.sin_addr.s_addr);
        printf("broadcast %lu %lu %lx %lx\n",(long unsigned)ntohl(from.s_addr), (long unsigned)ntohl(nw.sin_addr.s_addr),(long unsigned)ntohl(from.s_addr), (long unsigned)ntohl(nw.sin_addr.s_addr));      
        unsigned long network1=(ip & nm2);
        unsigned long network2=(net & nm2);
                  
        printf("broadcast %lx %lx %lu %lu %lx %lx\n",(ip & nm2), (net & nm2), ip|nm2, net|nm2,ip|nm2, net|nm2); 
        if(network1==network2)// reach to the destination network
                return 1;
        else return 0;        
}
                                             
char usage[] =
 "Usage: traceroute [-dnrv] [-w wait] [-m max_ttl] [-p port#] [-q nqueries] [-t tos] [-s src_addr] [-g gateway] host [data size]\n";

#include <pthread.h>
/* This is the prototype for our thread function */
//void *mythread(void *data);
/* We must initialize our mutex */
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
int activeth=0;
int idleth[MAX_TH];//keep tracks of the idle threads upto max threads of 10

/* create thread argument struct for StartTrace() */
typedef struct _thread_data_t {
  int tid;
  int * tos;  
} thread_data_t;
    
int main(argc, argv)
	char *argv[];
{
	char **av = argv;
	int tos = 0;

	   pthread_t tids[MAX_TH];
	      int i;
	thread_data_t thr_data[MAX_TH];
	
	argc--, av++;
	while (argc && *av[0] == '-')  {
        	while (*++av[0])
			switch (*av[0]) {
			case 'm':
				argc--, av++;
				max_ttl = atoi(av[0]);
				if (max_ttl <= 1) {
					Fprintf(stderr, "max ttl must be >1\n");
					exit(1);
				}
				goto nextarg;
			case 'p':
				argc--, av++;
				stport = atoi(av[0]);
				if (stport < 1) {
					Fprintf(stderr, "port must be >0\n");
					exit(1);
				}
				goto nextarg;
			case 'q':
				argc--, av++;
				nprobes = atoi(av[0]);
				if (nprobes < 1) {
					Fprintf(stderr, "nprobes must be >0\n");
					exit(1);
				}
				goto nextarg;
			case 'w':
				argc--, av++;
				waittime = atoi(av[0]);
				if (waittime <= 1) {
					Fprintf(stderr, "wait must be >1 sec\n");
					exit(1);
				}
				goto nextarg;
			}
	nextarg:
		argc--, av++;
	}
	printf("arg %d\n",argc);
	if (argc!=0)  {
		Printf(usage);
		exit(1);
	}
	setlinebuf (stdout);
        wherefrom.sin_addr.s_addr=getsrcip();
        printf("wherefrom %s \n",inet_ntoa(wherefrom.sin_addr));
	int fd,wd;
	fd = inotify_init ();
	if(fd<0)
	  perror ("inotify_init");
//	wd = inotify_add_watch (fd,LOG_FILENAME, IN_MODIFY | IN_CREATE);
//	if (wd < 0)
//	        perror ("inotify_add_watch");
        wd = inotify_add_watch (fd, "/tmp/bismark-passive-flowlog" , IN_MODIFY);	
	struct timeval time;
	int ret;
	
	time.tv_sec=5.0;
	time.tv_usec =0 ;
        
        fd_set rfds;	
//	FD_ZERO (&rfds);
//	FD_SET(fd, &rfds);

	char buf[BUF_LEN];

	int len, count=0;
	int idle=0;
	while (1) {//fd = inotify_init ();
	           //if(fd<0)
	           //perror ("inotify_init");
                   FD_ZERO (&rfds);
                   FD_SET(fd, &rfds);
	                                  
	           //wd = inotify_add_watch (fd, "/tmp/bismark-passive-flowlog" , IN_MODIFY | IN_CREATE | IN_ACCESS | IN_CLOSE_NOWRITE| IN_OPEN | IN_CLOSE_WRITE);
	           if (wd < 0)
                        perror ("inotify_add_watch");
	                                   
	           ret = select (fd+1, &rfds, NULL,NULL,&time);
	           printf ("one exit %d %f %d\n",(int)time.tv_sec,(float)time.tv_usec,ret);
	           
	           if (ret < 0)
	                   perror ("select");
                   else if (!ret)
	            {time.tv_usec=0; time.tv_sec=20.0;}        
	           if(ret>0)
	           { 
	             count=0;
	             len= read(fd,buf,BUF_LEN);
	             
	             if(len <0 ) {
	              perror( "read" );
	             }
	             while (count<len) {
	              struct inotify_event *event;
	             
                      event = (struct inotify_event *) &buf[count];
                      printf ("wd=%d mask=%u cookie=%u len=%u\n",event->wd, event->mask,event->cookie, event->len);
                      if(event->len) printf ("name=%s\n", event->name);
                     
                      count += EVENT_SIZE + event->len;
	             }
	             if(activeth==MAX_TH) {printf("no idle threads found, active %d\n",activeth); 
	             
	                                     continue;
	                                  }
	                                     
	             int sflag=0;
	             for(i=0;i<MAX_TH;i++)
	              if(idleth[i]==0) {idle=i;
	                                idleth[i]=1;
	                                sflag=1;
	                                break;
	                               }
	             if(sflag==0) 
	                {printf("no idle threads found, but active %d\n",activeth); 
                          exit(0);
                        }                       	               
	             thr_data[idle].tid=idle;
	             thr_data[idle].tos=&tos;
                     pthread_create(&tids[idle], NULL, StartTrace,&thr_data[idle] );
	             printf("after create %d\n",idle);
                     pthread_detach(tids[idle]);
//                     pthread_join(tids[idle], NULL);
//	             StartTrace(optlist, oix, &tos);
//                     printf("Thread id %d returned\n",idle);
	           }
        	 } 
	                       
}

//int  StartTrace (u_char * optlist, u_char * oix, int * tos)
void * StartTrace(void *arg)
{
       thread_data_t *data=(thread_data_t*) arg;
       int * tos= data->tos;
       int  id= data->tid; 
       pthread_mutex_lock(&log_mutex);
       activeth++;
       pthread_mutex_unlock(&log_mutex);
       char filename[100];
       bzero(filename,sizeof(filename));
//       checkfile(filename,id);              
       sprintf( filename, "%s%u", TRACE_FILENAME, id );
       printf("%s\n",filename);
       checkfile(filename,id);
	int ct=Extract(id);
	gzFile hd;
	if(ct>0) {printf("ct %d\n",ct); 
	          hd = gzopen (filename, "wb");
	
                  if (!hd) {
                            perror("Could not open update file for writing");
                            exit(1);
                           }                                                         
	                gzprintf(hd,"%" PRIu64 "\n", sessionid[id]);
	         }       
	int seq=0;
	int i=0;
	int k=0;
	int probe,ttl;
	struct protoent *pe;
        struct sockaddr_in *to = (struct sockaddr_in *) &whereto[id];
        struct sockaddr_in *from = (struct sockaddr_in *)&wherefrom;
                
        int on = 1;
        datalen[id]=0;        	
        printf("id %d %u\n",id,id);
	for(k=0;k<ct;k++)
	{
                seq=0;
        	(void) bzero((char *)&whereto[id], sizeof(struct sockaddr));
        	to->sin_family = AF_INET;
                to->sin_addr.s_addr=(in_addr_t)src[id][k];
                char line[200];
                bzero(line,sizeof(line));
                whois(inet_ntoa(to->sin_addr),id);
                printf("id %d %u\n",id,id);
                        
                char SUB[100];
                bzero(SUB,sizeof(SUB));
                sprintf(SUB,"sub%d",id);
                FILE *dhd=fopen(SUB,"r");
                char netmask[100];
                bzero(netmask,sizeof(netmask));
                unsigned int mask;      
                if(dhd==NULL) printf("error opening file %s\n",SUB);
                else if(fgets(line,sizeof line, dhd) !=NULL){
                  sscanf(line,"%s %u",netmask,&mask);
                }             
                printf("network: %s mask:%u\n",netmask,mask);
                datalen[id]=0;
                datalen[id] += sizeof(struct opacket);
        	printf("datalen %d\n",datalen[id]);	
        	outpacket[id] = (struct opacket *)malloc((unsigned)datalen[id]);
        	if (! outpacket[id]) {
 	        	perror("traceroute: malloc");
	        	exit(1);
        	}
        	
        	(void) bzero((char *)outpacket[id], datalen[id]);
        	outpacket[id]->ip.ip_dst = to->sin_addr;
        	outpacket[id]->ip.ip_tos = *(tos);
                outicpacket[id] = (struct icpacket *) malloc((unsigned)datalen[id]);
                if (! outicpacket[id]) {
	        	perror("traceroute: malloc");
	        	exit(1);
        	}
        	
        	outicpacket[id]->ip.ip_dst = to->sin_addr;
        	outicpacket[id]->ip.ip_tos = *(tos);
                
        	ident[id] = ((getpid()+id) & 0xffff) | 0x8000;
                port[id]= stport+max_ttl*id;
                printf("id %d ident %d port %d\n",id,ident[id],port[id]);
                
        	if ((pe = getprotobyname("icmp")) == NULL) {
		        Fprintf(stderr, "icmp: unknown protocol\n");
	        	exit(10);
        	}
        	if ((rcvsock[id] = socket(AF_INET, SOCK_RAW, pe->p_proto)) < 0) {
	        	printf("%d %d\n",pe->p_proto,  rcvsock[id]);
	        	perror("traceroute: icmp socket");
        		exit(5);
        		}
				  if ((sndsock[id] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        		perror("traceroute: raw socket");
	        	exit(5);
        	}

#ifdef SO_SNDBUF
        	if (setsockopt(sndsock[id], SOL_SOCKET, SO_SNDBUF, (char *)&datalen[id],
		       sizeof(datalen[id])) < 0) {
	        	perror("traceroute: SO_SNDBUF");
	        	exit(6);
        	}
#endif 

#ifdef IP_HDRINCL
	        if (setsockopt(sndsock[id], IPPROTO_IP, IP_HDRINCL, (char *)&on,
		       sizeof(on)) < 0) {
		       perror("traceroute: IP_HDRINCL");
        		exit(6);
        		}
#endif 

        	
        	gzprintf(hd, "traceroute to %s %d\n",inet_ntoa(to->sin_addr),flowid[id][k]);
        	(void) fflush(stderr);

        	for (ttl = 1; ttl <= max_ttl; ++ttl) {
	        	u_long lastaddr = 0;
	        	int gotlastaddr = 0;
        		int got_there = 0;
	        	int unreachable = 0;
	        	
        		gzprintf(hd,"ID: %d %2d %d %d %d", id, ttl, seq, port[id], ident[id]);
	        	for (probe = 0; probe < nprobes; ++probe) {
		        	int cc;
		        	struct timeval tv;
	        		struct ip *ip;
        			
		        	(void) gettimeofday(&tv, &tz[id]);
		        	send_probe(++seq, ttl,inet_ntoa(to->sin_addr),id);
			                        
	        		while ((cc = wait_for_reply(rcvsock[id], from))) {
		        	        i=packet_ok(packet, cc, from, seq,id);
			                if(i==0) continue;
			                else {
				                ip = (struct ip *)packet;
        					double dt = deltaT(&tv,id);
	        				if (!gotlastaddr || from->sin_addr.s_addr != lastaddr) {
                                                    #ifndef DISABLE_ANONYMIZATION
                                                       print(packet, cc, from, hd);     
                                                    #else
                                                     if(!is_ip_in_net(from->sin_addr,netmask,mask))//reaches network?
                                                     print(packet, cc, from, hd);
        	                                    #endif    
                                                     lastaddr = from->sin_addr.s_addr;              
                                                     ++gotlastaddr;
                                                     }					                                                                                                                                                                                            
				        	gzprintf(hd,"  %f ms", dt);
				        	if (i == -2) {
			                               if (ip->ip_ttl <= 1)
                                                       printf(" !");
	                                               ++got_there;
                                                        break;
                                                     }
					                                                                                                                                                                                                        
		        			switch(i - 1) {
			        		case ICMP_UNREACH_PORT:
#ifndef ARCHAIC
				        		if (ip->ip_ttl <= 1)
					        		Printf(" !");
#endif 
						        ++got_there;
        						break;
	        				case ICMP_UNREACH_NET:
		        				++unreachable;
			        			Printf(" !N");
				        		break;
                                                case ICMP_UNREACH_HOST:
						        ++unreachable;
        						Printf(" !H");
	        					break;
		        			case ICMP_UNREACH_PROTOCOL:
			        			++got_there;
				        		Printf(" !P");
					        	break;
	        				case ICMP_UNREACH_NEEDFRAG:
		        				++unreachable;
			        			Printf(" !F");
				        		break;
				        		case ICMP_UNREACH_SRCFAIL:
        						++unreachable;
	        					Printf(" !S");
		        				break;
			        		}
				        	break;
        				}
		        	}
        			if (cc == 0)
		        		gzprintf(hd," *");
	        		(void) fflush(stdout);
        		}
	        	gzprintf(hd,"\n");
	        	if (got_there || unreachable >= nprobes-1)
			        break;
        	}
        	free(outicpacket[id]);
        	free(outpacket[id]);
      }	
      
       if(ct>0) gzclose(hd);

        pthread_mutex_lock(&log_mutex);
        activeth--;
        idleth[id]=0;
        printf("Thread ID%ld: activet is now %d.\n",pthread_self(), activeth);
        pthread_mutex_unlock(&log_mutex);      
        pthread_exit(0);
	return 0;
}

//#ifdef notyet
/*
 * Checksum routine for Internet Protocol family headers (C Version)
 */
u_short
in_cksum(addr, len)
u_short *addr;
int len;
{
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)  {
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += *(u_char *)w;

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);			/* add carry */
	answer = ~sum;				/* truncate to 16 bits */
	return (answer);
}
//#endif 

/*
 * Construct an Internet address representation.
 * If the nflag has been supplied, give 
 * numeric value, otherwise try for symbolic name.
 */
char *
inetname(in)
	struct in_addr in;
{
	register char *cp;
	static char line[50];
	struct hostent *hp;
	static char domain[MAXHOSTNAMELEN + 1];
	static int first = 1;

	if (first && !nflag) {
		first = 0;
		if (gethostname(domain, MAXHOSTNAMELEN) == 0 &&
		    (cp = index(domain, '.')))
			(void) strcpy(domain, cp + 1);
		else
			domain[0] = 0;
	}
	cp = 0;
	if (!nflag && in.s_addr != INADDR_ANY) {
		hp = gethostbyaddr((char *)&in, sizeof (in), AF_INET);
		if (hp) {
			if ((cp = index(hp->h_name, '.')) &&
			    !strcmp(cp + 1, domain))
				*cp = 0;
			cp = hp->h_name;
		}
	}
	if (cp)
		(void) strcpy(line, cp);
	else {
		in.s_addr = ntohl(in.s_addr);
#define C(x)	((x) & 0xff)
		Sprintf(line, "%lu.%lu.%lu.%lu", (long unsigned int) C(in.s_addr >> 24),
			(long unsigned int) C(in.s_addr >> 16), (long unsigned int) C(in.s_addr >> 8), (long unsigned int) C(in.s_addr));
	}
	return (line);
}

