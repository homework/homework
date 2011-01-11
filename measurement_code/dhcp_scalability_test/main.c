#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>
#include <time.h>
#include <errno.h>
#include <sys/time.h>
#include <sys/queue.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <string.h>

#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <libconfig.h>

#include "dhcp.h"

#define DHCP_DISCOVERY_DELAY 10000

uint8_t pkt_buf[3000];
uint32_t pkt_count = 0;
uint32_t acked = 0;

struct nw_hdr {
  struct ether_header *ether;
  struct iphdr *ip;
  struct udphdr *udp;
  struct dhcp_packet *dhcp;
};

struct pkt_state {
  uint8_t addr[6];
  struct timeval start_ts;
  struct timeval dhcp_offer_ts;
  struct timeval dhcp_ack_ts;
  int state;
  uint32_t ip;
  TAILQ_ENTRY(pkt_state) entries;
};
TAILQ_HEAD(tailhead, pkt_state) head;

struct test_cfg {

  //snmp details
  uint32_t server_ip;
  oid cpu_OID[MAX_OID_LEN];
  oid pkt_in_OID[MAX_OID_LEN];
  oid pkt_out_OID[MAX_OID_LEN];
  size_t cpu_OID_len;
  size_t pkt_in_OID_len;
  size_t pkt_out_OID_len;
  char *snmp_community;
  netsnmp_session session;

  //device details
  char *dev_name;
  int dev_fd;
  int dev_ix;
  pcap_t *pcap;
  int pcap_fd;
    
  char *pkt_output;
  char *snmp_output;
    
  FILE *pkt_file;
  FILE *snmp_file;
  
  int flow_num;

  float data_rate; 
  int finished;

} obj_cfg;

int my_read_objid(char *in_oid, oid *out_oid, size_t *out_oid_len);
void send_data_raw_socket(int fd, int ix,  void *msg, int len);
void send_dhcp_discovery(uint8_t *mac_addr, uint32_t xid, uint8_t dhcp_msg_type,
		    char *hostname, uint32_t request_ip, uint32_t server_ip);

uint16_t Checksum(const uint16_t* buf, unsigned int nbytes) {
  uint32_t sum = 0;
  for (; nbytes > 1; nbytes -= 2) 
    sum += *buf++;
  if (nbytes == 1)
    sum += *(unsigned char*) buf;
  sum  = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);
  return ~sum;
}


void
destroy_cfg() {
  struct pcap_stat ps;

  fclose(obj_cfg.pkt_file);
  fclose(obj_cfg.snmp_file);

  //print pcap capture stats
  if(pcap_stats(obj_cfg.pcap, &ps) < 0) {
    printf("Failed to get stats:%s\n", pcap_geterr(obj_cfg.pcap));
  } else {
    printf("pcap stat : %u;%u;%u\n",ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
  }

  pcap_close(obj_cfg.pcap);
};

int 
load_cfg(struct test_cfg *test_cfg, const char *config) {
  config_t conf;
  config_setting_t *elem, *data;
  char *snmp_client, *snmp_community;
  int i, len, argc = 0;
  char *path, **argv, *in_oid, *out_oid, *str_val;

  test_cfg->finished = 0;

  config_init(&conf);
  if(config_read_file(&conf, config) == CONFIG_FALSE) {
    fprintf(stderr, "failed %s:%d %s\n", config, config_error_line(&conf), 
	    config_error_text(&conf));
    return 0;
  }

  //reading the traffic generator paramters
  elem = config_lookup(&conf, "switch_test_delay.server_ip");
  if(elem != NULL) {
    if((str_val = (char *)config_setting_get_string(elem)) != NULL) {
      test_cfg->server_ip = inet_addr(str_val);
      printf("server_ip:%lX\n",(long unsigned int) ntohl(test_cfg->server_ip));
    } else {
      printf("Failed to read server_ip\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.cpu_mib");
  if(elem != NULL) {
    test_cfg->cpu_OID_len = MAX_OID_LEN;
    if ( ((str_val = (char *)config_setting_get_string(elem)) == NULL) || 
	 (!my_read_objid(str_val, test_cfg->cpu_OID, &test_cfg->cpu_OID_len)) ) {
      printf("Failed to read cpu_oid\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.in_mib");
  if(elem != NULL) {
    test_cfg->pkt_in_OID_len = MAX_OID_LEN;
    if ( ((str_val = (char *)config_setting_get_string(elem)) == NULL) || 
	 (!my_read_objid(str_val, test_cfg->pkt_in_OID, &test_cfg->pkt_in_OID_len)) ) {
      printf("Failed to read in_oid\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.out_mib");
  if(elem != NULL) {
    test_cfg->pkt_out_OID_len = MAX_OID_LEN;
    if ( ((str_val = (char *)config_setting_get_string(elem)) == NULL) || 
	 (!my_read_objid(str_val, test_cfg->pkt_out_OID, &test_cfg->pkt_out_OID_len)) ) {
      printf("Failed to read out_oid\n");
      exit(1);
    }
  }
  elem = config_lookup(&conf, "switch_test_delay.snmp_community");
  if(elem != NULL) {
    if((str_val = (char *)config_setting_get_string(elem)) != NULL) {
      printf("community : %s\n", str_val);
      test_cfg->snmp_community = malloc(strlen(str_val) + 1);
      strcpy(test_cfg->snmp_community, str_val);
    } else {
      printf("Failed to read snmp community\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.data_dev");
  if(elem != NULL) {
    if((str_val = (char *)config_setting_get_string(elem)) != NULL) {
      test_cfg->dev_name = malloc(strlen(str_val) + 1);
      strcpy(test_cfg->dev_name, str_val);
    } else {
      printf("Failed to read data interface\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.pkt_output");
  if(elem != NULL) {
    if( ((str_val = (char *)config_setting_get_string(elem)) == NULL) || 
	((test_cfg->pkt_file = fopen(str_val, "w")) == NULL) ) {
      perror("Failed to open pkt_output filename\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.snmp_output");
  if(elem != NULL) {
    if( ((str_val = (char *)config_setting_get_string(elem)) == NULL) || 
	((test_cfg->snmp_file = fopen(str_val, "w")) == NULL) ) {
      perror("Failed to open snmp_output filename\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.flow_num");
  if(elem != NULL) {
    if((test_cfg->flow_num = config_setting_get_int(elem)) == 0) {
      printf("Failed to read flow_num\n");
      exit(1);
    }
  }

  config_destroy(&conf); 
  return 1;
  
};

void 
usage() {
  printf("./test_switch_delay configuration.cfg\n");
}

int
init_pcap() {
  char errbuf[PCAP_ERRBUF_SIZE];
  struct bpf_program fp;

  obj_cfg.pcap = pcap_open_live(obj_cfg.dev_name, 2000, 1, 0, errbuf);
  if(obj_cfg.pcap == NULL) {
    printf("pcap_open_live:%s\n", errbuf);
    exit(1);
  }

  //compile filter
  if(pcap_compile(obj_cfg.pcap, &fp, "udp and dst port 68", 1, 0) < 0) {
    printf("pcap_compile:%s\n", pcap_geterr(obj_cfg.pcap));
    exit(1);  
  }

  if( pcap_setfilter(obj_cfg.pcap, &fp) < 0) {
    printf("pcap_setfilter:%s\n", pcap_geterr(obj_cfg.pcap));
    exit(1);  
  }
  
  obj_cfg.pcap_fd = pcap_fileno(obj_cfg.pcap);
  if(obj_cfg.pcap_fd < 0) {
    printf("pcap_fileno:%s\n", pcap_geterr(obj_cfg.pcap));
    exit(1);
  } 
  
  //set pcap fd in non blocking, so that I can select on it. 
  if(pcap_setnonblock(obj_cfg.pcap, 0, errbuf) < -1) {
    printf("pcap_open_live:%s\n", errbuf);
    exit(1);    
  }

  //init in memory packet storage
  TAILQ_INIT(&head);     
};

int
extract_headers(uint8_t *data, uint32_t data_len, struct nw_hdr *hdr) {
  uint32_t pointer = 0;
  
  if(data_len < sizeof( struct ether_header))
    return 0;
  
  // parse ethernet header
  hdr->ether = (struct ether_header *) data;
  pointer += sizeof( struct ether_header);
  data_len -=  sizeof( struct ether_header);
  
  // parse ip header
  if(data_len < sizeof(struct iphdr))
    return 0;
  hdr->ip = (struct iphdr *) (data + pointer);
  if(data_len < hdr->ip->ihl*4) 
    return 0;
  pointer += hdr->ip->ihl*4;
  data_len -= hdr->ip->ihl*4;
  
  //parse udp header
  if(hdr->ip->protocol == IPPROTO_UDP) {
    hdr->udp = (struct udphdr *)(data + pointer);
    pointer += sizeof(struct udphdr);
    //TODO: check here details 

    hdr->dhcp = (struct dhcp_packet *)(data + pointer);
  } else {
    return 0;
  }
  return 1;
}

struct pkt_state *
get_state(uint8_t *mac_addr) {
  struct pkt_state *np;
  for (np = head.tqh_first; np != NULL; np = np->entries.tqe_next) 
    if(memcmp(np->addr, mac_addr, 6) == 0) break;
  return np;
}

void 
process_pcap_pkt(const u_char *pkt_data,  struct pcap_pkthdr *pkt_header) {
  struct nw_hdr *hdr = (struct nw_hdr *)malloc(sizeof(struct nw_hdr));
  char nw_src[20], nw_dst[20];
  struct pkt_state *state;

  bzero(hdr,sizeof(struct nw_hdr));
  if(extract_headers((uint8_t *)pkt_data, pkt_header->caplen, hdr)) {

    if( (state = get_state(hdr->ether->ether_dhost)) == NULL ) {
      printf("generate new state\n");
      state = malloc(sizeof(struct pkt_state));
      bzero(state,sizeof(struct pkt_state));
      memcpy(state->addr, hdr->ether->ether_dhost, 6);
      TAILQ_INSERT_TAIL(&head, state, entries);
    }

    //parse options
    uint8_t *data = (((uint8_t *)hdr->dhcp) + sizeof(struct dhcp_packet));
    uint16_t len = pkt_header->caplen - 
      (((int)hdr->dhcp - (int)pkt_data) + sizeof(struct dhcp_packet));

    //get the exact message type of the dhcp request
    uint8_t dhcp_msg_type = 0;
    while(len > 2) {
      uint8_t dhcp_option = data[0];
      uint8_t dhcp_option_len = data[1];
      
      if (dhcp_option_len == 0) exit(1);

      if(dhcp_option == 0x100) {
        //printf("Got end of options!!!!\n");
        break;
      } else if(dhcp_option == 53) {
        dhcp_msg_type = data[2];
        if((dhcp_msg_type <1) || (dhcp_msg_type > 8)) {
          printf("Invalid DHCP Message Type : %d\n", dhcp_msg_type);
          return;
        } 
        break;
      }
      len -= (2 + dhcp_option_len );
      data += (2 + dhcp_option_len );
    }
    //printf("dhcp type : %d, offered ip : %s\n",  
    //    dhcp_msg_type, (char *)inet_ntoa(hdr->dhcp->yiaddr));

    if(dhcp_msg_type == DHCPOFFER ) {
      if(state->state == DHCP_INIT) {
        state->ip = hdr->dhcp->yiaddr; 
        //printf("offered ip %s\n", (char *)inet_ntoa(hdr->dhcp->yiaddr));
        send_dhcp_discovery(hdr->ether->ether_dhost, hdr->dhcp->xid, DHCPREQUEST, 
            "test", ntohl(hdr->dhcp->yiaddr), ntohl(hdr->dhcp->siaddr));
        state->state = DHCP_OFFERED;
        memcpy(&state->dhcp_offer_ts, &pkt_header->ts, sizeof(struct timeval));
      }
    } else if(dhcp_msg_type == DHCPACK ) {      
      //printf("acked %d, state: %d\n", acked, state->state);
      if(state->state == DHCP_OFFERED) {
        state->state == DHCP_ACKED;
        memcpy(&state->dhcp_ack_ts, &pkt_header->ts, sizeof(struct timeval));
        acked++;
        if(acked == obj_cfg.flow_num) obj_cfg.finished = 1;
       }

    }
  }
}

void
get_snmp_status(struct timeval *ts) {
  netsnmp_session *ss;    
  netsnmp_pdu *pdu;
  netsnmp_pdu *response;
  int status, count;
  netsnmp_variable_list *vars;

  SOCK_STARTUP;
  ss = snmp_open(&obj_cfg.session);       /* establish the session */
  
  if (!ss) {
    snmp_sess_perror("ack", &obj_cfg.session);
    SOCK_CLEANUP;
    exit(1);
  }

  pdu = snmp_pdu_create(SNMP_MSG_GET);
  snmp_add_null_var(pdu, obj_cfg.cpu_OID,  obj_cfg.cpu_OID_len);
  snmp_add_null_var(pdu, obj_cfg.pkt_in_OID, obj_cfg.pkt_in_OID_len);
  snmp_add_null_var(pdu, obj_cfg.pkt_out_OID, obj_cfg.pkt_out_OID_len);
  
  status = snmp_synch_response(ss, pdu, &response);
  if (status == STAT_SUCCESS && response->errstat == SNMP_ERR_NOERROR) {    
    /* manipuate the information ourselves */
    for(vars = response->variables; vars; vars = vars->next_variable) {
      if (vars->type == ASN_OCTET_STR) {
	char *sp = (char *)malloc(1 + vars->val_len);
	memcpy(sp, vars->val.string, vars->val_len);
	sp[vars->val_len] = '\0';
	fprintf(obj_cfg.snmp_file, "%ld.%06ld;cpu;1;%s\n", ts->tv_sec, ts->tv_usec,sp);
	free(sp);
      } else if ((vars->type == ASN_INTEGER)  || (vars->type == 0x41)) {
	if( memcmp(vars->name, obj_cfg.pkt_in_OID, obj_cfg.pkt_in_OID_len*sizeof(int)) == 0) 
	  fprintf(obj_cfg.snmp_file, "%ld.%06ld;pkt_in;1;%ld\n", ts->tv_sec, ts->tv_usec, 
		  *vars->val.integer);
	
	if( memcmp(vars->name, obj_cfg.pkt_out_OID, obj_cfg.pkt_out_OID_len*sizeof(int)) == 0) 
	  fprintf(obj_cfg.snmp_file, "%ld.%06ld;pkt_out;1;%ld\n", ts->tv_sec, ts->tv_usec, 
		  *vars->val.integer);
	
      } else 
	printf("Unkknown type ASN type : %x\n", vars->type);
    }
  } else {
    printf("failed to get cpu value\n");
  }

  if (response)
    snmp_free_pdu(response);
  snmp_close(ss);
  SOCK_CLEANUP;
}

void 
send_dhcp_discovery(uint8_t *mac_addr, uint32_t xid, uint8_t dhcp_msg_type,
		    char *hostname, uint32_t request_ip, uint32_t server_ip) {
  int len;
  
  //message_type + netmask + router + nameserver + lease_time + end option
  //lease time is seconds since it will timeout
  
    //setting up ethernet header details
  struct ether_header *ether = (struct ether_header *) pkt_buf;
  ether->ether_type = htons(ETHERTYPE_IP);
  memcpy(ether->ether_dhost, "\xFF\xFF\xFF\xFF\xFF\xFF", ETH_ALEN);
  memcpy(ether->ether_shost,  (const uint8_t *)mac_addr, ETH_ALEN);
 
  //setting up ip header details   
  struct iphdr *ip = (struct iphdr *) (pkt_buf + sizeof(struct ether_header));
  ip->ihl = 5;
  ip->version = 4;
  ip->tos = 0; 
  ip->id = 0;
  ip->frag_off = 0;
  ip->ttl = 0x80;
  ip->protocol = 0x11;
  ip->saddr =  0; 
  ip->daddr =  inet_addr("255.255.255.255");
  
  //setting up udp header details   
  struct udphdr *udp = (struct udphdr *)( pkt_buf + sizeof(struct ether_header) + 
					  sizeof(struct iphdr));
  udp->source = htons(68);
  udp->dest = htons(67);
  udp->check = 0x0;
  
  struct dhcp_packet  *reply = 
    (struct dhcp_packet *)(pkt_buf + sizeof(struct ether_header) + 
			   sizeof(struct iphdr) + sizeof(struct udphdr));
  reply->op = BOOTREQUEST;
  reply->htype = 0x01;
  reply->hlen = 0x6;
  reply->xid = xid;
  reply->yiaddr = 0;
  reply->siaddr =  0;
  memcpy(reply->chaddr, mac_addr, 6);
  reply->cookie =  0x63538263;//DHCP_OPTIONS_COOKIE;

    //setting up options
  uint8_t *options = (uint8_t *)(pkt_buf + sizeof(struct ether_header) + 
				 sizeof(struct iphdr) +sizeof(struct udphdr) + 
				 sizeof(struct dhcp_packet));
  
  len =  sizeof( struct ether_header) + sizeof(struct iphdr) + 
    sizeof(struct udphdr) + sizeof(struct dhcp_packet);
  
  //setting up dhcp msg type
  options[0] = 53;
  options[1] = 1;  options[2] = dhcp_msg_type;
  options += 3;
  len += 3;
  
  if(server_ip != 0) {
    //router 
    options[0] = 54;
    options[1] = 4;
    *((uint32_t *)(options + 2)) = htonl(server_ip); 
    options += 6;    
    len += 6;    
  }
  
  if(request_ip != 0) {
    //selected host ip
    options[0] = 50;
    options[1] = 4;
    *((uint32_t *)(options + 2)) = htonl(request_ip); 
    options += 6;    
    len += 6;    
  }
  
  //hostname
  options[0] =12;
  options[1] = strlen(hostname);
  memcpy(options + 2, hostname, strlen(hostname));
  options += (2 + strlen(hostname));
  len += (2 + strlen(hostname));
  
  options[0] = 0xff; 
  len++;
  
  ip->tot_len = htons(len - sizeof(struct ether_header));
  ip->check = Checksum((const uint16_t*)ip, 20);
  udp->len = htons(len - sizeof(struct ether_header) - sizeof(struct iphdr));
  
  send_data_raw_socket(obj_cfg.dev_fd, obj_cfg.dev_ix, pkt_buf, len);
}

void *
dhcp_discovery_thread( void *ptr ) {
  uint8_t mac_addr[] = {0x08, 0x00, 0x27, 0xee, 0x1d, 0x00};
  int32_t i;
  struct pkt_state *state;
  struct timeval now, prev;

  for( i = 0; i < obj_cfg.flow_num;i++) {
    mac_addr[5] = i;
    state = malloc(sizeof(struct pkt_state));
    bzero(state,sizeof(struct pkt_state));
    memcpy(state->addr, mac_addr, 6);
    gettimeofday(&state->start_ts, NULL);
    TAILQ_INSERT_TAIL(&head, state, entries);
    send_dhcp_discovery(mac_addr, 0x223311,  DHCPDISCOVER, "hello", 0 ,0 );
    gettimeofday(&prev, NULL);
    gettimeofday(&now, NULL); 
    while(timediff(&now, &prev) < DHCP_DISCOVERY_DELAY) {
      gettimeofday(&now, NULL);
      pthread_yield();
    }
  }
}

void *
packet_capture( void *ptr ) {
  fd_set set;
  struct timeval timeout, last_snmp, now, start;
  struct pcap_pkthdr *pkt_header;
  const u_char *pkt_data;
  int ret;

  gettimeofday(&start, NULL); 
  gettimeofday(&last_snmp, NULL);
  get_snmp_status(&last_snmp);
  
  while(!obj_cfg.finished) {       
    /* Initialize the file descriptor set. */
    FD_ZERO (&set);
    FD_SET(obj_cfg.pcap_fd, &set);
    //FD_SET(obj_cfg.echo_pcap_fd, &set);
    gettimeofday(&now, NULL);

    /* Initialize the timeout data structure. */
    if((last_snmp.tv_usec - now.tv_usec) < 0) {
      timeout.tv_usec = 1000000 + (last_snmp.tv_usec - now.tv_usec);
      timeout.tv_sec = 9 - now.tv_sec + last_snmp.tv_sec;
    } else {
      timeout.tv_usec = (last_snmp.tv_usec - now.tv_usec);
      timeout.tv_sec = 10 - now.tv_sec + last_snmp.tv_sec;
    }
      
    if(( timeout.tv_sec <= 0)) {
      memcpy(&last_snmp, &now, sizeof(struct timeval));
      get_snmp_status(&last_snmp);
      //printf("send snmp now:%ld\n", now.tv_sec, last_snmp.tv_sec);
      timeout.tv_sec = 10;
      timeout.tv_usec = 0;
    }

    //printf(" %ld.%06ld: timed out at %ld.%06ld\n", now.tv_sec, now.tv_usec, timeout.tv_sec, timeout.tv_usec);
    if( (ret = select(FD_SETSIZE, &set, NULL, NULL, 
            &timeout)) < 0) {
      perror("capture select");
      exit(1);
    }
    if(ret == 0) {
      gettimeofday(&last_snmp, NULL);
      get_snmp_status(&last_snmp);
      printf("send snmp %ld\n", last_snmp.tv_sec);
    } else {
      /* Service all the sockets with input pending. */
      if (FD_ISSET(obj_cfg.pcap_fd, &set))  {
        if(pcap_next_ex(obj_cfg.pcap, &pkt_header,
              &pkt_data) < 0) {
          perror("pcap_next_en");
          exit(1);
        }
        process_pcap_pkt(pkt_data, pkt_header);
      }
    }
    if(now.tv_sec - start.tv_sec > 60) 
      break;
  }
  printf("this is the packet capturer\n");
};

uint32_t
timediff(struct timeval *now, struct timeval *last_pkt) {
  return (now->tv_sec - last_pkt->tv_sec) * 1000000 +
    (now->tv_usec - last_pkt->tv_usec);
}

int 
printf_and_check(char *filename, char *msg) {
  FILE *ctrl = fopen(filename, "w");
  //printf("echo %s > %s\n", msg, filename);
  if(ctrl == NULL) {
    perror("failed to open file"); 
    exit(1);
  }

  if (fprintf(ctrl, "%s\n", msg) < 0) {
    perror("failed to write command");
    exit(1);
  }

  fclose(ctrl);
  return 1;
}

void
process_data() {
  struct pkt_state *state;
  while (head.tqh_first != NULL) {
    state = head.tqh_first;
    fprintf(obj_cfg.pkt_file, "%02x:%02x:%02x:%02x:%02x:%02x;%ld.%06ld;%ld.%06ld;%ld.%06ld;%s\n",   
        state->addr[0],state->addr[1],state->addr[2],state->addr[3],state->addr[4],state->addr[5],
        (long int)state->start_ts.tv_sec,   
        (long int)state->start_ts.tv_usec,  
        (long int)state->dhcp_offer_ts.tv_sec,   
        (long int)state->dhcp_offer_ts.tv_usec,  
        (long int)state->dhcp_ack_ts.tv_sec,   
        (long int)state->dhcp_ack_ts.tv_usec,
        (char *)inet_ntoa(state->ip));   
    TAILQ_REMOVE(&head, head.tqh_first, entries);
    free(state);
  }
  //fclose(obj_cfg.pkt_file);
};

int 
initialize_snmp() {
  struct in_addr addr;
  /*
   * Initialize the SNMP library
   */
  init_snmp("switch_delay_test");

  /*
   * Initialize a "session" that defines who we're going to talk to
   */
  snmp_sess_init( &obj_cfg.session );                   /* set up defaults */
  addr.s_addr = obj_cfg.server_ip;
  obj_cfg.session.peername = strdup((char *)inet_ntoa(addr));
    
  /* set the SNMP version number */
  obj_cfg.session.version = SNMP_VERSION_1;

  /* set the SNMPv1 community name used for authentication */
  obj_cfg.session.community = obj_cfg.snmp_community;
  obj_cfg.session.community_len = strlen(obj_cfg.snmp_community);
}

void 
send_data_raw_socket(int fd, int ix, void *msg, int len) {
  struct sockaddr_ll socket_address;
  int ret;
  
  bzero(&socket_address, sizeof(socket_address));
  socket_address.sll_family   = PF_PACKET;
  socket_address.sll_protocol = htons(ETH_P_ALL);
  socket_address.sll_ifindex  = ix;
  socket_address.sll_hatype   = ARPHRD_ETHER; 
  socket_address.sll_halen    = ETH_ALEN;
  socket_address.sll_pkttype  = PACKET_OTHERHOST;
  
  /*queue the packet*/
  ret = write(fd, msg, len);
	
  if ( ret < 0 && errno != ENOBUFS ) {
    fprintf(stderr, "sending of data failed\n");
  }
  if ( ret < 0 && errno == ENOBUFS ) {
    printf(stderr, "buffer fulll!\n");
  }


}


void 
initialize_raw_socket() {
  struct ifreq ifr;
  struct sockaddr_ll saddrll;
  struct channel_info * ch_info;
  
  obj_cfg.dev_fd = socket(AF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
  if( obj_cfg.dev_fd == -1) {
    perror("raw socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL))");
    exit(1);
  }
  
  // bind to a specific port
  strncpy(ifr.ifr_name, obj_cfg.dev_name,IFNAMSIZ);
  if( ioctl(obj_cfg.dev_fd, SIOCGIFINDEX, &ifr)  == -1 ) {
    perror("ioctl()");
    exit(1);
  }
  obj_cfg.dev_ix = ifr.ifr_ifindex;
  memset(&saddrll, 0, sizeof(saddrll));
  saddrll.sll_family = AF_PACKET;
  saddrll.sll_protocol = ETH_P_ALL;
  saddrll.sll_ifindex = ifr.ifr_ifindex;
  if ( bind(obj_cfg.dev_fd, (struct sockaddr *) &saddrll, sizeof(struct sockaddr_ll)) == -1 ) {
    perror("bind()");
    exit(1);
  }

}

int 
main(int argc, char **argv) {
  pthread_t thrd_capture, thrd_echo, thrd_data;

  if(argc < 1) {
    printf("Forgot to set the configuration file name\n");
    exit(1);
  }
  
  printf("switch delay test starting...\n");

  //parse config file
  if(!load_cfg(&obj_cfg, argv[1])) {
    printf("Failed to process configuration file\n");
    exit(1);
  }

  initialize_snmp();
  initialize_raw_socket();
  init_pcap();

  if( (pthread_create( &thrd_capture, NULL, packet_capture, NULL)) 
      || (pthread_create( &thrd_echo, NULL, dhcp_discovery_thread, NULL)) 
      //      || (pthread_create( &thrd_data, NULL, data_generate, NULL)) 
      ) {
    perror("pthread_create");
    exit(1);
  }

  pthread_join(thrd_echo, NULL);
  pthread_join(thrd_capture, NULL); 
  //  pthread_join(thrd_data, NULL); 

  process_data();
  destroy_cfg();

  exit(0);
}

int
my_read_objid(char *in_oid, oid *out_oid, size_t *out_oid_len) {
  int oid_len = *out_oid_len, p = 0, tmp = 0, len = strlen(in_oid);
  *(out_oid_len) = 0;
  while(1) {
    tmp = p;
    while((in_oid[tmp] != '.') &&
	  (in_oid[tmp] != '\0')) {
      tmp++;
    }
    in_oid[tmp] = '\0';
    tmp++;
    out_oid[*(out_oid_len)] = (oid)strtol(in_oid+p, NULL, 10);
    if(oid_len == *out_oid_len) return 0;
    *(out_oid_len)+=1;
    p=tmp;
    if(p >= len)
      break;
  }
  return 1;
}
