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

#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>

#include <glib-object.h>
#include <json-glib/json-glib.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <curl/curl.h>

#include <libconfig.h>

uint8_t pkt_buf[3000];
uint32_t pkt_count = 0;

struct pktgen_hdr {
  uint32_t id;
  uint32_t echo_snd_tv_sec;
  uint32_t echo_snd_tv_usec;
  uint32_t echo_rcv_tv_sec;
  uint32_t echo_rcv_tv_usec;
};
struct nw_hdr {
  struct ether_header *ether;
  struct iphdr *ip;
  struct udphdr *udp;
  struct pktgen_hdr *pktgen;
};

struct pkt_state {
  uint32_t seq_num;
  struct timeval data_rcv_ts, echo_snd_ts, data_snd_ts;
  uint32_t nw_dst;
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
  char *data_dev_name;
  int data_dev_fd;
  int data_dev_ix;
  pcap_t *data_pcap;
  int data_pcap_fd;
  char *echo_dev_name;
  int echo_dev_fd;
  int echo_dev_ix;
  pcap_t *echo_pcap;
  int echo_pcap_fd;
    
  char *pkt_output;
  char *snmp_output;
    
  FILE *pkt_file;
  FILE *snmp_file;
  
  int flow_num;
  char *flow_type;

  uint16_t pkt_size;
  uint32_t duration;
  float data_rate; 
  float probe_rate; 
  int finished;

} obj_cfg;

int my_read_objid(char *in_oid, oid *out_oid, size_t *out_oid_len);
void generate_packet(int len);
void send_data_raw_socket(int fd, int ix,  void *msg, int len);

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
      test_cfg->data_dev_name = malloc(strlen(str_val) + 1);
      strcpy(test_cfg->data_dev_name, str_val);
    } else {
      printf("Failed to read data interface\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.echo_dev");
  if(elem != NULL) {
    if((str_val = (char *)config_setting_get_string(elem)) != NULL) {
      test_cfg->echo_dev_name = malloc(strlen(str_val) + 1);
      strcpy(test_cfg->echo_dev_name, str_val);
    } else {
      printf("Failed to read echo interface\n");
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

  elem = config_lookup(&conf, "switch_test_delay.flow_type");
  if(elem != NULL) {
    if((str_val = (char *)config_setting_get_string(elem)) != 0) {
      test_cfg->flow_type = malloc(strlen(str_val) + 1);
      strcpy(test_cfg->flow_type, str_val);
    } else {
      printf("Failed to read flow_type\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.pkt_size");
  if(elem != NULL) {
    if((test_cfg->pkt_size = config_setting_get_int(elem)) == 0) {
      printf("Failed to read pkt_size\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.duration");
  if(elem != NULL) {
    if((test_cfg->duration = config_setting_get_int(elem)) == 0) {
      printf("Failed to read duration\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.data_rate");
  if(elem != NULL) {
    if((test_cfg->data_rate = config_setting_get_int(elem)) == 0) {
      printf("Failed to read data_rate\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.probe_rate");
  if(elem != NULL) {
    if((test_cfg->probe_rate = config_setting_get_int(elem)) == 0) {
      printf("Failed to read data_rate\n");
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

char *curl_buf;
uint32_t curl_buf_len;
void
curl_write_init() {
  curl_buf=NULL;
  curl_buf_len = 0;
}

/* curl calls this routine to get more data */ 
static size_t 
curl_write_method(char *buffer, size_t size,
	       size_t nitems, void *userp) {
    curl_buf = realloc(curl_buf, curl_buf_len + nitems*size + 1);
    if(curl_buf == NULL) {
      perror("curl_write_callback realloc");
      exit(1);
    }
    memcpy(curl_buf + curl_buf_len, buffer, nitems*size);
    curl_buf[curl_buf_len + nitems*size] = '\0';
    curl_buf_len += nitems*size;
  
    return (nitems*size);
}

void
destroy_cfg() {
  struct pcap_stat ps;

  fclose(obj_cfg.pkt_file);
  fclose(obj_cfg.snmp_file);

  //print pcap capture stats
  if(pcap_stats(obj_cfg.data_pcap, &ps) < 0) {
    printf("Failed to get stats:%s\n", pcap_geterr(obj_cfg.data_pcap));
  } else {
    printf("pcap stat : %u;%u;%u\n",ps.ps_recv, ps.ps_drop, ps.ps_ifdrop);
  }

  pcap_close(obj_cfg.data_pcap);
};

void
curl_write_destroy() {
  free(curl_buf);
  curl_buf=NULL;
  curl_buf_len = 0;
}

int
install_flows() {
  char msg[1024];
  struct in_addr addr;

  CURL *curl;
  CURLcode res;
  
  JsonParser *parser;
  JsonNode *root;
  GError *error;
  uint32_t success = 0;
  
  // using the more generic 
  curl = curl_easy_init();
  
  //json parser
  g_type_init ();
  parser = json_parser_new ();
  
  if(curl) {
    //init lib curl obj
    curl_write_init();
    
    //set url
    addr.s_addr = obj_cfg.server_ip;
    snprintf(msg, 1024, "https://%s/ws.v1/network_stack_test/installflows/%d", (char *)inet_ntoa(addr), 
	     obj_cfg.flow_num);
    curl_easy_setopt(curl, CURLOPT_URL, msg);
    
    // this is an http get request
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    
    //don't get in trouble verifying the ssl credentials
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    
    //when you receive data push them to the buffering function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_method);
    
    do {
      //get the data from the web service 
      res = curl_easy_perform(curl);
      if(res != CURLE_OK) {
	printf("curl error: %s\n", curl_easy_strerror(res));
	exit(1);
      }

      //load json data to a json parser
      error = NULL;
      json_parser_load_from_data(parser, curl_buf, curl_buf_len, &error);
      if (error) {
	g_print ("Unable to parse %s: %s\n",  curl_buf, error->message);
	exit(1);
      }

      root = json_parser_get_root(parser);
      if(root == NULL) {
	printf("not exactly what I want\n");
	exit(1);
      } 
      JsonReader *reader = json_reader_new(root);

      json_reader_read_member (reader, "result");
      success = json_reader_get_int_value (reader);  
      json_reader_end_element (reader);
      printf("result:%d\n", success);

      curl_write_destroy();
      
      if(!success) sleep(3);
    } while(!success);  
    
    /* always cleanup */ 
    curl_easy_cleanup(curl);
  }
}

int
init_pcap() {
  char errbuf[PCAP_ERRBUF_SIZE];
  obj_cfg.data_pcap = pcap_open_live(obj_cfg.data_dev_name, 70, 1, 0, errbuf);
  if(obj_cfg.data_pcap == NULL) {
    printf("pcap_open_live:%s\n", errbuf);
    exit(1);
  }
  
  obj_cfg.data_pcap_fd = pcap_fileno(obj_cfg.data_pcap);
  if(obj_cfg.data_pcap_fd < 0) {
    printf("pcap_fileno:%s\n", pcap_geterr(obj_cfg.data_pcap));
    exit(1);
  } 
  
  //set pcap fd in non blocking, so that I can select on it. 
  if(pcap_setnonblock(obj_cfg.data_pcap, 0, errbuf) < -1) {
    printf("pcap_open_live:%s\n", errbuf);
    exit(1);    
  }

  obj_cfg.echo_pcap = pcap_open_live(obj_cfg.echo_dev_name, 70, 1, 0, errbuf);
  if(obj_cfg.echo_pcap == NULL) {
    printf("pcap_open_live:%s\n", errbuf);
    exit(1);
  }
  
  obj_cfg.echo_pcap_fd = pcap_fileno(obj_cfg.echo_pcap);
  if(obj_cfg.echo_pcap_fd < 0) {
    printf("pcap_fileno:%s\n", pcap_geterr(obj_cfg.echo_pcap));
    exit(1);
  } 
  
  //set pcap fd in non blocking, so that I can select on it. 
  if(pcap_setnonblock(obj_cfg.echo_pcap, 0, errbuf) < -1) {
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
    hdr->pktgen = (struct pktgen_hdr *)(data + pointer);
  } else {
    return 0;
  }
  return 1;
}

void 
process_pcap_pkt(const u_char *pkt_data,  struct pcap_pkthdr *pkt_header) {
  struct nw_hdr *hdr = (struct nw_hdr *)malloc(sizeof(struct nw_hdr));
  char nw_src[20], nw_dst[20];
  struct pkt_state *state;
  bzero(hdr,sizeof(struct nw_hdr));
  if(extract_headers((uint8_t *)pkt_data, pkt_header->caplen, hdr)) {
    state = malloc(sizeof(struct pkt_state));
    bzero(state,sizeof(struct pkt_state));
    state->seq_num = ntohl(hdr->pktgen->id);
    state->data_rcv_ts.tv_sec = pkt_header->ts.tv_sec;
    state->data_rcv_ts.tv_usec = pkt_header->ts.tv_usec;
    state->data_snd_ts.tv_sec = ntohl(hdr->pktgen->echo_snd_tv_sec);
    state->data_snd_ts.tv_usec = ntohl(hdr->pktgen->echo_snd_tv_usec);
    state->echo_snd_ts.tv_sec = ntohl(hdr->pktgen->echo_rcv_tv_sec);
    state->echo_snd_ts.tv_usec = ntohl(hdr->pktgen->echo_rcv_tv_usec);
    state->nw_dst = hdr->ip->daddr;
    TAILQ_INSERT_TAIL(&head, state, entries);
  }
}

void 
generate_reply(const u_char *pkt_data,  struct pcap_pkthdr *pkt_header) {
  char nw_src[20], nw_dst[20], *msg, tmp_mac[ETH_ALEN];
  struct pkt_state *state;
  struct ether_header *ether;
  struct iphdr *ip;
  struct udphdr *udp;
  struct  pktgen_hdr *pktgen;
  uint32_t tmp_ip;
  uint16_t tmp_port;

  msg = malloc(pkt_header->len);
  memcpy(msg, pkt_data, pkt_header->caplen);

  ether = (struct ether_header *)msg;
  ip = (struct iphdr *)(msg + ETHER_HDR_LEN);
  udp = (struct udphdr *)(msg + ETHER_HDR_LEN + sizeof(struct iphdr)); 
  pktgen = (struct pktgen_hdr *)(msg + ETHER_HDR_LEN + sizeof(struct iphdr) + sizeof(struct udphdr)); 

  if((ether->ether_type != htons(ETHERTYPE_IP)) ||
     (ip->protocol != IPPROTO_UDP) ||
     (udp->source != htons(41215)) || (udp->dest != htons(53))) {
    printf("received incorect packet\n");
    return;
  }

  printf("packet received on echo server\n");  
  //revert mac address
  memcpy(tmp_mac, ether->ether_shost, ETH_ALEN); 
  memcpy(ether->ether_shost, ether->ether_dhost, ETH_ALEN); 
  memcpy(ether->ether_dhost, tmp_mac, ETH_ALEN); 
  
  //revert ip addr
  tmp_ip = ip->saddr;
  ip->saddr = ip->daddr;
  ip->daddr = tmp_ip;
  ip->check =  0;
  ip->check =  Checksum((uint16_t *)ip, 20);
  
  //revert ip address
  tmp_port = udp->source; 
  udp->source = udp->dest; 
  udp->dest = tmp_port;

  //append timestamp
  printf("packet received pkt %ld\n",(long int) ntohl(pktgen->id));
  pktgen->echo_rcv_tv_sec = htonl(pkt_header->ts.tv_sec);
  pktgen->echo_rcv_tv_usec = htonl(pkt_header->ts.tv_usec);
  
  send_data_raw_socket(obj_cfg.echo_dev_fd, obj_cfg.echo_dev_ix, msg, pkt_header->len);
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

void *
packet_capture( void *ptr ) {
  fd_set set;
  struct timeval timeout, last_snmp, now;
  struct pcap_pkthdr *pkt_header;
  const u_char *pkt_data;
  int ret;

  gettimeofday(&last_snmp, NULL);
  get_snmp_status(&last_snmp);
  
  while(!obj_cfg.finished) {       
    /* Initialize the file descriptor set. */
    FD_ZERO (&set);
    FD_SET(obj_cfg.data_pcap_fd, &set);
    FD_SET(obj_cfg.echo_pcap_fd, &set);
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
      if (FD_ISSET(obj_cfg.data_pcap_fd, &set))  {
	if(pcap_next_ex(obj_cfg.data_pcap, &pkt_header,
			&pkt_data) < 0) {
	  perror("pcap_next_en");
	  exit(1);
	}
	process_pcap_pkt(pkt_data, pkt_header);
      } else if (FD_ISSET(obj_cfg.echo_pcap_fd, &set))  {
	if(pcap_next_ex(obj_cfg.echo_pcap, &pkt_header,
			&pkt_data) < 0) {
	  perror("pcap_generate_reply");
	  exit(1);
	}
	generate_reply(pkt_data, pkt_header);
      }
    }
  };
  printf("this is the packet capturer\n");
};

uint32_t
timediff(struct timeval *now, struct timeval *last_pkt) {
  return (now->tv_sec - last_pkt->tv_sec) * 1000000 +
    (now->tv_usec - last_pkt->tv_usec);
}

void *
echo_generate( void *ptr ) {
  char intf_file[1024], msg[1024];
  FILE *file;
  int i;
  struct timeval now, last_pkt, start;
  uint32_t delay; //time between consecutive pkts in microsec

  gettimeofday(&start, NULL);
  gettimeofday(&last_pkt, NULL);
  
  delay = (uint32_t)((8*obj_cfg.pkt_size*1000)/(obj_cfg.data_rate));

  while (1) {
    pthread_yield();
    gettimeofday(&now, NULL);    
    if(timediff(&now, &last_pkt) >= delay ) {
      /* printf("delay : %ld, now : %ld.%06ld, last : %ld.%06ld diff %ld\n", delay, now.tv_sec, now.tv_usec,  */
      /* 	     last_pkt.tv_sec, last_pkt.tv_usec, timediff(&now, &last_pkt)); */
      generate_packet(obj_cfg.pkt_size);
      last_pkt.tv_usec += delay%1000000;
      if(last_pkt.tv_usec >= 1000000) {
	last_pkt.tv_usec -= 1000000;
	last_pkt.tv_sec++;
      }
      last_pkt.tv_sec += (uint32_t)(delay/1000000);
    } else if (timediff(&now, &start) >= obj_cfg.duration*1000000) {
      break;
    }
  }

  obj_cfg.finished = 1;
  return;
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

void *
data_generate( void *ptr ) {
  char intf_file[1024], msg[1024];
  FILE *file;
  struct in_addr addr;

  printf_and_check("/proc/net/pktgen/kpktgend_0",  "rem_device_all");

  snprintf(msg, 1024, "add_device %s", obj_cfg.data_dev_name);
  printf_and_check("/proc/net/pktgen/kpktgend_0",msg );

  snprintf(intf_file, 1024, "/proc/net/pktgen/%s",obj_cfg.data_dev_name);
  printf_and_check(intf_file, "clone_skb 0");
  uint32_t delay = (uint32_t)((8*obj_cfg.pkt_size*1000)/(obj_cfg.data_rate));
  snprintf(msg, 1024, "delay %lu", (long unsigned int)delay);
  printf("delay %lu\n", (long unsigned int)delay);
  printf_and_check(intf_file, msg);
  snprintf(msg, 1024, "count %lu", 
	   (long unsigned int)(obj_cfg.duration*(1000000000/delay)));
  printf("duration %d delay %d count %lu\n", obj_cfg.duration, delay,
	 (long unsigned int)(obj_cfg.duration*(1000000000/delay)));
  printf_and_check(intf_file, msg);
  snprintf(msg, 1024, "pkt_size %d", obj_cfg.pkt_size);
  printf_and_check(intf_file, msg);

  if(strcmp(obj_cfg.flow_type, "wildcard") == 0) {
    printf_and_check(intf_file,  "dst_min 10.3.1.0");
    addr.s_addr = htonl(ntohl(inet_addr("10.3.1.0")) + ((obj_cfg.flow_num) << 8) - 1);
  } else if (strcmp(obj_cfg.flow_type, "exact")== 0) {
    printf_and_check(intf_file,  "dst_min 10.3.0.1");
    addr.s_addr = htonl(ntohl(inet_addr("10.3.0.1")) + (obj_cfg.flow_num));
  } else  {
    printf("Invalid flow type\n");
    exit(1);
  }
  snprintf(msg, 1024, "dst_max %s", (char *)inet_ntoa(addr)); 
  printf_and_check(intf_file, msg);
  printf_and_check(intf_file,"flag IPDST_RND");

  snprintf(msg, 1024, "vlan_id %ld", (long int)0xffff);
  printf_and_check(intf_file, msg);
  printf_and_check(intf_file, "vlan_p 0"); 
  printf_and_check(intf_file, "vlan_cfi 0"); 
  printf_and_check(intf_file, "dst_mac 10:20:30:40:50:60");
  printf_and_check(intf_file, "src_mac 10:20:30:40:50:61");
  printf_and_check(intf_file, "src_min 10.2.0.1");
  printf_and_check(intf_file, "src_max 10.2.0.1");
  printf_and_check(intf_file, "tos 0");
  printf_and_check(intf_file, "udp_src_max 8080");
  printf_and_check(intf_file, "udp_src_min 8080");
  printf_and_check(intf_file, "udp_dst_max 8080");
  printf_and_check(intf_file, "udp_dst_min 8080");

  //start packet generation
  printf_and_check("/proc/net/pktgen/pgctrl", "start");

  obj_cfg.finished = 1;
};

void
process_data() {
  struct pkt_state *state;
  while (head.tqh_first != NULL) {
    state = head.tqh_first;
    fprintf(obj_cfg.pkt_file, "%ld.%06ld;%ld.%06ld;%ld;%s\n",  
	    (long int)state->data_rcv_ts.tv_sec,  
	    (long int)state->data_rcv_ts.tv_usec, 
	    (long int)state->data_snd_ts.tv_sec,  
	    (long int)state->data_snd_ts.tv_usec,
	    (long int)state->seq_num,
	    (char *)inet_ntoa(state->nw_dst));  
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

uint16_t id=0x1140;

void 
generate_packet(int len) {
  struct ether_header *ether;
  struct iphdr *ip;
  struct udphdr *udp;
  struct pktgen_hdr *pktgen;
  struct timeval now;

  uint32_t src_ip = ntohl(inet_addr("10.2.0.0")) + ((rand()%(obj_cfg.flow_num + 1)) << 2) + 2;
  uint32_t dst_ip = ntohl(inet_addr("10.3.0.0")) + (rand()%65533) + 4;

  ether = (struct ether_header *)pkt_buf;
  memcpy(ether->ether_shost, "\x08\x00\x27\x62\x1c\x95" /*"\x08\x00\x27\x89\x68\xfa"*/, ETH_ALEN); 
  memcpy(ether->ether_dhost, "\x08\x00\x27\x33\x3a\x38" /*"\x08\x00\x27\x75\xff\x61"*/, ETH_ALEN); 
  ether->ether_type = htons(ETHERTYPE_IP);

  ip = (struct iphdr *)(pkt_buf + ETHER_HDR_LEN);
  bzero(ip, sizeof(struct iphdr));
  ip->ihl = 5;
  ip->version = 4;
  ip->ttl = 0x40;
  //  ip->id = htons(id++);
  ip->protocol = IPPROTO_UDP;
  ip->tot_len = htons(len - ETHER_HDR_LEN );
  ip->saddr = htonl(src_ip);
  ip->daddr = htonl(dst_ip);
  ip->check =  Checksum((uint16_t *)ip, 20);
  
  udp = (struct udphdr *)(pkt_buf + ETHER_HDR_LEN + sizeof(struct iphdr));
  udp->source = htons(41215);
  udp->dest =  htons(53);
  udp->len = htons(len -  ETHER_HDR_LEN - sizeof(struct iphdr));
  udp->check = 0; //htons(0x4a77);

  pktgen = (struct pktgen_hdr *)(pkt_buf + ETHER_HDR_LEN + sizeof(struct iphdr) 
			     + sizeof(struct udphdr));
  pktgen->id = htonl(++pkt_count);
  gettimeofday(&now, NULL);
  pktgen->echo_snd_tv_sec = htonl(now.tv_sec);
  pktgen->echo_snd_tv_usec = htonl(now.tv_usec);
  
  printf("seding packet %d\n", pkt_count);

  send_data_raw_socket(obj_cfg.data_dev_fd, obj_cfg.data_dev_ix, pkt_buf, len);
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
}


void 
initialize_raw_socket() {
  struct ifreq ifr;
  struct sockaddr_ll saddrll;
  struct channel_info * ch_info;
  
  obj_cfg.data_dev_fd = socket(AF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
  if( obj_cfg.data_dev_fd == -1) {
    perror("raw socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL))");
    exit(1);
  }
  
  // bind to a specific port
  strncpy(ifr.ifr_name, obj_cfg.data_dev_name,IFNAMSIZ);
  if( ioctl(obj_cfg.data_dev_fd, SIOCGIFINDEX, &ifr)  == -1 ) {
    perror("ioctl()");
    exit(1);
  }
  obj_cfg.data_dev_ix = ifr.ifr_ifindex;
  memset(&saddrll, 0, sizeof(saddrll));
  saddrll.sll_family = AF_PACKET;
  saddrll.sll_protocol = ETH_P_ALL;
  saddrll.sll_ifindex = ifr.ifr_ifindex;
  if ( bind(obj_cfg.data_dev_fd, (struct sockaddr *) &saddrll, sizeof(struct sockaddr_ll)) == -1 ) {
    perror("bind()");
    exit(1);
  }

  obj_cfg.echo_dev_fd = socket(AF_PACKET,SOCK_RAW, htons(ETH_P_ALL));
  if( obj_cfg.echo_dev_fd == -1) {
    perror("raw socket(AF_PACKET,SOCK_RAW,htons(ETH_P_ALL))");
    exit(1);
  }
  
  // bind to a specific port
  strncpy(ifr.ifr_name, obj_cfg.echo_dev_name,IFNAMSIZ);
  if( ioctl(obj_cfg.echo_dev_fd, SIOCGIFINDEX, &ifr)  == -1 ) {
    perror("ioctl()");
    exit(1);
  }
  obj_cfg.echo_dev_ix = ifr.ifr_ifindex;
  memset(&saddrll, 0, sizeof(saddrll));
  saddrll.sll_family = AF_PACKET;
  saddrll.sll_protocol = ETH_P_ALL;
  saddrll.sll_ifindex = ifr.ifr_ifindex;
  if ( bind(obj_cfg.echo_dev_fd, (struct sockaddr *) &saddrll, sizeof(struct sockaddr_ll)) == -1 ) {
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
  install_flows();

  if( (pthread_create( &thrd_capture, NULL, packet_capture, NULL)) 
      || (pthread_create( &thrd_echo, NULL, echo_generate, NULL)) 
      || (pthread_create( &thrd_data, NULL, data_generate, NULL)) 
      ) {
    perror("pthread_create");
    exit(1);
  }

  pthread_join(thrd_capture, NULL);
  pthread_join(thrd_echo, NULL); 
  pthread_join(thrd_data, NULL); 

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
