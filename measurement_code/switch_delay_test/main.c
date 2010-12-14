#include <stdio.h>
#include <stdint.h>
#include <pthread.h>
#include <pcap.h>
#include <sys/time.h>

#include <stdlib.h>
#include <glib-object.h>
#include <json-glib/json-glib.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <curl/curl.h>

#include <libconfig.h>

struct test_cfg {
  uint32_t server_ip;
  uint16_t server_port;

  oid cpu_OID[MAX_OID_LEN];
  oid pkt_in_OID[MAX_OID_LEN];
  oid pkt_out_OID[MAX_OID_LEN];
  size_t cpu_OID_len;
  size_t pkt_in_OID_len;
  size_t pkt_out_OID_len;

  char *snmp_community;
  char *intf_name;
    
  char *pkt_output;
  char *snmp_output;
    
  FILE *pkt_file;
  FILE *snmp_file;
  
  int flow_num;
  char *flow_type;

  uint16_t pkt_size;
  uint32_t duration;
  float data_rate; 
  int finished;

  pcap_t *pcap;
  int pcap_fd;
} obj_cfg;

int my_read_objid(char *in_oid, oid *out_oid, size_t *out_oid_len);



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
    fprintf(stderr, "failed %s:%d %s\n", config, config_error_line(&conf), config_error_text(&conf));
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

  elem = config_lookup(&conf, "switch_test_delay.server_port");
  if(elem != NULL) {
    if((test_cfg->server_port = config_setting_get_int(elem)) == 0) {
      printf("Failed to read server_port\n");
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
  elem = config_lookup(&conf, "switch_test_delay.community");
  if(elem != NULL) {
    if((str_val = (char *)config_setting_get_string(elem)) != NULL) {
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
      test_cfg->intf_name = malloc(strlen(str_val) + 1);
      strcpy(test_cfg->intf_name, str_val);
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

  elem = config_lookup(&conf, "switch_test_delay.rate");
  if(elem != NULL) {
    if((test_cfg->data_rate = config_setting_get_int(elem)) == 0) {
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
    snprintf(msg, 1024, "https://%s/ws.v1/switch_delay_test/installflows/%d/%s", (char *)inet_ntoa(addr), 
	     obj_cfg.flow_num, obj_cfg.flow_type);
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
  obj_cfg.pcap = pcap_open_live(obj_cfg.intf_name, 100, 1, 0, errbuf);
  if(obj_cfg.pcap == NULL) {
    printf("pcap_open_live:%s\n", errbuf);
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
};

void 
process_pcap_pkt(const u_char *pkt_data,  struct pcap_pkthdr *pkt_header) {
  printf("processing pkt\n");
}

void *
packet_capture( void *ptr ) {
  fd_set set;
  struct timeval timeout, last_snmp, now;
  struct pcap_pkthdr *pkt_header;
  const u_char *pkt_data;
  int ret;

  gettimeofday(&last_snmp, NULL);

  while(!obj_cfg.finished) {       
    /* Initialize the file descriptor set. */
    FD_ZERO (&set);
    FD_SET(obj_cfg.pcap_fd, &set);
    gettimeofday(&now, NULL);

    /* Initialize the timeout data structure. */
    if((last_snmp.tv_usec - now.tv_usec) < 0) {
      timeout.tv_usec = 1000000 + (last_snmp.tv_usec - now.tv_usec);
      timeout.tv_sec = 9 - now.tv_sec + last_snmp.tv_sec;
    } else {
      timeout.tv_usec = (last_snmp.tv_usec - now.tv_usec);
      timeout.tv_sec = 10 - now.tv_sec + last_snmp.tv_sec;
    }
      

    if( timeout.tv_sec <= 0) {
      memcpy(&last_snmp, &now, sizeof(struct timeval));
      printf("send snmp now:%ld\n", now.tv_sec, last_snmp.tv_sec);
      timeout.tv_sec = 10;
      timeout.tv_usec = 0;
    }

    printf(" %ld.%06ld: timed out at %ld.%06ld\n", now.tv_sec, now.tv_usec, timeout.tv_sec, timeout.tv_usec);
    if( (ret = select(FD_SETSIZE, &set, NULL, NULL, 
		      &timeout)) < 0) {
      perror("capture select");
      exit(1);
    }
    if(ret == 0) {
      gettimeofday(&last_snmp, NULL);
      printf("send snmp%ld\n", last_snmp.tv_sec);
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
  };
  printf("this is the packet capturer\n");
};

void *
packet_generate( void *ptr ) {
  struct timeval start, now;
  char intf_file[1024];
  FILE *file;
  struct in_addr addr;

  //clean up any previous devices in the pktgen intf
  if((file = fopen("/proc/net/pktgen/kpktgend_0", "w")) == NULL)  {
    perror("fopen kpktgend_0");
    exit(1);
  }
  fprintf(file, "rem_device_all\n");
  fclose(file);

  //add the device over which we send packets
  //if((file = fopen("/proc/net/pktgen/kpktgend_0", "w")) == NULL)  {
  if((file = fopen("kpktgend_0", "w")) == NULL)  {
    perror("fopen kpktgend_0");
    exit(1);
  }
  fprintf(file, "add_device %s\n", obj_cfg.intf_name);
  fclose(file);

  snprintf(intf_file, 1024, "/proc/net/pktgen/%s",obj_cfg.intf_name);
  snprintf(intf_file, 1024, "%s",obj_cfg.intf_name);
  if((file = fopen(intf_file, "w")) == NULL)  {
    perror("fopen intf_file");
    exit(1);
  }
  fprintf(file, "clone_skb 0\n");
  uint32_t delay = (uint32_t)((obj_cfg.data_rate*1000000000)/(8*obj_cfg.pkt_size));
  fprintf(file, "delay %lu\n", (long unsigned int)delay);
  printf("delay %lu\n", (long unsigned int)delay);
  fprintf(file, "count %lu\n", (long unsigned int)(obj_cfg.duration*1000000000/delay));
  printf("count %lu\n", (long unsigned int)(obj_cfg.duration*1000000000/delay));
  fprintf(file, "pkt_size %d\n", obj_cfg.pkt_size);

  fprintf(file, "dst_min 10.3.0.1\n");
  addr.s_addr = htonl(ntohl(inet_addr("10.3.0.1")) + obj_cfg.flow_num);
  fprintf(file, "dst_max %s\n", (char *)inet_ntoa(addr)); 
  fprintf(file, "flag IPDST_RND\n"); 

  fprintf(file, "vlan_id 0xffff\n");
  fprintf(file, "vlan_p 0\n"); 
  fprintf(file, "vlan_cfi 0\n"); 
  fprintf(file, "dst_mac 10:20:30:40:50:60\n");
  fprintf(file, "src_mac 10:20:30:40:50:61\n");
  fprintf(file, "src_min 10.2.0.1\n");
  fprintf(file, "src_max 10.2.0.1\n");
  fprintf(file, "tos 4\n");
  fprintf(file, "udp_src_max 8080\n");
  fprintf(file, "udp_src_min 8080\n");
  fprintf(file, "udp_dst_max 8080\n");
  fprintf(file, "udp_dst_min 8080\n");

  fclose(file);

  //start packet generation
  //  if((file = fopen("/proc/net/pktgen/pgctrl", "w")) == NULL)  {
  if((file = fopen("pgctrl", "w")) == NULL)  {
    perror("fopen pgctrl");
    exit(1);
  }
  fprintf(file, "start\n");
  fclose(file);

  /* gettimeofday(&start, NULL); */
  /* do { */
  /*   pthread_yield(); */
  /*   gettimeofday(&now, NULL); */
  /* } while(now.tv_sec - start.tv_sec < 31); */

    printf("this is the packet generator\n");
    obj_cfg.finished = 1;
};

int 
main(int argc, char **argv) {
  pthread_t thrd_capture, thrd_generate;

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

  init_pcap();

  if( (pthread_create( &thrd_capture, NULL, packet_capture, NULL)) ||
      (pthread_create( &thrd_generate, NULL, packet_generate, NULL))) {
    perror("pthread_create");
    exit(1);
  }

  pthread_join(thrd_capture, NULL);
  pthread_join(thrd_generate, NULL); 

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
