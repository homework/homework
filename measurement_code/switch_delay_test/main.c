#include <stdio.h>
#include <stdint.h>

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

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
};


int my_read_objid(char *in_oid, oid *out_oid, size_t *out_oid_len);

int 
load_cfg(struct test_cfg *test_cfg, const char *config) {
  config_t conf;
  config_setting_t *elem, *data;
  char *snmp_client, *snmp_community;
  int i, len, argc = 0;
  char *path, **argv, *in_oid, *out_oid, *str_val;

  config_init(&conf);
  if(config_read_file(&conf, config) == CONFIG_FALSE) {
    fprintf(stderr, "failed %s:%d %s\n", config, config_error_line(&conf), config_error_text(&conf));
    return 0;
  }

  //reading the traffic generator paramters
  elem = config_lookup(&conf, "switch_test_delay.server_ip");
  if(elem != NULL) {
    if((str_val = config_setting_get_string(elem)) != NULL) {
      test_cfg->server_ip = inet_addr(str_val);
      printf("server_ip:%lX\n", ntohl(test_cfg->server_ip));
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
    if ( ((str_val = config_setting_get_string(elem)) == NULL) || 
	 (!my_read_objid(str_val, test_cfg->cpu_OID, &test_cfg->cpu_OID_len)) ) {
      printf("Failed to read cpu_oid\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.in_mib");
  if(elem != NULL) {
    test_cfg->pkt_in_OID_len = MAX_OID_LEN;
    if ( ((str_val = config_setting_get_string(elem)) == NULL) || 
	 (!my_read_objid(str_val, test_cfg->pkt_in_OID, &test_cfg->pkt_in_OID_len)) ) {
      printf("Failed to read in_oid\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.out_mib");
  if(elem != NULL) {
    test_cfg->pkt_out_OID_len = MAX_OID_LEN;
    if ( ((str_val = config_setting_get_string(elem)) == NULL) || 
	 (!my_read_objid(str_val, test_cfg->pkt_out_OID, &test_cfg->pkt_out_OID_len)) ) {
      printf("Failed to read out_oid\n");
      exit(1);
    }
  }
  elem = config_lookup(&conf, "switch_test_delay.community");
  if(elem != NULL) {
    if((str_val = config_setting_get_string(elem)) != NULL) {
      test_cfg->snmp_community = malloc(strlen(str_val) + 1);
      strcpy(test_cfg->snmp_community, str_val);
    } else {
      printf("Failed to read snmp community\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.data_dev");
  if(elem != NULL) {
    if((str_val = config_setting_get_string(elem)) != NULL) {
      test_cfg->intf_name = malloc(strlen(str_val) + 1);
      strcpy(test_cfg->intf_name, str_val);
    } else {
      printf("Failed to read data interface\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.pkt_output");
  if(elem != NULL) {
    if( ((str_val = config_setting_get_string(elem)) == NULL) || 
	((test_cfg->pkt_file = fopen(str_val, "w")) == NULL) ) {
      perror("Failed to open pkt_output filename\n");
      exit(1);
    }
  }

  elem = config_lookup(&conf, "switch_test_delay.snmp_output");
  if(elem != NULL) {
    if( ((str_val = config_setting_get_string(elem)) == NULL) || 
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
    if((str_val = config_setting_get_string(elem)) != 0) {
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

int 
main(int argc, char **argv) {
  struct test_cfg obj_cfg;

  if(argc < 1) {
    printf("Forgot to set the configuration file name\n");
    exit(1);
  }
  
  printf("switch delay test starting...\n");

  if(!load_cfg(&obj_cfg, argv[1])) {
    printf("Failed to process configuration file\n");
    exit(1);
  }

  //libcurl, libconfig ....

  
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
