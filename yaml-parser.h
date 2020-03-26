#ifndef _YAML_CONFIG_H
#define _YAML_CONFIG_H

typedef int (yaml_config_pair)(char *key,const char *val,void *data);

int yaml_config_pairs(char *cfg_file,char *keybuf,size_t keysize, yaml_config_pair callback,void *data);

#endif

