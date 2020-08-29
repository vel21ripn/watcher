
#include <yaml.h>

#include <stdlib.h>
#include <stdio.h>

#include "yaml-parser.h"

#define P_KEY (char *)1
#define P_VAL (char *)2
#define P_SEQ (char *)3
#define P_LVL (char *)4

static int is_str(char *s) {
    return ((unsigned long int)s & 0x7) == 0;
}

static void print_path(char **path,int last,char *buf,size_t buflen) {
	int i,l;

	for(i=1,l=0; i < last; i++) {
		if(path[i] != P_KEY) continue;
		if(i+1 > last) break;
		if(l && l < buflen-2) 
				buf[l++]='.';
		if(is_str(path[i+1])) {
			int sl = strlen(path[i+1]);
			if(sl < buflen - l - 1) {
					strcpy(&buf[l],path[i+1]);
					l += sl;
			}
			i++;
		}
    }
    buf[l] = '\0';
}

static int _yaml_trace_parser = 0;
#define MAX_PATH_LEN 128
int yaml_config_pairs(char *cfg_file,char *keybuf,size_t keysize, yaml_config_pair callback,void *data) {
    FILE *file;
    yaml_parser_t parser;
    yaml_token_t  token;
    char *path[MAX_PATH_LEN]= {"> ",NULL};
    int ipath = 0;

    file = fopen(cfg_file, "rb");
    if(!file) return 0;

    if(!yaml_parser_initialize(&parser)) return 0;

    yaml_parser_set_input_file(&parser, file);

    do {
		if(ipath >= MAX_PATH_LEN) {
			token.type = YAML_NO_TOKEN;
			break;
		}
        yaml_parser_scan(&parser, &token);
        switch(token.type)
        {
        case YAML_STREAM_START_TOKEN:    if(_yaml_trace_parser) puts("STREAM START");
										 break;
        case YAML_STREAM_END_TOKEN:      if(_yaml_trace_parser) puts("STREAM END");
										 break;
        case YAML_DOCUMENT_START_TOKEN:  if(_yaml_trace_parser) puts("DOC START");
										 break;
        case YAML_DOCUMENT_END_TOKEN:    if(_yaml_trace_parser) puts("DOC END");
										 break;
        case YAML_BLOCK_SEQUENCE_START_TOKEN: if(_yaml_trace_parser) puts("\t<b>Start Block (Sequence)</b>");
										 break;

        case YAML_KEY_TOKEN:     if(_yaml_trace_parser)printf("\t(Key token)   "); 
                                 path[++ipath] = P_KEY;
								 break;
        case YAML_VALUE_TOKEN:   if(_yaml_trace_parser)printf("\t(Value token) ");
                                 path[++ipath] = P_VAL;
								 break;
        case YAML_BLOCK_ENTRY_TOKEN:
                                 if(_yaml_trace_parser) puts("\t<b>Start Block (Entry)</b>");    
                                 path[++ipath] = P_SEQ;
								 break;
        case YAML_BLOCK_END_TOKEN:
                                 if(_yaml_trace_parser)  puts("\t<b>End block</b>");
                                 if(path[ipath] == P_LVL) ipath--;

                                 if(path[ipath] == P_VAL &&
                                    path[ipath-2] == P_KEY ) ipath-=3;
                                 break;
        case YAML_BLOCK_MAPPING_START_TOKEN:
                                 if(_yaml_trace_parser) puts("\n\t[Block mapping]");
                                 path[++ipath] = P_LVL;
								 break;
        case YAML_SCALAR_TOKEN:
                                if(_yaml_trace_parser)printf("\tscalar %s \n", token.data.scalar.value);
                                path[++ipath] = strdup((char *)token.data.scalar.value);

                                if(path[ipath-1] == P_VAL || path[ipath-1] == P_SEQ) { 
                                     print_path(path,ipath,keybuf,keysize);
                                     callback(keybuf,path[ipath],data);
                                }

                                if(path[ipath-1] == P_VAL && path[ipath-3] == P_KEY) {
                                     free(path[ipath]);
                                     free(path[ipath-2]);
                                     ipath -= 4;
                                }
                                if(path[ipath-1] == P_SEQ) {
                                     free(path[ipath]);
                                     ipath -= 2;
                                }
                                break;
        default:
            if(_yaml_trace_parser) printf("Got token of type %d\n", token.type);
        }
        if(token.type == YAML_NO_TOKEN || token.type == YAML_STREAM_END_TOKEN) break;
        yaml_token_delete(&token);
    } while(1);

    yaml_parser_delete(&parser);
    fclose(file);

    return token.type == YAML_STREAM_END_TOKEN;
}

#ifdef MAIN_TESTING
static int cfg_print(char *key,const char *val,void *data) {
    printf("%s=%s\n",key,val);
    return 0;
}

int
main(int argc, char *argv[])
{
    char buf[256];
    yaml_config_pairs(argv[1],buf,sizeof(buf),cfg_print,NULL);
}
#endif

/*
 * vim: set tabstop=4:shiftwidth=4:sts=4:expandtab:foldmethod=marker:foldmarker={{{{,}}}}:
 */

