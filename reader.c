
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <stdarg.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <pcre.h>

#include "reader.h"
#include "yaml-parser.h"

static const int signum = SIGUSR2;

char *PidFile = NULL;

struct file_str {
	struct file_str *next;
	char str[];
};

pthread_mutex_t fc_mutex;

struct file_cache {
	char		name[256];
	time_t		rt;
	int		lines;
	struct file_str *data;
} file_cache[READER_CFG_MAX];

struct reader_helper *RD[READER_CFG_MAX];
int RD_count = 0;
struct reader_config {
        int             line,word,p_int,delta,numbers;
        char            name[32],merge[32],fmt[16];
        char            *file;
        char            *filter, *subst;
	pcre		*re,*s_re;
};

static struct reader_config default_rc = { .name="default" },
			    RC[READER_CFG_MAX];


void reader_update_result(struct reader_helper *rr) {
	char ofmt[128];
	float avg = rr->value_last;
	if(rr->values_count > 1) {
		avg = rr->value_sum / rr->values_count;
	}
	snprintf(ofmt,sizeof(ofmt)-1,"%s %s %s %s %%d\n",rr->fmt,rr->fmt,rr->fmt,rr->fmt);
	snprintf(rr->result,sizeof(rr->result)-1,ofmt,
		rr->value_last,avg,rr->value_min,rr->value_max,rr->values_count);
#if 0
	for(i=0; i < rr->values_count; i++)
		l += snprintf(&rr->result[l],sizeof(rr->result)-1-l," %g",rr->values[i]);
#endif
}

void free_reader_cache(struct file_cache *rc) {
struct file_str *c,*n;
for(n = NULL, c = rc->data; c; c = n) {
	n = c->next;
	free(c);
}
rc->data = NULL;
rc->lines = 0;
}

struct file_cache *reader_fetch_data(char *file,int p_int) {
int i,l;
FILE *fd;
char line_buf[512],*str;
struct file_str *c,*n;
time_t tm = time(NULL);
//	fprintf(stderr,"Fetch %s\n",file);

	for(i=0; i < READER_CFG_MAX && file_cache[i].name[0]; i++) {
		if(!strcmp(file_cache[i].name,file)) {
			if(file_cache[i].rt > tm-p_int) {
//				fprintf(stderr,"Cached %s from %d\n",file,i);
				return &file_cache[i];
			} else {
//				fprintf(stderr,"Expired %s from %d\n",file,i);
				break;
			}
		}
	}
	if(i >= READER_CFG_MAX) return NULL;
//	fprintf(stderr,"Read %d %s\n",i,file);
	strncpy(file_cache[i].name,file,sizeof(file_cache[i].name)-1);
	free_reader_cache(&file_cache[i]);

	fd = fopen(file,"r");
	if(!fd) return NULL;
	n = NULL;
	c = NULL;
	while((str = fgets(line_buf,sizeof(line_buf)-1,fd)) != NULL) {
		l = strlen(str);
		if(l > 0 && str[l-1] == '\n') {
			l--;
			str[l] = '\0';
		}
		c = malloc(sizeof(struct file_str)+l+2);
		if(!c) return NULL; //FIXME
		c->next = NULL;
		strcpy(&c->str[0],str);
		if(!file_cache[i].data) file_cache[i].data = c;
		if(n) n->next = c;
		n = c;
		file_cache[i].lines++;
//		fprintf(stderr,"Fetch %d:%d:%s\n",i,file_cache[i].lines,str);
	}
	fclose(fd);
	file_cache[i].rt = time(NULL);
	return &file_cache[i];
}


int reader_get_data(struct reader_helper *rr) {
char line_buf[512],*saveptr1,*str,*wt;
struct file_cache *fc;
struct file_str *fstr;
int line,word,next,i;
float v;
	rr->stage = 1;
	if(!rr || !rr->file[0]) return 1;

	rr->stage++;
	pthread_mutex_lock(&fc_mutex);
	fc = reader_fetch_data(rr->file,rr->p_int);
	pthread_mutex_unlock(&fc_mutex);
	if(!fc) return 1;
	rr->stage++;
	fstr = fc->data;
	for(line=1; fstr && line <= rr->line; fstr = fstr->next ) {
		strncpy(line_buf,fstr->str,sizeof(line_buf));
		str = line_buf;
//		fprintf(stderr,"Line %d %s\n",rr->line,line_buf);
		if(rr->re) {
			int pcreExecRet;
			int mvector[32];
			pcreExecRet = pcre_exec(rr->re,NULL,str,strlen(str),
					0,0,mvector,32);
			if(pcreExecRet >= 0) {
				line++;
			}
		} else {
			line++;
		}
	}
	if(!str) return 1;

	rr->stage++;
	wt = strchr(line_buf,'\n');
	if(wt) *wt = '\0';
//	fprintf(stderr,"Line %d %s OK\n",rr->line,line_buf);
	for(word=1,str = line_buf; word <= rr->word; word++,str = NULL) {
		wt = strtok_r(str," \t,:;",&saveptr1);
		if(!wt) break;
	}
	if(!wt) return 1;

	rr->stage++;
//	fprintf(stderr,"Word %d '%s' OK\n",rr->word,wt);
	if(rr->s_re) {
		int mvector[16];
		int pcreExecRet = pcre_exec(rr->s_re,NULL,wt,strlen(wt), 0,0,mvector,16);
//		fprintf(stderr,"pcre_exec %d %d %d OK\n",pcreExecRet,mvector[2],mvector[3]);
		if(pcreExecRet >= 2) {
			wt[mvector[3]] = '\0';
			wt += mvector[2];
//			fprintf(stderr,"subst '%s' OK\n",wt);
		} else {
			*wt = '\0';
			fprintf(stderr,"subst RE not match!\n");
		}
	}
	v = strtof(wt,&saveptr1);
	if(*saveptr1) return 1;

	rr->stage = 0;
	if(rr->delta) {
		float t = rr->values_count ? v - rr->value_delta : 0;
		rr->value_delta = v;
		v = t/rr->p_int;
	}
//	fprintf(stderr,"value %s %g OK\n",rr->name,v);
	rr->value_last = v;
	if(rr->values_count < rr->numbers) {
		if(rr->values_count) rr->value_index++;
		rr->values[rr->value_index] = v;
		if( (rr->values_count && !rr->delta) || 
		    (rr->values_count > 1 && rr->delta) ) {
			if(v < rr->value_min) rr->value_min = v;
			if(v > rr->value_max) rr->value_max = v;
		} else {
			rr->value_min = v;
			rr->value_max = v;
		}
		rr->values_count++;
		rr->value_sum += v;
//	fprintf(stderr,"value0 %s %g min:%g max:%g\n",rr->name,v,rr->value_min,rr->value_max);
		return 0;
	}
	next = (rr->value_index + 1) % rr->numbers;
	rr->values[next] = v;
	rr->value_index = next;
	rr->value_min = v;
	rr->value_max = v;
	rr->value_sum = 0.0;
	for(i=0; i < rr->numbers; i++) {
		rr->value_sum += rr->values[i];
		if(rr->values[i] < rr->value_min) rr->value_min = rr->values[i];
		if(rr->values[i] > rr->value_max) rr->value_max = rr->values[i];
	}
//	fprintf(stderr,"value1 %s %g min:%g max:%g\n",rr->name,v,rr->value_min,rr->value_max);
	return 0;
}

long int delta_tv(struct timeval *tv1,struct timeval *tv0) {
int64_t t1 = tv1->tv_sec*1000 + tv1->tv_usec/1000;
int64_t t0 = tv0->tv_sec*1000 + tv0->tv_usec/1000;
return (long int)(t0 - t1);
}

#define BUF_TIME_SIZE 32
static u_int64_t tv_start = 0;
char *getctm(char *buf) {
struct timeval tv0;
u_int64_t tv = 0;
gettimeofday(&tv0,NULL);
tv = tv0.tv_sec * 1000 + tv0.tv_usec/1000;

if(!tv_start) tv_start = tv;
tv -= tv-tv_start;
snprintf(buf,BUF_TIME_SIZE - 1,"%d.%03d",(int)tv / 1000,(int)tv % 1000);
return buf;
}

void my_sig_h(int s) {
// nothing
}

static int debug_cmd_helper = 0;

void *cmd_helper(void *par)
{
sigset_t s,sw;
struct reader_helper *rr = (struct reader_helper*)par;
char *name = rr->name;
int t_start;
int count=0;
char tm_buf[BUF_TIME_SIZE];
FILE *flog;
struct timespec now;
struct itimerspec itv;
int tfd = -1;
u_int64_t exptm;

rr->tid = syscall(__NR_gettid);

sigemptyset(&s);
sigaddset(&s,signum);
sigprocmask(SIG_UNBLOCK, &s, NULL);
signal(signum,my_sig_h);
siginterrupt(signum,1);

flog = stderr;

if (clock_gettime(CLOCK_REALTIME, &now) == -1) {
	fprintf(flog,"%s %s %s clock_gettime %s\n",
		getctm(tm_buf),__func__,name, strerror(errno));
	fflush(flog);
	rr->work = 0;
	return NULL;
}

tfd = timerfd_create(CLOCK_REALTIME, 0);
if(tfd < 0) {
	fprintf(flog,"%s %s %s create_timerfd %s\n",
		getctm(tm_buf),__func__,name, strerror(errno));
	fflush(flog);
	rr->work = 0;
	return NULL;
}
itv.it_value.tv_sec = now.tv_sec + rr->p_int;
itv.it_value.tv_nsec = now.tv_nsec;
itv.it_interval.tv_sec = rr->p_int;
itv.it_interval.tv_nsec = 0;
if (timerfd_settime(tfd, TFD_TIMER_ABSTIME, &itv, NULL) == -1) {
	fprintf(flog,"%s %s %s timerfd_settime %s\n",
		getctm(tm_buf),__func__,name, strerror(errno));
	fflush(flog);
	rr->work = 0;
	return NULL;
}

if(debug_cmd_helper) {
	fprintf(flog,"%s %s %s %d/%u/%lu\n",getctm(tm_buf),__func__,name,
		getpid(), rr->tid, pthread_self());
	fflush(flog);
}

do {
	if(reader_get_data(rr)) {
		strcpy(rr->result,"0 0 0 0 0\n");
		fprintf(flog,"%s %s %s count %d reader_get_data error stage %d\n",
			getctm(tm_buf),__func__,name,count,rr->stage);
		fflush(flog);
	} else {
		reader_update_result(rr);
	}

	if(debug_cmd_helper) {
		fprintf(flog,"%s %s %s count %d result %s",
			getctm(tm_buf),__func__,name,count,rr->result);
		fflush(flog);
	}

	sigemptyset(&sw);
	sigaddset(&sw,signum);
	sigpending (&sw);
	if(sigismember (&sw, signum)) break;

	do {
		t_start = read(tfd, &exptm, sizeof(u_int64_t));
	} while(rr->work && t_start < 0 && errno == EINTR);
	if(!rr->work) break;

	if(t_start != sizeof(u_int64_t)) break;
	count++;
} while(rr->work);

if(debug_cmd_helper) {
	fprintf(flog,"%s %s %s %d/%lu exit\n",
		getctm(tm_buf),__func__,name,getpid(),pthread_self());
	fflush(flog);
}
if(tfd >= 0) close(tfd);
if(flog != stderr) fclose(flog);
rr->work = 0;
return NULL;
}

void delete_reader(struct reader_helper *rr) {
	if(rr->work && rr->tid && rr->th_cmd_helper) {
		long int *rv;
		rr->work = 0;
		syscall(__NR_tkill,rr->tid,signum);
		pthread_join(rr->th_cmd_helper,(void **)&rv);
	}
	free(rr);
}

struct reader_helper *create_reader(struct reader_config *rc) {

struct reader_helper *rr;
int i;
int err_pos;
const char *re_err;

	if(rc->numbers > READER_CFG_MAX) return NULL;
	if(!rc->p_int  || rc->p_int > 600) return NULL;

	rr = calloc(1,sizeof(*rr));

	if(!rr) return rr;

	bzero((char *)rr,sizeof(*rr));
	strncpy(rr->name,rc->name,sizeof(rr->name)-1);
	strncpy(rr->file,rc->file,sizeof(rr->file)-1);
	strncpy(rr->fmt, rc->fmt ? rc->fmt:"%g",sizeof(rr->fmt)-1);
	if(rc->filter) strncpy(rr->filter,rc->filter,sizeof(rr->filter)-1);
	if(rc->subst) strncpy(rr->subst,rc->subst,sizeof(rr->subst)-1);
	rr->line = rc->line;
	rr->word = rc->word;
	rr->p_int = rc->p_int;
	rr->delta = rc->delta != 0;
	rr->numbers = rc->numbers;
	for(i = 0; i < READER_CFG_MAX; i++) rr->values[i] = 0.0;
	rr->value_last = rr->value_min = rr->value_max = 0.0;
	strcpy(rr->result,"none\n");
	if(rc->filter)
		rr->re = pcre_compile(rr->filter,0,&re_err,&err_pos,NULL);
	if(rc->subst)
		rr->s_re = pcre_compile(rr->subst,0,&re_err,&err_pos,NULL);
	return rr;
}

int run_reader_helper(struct reader_helper *rr) {
	rr->work = 1;
	if(pthread_create(&rr->th_cmd_helper,NULL,cmd_helper,(void *)rr)) {
		free(rr);
		return 1;
	}
	// pthread_detach(rr->th_cmd_helper);
	return 0;
}



void merge_config_default(struct reader_config *rc,const struct reader_config *std) {
const char *w = "unknown";
do {
  w = "line";
  if(!rc->line) rc->line = std->line;
  if(!rc->line) break;
  w = "word";
  if(!rc->word) rc->word = std->word;
  if(!rc->word) break;
  w = "interval";
  if(!rc->p_int) rc->p_int = std->p_int;
  if(!rc->p_int) break;
  w = "number";
  if(!rc->numbers) rc->numbers = std->numbers;
  if(!rc->numbers) break;

  if(!rc->fmt[0]) strncpy(rc->fmt,std->fmt,sizeof(rc->fmt));
  if(!rc->fmt[0]) strncpy(rc->fmt,"%g",sizeof(rc->fmt));

  if(!rc->delta) rc->delta = std->delta;
  return;
} while(0);

fprintf(stderr,"Invalid default options '%s' for %s\n",w,rc->name);
exit(1);
}

void merge_config(struct reader_config *rc,const struct reader_config *std) {
  if(!rc->line) rc->line = std->line;
  if(!rc->word) rc->word = std->word;
  if(!rc->p_int) rc->p_int = std->p_int;
  if(!rc->numbers) rc->numbers = std->numbers;
  if(!rc->fmt[0]) strncpy(rc->fmt,std->fmt,sizeof(rc->fmt));
  if(!rc->delta) rc->delta = std->delta;
  if(!rc->filter) rc->filter = std->filter;
  if(!rc->subst) rc->subst = std->subst;
}


struct reader_config *find_rc(const char *key,char **par,int no_add) {
    char *c;
    static char kbuf[64];
    int i;

    if(!strncmp(key,"default.",8)) {
	strncpy(kbuf,key+8,sizeof(kbuf)-1);
	if(par) *par = kbuf;
//	fprintf(stderr,"Return default %s\n",kbuf);
	return &default_rc;
    }
    // source.name.par
    strncpy(kbuf,key+7,sizeof(kbuf)-1);
    c = strchr(kbuf,'.');
    if(par) *par = c ? c+1:NULL;
    if(c) *c = '\0';
    for(i=0; i < READER_CFG_MAX; i++) {
	if(RC[i].name[0]) {
		if(!strcmp(kbuf,RC[i].name)) {
//			fprintf(stderr,"%s: Return '%s' %d\n",__func__,kbuf,i);
			return &RC[i];
		}
		continue;
	}
	if(no_add) return NULL;
//	fprintf(stderr,"%s: Add '%s' %d\n",__func__,kbuf,i);
	strncpy(RC[i].name,kbuf,sizeof(RC[i].name));
	return &RC[i];
    }
    return NULL;
}

static int cfg_valid_re(const char *str_re) {
const char* error;
int erroroffset;
pcre *re;
	if(!str_re) return 0;
//	fprintf(stderr,"%s: %s\n",__func__,str_re);
	re = pcre_compile(str_re,0,&error,&erroroffset, NULL);
	if(re == NULL) {
		fprintf(stderr,"Bad re: %s pos %d\n",error,erroroffset);
		return 0;
	}
	pcre_free(re);
	return 1;
}

static int cfg_error = 0;
static int cfg_print(char *key,const char *val,void *data) {
struct reader_config *rc;
char *par;

    if(!strcmp(key,"PidFile")) {
	PidFile = strdup(val);
	return 0;
    }
    if(!strncmp(key,"default.",8) || !strncmp(key,"source.",7)) {
	par = NULL;
	rc = find_rc(key,&par,0);
	if(rc) {
		if(!par) return 0;
		if(!strcmp(par,"file")) {
			rc->file = strdup(val);
			return 0;
		}
		if(!strcmp(par,"line")) {
			rc->line = strtol(val,NULL,10);
			return 0;
		}
		if(!strcmp(par,"word")) {
			rc->word = strtol(val,NULL,10);
			return 0;
		}
		if(!strcmp(par,"interval")) {
			rc->p_int = strtol(val,NULL,10);
			return 0;
		}
		if(!strcmp(par,"delta")) {
			rc->delta = strtol(val,NULL,10);
			return 0;
		}
		if(!strcmp(par,"number")) {
			rc->numbers = strtol(val,NULL,10);
			return 0;
		}
		if(!strcmp(par,"filter")) {
			if(!cfg_valid_re(val)) { cfg_error = 1; return 0; }
			rc->filter = strdup(val);
			if(!rc->filter) abort();
			return 0;
		}
		if(!strcmp(par,"subst")) {
			if(!cfg_valid_re(val)) { cfg_error = 1; return 0; }
			rc->subst = strdup(val);
			if(!rc->subst) abort();
			return 0;
		}
		if(!strcmp(par,"fmt")) {
			strncpy(rc->fmt,val,sizeof(rc->fmt)-1);
			return 0;
		}
		if(!strcmp(par,"merge")) {
			strncpy(rc->merge,val,sizeof(rc->merge)-1);
			return 0;
		}
	}

    }
    fprintf(stderr, " Unknown option %s=%s\n",key,val);
    cfg_error = 1;
    return 0;
}

void stop_readers(void)
{
int i;
	for(i=0; i < READER_CFG_MAX; i++) {
		if(RD[i]) delete_reader(RD[i]);
	}
}

int parse_readers(char *cfg)
{
char buf[256];
int i;
	if(!cfg) return 1;

	if(!yaml_config_pairs(cfg,buf,sizeof(buf),cfg_print,NULL) || cfg_error) {
//		fprintf(stderr,"cfg error %d\n",cfg_error);
		return 1;
	}

	for(i=0; i < READER_CFG_MAX && RC[i].name[0]; i++) {
		if(!RC[i].file) {
			stop_readers();
			return 1;
		}
		if(RC[i].merge[0]) {
			char *par = NULL,m_key[64];
			strcpy(m_key,"source.");
			strcat(m_key,RC[i].merge);
			struct reader_config *rc = find_rc(m_key,&par,1);
			if(!rc) {
				fprintf(stderr,"Name '%s' not found\n",RC[i].merge);
				return 1;
			}
			merge_config(&RC[i],rc);
		}
		merge_config_default(&RC[i],&default_rc);
		RD[i] = create_reader(&RC[i]);
		if(!RD[i]) {
			stop_readers();
			return 1;
		}
		RD_count = i;
	}
	for(i=0; i < READER_CFG_MAX && RC[i].name[0]; i++) {
		free(RC[i].file);
		RC[i].file = NULL;
		if(RC[i].filter) {
			free(RC[i].filter);
			RC[i].filter = NULL;
		}
	}
	pthread_mutex_init(&fc_mutex,NULL);
	return 0;
}

int check_readers(void) {
int i;
	for(i=0; i <= RD_count; i++) {
		if(!RD[i]) return 1;
		if(reader_get_data(RD[i])) return 1;
		RD[i]->values_count = 0;
	}
	return 0;
}

int run_readers(void) {
int i;
	for(i=0; i <= RD_count; i++) {
		if(run_reader_helper(RD[i])) return 1;
	}
	return 0;
}

int count_readers(void) {
int i,n;
	for(i=0,n=0; i <= RD_count; i++) {
		if(RD[i]->work) n++;
	}
	return n != RD_count+1;
}


#ifdef MAIN_TESTING

int main(int argc,char **argv) {

sigset_t s;
int rsignal;

	if(!argv[1]) abort();

	if(parse_readers(argv[1])) exit(1);
	if(run_readers()) exit(1);
	sigemptyset(&s);
	sigaddset(&s,SIGINT);
	sigprocmask(SIG_BLOCK, &s, NULL);
	siginterrupt(SIGINT,1);
	sigwait(&s,&rsignal);
	
	stop_readers();
	exit(0);
}
#endif

