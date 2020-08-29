
#define READER_CFG_MAX 64
#define READER_MAX_NUMBER 256

struct reader_helper {
	pthread_t	th_cmd_helper;
	pid_t		tid;
	timer_t		timer_id;
	volatile int	work;
	int		line,word,p_int,delta,numbers;
	int		values_count,value_index,stage;
	float		values[READER_MAX_NUMBER],value_delta,
			value_last,value_min,value_max,value_sum;
	char		fmt[16];
	char 		name[32];
	char		file[256];
	char		result[64];
	char 		filter[64],subst[64];
	pcre		*re,*s_re;
};


int parse_readers(char *cfg);
int check_readers(void);
int run_readers(void);
int count_readers(void);
void stop_readers(void);

struct reader_config;

struct reader_helper *create_reader(struct reader_config *rc);
void delete_reader(struct reader_helper *);

extern struct reader_helper *RD[READER_CFG_MAX];
extern int RD_count;
extern char *PidFile;
extern char *fuse_mount_options;
extern char *fuse_mount_point;
