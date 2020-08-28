
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
	char		result[64];
	char		file[256];
	char 		name[32];
};


int parse_readers(char *cfg);
int check_readers(void);
int run_readers(void);
int count_readers(void);
void stop_readers(void);

struct reader_helper *create_reader(char *name,char *file,int line,int word,int interval,int delta,int numbers);
void delete_reader(struct reader_helper *);

extern struct reader_helper *RD[READER_CFG_MAX];
extern int RD_count;
extern char *PidFile;
