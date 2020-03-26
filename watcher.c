/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPLv2.
  See the file COPYING.
*/

/** @file
 *
 * minimal example filesystem using high-level API
 *
 * Compile with:
 *
 *     gcc -Wall hello.c `pkg-config fuse3 --cflags --libs` -o hello
 *
 * ## Source code ##
 * \include hello.c
 */


#define FUSE_USE_VERSION 29

#include <pthread.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <stddef.h>
#include <assert.h>
#include <unistd.h>
#include <signal.h>
#include <fuse.h>

#include "yaml-parser.h"
#include "reader.h"

/*
 * Command line options
 *
 * We can't set default values for the char* fields here because
 * fuse_opt_parse would attempt to free() them when the user specifies
 * different values on the command line.
 */

static struct options {
	char *config;
	int show_help;
} options;

#define OPTION(t, p, v)                           \
    { t, offsetof(struct options, p), v }
static const struct fuse_opt option_spec[] = {
	OPTION("-C %s", config, 1),
	OPTION("--config=%s", config, 1),
	OPTION("-h", show_help, 0),
	OPTION("--help", show_help, 0),
	FUSE_OPT_END
};

static void *log_init(struct fuse_conn_info *conn)
//			struct fuse_config *cfg)
{
//	(void) conn;
//	cfg->kernel_cache = 1;
	if(run_readers()) {
		fprintf(stderr,"run_readers error\n");
		kill(0,SIGTERM);
	}
	sleep(1);
	if(count_readers()) {
		fprintf(stderr,"run_readers error\n");
		kill(0,SIGTERM);
	}
	return NULL;
}

static int log_getattr(const char *path, struct stat *stbuf)
//			 struct fuse_file_info *fi)
{
//	(void) fi;
	int i;

	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
		return 0;
	}
	for(i=0; i <= RD_count; i++) {
		if(!strcmp(path+1,RD[i]->name)) {
			stbuf->st_mode = S_IFREG | 0444;
			stbuf->st_nlink = 1;
			stbuf->st_size = RD[i]->work ? strlen(RD[i]->result): 6;
			return 0;
		}
	}

	return -ENOENT;
}

static int log_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
//			 enum fuse_readdir_flags flags)
{
//	(void) flags;

	(void) offset;
	(void) fi;
	int i;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	for(i=0; i <= RD_count; i++) {
		filler(buf, RD[i]->name, NULL, 0);
	}

	return 0;
}

static int log_open(const char *path, struct fuse_file_info *fi)
{
int i;
	for(i=0; i <= RD_count; i++) {
		if(!strcmp(path+1,RD[i]->name)) {
			if ((fi->flags & O_ACCMODE) != O_RDONLY)
				return -EACCES;
			return 0;
		}
	}
	return -ENOENT;
}

static int log_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	(void) fi;
	size_t len;
	int i;
	char *data;

	for(i=0; i <= RD_count; i++) {
		if(!strcmp(path+1,RD[i]->name)) break;
	}
	if(i > RD_count)
		return -ENOENT;
	data = RD[i]->work ? RD[i]->result : "ERROR";
	len = strlen(data);
	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, data + offset, size);
	} else
		size = 0;

	return size;
}

static const struct fuse_operations log_oper = {
	.init           = log_init,
	.getattr	= log_getattr,
	.readdir	= log_readdir,
	.open		= log_open,
	.read		= log_read,
};

static void show_help(const char *progname)
{
	printf("usage: %s options mountpoint\n\n", progname);
	printf("File-system specific options:\n"
	       "   -C cfg\n"
	       "   --config=cfg          Name of configuration file\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	int ret;
	struct fuse_args args = FUSE_ARGS_INIT(argc, argv);
	
	
	/* Parse options */
	if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
		return 1;

	if(!options.config) {
		show_help(argv[0]);
		options.show_help = 1;
	}

	/* When --help is specified, first print our own file-system
	   specific help text, then signal fuse_main to show
	   additional help (by adding `--help` to the options again)
	   without usage: line (by setting argv[0] to the empty
	   string) */

	if (options.show_help) {
		show_help(argv[0]);
		fuse_opt_add_arg(&args, "--help");
		args.argv[0][0] = '\0';
	} else {
	    if(parse_readers(options.config)) {
		fprintf(stderr,"Config error\n");
		exit(1);
	    }
	}
	ret = fuse_main(args.argc, args.argv, &log_oper, NULL);
	stop_readers();
	fprintf(stderr,"exit\n");
	fuse_opt_free_args(&args);
	return ret;
}
