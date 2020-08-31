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
#define _GNU_SOURCE

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
#include <getopt.h>
#include <fuse.h>
#include <pcre.h>

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
    int show_help;
} options;

#define OPTION(t, p, v)                           \
    { t, offsetof(struct options, p), v }
static const struct fuse_opt option_spec[] = {
    OPTION("-h", show_help, 0),
    OPTION("--help", show_help, 0),
    FUSE_OPT_END
};

/*
 * pidfile
 */
// create_pidfile,is_valid_pidfile  {{{{
static int create_pidfile(char *pfile) {
int fd,pid_file_ok;
ssize_t n;
char buf[64];
fd = creat(pfile,0644);
if(fd < 0) return 1;
snprintf(buf,sizeof(buf)-1,"%d\n",getpid());
n = write(fd,buf,strlen(buf));
fd = close(fd);
pid_file_ok = fd == 0 && n == strlen(buf);
return pid_file_ok == 0;
}

static int is_valid_pidfile(char *pfile,int nocreate) {
int fd;
ssize_t n;
char buf[64];
struct stat st;

fd = open(pfile,O_RDONLY);
if(fd < 0) 
    return nocreate ? 0 : create_pidfile(pfile);
bzero(buf,sizeof(buf));
n = read(fd,buf,sizeof(buf)-1);
close(fd);
if(n > 0) {
    int pid;
    if(sscanf(buf,"%d",&pid) == 1) {
        snprintf(buf,sizeof(buf)-1,"/proc/%d",pid);
        if(stat(buf,&st) < 0) {
            return nocreate ? 0 : create_pidfile(pfile);
        }
    }
    return 1;
}
return nocreate ? 0 : create_pidfile(pfile);
}
//}}}}

static void *log_init(struct fuse_conn_info *conn)
//          struct fuse_config *cfg)
{
//  (void) conn;
//  cfg->kernel_cache = 1;
    if(run_readers()) {
        fprintf(stderr,"run_readers error\n");
        kill(0,SIGTERM);
    }
    sleep(1);
    if(count_readers()) {
        fprintf(stderr,"count_readers error\n");
        kill(0,SIGTERM);
    }
    if(PidFile) {
            if(is_valid_pidfile(PidFile,0)) {
                    fprintf(stderr,"Found valid PID file %s\n",PidFile);
                    kill(0,SIGTERM);
            }
    }
return NULL;
}

static int log_getattr(const char *path, struct stat *stbuf)
//           struct fuse_file_info *fi)
{
//  (void) fi;
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
//           enum fuse_readdir_flags flags)
{
//  (void) flags;

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
    .getattr    = log_getattr,
    .readdir    = log_readdir,
    .open       = log_open,
    .read       = log_read,
};

static void show_help(const char *progname)
{
    printf("usage: %s options [mountpoint]\n\n", progname);
    printf("File-system specific options:\n"
           "   -C cfg\n"
           "   --config=cfg          Name of configuration file\n"
           "   -d                    Run in debug mode.\n"
           "\n");
}

static struct option long_options[] = {
       {"help",    no_argument,       0, 'h' },
       {"debug",   no_argument,       0, 'd' },
       {"config",  required_argument, 0, 'C'},
       {0,         0,                 0,  0 }
};

int main(int argc, char *argv[])
{
    int ret;
        int opt, option_index = 0,debug = 0,help = 0;
    char *cfg_opt = NULL;
    struct fuse_args args = FUSE_ARGS_INIT(0, NULL);

    fuse_opt_add_arg(&args, argv[0]);

    while((opt = getopt_long(argc, argv, "dhC:", long_options, &option_index)) != EOF) {
      switch (opt) {
        case 'd': debug++;  break;
        case 'h': help = 1; break;
        case 'C': cfg_opt = strdup(optarg); break;
        default: show_help(argv[0]);
             exit(1);
      }
    }

    if(help) {
        show_help(argv[0]);
        fuse_opt_add_arg(&args, "--help");
        ret = fuse_main(args.argc, args.argv, &log_oper, NULL);
        exit(0);
    }

    if(!cfg_opt) show_help(argv[0]);

    if(parse_readers(cfg_opt)) {
        fprintf(stderr,"Config error\n");
        exit(1);
    }
    if(debug) fuse_opt_add_arg(&args, "-d");
    if(fuse_mount_options) {
        char *tok,*next=NULL;
        while((tok = strtok_r(fuse_mount_options," \t",&next)) != NULL) {
            fuse_opt_add_arg(&args, tok);
            fuse_mount_options = NULL;
        }
    }
    if(optind < argc) {
        if(fuse_mount_point)
            fprintf(stderr,"Override mount point from config!\n");
        fuse_mount_point = strdup(argv[optind]);
    }

    if(!fuse_mount_point) {
        fprintf(stderr,"Missing mount point\n");
        exit(1);
    }
    fuse_opt_add_arg(&args, fuse_mount_point);

    if (fuse_opt_parse(&args, &options, option_spec, NULL) == -1)
        return 1;

    if(PidFile) {
        if(is_valid_pidfile(PidFile,1)) {
                fprintf(stderr,"Found valid PID file %s\n",PidFile);
                exit(1);
        }
    }
    ret = fuse_main(args.argc, args.argv, &log_oper, NULL);
    stop_readers();
    fprintf(stderr,"exit\n");
    if(PidFile) unlink(PidFile);
    fuse_opt_free_args(&args);
    return ret;
}

/*
 * vim: set tabstop=4:shiftwidth=4:sts=4:expandtab:foldmethod=marker:foldmarker={{{{,}}}}:
 * retab!
 */
