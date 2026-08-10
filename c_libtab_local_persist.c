#include <u.h>
#include <libc.h>
#include "clibtab/tab_internal.h"

extern int rename(const char *oldpath, const char *newpath);

static int
posix_write_atomic(const char *path, const char *bytes, int n)
{
	char tmp[1024];
	int fd;
	long written;

	snprint(tmp, sizeof tmp, "%s.tmp.%d", path, (int)getpid());
	fd = create(tmp, OWRITE, 0644);
	if(fd < 0){
		tab_seterror("tab_commit: create %s: %r", tmp);
		return -1;
	}
	written = write(fd, (void *)bytes, n);
	if(written != n){
		tab_seterror("tab_commit: short write to %s: %ld of %d (%r)",
			tmp, written, n);
		close(fd);
		remove(tmp);
		return -1;
	}
	if(fsync(fd) < 0){
		tab_seterror("tab_commit: fsync %s: %r", tmp);
		close(fd);
		remove(tmp);
		return -1;
	}
	close(fd);
	if(rename(tmp, path) < 0){
		tab_seterror("tab_commit: rename %s -> %s: %r", tmp, path);
		remove(tmp);
		return -1;
	}
	return 0;
}

int
tab_commit(Tab *t)
{
	char *buf;
	int len, rc;

	tab_clearerror();
	if(t == nil){
		tab_seterror("tab_commit: nil Tab");
		return -1;
	}
	if(t->dial != nil){
		tab_seterror("tab_commit: 9P dial persistence is unavailable in cgo build");
		return -1;
	}

	buf = tab_serialize(t, &len);
	if(buf == nil)
		return -1;

	rc = posix_write_atomic(t->path, buf, len);
	free(buf);
	if(rc == 0)
		t->dirty = 0;
	return rc;
}
