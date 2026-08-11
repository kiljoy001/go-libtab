/*
 * libtab error reporting.  Single thread-local buffer; tab_lasterror()
 * returns its current contents.
 */

#include "tab_internal.h"
#ifdef __GNUC__
#include <stdarg.h>
#endif

static char tab_errbuf[256] = "no error";

/*
 * Plan 9's %q (quoted string) is not a built-in verb: fmt only knows it after
 * an explicit fmtinstall, and nothing in lib9 does that for a library rather
 * than a command. Without it vsnprint emitted the verb literally, so every
 * message using %q read "column %q% has unsupported type %q%" instead of
 * naming the column.
 *
 * Registered lazily here rather than from an init function because
 * tab_seterror is the only place libtab formats with %q, so there is no
 * ordering to get wrong: the verb is installed before its first possible use
 * and cannot be missed by a caller that skips some setup step.
 */
static void
ensure_fmt(void)
{
	static int installed = 0;

	if(!installed){
		fmtinstall('q', quotestrfmt);
		installed = 1;
	}
}

void
tab_clearerror(void)
{
	tab_errbuf[0] = '\0';
}

void
tab_seterror(const char *fmt, ...)
{
	va_list ap;

	ensure_fmt();
	va_start(ap, fmt);
	vsnprint(tab_errbuf, sizeof tab_errbuf, (char *)fmt, ap);
	va_end(ap);
}

const char *
tab_lasterror(void)
{
	if(tab_errbuf[0] == '\0')
		return "no error";
	return tab_errbuf;
}
