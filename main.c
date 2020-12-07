#include <u.h>
#include <libc.h>
#include <bio.h>
#include <mach.h>

int verbosity, keepgoing;
char *out = "out.dol";

typedef struct Dolhdr Dolhdr;
	
struct Dolhdr
{
	u32int txtoff[7];
	u32int datoff[11];
	u32int txtaddr[7];
	u32int dataddr[11];
	u32int txtsz[7];
	u32int datsz[11];
	u32int bssaddr;
	u32int bsssz;
	u32int entry;
	uchar padding[26];
};

#pragma varargck argpos error 1
void
error(char *fmt, ...)
{
	va_list args;
	char *str;

	va_start(args, fmt);
	str = vsmprint(fmt, args);
	fprint(2, "%s: %s\n", argv0, str);
	if(!keepgoing)
		exits(str);
	free(str);
	va_end(args);
}

#pragma varargck argpos error 1
void
verbose(int l, char *fmt, ...)
{
	va_list args;

	if(verbosity < l)
		return;

	va_start(args, fmt);
	vfprint(1, fmt, args);
	va_end(args);
}

#define verbose(lvl, ...) if(verbosity < (lvl)) {} else print(__VA_ARGS__);

void
usage(void)
{
	fprint(2, "usage: %s [-k] [-o out] exec\n", argv0);
	exits("usage");
}

void
main(int argc, char **argv)
{
	Dolhdr dol;
	Fhdr fhdr;
	int ofd, ifd;
	char buf[2048];

	ARGBEGIN {
	case 'o':
		out = EARGF(usage());
		break;
	case 'k':
		keepgoing++;
		break;
	case 'v':
		verbosity++;
		break;
	default:
		usage();
	} ARGEND;

	if(argc != 1)
		usage();

	if((ifd = open(*argv, OREAD)) < 0)
		sysfatal("open: %r");

	if((ofd = create(out, OWRITE|OTRUNC, 0755)) < 0)
		sysfatal("create: %r");

	crackhdr(ifd, &fhdr);

	verbose(1, "executable is %s\n", fhdr.name);

	if(fhdr.type != FPOWER && fhdr.type != FPOWERB)
		error("not a PowerPC executable (%d)", fhdr.type);

	machbytype(fhdr.type);

	dol.txtaddr[0] = beswal(fhdr.txtaddr);
	dol.txtoff[0] = beswal(fhdr.txtoff);
	dol.txtsz[0] = beswal(fhdr.txtsz);
	if(fhdr.txtaddr < 0x80003F00 || fhdr.txtaddr > 0x81330000)
		error("text outside standard executable area (0x%08lX)", (ulong)fhdr.txtaddr);

	verbose(2,
		"TEXT section 0:\n"
		"address: 0x%08ulX\n"
		"offset (file): 0x%08ulX\n"
		"size: 0x%08ulX bytes\n\n",
		beswal(dol.txtaddr[0]), beswal(dol.txtoff[0]), beswal(dol.txtsz[0])
	);

	dol.dataddr[0] = beswal(fhdr.dataddr);
	dol.datoff[0] = beswal(fhdr.datoff);
	dol.datsz[0] = beswal(fhdr.datsz);

	verbose(2,
		"DATA section 0:\n"
		"address: 0x%08ulX\n"
		"offset (file): 0x%08ulX\n"
		"size: 0x%08ulX bytes\n\n",
		beswal(dol.dataddr[0]), beswal(dol.datoff[0]), beswal(dol.datsz[0])
	);

	dol.bssaddr = fhdr.dataddr + fhdr.datsz;	/* FIXME? */
	dol.bsssz = fhdr.bsssz;

	verbose(2,
		"BSS segment:\n"
		"address: 0x%08ulX\n"
		"size: 0x%08ulX bytes\n\n",
		beswal(dol.bssaddr), beswal(dol.bsssz)
	);

	dol.entry = beswal(fhdr.entry);

	verbose(1, "entry point: 0x%08ulX\n", beswal(dol.entry));

	/* TODO validate addresses */

	if(write(ofd, &dol, sizeof(dol)) != sizeof(dol))
		sysfatal("write: %r");

	seek(ifd, fhdr.hdrsz+1, 0);
	while(read(ifd, buf, sizeof(buf)) > 0)
		if(write(ofd, buf, sizeof(buf)) != sizeof(buf))
			sysfatal("write: %r");

	close(ofd);
	close(ifd);
	exits(0);
}
