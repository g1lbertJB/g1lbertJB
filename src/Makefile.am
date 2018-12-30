AM_CFLAGS =	                   \
	$(GLOBAL_CFLAGS)           \
	$(libimobiledevice_CFLAGS) \
	$(libplist_CFLAGS)         \
	$(libzip_CFLAGS)           \
	$(zlib_CFLAGS)             \
	$(libcurl_CFLAGS)

AM_LDFLAGS =\
	$(AC_LDFLAGS)              \
	$(libimobiledevice_LIBS)   \
	$(libplist_LIBS)           \
	$(libzip_LIBS)             \
	$(zlib_LIBS)               \
	$(libcurl_LIBS)

bin_PROGRAMS = unthreadedjb

unthreadedjb_SOURCES = \
	idevicebackup2.c \
	jailbreak.c \
	device.c \
	lockdown.c \
	afc.c \
	backup.c \
	backup_file.c \
	mbdb.c \
	mbdb_record.c \
	file.c

unthreadedjb_CFLAGS = $(AM_CFLAGS)
unthreadedjb_LDFLAGS = $(AM_LDFLAGS)
unthreadedjb_LDADD = $(AM_LDADD)
