XSLTPROC=@XSLTPROC@
XSLTPROC_FLAGS=@XSLTPROC_FLAGS@
MAN_STYLESHEET=$(top_srcdir)/doc/man.xsl
CLEANFILES =

man_MANS = \
	ad.1 \
	afpldaptest.1 \
	afppasswd.1 \
	afpstats.1 \
	apple_dump.1 \
	asip-status.1 \
	dbd.1 \
	macusers.1 \
	netatalk-config.1

EXTRA_DIST = \
	ad.1.xml \
	afpldaptest.1.xml \
	afppasswd.1.xml \
	afpstats.1.xml \
	apple_dump.1.xml \
	asip-status.1.xml \
	dbd.1.xml \
	macusers.1.xml \
	netatalk-config.1.xml

if HAVE_XSLTPROC
CLEANFILES += $(man_MANS)

$(man_MANS) : %.1 : %.1.xml
	@xsltproc $(MAN_STYLESHEET) $<

html-local: $(man_MANS) $(MAN_STYLESHEET)
endif
