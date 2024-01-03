XSLTPROC=@XSLTPROC@
XSLTPROC_FLAGS=@XSLTPROC_FLAGS@
MAN_STYLESHEET=$(top_srcdir)/doc/man.xsl
CLEANFILES =

man_MANS = \
	afp.conf.5 \
	afp_signature.conf.5 \
	afp_voluuid.conf.5 \
	extmap.conf.5

EXTRA_DIST = \
	afp_signature.conf.5.xml \
	afp_voluuid.conf.5.xml \
	afp.conf.5.xml \
	extmap.conf.5.xml

if HAVE_XSLTPROC
CLEANFILES += $(man_MANS)

$(man_MANS) : %.5 : %.5.xml
	@xsltproc $(MAN_STYLESHEET) $<

html-local: $(man_MANS) $(MAN_STYLESHEET)
endif
