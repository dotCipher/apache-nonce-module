mod_mod_hello_filter.la: mod_mod_hello_filter.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_mod_hello_filter.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_mod_hello_filter.la
