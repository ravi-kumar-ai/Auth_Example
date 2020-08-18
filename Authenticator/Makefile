ifndef CC
CC=gcc
endif

ifndef CFLAGS
CFLAGS = -MMD -O2 -Wall -g
endif


CFLAGS += $(EXTRA_CFLAGS)
CFLAGS += -I$(abspath ./src)
CFLAGS += -I$(abspath ./src/utils)


-include .config

ifdef CONFIG_TESTING_OPTIONS
CFLAGS += -DCONFIG_TESTING_OPTIONS
CONFIG_WPS_TESTING=y
endif

CONFIG_OS=unix

OBJS += auth_init/main.o
OBJS += auth_init/config_file.o

OBJS += ../src/ap/hostapd.o
OBJS += ../src/ap/drv_callbacks.o
OBJS += ../src/ap/utils.o
OBJS += ../src/ap/ieee802_1x.o
OBJS += ../src/ap/ap_config.o
OBJS += ../src/ap/sta_info.o

OBJS_c += ../src/utils/os_$(CONFIG_OS).o

#NEED_RC4=y
#NEED_MD5=y
#NEED_SHA1=y

OBJS += ../src/drivers/drivers.o
CFLAGS += -DHOSTAPD

ifndef CONFIG_ELOOP
CONFIG_ELOOP=eloop
endif
OBJS += ../src/utils/$(CONFIG_ELOOP).o
OBJS_c += ../src/utils/$(CONFIG_ELOOP).o

ifeq ($(CONFIG_ELOOP), eloop)
# Using glibc < 2.17 requires -lrt for clock_gettime()
LIBS += -lrt
LIBS_c += -lrt
LIBS_h += -lrt
LIBS_n += -lrt
endif

OBJS += ../src/utils/common.o
OBJS_c += ../src/utils/common.o
OBJS += ../src/utils/wpa_debug.o
OBJS_c += ../src/utils/wpa_debug.o
OBJS += ../src/utils/wpabuf.o
OBJS += ../src/utils/os_$(CONFIG_OS).o

OBJS += ../src/eapol_auth/eapol_auth_sm.o

ifndef CONFIG_NO_DUMP_STATE
# define HOSTAPD_DUMP_STATE to include support for dumping internal state
# through control interface commands (undefine it, if you want to save in
# binary size)
CFLAGS += -DHOSTAPD_DUMP_STATE
OBJS += ../src/eapol_auth/eapol_auth_dump.o
endif

OBJS += ../src/radius/radius.o
OBJS += ../src/radius/radius_client.o
OBJS += ../src/radius/radius_das.o

OBJS += ../src/ap/accounting.o

OBJS += ../src/ap/vlan_init.o
OBJS += ../src/ap/vlan_ifconfig.o
OBJS += ../src/ap/vlan.o

include ../src/drivers/drivers.mak
OBJS += $(DRV_AP_OBJS)
CFLAGS += $(DRV_AP_CFLAGS)
LDFLAGS += $(DRV_AP_LDFLAGS)
LIBS += $(DRV_AP_LIBS)

# Basic EAP functionality is needed for EAPOL
OBJS += eap_register.o
OBJS += ../src/eap_server/eap_server.o
OBJS += ../src/eap_common/eap_common.o
OBJS += ../src/eap_server/eap_server_methods.o
OBJS += ../src/eap_server/eap_server_identity.o
CFLAGS += -DEAP_SERVER_IDENTITY

ifndef CONFIG_TLS
CONFIG_TLS=openssl
endif

ifeq ($(CONFIG_TLS), openssl)
CONFIG_CRYPTO=openssl
OBJS += ../src/crypto/crypto_openssl.o
HOBJS += ../src/crypto/crypto_openssl.o
NEED_SHA256=y
NEED_TLS_PRF_SHA256=y
LIBS += -lcrypto
LIBS_h += -lcrypto
LIBS_n += -lcrypto
ifndef CONFIG_TLS_DEFAULT_CIPHERS
CONFIG_TLS_DEFAULT_CIPHERS = "DEFAULT:!EXP:!LOW"
endif
CFLAGS += -DTLS_DEFAULT_CIPHERS=\"$(CONFIG_TLS_DEFAULT_CIPHERS)\"
endif

ifndef TLS_FUNCS
OBJS += ../src/crypto/tls_none.o
ifeq ($(CONFIG_TLS), internal)
CONFIG_INTERNAL_AES=y
CONFIG_INTERNAL_SHA1=y
CONFIG_INTERNAL_MD5=y
CONFIG_INTERNAL_RC4=y
endif
endif


#OBJS += ../src/crypto/sha256-prf.o
#OBJS += ../src/crypto/sha256-tlsprf.o
#OBJS += ../src/crypto/random.o
#HOBJS += ../src/crypto/random.o
#HOBJS += ../src/utils/eloop.o
OBJS += ../src/ap/ap_list.o

ifdef CONFIG_IPV6
CFLAGS += -DCONFIG_IPV6
endif

OBJS += ../src/drivers/driver_common.o

ALL=authenticator hostapd_cli

all: verify_config $(ALL)

Q=@
E=echo
ifeq ($(V), 1)
Q=
E=true
endif
ifeq ($(QUIET), 1)
Q=@
E=true
endif

ifdef CONFIG_CODE_COVERAGE
%.o: %.c
	@$(E) "  CC " $<
	$(Q)cd $(dir $@); $(CC) -c -o $(notdir $@) $(CFLAGS) $(notdir $<)
else
%.o: %.c
	$(Q)$(CC) -c -o $@ $(CFLAGS) $<
	@$(E) "  CC " $<
endif

verify_config:
	@if [ ! -r .config ]; then \
		echo 'Building authenticator requires a configuration file'; \
		echo '(.config). See README for more instructions. You can'; \
		echo 'run "cp defconfig .config" to create an example'; \
		echo 'configuration.'; \
		exit 1; \
	fi


../src/drivers/build.hostapd:
	@if [ -f ../src/drivers/build.wpa_supplicant ]; then \
		$(MAKE) -C ../src/drivers clean; \
	fi
	@touch ../src/drivers/build.hostapd

BCHECK=../src/drivers/build.hostapd

hostapd: $(BCHECK) $(OBJS)
	$(Q)$(CC) $(LDFLAGS) -o hostapd $(OBJS) $(LIBS)
	@$(E) "  LD " $@

ifdef CONFIG_WPA_TRACE
OBJS_c += ../src/utils/trace.o
endif
hostapd_cli: $(OBJS_c)
	$(Q)$(CC) $(LDFLAGS) -o hostapd_cli $(OBJS_c) $(LIBS_c)
	@$(E) "  LD " $@

NOBJS = nt_password_hash.o ../src/crypto/ms_funcs.o $(SHA1OBJS)
NOBJS += ../src/utils/common.o
ifdef NEED_RC4
ifdef CONFIG_INTERNAL_RC4
ifndef CONFIG_NO_RC4
NOBJS += ../src/crypto/rc4.o
endif
endif
endif
ifdef CONFIG_INTERNAL_MD5
NOBJS += ../src/crypto/md5-internal.o
endif
NOBJS += ../src/crypto/crypto_$(CONFIG_CRYPTO).o
NOBJS += ../src/utils/os_$(CONFIG_OS).o
NOBJS += ../src/utils/wpa_debug.o
NOBJS += ../src/utils/wpabuf.o
ifdef CONFIG_WPA_TRACE
NOBJS += ../src/utils/trace.o
LIBS_n += -lbfd
endif

HOBJS += hlr_auc_gw.o ../src/utils/common.o ../src/utils/wpa_debug.o ../src/utils/os_$(CONFIG_OS).o ../src/utils/wpabuf.o ../src/crypto/milenage.o
HOBJS += ../src/crypto/aes-encblock.o
ifdef CONFIG_INTERNAL_AES
HOBJS += ../src/crypto/aes-internal.o
HOBJS += ../src/crypto/aes-internal-enc.o
endif
ifeq ($(CONFIG_TLS), linux)
HOBJS += ../src/crypto/crypto_linux.o
endif

nt_password_hash: $(NOBJS)
	$(Q)$(CC) $(LDFLAGS) -o nt_password_hash $(NOBJS) $(LIBS_n)
	@$(E) "  LD " $@

hlr_auc_gw: $(HOBJS)
	$(Q)$(CC) $(LDFLAGS) -o hlr_auc_gw $(HOBJS) $(LIBS_h)
	@$(E) "  LD " $@

lcov-html:
	lcov -c -d .. > lcov.info
	genhtml lcov.info --output-directory lcov-html

clean:
	$(MAKE) -C ../src clean
	rm -f core *~ *.o hostapd hostapd_cli nt_password_hash hlr_auc_gw
	rm -f *.d *.gcno *.gcda *.gcov
	rm -f lcov.info
	rm -rf lcov-html

-include $(OBJS:%.o=%.d)
