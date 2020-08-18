#include "includes.h"

#include "common.h"
#include "eap_server/eap_methods.h"
#include "eap_register.h"


/**
 * eap_server_register_methods - Register statically linked EAP server methods
 * Returns: 0 on success, -1 or -2 on failure
 *
 * This function is called at program initialization to register all EAP
 * methods that were linked in statically.
 */
int eap_server_register_methods(void)
{
	int ret = 0;

	ret = eap_server_identity_register();

	return ret;
}
