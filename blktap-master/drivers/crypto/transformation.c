/*
 * Copyright (c) 2010, XenSource Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of XenSource Inc. nor the names of its contributors
 *       may be used to endorse or promote products derived from this software
 *       without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 2014 Citrix Systems, Inc.
 */

#include <libconfig.h>
#include <errno.h>
#include <dlfcn.h>
#include <string.h>
#include <sys/types.h>

#include "compat-crypto-openssl.h"
#include "xts_aes.h"
#include "transformation.h"

crypt_encrypt pcrypt_encrypt = xts_aes_plain_encrypt;
crypt_decrypt pcrypt_decrypt = xts_aes_plain_decrypt;

int transformation_setup(int transformation_method) {
	if (transformation_method == 1) {
		return 0;
	}

	/* not the default transformation */
	config_t cfg;
	config_init(&cfg);
	if(! config_read_file(&cfg, "/etc/blktap.cfg")) {
		fprintf(stderr, "%s:%d - %s\n", config_error_file(&cfg),
			config_error_line(&cfg), config_error_text(&cfg));
		config_destroy(&cfg);
		return ENOENT;
	}

	config_setting_t *setting;
	setting = config_lookup(&cfg, "transformation_methods");
	if(setting) {
		int i;
		int count = config_setting_length(setting);
		for(i = 0; i < count; ++i) {
			config_setting_t *method = config_setting_get_elem(setting, i);
			const char *lib, *crypt_encrypt, *crypt_decrypt;
			int cookie;
			if(!(config_setting_lookup_string(method, "lib", &lib)
				 && config_setting_lookup_string(method, "crypt_encrypt", &crypt_encrypt)
				 && config_setting_lookup_string(method, "crypt_decrypt", &crypt_decrypt)
				 && config_setting_lookup_int(method, "cookie", &cookie)))
				continue;
			if (cookie != transformation_method) {
				continue;
			}
			dlerror();
			static void *transformation_handle;
			transformation_handle = dlopen(lib, RTLD_LAZY);
			if (transformation_handle == NULL) {
                        	return -EINVAL;
	                }
			pcrypt_encrypt = dlsym(transformation_handle, crypt_encrypt);
			pcrypt_decrypt = dlsym(transformation_handle, crypt_decrypt);
			return 0;
		}
		return ENOENT;
	} else {
		config_destroy(&cfg);
		return ENOENT;
	}
	config_destroy(&cfg);
	return 0;
}
