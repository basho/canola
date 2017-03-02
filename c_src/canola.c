/* -------------------------------------------------------------------

canola: Erlang Wrapper for Pluggable Authentication Modules (PAM)

Copyright (c) 2013 Basho Technologies, Inc. All Rights Reserved.

This file is provided to you under the Apache License,
Version 2.0 (the "License"); you may not use this file
except in compliance with the License.  You may obtain
a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.

------------------------------------------------------------------- */

/* Parts of this code are inspired, but not derived from:
 * http://www.freebsd.org/doc/en/articles/pam/pam-sample-appl.html
 * http://www.freebsd.org/doc/en/articles/pam/pam-sample-conv.html
 * And the PostgreSQL PAM authentication code. */

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <syslog.h>
#include <string.h>

#include <ei.h>

#include <security/pam_appl.h>

static pam_handle_t *pamh;
static struct pam_conv pamc;
static int debug = 0;

int conv_fun(int num_msg, const struct pam_message **msgs, struct pam_response **rsps, void *data) {
    int i, len;
    struct pam_message *m = (struct pam_message*)*msgs;
    struct pam_response *r;
    if (num_msg < 1 || num_msg >= PAM_MAX_NUM_MSG) {
        if (debug) {
            syslog(LOG_INFO, "bad number of messages");
        }
        return PAM_CONV_ERR;
    }
    /* allocate memory for a response to each message */
    if ((*rsps = calloc(num_msg, sizeof(struct pam_response))) == NULL) {
        return PAM_BUF_ERR;
    }
    r = *rsps;
    for (i = 0; i < num_msg; i++) {
        if (m->msg == NULL) {
            if (debug) {
                syslog(LOG_INFO, "NULL message received");
            }
            goto fail;
        }
        /* fill in the defaults for a response */
        r->resp = NULL;
        r->resp_retcode = 0; /* always 0, apparently */

        switch(m->msg_style) {
            case PAM_PROMPT_ECHO_OFF:
                /* pam is asking for a non-echoed string, assume it is the password */
                len = strlen((char*)data);
                r->resp = malloc(len+1);
                strcpy(r->resp, (char*)data);
                if (debug) {
                    syslog(LOG_INFO, "Asked for ECHO_OFF string with prompt %s", m->msg);
                }
                break;
            case PAM_ERROR_MSG:
                if (debug) {
                    syslog(LOG_INFO, "Asked to print ERROR_MSG %s", m->msg);
                }
                break;
            case PAM_TEXT_INFO:
                if (debug) {
                    syslog(LOG_INFO, "Asked to print TEXT_INFO %s", m->msg);
                }
                break;
            case PAM_PROMPT_ECHO_ON:
                if (debug) {
                    syslog(LOG_INFO, "Asked for ECHO_ON string with prompt %s", m->msg);
                }
                /* fall through */
            default:
                if (debug) {
                    syslog(LOG_INFO, "Unknown message style %d", m->msg_style);
                }
                goto fail;
        }
        m++;
        r++;
    }
    return PAM_SUCCESS;
fail:
    r = *rsps;
    for (i = 0; i < num_msg; ++i) {
        if (r->resp != NULL) {
            /* may contain password, zero before free */
            memset(r->resp, 0, strlen(r->resp));
            free(r->resp);
        }
        r++;
    }
    /* zero out before free */
    memset(*rsps, 0, num_msg * sizeof **rsps);
    free(*rsps);
    *rsps=NULL;
    return PAM_CONV_ERR;
}

void delay(int retval, unsigned usec_delay, void *appdata) {
    return;
}

int main(int argc, char** argv) {
    char command[4];
    int index, version, arity, type, size, ret;
    char *buf = NULL, *password = NULL, *username = NULL, *service = NULL, li;
    char outbuf[5]; /* only holds +OK or +ERR */
    if (argc > 1 && strncmp("-d", argv[1], 2) == 0) {
        /* pass -d on the command line to enable syslog debug output */
        openlog("canola-port", LOG_PID, LOG_USER);
        syslog(LOG_INFO, "Debugging enabled");
        debug = 1;
    }
    while(read(0, command, 4)) {
        unsigned int inlen = command[0] << 24 | command[1] << 16 | command[2] << 8 | command[3];
        if (debug) {
            syslog(LOG_INFO, "Got message header of length %d", inlen);
        }
        buf = (char*)malloc(inlen+1);
        read(0, buf, inlen);
        index = 0;

        if (ei_decode_version(buf, &index, &version)) goto done;

        if (ei_decode_tuple_header(buf, &index, &arity)) goto done;

        if (arity != 3) goto done;

        ei_get_type(buf, &index, &type, &size);

        if(type != 'm') goto done;
        username = (char*)malloc(size+1);
        username[size] = '\0';
        if(ei_decode_binary(buf, &index, username, (long*)&size)) goto done;

        ei_get_type(buf, &index, &type, &size);

        if(type != 'm') goto done;
        password = (char*)malloc(size+1);
        password[size] = '\0';
        if(ei_decode_binary(buf, &index, password, (long*)&size)) goto done;

        ei_get_type(buf, &index, &type, &size);

        if(type != 'm') goto done;
        service = (char*)malloc(size+1);
        service[size] = '\0';
        if(ei_decode_binary(buf, &index, service, (long*)&size)) goto done;

        pamc.conv = &conv_fun;
        pamc.appdata_ptr = (void *)password;
        if (debug) {
            syslog(LOG_INFO, "Initializing PAM with service %s", service);
        }
        ret = pam_start(service, username, &pamc, &pamh);
        if (ret != PAM_SUCCESS) {
            if (debug) {
                syslog(LOG_INFO, "Could not initialize PAM");
            }
            sprintf(outbuf, "-ERR");
        } else {
            if (debug) {
                syslog(LOG_INFO, "Authenticating with username %s", username);
            }
#ifdef HAVE_PAM_FAIL_DELAY
            /* disable the delay for failed authentications */
            pam_set_item(pamh, PAM_FAIL_DELAY, &delay);
#endif
            if ((ret = pam_authenticate(pamh, 0)) != PAM_SUCCESS) {
                if (debug) {
                    syslog(LOG_INFO, "Failed to authenticate");
                }
                sprintf(outbuf, "-ERR");
            } else {
                if ((ret = pam_acct_mgmt(pamh, 0)) != PAM_SUCCESS) {
                    if (debug) {
                        syslog(LOG_INFO, "Failed account validation");
                    }
                    sprintf(outbuf, "-ERR");
                } else {
                    if (debug) {
                        syslog(LOG_INFO, "Authenticated OK");
                    }
                    sprintf(outbuf, "+OK");
                }
            }
        }
        pam_end(pamh, ret);
        size = strlen(outbuf);
        if (debug) {
            syslog(LOG_INFO, "Output is %s of length %d", outbuf, size);
        }
        li = (size >> 24) & 0xff;
        write(1, &li, 1);

        li = (size >> 16) & 0xff;
        write(1, &li, 1);

        li = (size >> 8) & 0xff;
        write(1, &li, 1);

        li = size & 0xff;
        write(1, &li, 1);

        printf("%s", outbuf);
        fflush(stdout);
        free(buf);
        buf = NULL;
        free(username);
        username = NULL;
        free(password);
        password = NULL;
        free(service);
        service = NULL;
    }
done:
    if(buf) {
        free(buf);
    }

    if(username) {
        free(username);
    }

    if(password) {
        free(password);
    }

    if(service) {
        free(service);
    }

    if(debug) {
        closelog();
    }

    return 1;
}
