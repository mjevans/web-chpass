/*
 * nipasswd.c - Non-interactive password utility.
 *
 * Part of the "web-chpass" package.
 * https://github.com/chip-rosenthal/web-chpass
 *
 * Chip Rosenthal
 * <chip@unicom.com>
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <pwd.h>
#include <grp.h>
#include <errno.h>
#include <assert.h>
#include <security/pam_appl.h>

#define USAGE			"usage: %s [-Da]"
#define NIPASSWD_PAM_SERVICE	"nipasswd"
#define FAIL_DELAY		5 /* secs */
#define BUFLEN			65536 /* Allow /very/ long passwords */
#define BUFGRP			512 /* Normally this should be 32 characters or less, 511 is way overkill */

/* DEFS = -DAUTH_MIN_UID=$(AUTH_MIN_UID) -DAUTH_MAX_UID=$(AUTH_MAX_UID) -DCHANGE_MIN_UID=$(CHANGE_MIN_UID) -DCHANGE_MAX_UID=$(CHANGE_MAX_UID) -DCHANGE_GROUP_REQ=$(CHANGE_GROUP_REQ) */

#ifndef AUTH_MIN_UID
#define AUTH_MIN_UID	-1	/* do not auth users below this uid	*/
#endif
#ifndef CHANGE_MIN_UID
#define CHANGE_MIN_UID	-1	/* do not change users below this uid	*/
#endif
#ifndef AUTH_MAX_UID
#define AUTH_MAX_UID	-1	/* do not auth users below this uid	*/
#endif
#ifndef CHANGE_MAX_UID
#define CHANGE_MAX_UID	-1	/* do not change users below this uid	*/
#endif
#define STRING_LOCAL(x) #x
#ifndef AUTH_GROUP_REQ
#define AUTH_GROUP_REQ :	/* If no valid groups are enumerated then this check is disabled */
#endif
#ifndef CHANGE_GROUP_REQ
#define CHANGE_GROUP_REQ :	/* If no valid groups are enumerated then this check is disabled */
#endif

#define QUOTE(name)		#name
#define STR(macro)		QUOTE(macro)
#define CHANGE_GROUP_STR	STR(CHANGE_GROUP_REQ)
#define AUTH_GROUP_STR		STR(AUTH_GROUP_REQ)

#define EX_SUCCESS	0	/* password successfully changed	*/
#define EX_ERROR	1	/* failed due to an error		*/
#define EX_DENIED	2	/* failed due to username/password auth	*/
#define EX_BADPW	3	/* failed due to bad password checks	*/

#define Dprintf	if (!Debug) ; else fprintf

int Debug = 0;			/* enable debugging messages		*/
int Do_auth_only = 0;		/* authenticate but don't change passwd	*/

/*
 * This information is global so it can be accessed by die().
 */
pam_handle_t *pam_h = NULL;
int pam_rc;

/*
 * This information is global so it can be accessed by pam_conv_func().
 */
int pam_conv_resp_count = 0;
char username[BUFLEN];
char old_password[BUFLEN];
char new_password[BUFLEN];

int user_ok(const char *username, struct passwd *save_pw);
int pam_conv_func(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr);
void fgetline(char *buf, size_t buflen, FILE *fp);
char *xstrdup(const char *s);
void die(int exitstat, const char *fmt, ...);
const char *pam_msg_style_str(int n);


int main(int argc, char *argv[])
{
	struct pam_conv pam_conv = { pam_conv_func, NULL };
	int i;

	while ((i = getopt(argc, argv, "Da")) != EOF) {
		switch (i) {
		case 'D':
			Debug = 1;
			break;
		case 'a':
			Do_auth_only = 1;
			break;
		default:
			die(EX_ERROR, USAGE, argv[0]);
		}
	}
	if (argc-optind != 0) {
		die(EX_ERROR, USAGE, argv[0]);
	}

	fgetline(username, sizeof(username), stdin);
	fgetline(old_password, sizeof(old_password), stdin);
	if (!Do_auth_only) {
		fgetline(new_password, sizeof(new_password), stdin);
	}
	if (getc(stdin) != EOF) {
		die(EX_ERROR, "Excess input.");
	}

	struct passwd pw;
	if (!user_ok(username, &pw)) {
		(void) sleep(FAIL_DELAY);
		die(EX_DENIED, "Access denied.");
	}

	/*
	 * Make sure our real UID matches the account that's being changed.
	 * On Debian with pam_ldap, this is required else there is
	 * a prompt for the LDAP admin passwd.
	 */
	if (setreuid(pw.pw_uid, 0) != 0) {
		die(EX_ERROR, "Cannot set user id: %m");
	}

	pam_rc = pam_start(NIPASSWD_PAM_SERVICE, username, &pam_conv, &pam_h);
	if (pam_rc != PAM_SUCCESS) {
		die(EX_ERROR, "Error initializing PAM subsystem: %s",
			pam_strerror(pam_h, pam_rc));
	}
#ifdef PAM_FAIL_DELAY
	pam_fail_delay(pam_h, FAIL_DELAY*1000);
#endif

	if (Do_auth_only) {

                /*
                 * Attempt to authenticate the user.
                 */
                pam_rc = pam_authenticate(pam_h, 0);
                switch (pam_rc) {
                case PAM_USER_UNKNOWN:
                case PAM_AUTH_ERR:
                        die(EX_DENIED, "Access denied.");
                case PAM_SUCCESS:
                        break;
                default:
                        die(EX_ERROR, "PAM error authenticating user: %s",
                                pam_strerror(pam_h, pam_rc));
                }

        } else {

                /*
                 * Attempt to change the password.
                 */
                pam_rc = pam_chauthtok(pam_h, 0);
                if (pam_rc != PAM_SUCCESS) {
                        die(EX_ERROR, "Error setting new password: %s:",
                                pam_strerror(pam_h, pam_rc));
                }

        }

	Dprintf(stderr, "main: terminating with success exit status\n");
	(void) pam_end(pam_h, PAM_SUCCESS);
	exit(EX_SUCCESS);
}


/*
 * user_ok() - Verify it is alright to handle this user.
 *
 * The main purpose of this procedure is to enforce the min UID checks.
 * But so long as we are at it, we can bounce unknown users without the
 * overhead of stoking up PAM.
 */
int user_ok(const char *username, struct passwd *save_pw)
{
	struct passwd *pw;
	struct group *gstat;
	char *ts, *te, gbuf[BUFGRP];
	char gs[] = ":";
	size_t offset;
	int group_ok = 0, group_exists = 0;

	if ((pw = getpwnam(username)) == NULL) {
		return 0;
	}
	if (pw->pw_uid < (Do_auth_only ? AUTH_MIN_UID : CHANGE_MIN_UID) && (int)0 <= (int)(Do_auth_only ? AUTH_MIN_UID : CHANGE_MIN_UID)) {
		return 0;
	}
	if (pw->pw_uid > (Do_auth_only ? AUTH_MAX_UID : CHANGE_MAX_UID) && (int)0 <= (int)(Do_auth_only ? AUTH_MAX_UID : CHANGE_MAX_UID)) {
		return 0;
	}

	if (Do_auth_only){
		ts = AUTH_GROUP_STR;
	} else {
		ts = CHANGE_GROUP_STR;
	}
	while(NULL != ts && 0 == group_ok) {
		te = strpbrk(ts, gs);
		if(NULL == te) {
			strncpy(gbuf, ts, BUFGRP);
			gbuf[BUFGRP - 1] = '\0';
		} else {
			offset = te - ts;
			if (offset > BUFGRP - 1) {
				offset = BUFGRP - 1;
			}
			strncpy(gbuf, ts, offset);
			gbuf[offset] = '\0';
			te++;
		}
		ts = te;
		if(strlen(gbuf) < 1) {
			continue;
		}
		errno = 0;
		gstat = getgrnam(gbuf);
		if(0 != errno){
			die(EX_ERROR, "FATAL ERROR resolving group \"%s\" via getgrnam: errno %d: %s\n", gbuf, errno, strerror(errno));
		}
		if (NULL == gstat) {
			Dprintf(stderr, "test user_ok: Group isn't NULL but getgrnam is: %s\n", gbuf);
			continue;
		}
		group_exists = 1;
		if(gstat->gr_gid == pw->pw_gid){
			group_ok = 1;
		} else {
			for(offset=0; NULL != (gstat->gr_mem)[offset]; offset++) {
				if(0 == strcmp(pw->pw_name, (gstat->gr_mem)[offset])) {
					group_ok = 1;
					break;
				}
			}
		}
	}
	if (0 == group_ok && 1 == group_exists) {
		return 0;
	}

	if (save_pw != NULL) {
		*save_pw = *pw;
	}

	return 1;
}


int pam_conv_func(int num_msg, const struct pam_message **msg, struct pam_response **resp, void *appdata_ptr)
{
	struct pam_response *resp_buf;
	int handled_this, i;

	Dprintf(stderr,
		"pam_conv_func: entered, pam_conv_resp_count=%d num_msg=%d\n",
		pam_conv_resp_count, num_msg);
	resp_buf = calloc(num_msg, sizeof(struct pam_response));
	if (resp_buf == NULL) {
		die(EX_ERROR, "System error:  malloc failed.");
	}

	for (i = 0 ; i < num_msg ; ++i) {

		handled_this = -1;
		resp_buf[i].resp = NULL;
		resp_buf[i].resp_retcode = PAM_SUCCESS;

		/*
		 * pam_conv_resp_count counts the number of prompted
		 * responses we've sent back to PAM.  There should
		 * be three:  old password, new password, and confirm
		 * new password.
		 */
		switch (pam_conv_resp_count) {

		case 0:	/* prompt for old password */
			switch (msg[i]->msg_style) {

			case PAM_PROMPT_ECHO_OFF:
				resp_buf[i].resp = xstrdup(old_password);
				++pam_conv_resp_count;
				handled_this = 1;
				break;

			case PAM_TEXT_INFO:
				/* "Changing password for ..." */
				handled_this = 1;
				break;

			default:
				handled_this = 0;
				break;

			}
			break;

		case 1: /* prompt for new password */
			switch (msg[i]->msg_style) {

			case PAM_PROMPT_ECHO_OFF:
				resp_buf[i].resp = xstrdup(new_password);
				++pam_conv_resp_count;
				handled_this = 1;
				break;

			case PAM_TEXT_INFO:
				/* "Changing password for ..." */
				handled_this = 1;
				break;

#define EXPMSSG "You are required to change your password immediately"

			case PAM_ERROR_MSG:
				if (strncmp(msg[i]->msg, EXPMSSG, strlen(EXPMSSG)) == 0) {
					handled_this = 1;
					break;
				}
				/* else fall thru */

			default:
				handled_this = 0;
				break;

			}
			break;

		case 2: /* confirm new password */
			switch (msg[i]->msg_style) {

			case PAM_PROMPT_ECHO_OFF:
				resp_buf[i].resp = xstrdup(new_password);
				++pam_conv_resp_count;
				handled_this = 1;
				break;

			case PAM_ERROR_MSG:
                                pam_rc = PAM_PERM_DENIED;
                                die(EX_BADPW, "%s", msg[i]->msg);
				break;

			default:
				handled_this = 0;
				break;

			}
			break;

		case 3: /* possible additional message */
			switch (msg[i]->msg_style) {

			case PAM_TEXT_INFO:
				/* "Password changed." */
				handled_this = 1;
				break;

			case PAM_ERROR_MSG:
                                pam_rc = PAM_PERM_DENIED;
                                die(EX_BADPW, "%s", msg[i]->msg);
				break;

			default:
				handled_this = 0;
				break;

			}
			break;

		default: /* don't know what this is */
			handled_this = 0;
			break;

		}

		assert(handled_this >= 0);
		Dprintf(stderr,
			"pam_conv_func: msg_style=\"%s\" msg=\"%s\" resp=\"%s\"\n",
			pam_msg_style_str(msg[i]->msg_style),
			msg[i]->msg, resp_buf[i].resp);

		if (!handled_this) {
			die(EX_ERROR, "System Error - Unexpected PAM message (%s): %s",
				pam_msg_style_str(msg[i]->msg_style), msg[i]->msg);
		}

	}

	*resp = resp_buf;
	return PAM_SUCCESS;
}


void fgetline(char *buf, size_t buflen, FILE *fp)
{
	int n;

	if (fgets(buf, buflen, fp) == NULL) {
		if (feof(fp)) {
			die(EX_ERROR, "premature end of input");
		} else {
			die(EX_ERROR, "error reading input: %m");
		}
	}

	n = strlen(buf);
	if (n > 0 && buf[n-1] != '\n') {
		die(EX_ERROR, "input rejected: buffer overflow");
	}
	buf[n-1] = '\0';
}


char *xstrdup(const char *s)
{
	char *s1;
	if ((s1 = strdup(s)) == NULL) {
		die(EX_ERROR, "System error:  malloc failed.");
	}
	return s1;
}


void die(int exitstat, const char *fmt, ...)
{
	va_list ap;
	int save_errno = errno;
	char mssgbuf[1024], *s;

	va_start(ap, fmt);
	vsnprintf(mssgbuf, sizeof(mssgbuf), fmt, ap);
	if ((s = strstr(mssgbuf, "%m")) != NULL)  {
		*s = '\0';
		s += 2;
		fputs(mssgbuf, stderr);
		fputs(strerror(save_errno), stderr);
		fputs(s, stderr);
	} else {
		fputs(mssgbuf, stderr);
	}
	putc('\n', stderr);

	if (pam_h != NULL) {
		Dprintf(stderr, "die: terminating with PAM status: %s\n",
			pam_strerror(pam_h, pam_rc));
		(void) pam_end(pam_h, pam_rc);
		pam_h = NULL;
	}
	exit(exitstat);
	/*NOTREACHED*/
}


const char *pam_msg_style_str(int n)
{
	static char smbuf[64];
	switch (n) {
	case PAM_PROMPT_ECHO_OFF:
		return "PAM_PROMPT_ECHO_OFF";
	case PAM_PROMPT_ECHO_ON:
		return "PAM_PROMPT_ECHO_ON";
	case PAM_ERROR_MSG:
		return "PAM_ERROR_MSG";
	case PAM_TEXT_INFO:
		return "PAM_TEXT_INFO";
	default:
		sprintf(smbuf, "<code %d>", n);
		return smbuf;
	}
}
