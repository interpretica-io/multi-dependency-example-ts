/** @file
 * @brief smb Group
 *
 * What the group prologue leaves for the tests and the epilogue: the
 * suite-owned smbd's directory, the marker of what the prologue changed,
 * and the account it made on that smbd.
 *
 * Copyright (C) 2026 Maxim Menshikov
 *
 * @author Maxim Menshikov <maximmenshchikov@gmail.com>
 */

#ifndef __MDE_SMB_COMMON_H__
#define __MDE_SMB_COMMON_H__

#include <stdlib.h>
#include <string.h>

#include "te_string.h"
#include "tapi_file.h"

#include "tsapi_mde.h"

/** Directory of the smbd the prologue starts: config, state, logs. */
#define MDE_SMB_DIR     "/tmp/mde-smb"

/**
 * What the prologue changed, one item per line, so that the epilogue
 * undoes exactly that: @c smbd (it started the smbd), @c "acl <dir>"
 * (it added an ACL entry to a usershare directory that already had an
 * ACL), @c "aclnew <dir>" (it gave that directory its first ACL).
 */
#define MDE_SMB_MARK    "/tmp/mde-smbd.started"

/**
 * The account the prologue made on its smbd, as one line
 * "<user> <password>", readable by the agent's user only.
 */
#define MDE_SMB_CRED    MDE_SMB_DIR "/cred"

/**
 * Read the account the group prologue made on its smbd.
 *
 * The file is read over RCF rather than with a shell, so the password
 * does not end up in the log of a job's output.
 *
 * @param[in]  session  Session.
 * @param[out] user     User name.
 * @param[out] password Password.
 *
 * @return @c true when there is such an account.
 */
static inline bool
smb_suite_account(tsapi_mde_session *session, te_string *user,
                  te_string *password)
{
    char       *buf = NULL;
    const char *sep;
    const char *end;
    bool        found = false;

    if (!tsapi_mde_exists(session, MDE_SMB_CRED))
        return false;

    if (tapi_file_read_ta(session->ta, MDE_SMB_CRED, &buf) != 0 ||
        buf == NULL)
    {
        free(buf);
        return false;
    }

    sep = strchr(buf, ' ');
    if (sep != NULL && sep != buf)
    {
        end = sep + 1 + strcspn(sep + 1, "\r\n ");
        if (end != sep + 1)
        {
            te_string_append_buf(user, buf, (size_t)(sep - buf));
            te_string_append_buf(password, sep + 1,
                                 (size_t)(end - (sep + 1)));
            found = true;
        }
    }

    free(buf);

    return found;
}

#endif /* !__MDE_SMB_COMMON_H__ */
