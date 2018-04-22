#include <aclapi.h>

#include "security.h"

/*
 * Versions of Pageant prior to 0.61 expected this SID on incoming
 * communications. For backwards compatibility, and more particularly
 * for compatibility with derived works of PuTTY still using the old
 * Pageant client code, we accept it as an alternative to the one
 * returned from get_user_sid() in winpgntc.c.
 */
PSID get_default_sid(void)
{
    HANDLE proc = NULL;
    DWORD sidlen;
    PSECURITY_DESCRIPTOR psd = NULL;
    PSID sid = NULL, copy = NULL, ret = NULL;

    if ((proc = OpenProcess(MAXIMUM_ALLOWED, FALSE,
                            GetCurrentProcessId())) == NULL)
        goto cleanup;

    if (GetSecurityInfo(proc, SE_KERNEL_OBJECT, OWNER_SECURITY_INFORMATION,
                          &sid, NULL, NULL, NULL, &psd) != ERROR_SUCCESS)
        goto cleanup;

    sidlen = GetLengthSid(sid);

    copy = (PSID)malloc(sidlen);

    if (!CopySid(sidlen, copy, sid))
        goto cleanup;

    /* Success. Move sid into the return value slot, and null it out
     * to stop the cleanup code freeing it. */
    ret = copy;
    copy = NULL;

  cleanup:
    if (proc != NULL)
        CloseHandle(proc);
    if (psd != NULL)
        LocalFree(psd);
    if (copy != NULL)
        free(copy);

    return ret;
}

PSID get_user_sid(void)
{
    HANDLE proc = NULL, tok = NULL;
    TOKEN_USER *user = NULL;
    DWORD toklen, sidlen;
    PSID sid = NULL, ret = NULL;

    if ((proc = OpenProcess(MAXIMUM_ALLOWED, FALSE,
                            GetCurrentProcessId())) == NULL)
        goto cleanup;

    if (!OpenProcessToken(proc, TOKEN_QUERY, &tok))
        goto cleanup;

    if (!GetTokenInformation(tok, TokenUser, NULL, 0, &toklen) &&
        GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        goto cleanup;

    if ((user = (TOKEN_USER *)LocalAlloc(LPTR, toklen)) == NULL)
        goto cleanup;

    if (!GetTokenInformation(tok, TokenUser, user, toklen, &toklen))
        goto cleanup;

    sidlen = GetLengthSid(user->User.Sid);

    sid = (PSID)malloc(sidlen);

    if (!CopySid(sidlen, sid, user->User.Sid))
        goto cleanup;

    /* Success. Move sid into the return value slot, and null it out
     * to stop the cleanup code freeing it. */
    ret = sid;
    sid = NULL;

  cleanup:
    if (proc != NULL)
        CloseHandle(proc);
    if (tok != NULL)
        CloseHandle(tok);
    if (user != NULL)
        LocalFree(user);
    if (sid != NULL)
        free(sid);

    return ret;
}

int check_security(HANDLE obj)
{
    PSID objowner = NULL, defaultsid = NULL, usersid = NULL;
    PSECURITY_DESCRIPTOR psd = NULL;
    int ret = 0;

    if (GetSecurityInfo(obj, SE_KERNEL_OBJECT,
                        OWNER_SECURITY_INFORMATION,
                        &objowner, NULL, NULL, NULL,
                        &psd) != ERROR_SUCCESS) {
        goto fail;
    }

    if (!objowner) {
        goto fail;
    }

    defaultsid = get_default_sid();
    if (defaultsid && EqualSid(defaultsid, objowner)) {
        ret = 1;
        goto done;
    }

    usersid = get_user_sid();
    if (usersid && EqualSid(usersid, objowner)) {
        ret = 1;
        goto done;
    }

fail:
    ret = 0;

done:
    if (defaultsid)
        free(defaultsid);
    if (usersid)
        free(usersid);
    if (psd)
        LocalFree(psd);

    return ret;
}
