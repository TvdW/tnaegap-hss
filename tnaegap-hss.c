#include <windows.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>

#include "security.h"

#define AGENT_COPYDATA_ID 0x804e50ba /* random goop */

int answer_msg(void *msg)
{
    size_t msg_size, msg_pos;
    unsigned int query_size;
    MEMORY_BASIC_INFORMATION info;
    int fd = -1, msg_done;
    struct sockaddr_un addr;
    char *error = NULL;

    VirtualQuery(msg, &info, sizeof(info));
    msg_size = info.RegionSize;

    if (msg_size < 4) {
        error = "Message less than 4 bytes?";
        goto done;
    }

    query_size = ntohl(*(unsigned int*)msg);
    if (query_size + 4 > msg_size) {
        error = "Unlikely query size";
        goto done;
    }

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        error = "Can't create unix socket";
        goto done;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, getenv("SSH_AUTH_SOCK"), sizeof(addr.sun_path)-1);

    if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        error = "Can't connect to unix socket";
        goto done;
    }

    if (write(fd, msg, query_size+4) != query_size+4) {
        error = "Partial write...";
        goto done;
    }

    msg_pos = 0;
    msg_done = 0;
    while (msg_pos < msg_size && !msg_done) {
        int rc;
        unsigned int response_size;

        rc = read(fd, msg+msg_pos, msg_size-msg_pos);
        if (rc <= 0) {
            error = "Failed to read from socket";
            goto done;
        }

        msg_pos += rc;
        if (msg_pos >= 4) {
            response_size = ntohl(*(unsigned int*)msg) + 4;
            if (response_size >= msg_pos) {
                msg_done = 1;
            } else if (response_size > msg_size) {
                error = "Impossibly long answer";
                goto done;
            }
        }
    }

done:
    if (fd > 0)
        close(fd);
    if (error)
        fprintf(stderr, "[warn] %s\n", error);
    return error ? 0 : 1;
}

LRESULT CALLBACK
WndProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg)
    {
        case WM_CREATE:
            return 0;
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
            break;

        case WM_COPYDATA:
        {
            COPYDATASTRUCT *cds;
            char *mapname;
            HANDLE filemap;
            void *p;
            int ret = 0;

            cds = (COPYDATASTRUCT*)lParam;
            if (cds->dwData != AGENT_COPYDATA_ID)
                return 0; /* Message wasn't for us */

            mapname = (char*)cds->lpData;
            if (mapname[cds->cbData - 1] != '\0')
                return 0; /* Invalid string */

            filemap = OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, mapname);
            if (filemap != NULL && filemap != INVALID_HANDLE_VALUE) {
                if (check_security(filemap)) {
                    p = MapViewOfFile(filemap, FILE_MAP_WRITE, 0, 0, 0);
                    ret = answer_msg(p);
                    UnmapViewOfFile(p);
                }
            }
            CloseHandle(filemap);

            return ret;
            break;
        }
    }

    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

int CALLBACK
myMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    HWND hwnd;
    WNDCLASSEX wndclass;
    BOOL bRet;
    MSG msg;

    memset(&wndclass, 0, sizeof(wndclass));
    wndclass.lpszClassName = "Pageant";
    wndclass.cbSize = sizeof(wndclass);
    wndclass.style = 0;
    wndclass.lpfnWndProc = WndProc;
    wndclass.hInstance = hInstance;
    RegisterClassEx(&wndclass);

    hwnd = CreateWindow(
        "Pageant",
        "Pageant",
        0,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        CW_USEDEFAULT,
        NULL,
        NULL,
        hInstance,
        NULL
    );

    while ((bRet = GetMessage(&msg, hwnd, 0, 0)) != 0) {
        if (bRet == -1) {
            return 1;
        }

        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return 0;
}

void* start_thread(void* arg)
{
    int *out = (int*)arg;
    *out = myMain(GetModuleHandle(NULL), NULL, GetCommandLine(), SW_SHOW);
    return NULL;
}

int main(int argc, char** argv)
{
    int new_only = 0;

    int i;
    for (i = 1; i < argc; i++) {
        if (argv[i][0] == '-') {
            int j;
            for (j = 1; argv[i][j] != '\0'; j++) {
                switch (argv[i][j]) {
                    case 'n':
                        new_only = 1;
                        break;
                    case 'h':
                        printf("Usage: %s [flags]\n\n", argv[0]);
                        printf("Valid flags:\n");
                        printf("    -n      Exit quietly if there's already a Pageant process\n");
                        printf("    -h      Shows this help section\n");
                        return 0;
                        break;
                    default:
                        fprintf(stderr, "Invalid flag %c\n", argv[i][j]);
                        return 1;
                }
            }
        }
    }

    if (FindWindow("Pageant", "Pageant") != NULL) {
        if (new_only) {
            return 0;
        }
        fprintf(stderr, "Pageant already running, not starting a new one\n");
        return 1;
    }

    if (!getenv("SSH_AUTH_SOCK")) {
        fprintf(stderr, "No value for required environment variable SSH_AUTH_SOCK\n");
        return 1;
    }

    pthread_t thread;
    int out;
    if (pthread_create(&thread, NULL, start_thread, &out)) {
        fprintf(stderr, "Can't spawn thread\n");
        return 1;
    }
    if (pthread_join(thread, NULL)) {
        fprintf(stderr, "Failed to wait for thread\n");
        return 1;
    }
    return out;
}
