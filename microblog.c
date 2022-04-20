#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// NIX
#include <pthread.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

extern int errno;

//------------------------------------
// Error Messgaes
// ------------------------------------
enum error_codes {
    ERR_SOC_CREATE = -1,
    ERR_SOC_BIND = -2,
    ERR_SOC_LISTEN = -3,
    ERR_SOC_ACCEPT = -4
};
char *error_msgs[] = {
    "",                       // 0
    "Socket create failed.",  // 1
    "Socket bind failed.",    // 2
    "Socket listen failed.",  // 3
    "Socket accept failed.",   // 4
};
static inline void exit_with_error(enum error_codes err_code) {
    perror(error_msgs[-err_code]);
    exit(err_code);
}
//------------------------------------
// HTTP Related
// ------------------------------------
typedef enum http_s_codes_e {
    S_OK = 200,
    S_BAD_REQUEST = 400,
    S_NOT_FOUND = 404,
    S_SERVER_ERROR = 500,
    S_NOT_IMPLEMENTED = 501
} http_s_code;

#define HTTP_VERSION "1.1"
#define S_BAD_REQUEST_MSG "Bad request!"
#define S_SERVER_ERROR_MSG "Internal Server Error!"
#define S_NOT_FOUND_MSG "Content not found!"
#define S_NOT_IMPLEMENTED_MSG "Not implemented!"

#define TEXT_PLAIN "text/plain"
#define TEXT_HTML "text/html"

#define REQ_SIZE (1 << 13)
#define REQ_RES_SIZE (1 << 3)

#define REP_FMT "%s%s\n"
#define REP_H_FMT "HTTP/%s %d \nContent-Type: %s\nContent-Length: %zu\n\n"
#define REP_H_FMT_LEN (sizeof(REP_H_FMT) + (1 << 6))
#define REP_MAX_CNT_SIZE (1 << 19)
#define REP_MAX_SIZE (REP_H_FMT_LEN + REP_MAX_CNT_SIZE)

enum set_http_rep_ret {
    SHR_ENC_ERROR = -1,
    SHR_HEAD_OVERFLOW = -2,
    SHR_CNT_ENC_EROR = -3,
    SHR_CNT_OVERFLOW = -4
};
static int set_http_rep(const char *http_ver, const http_s_code s_code,
                        const char *cnt_type, const char *cnt,
                        const size_t cnt_size, char *rep_buff) {
    char h_buff[REP_H_FMT_LEN] = {0};
    int bw_head = snprintf(h_buff, REP_H_FMT_LEN, REP_H_FMT, http_ver, s_code,
                           cnt_type, cnt_size);
    if (bw_head < 0)
        return SHR_ENC_ERROR;
    else if (bw_head >= REP_H_FMT_LEN)
        return SHR_HEAD_OVERFLOW;
    size_t buff_size = bw_head + cnt_size;
    if (buff_size > REP_MAX_SIZE) return SHR_CNT_OVERFLOW;
    int bw_rep = snprintf(rep_buff, buff_size, REP_FMT, h_buff, cnt);
    if (bw_rep < 0) return SHR_CNT_ENC_EROR;
    return bw_rep;
}

static int set_http_rep_200(const char *cnt_type, const char *cnt,
                            const size_t cnt_len, char *rep_buff) {
    return set_http_rep(HTTP_VERSION, S_OK, cnt_type, cnt, cnt_len, rep_buff);
}

static int set_http_rep_400(char *rep_buff) {
    return set_http_rep(HTTP_VERSION, S_BAD_REQUEST, TEXT_PLAIN,
                        S_BAD_REQUEST_MSG, strlen(S_BAD_REQUEST_MSG), rep_buff);
}

static int set_http_rep_404(char *rep_buff) {
    return set_http_rep(HTTP_VERSION, S_NOT_FOUND, TEXT_PLAIN, S_NOT_FOUND_MSG,
                        strlen(S_NOT_FOUND_MSG), rep_buff);
}

static int set_http_rep_500(char *result) {
    return set_http_rep(HTTP_VERSION, S_SERVER_ERROR, TEXT_PLAIN,
                        S_SERVER_ERROR_MSG, strlen(S_SERVER_ERROR_MSG), result);
}

static int set_http_rep_501(char *rep_buff) {
    return set_http_rep(HTTP_VERSION, S_NOT_FOUND, TEXT_PLAIN,
                        S_NOT_IMPLEMENTED_MSG, strlen(S_NOT_IMPLEMENTED_MSG),
                        rep_buff);
}

//------------------------------------
// POSTS:In Memory
// ------------------------------------
#define POSTS_OFFSET 1
typedef struct post_s {
    char *content_type;
    char *body;
} post;
post posts[] = {
#include "posts"
};
const size_t posts_size = (sizeof(posts) / sizeof(post));

//------------------------------------
// HTTP Request "Parsing"
// ------------------------------------
static inline bool http_req_is_get(const char *req_buff) {
    return (strncmp(req_buff, "GET ", 4) == 0 && req_buff[4] == '/');
}

static inline bool http_req_is_home(const char *req_buff) {
    return (req_buff[5] == ' ');
}

static void set_http_req_res(char *req_buff, size_t f_idx,
                             char *http_req_res_buff) {
    char *req_buff_it = &req_buff[f_idx];
    int req_buff_cnt = REQ_SIZE;
    int req_res_buff_cnt = REQ_RES_SIZE - 1;
    while (!isspace(*req_buff_it) && *req_buff_it != '\0' &&
           req_buff_cnt-- > 0 && req_res_buff_cnt-- > 0) {
        *http_req_res_buff++ = *req_buff_it++;
    }
    *http_req_res_buff = '\0';
}

enum set_post_idx_ret_e {
    SP_SUCCES = 0,
    SP_OVERFLOW = -1,
    SP_UNDERFLOW = -2,
    SP_INCONV = -3,
    SP_OUT_OF_RANGE = -4
} set_post_idx_ret;
static int set_post_idx(size_t *post_idx, const char *http_req_res_buff) {
    char *end;
    errno = 0;
    long post_idx_long = strtol(http_req_res_buff, &end, 10);
    if (post_idx_long > SIZE_T_MAX ||
        (errno == ERANGE && post_idx_long == LONG_MAX))
        return SP_OVERFLOW;
    if (post_idx_long < INT_MIN ||
        (errno == ERANGE && post_idx_long == LONG_MIN))
        return SP_UNDERFLOW;
    if (*end != '\0') return SP_INCONV;
    if (post_idx_long < 0) return SP_INCONV;
    *post_idx = post_idx_long;
    if (*post_idx < POSTS_OFFSET || *post_idx >= posts_size)
        return SP_OUT_OF_RANGE;
    return SP_SUCCES;
}
static inline bool http_req_is_final(const char *req_buff,
                                     const int req_buff_len) {
    if (req_buff_len < 2) return false;
    return req_buff[req_buff_len - 2] == '\r' &&
           req_buff[req_buff_len - 1] == '\n';
}
//------------------------------------
// Thread Pool
// ------------------------------------
// TODO: change from forks to pthreads
// ------------------------------------
// Sever
// ------------------------------------
#define DEFAULT_BACKLOG INT_MAX
#define DEFAULT_PORT 8080
#define DEFAULT_MAX_FORKS 5
#define DEFAULT_TIMEOUT 10000

int max_forks = DEFAULT_MAX_FORKS;
int cur_forks = 0;

enum server_receive_ret {
    SR_CON_CLOSE = -1,
    SR_READ_ERR = -2,
    SR_READ_OVERFLOW = -3
};
static int server_receive(int client_sock_fd, char *req_buff) {
    int b_req = 0;
    int tot_b_req = 0;
    while ((b_req = recv(client_sock_fd, &req_buff[tot_b_req],
                         REQ_SIZE - tot_b_req, 0)) > 0) {
        // Connection was closed by the peer
        if (b_req == 0) return SR_CON_CLOSE;
        // Reading Error
        if (b_req == -1) return SR_READ_ERR;
        tot_b_req += b_req;
        // HTTP Request is sent
        if (http_req_is_final(req_buff, tot_b_req)) break;
        // req_buff overflows
        if (tot_b_req >= REQ_SIZE) return SR_READ_OVERFLOW;
    }
    return tot_b_req;
}

enum server_send_errno { SS_ERROR = -1 };
static int server_send(int client_sock_fd, char *rep_buff) {
    int w_rep = 0;
    int tot_w_rep = 0;
    size_t total = strlen(rep_buff) + 1;
    while ((w_rep = send(client_sock_fd, rep_buff, total - tot_w_rep, 0)) > 0) {
        if (w_rep < 0) return SS_ERROR;
        tot_w_rep += w_rep;
    }
    return tot_w_rep;
}

void server_proc_req(int client_sock_fd) {
    char rep_buff[REP_MAX_SIZE] = {0};
    char req_buff[REQ_SIZE] = {0};
    char http_req_res_buff[REQ_RES_SIZE] = {0};
    int rec_status = server_receive(client_sock_fd, req_buff);
    int rep_status;
    if (rec_status == SR_CON_CLOSE) {
        // Connection closed by peer
        // There's no reason to send anything further
        exit(EXIT_SUCCESS);
    } else if (rec_status == SR_READ_ERR || rec_status == SR_READ_OVERFLOW) {
        // Cannot Read Request(SR_READ_ERR) OR
        // Request is bigger than(REQ_SIZE)
        // In this case we, return 400(BAD REQUEST)
        rep_status = set_http_rep_400(rep_buff);
    } else if (http_req_is_get(req_buff)) {
        // Request is a valid GET
        if (http_req_is_home(req_buff)) {
            // The resource is "/" we return posts[0]
            rep_status = set_http_rep_200(posts[0].content_type, posts[0].body,
                                          strlen(posts[0].body) + 1, rep_buff);
        } else {
            // The resource is different than "/"
            size_t p_idx;
            set_http_req_res(req_buff, 5, http_req_res_buff);
            if (set_post_idx(&p_idx, http_req_res_buff) < 0) {
                // If the resource is not a number, or is a number
                // out of range, we return 404 NOT FOUND
                rep_status = set_http_rep_404(rep_buff);
            } else {
                // We return the corresponding post based on the index
                struct post_s post = posts[p_idx];
                rep_status = set_http_rep_200(post.content_type, post.body,
                                              strlen(post.body) + 1, rep_buff);
            }
        }
    } else {
        // The request looks valid but it's not a GET
        // We return 501
        rep_status = set_http_rep_501(rep_buff);
    }

    if (rep_status < 0) {
        // TODO: LOG

        // There was an error constructing the response
        // Return 500
        rep_status = set_http_rep_500(rep_buff);
    } else {
        server_send(client_sock_fd, rep_buff);
    }
    close(client_sock_fd);
    exit(EXIT_SUCCESS);
}

void start_server() {
    // Creates a Server Socket
    int server_sock_fd = socket(
        AF_INET, // Address Familiy specific to IPV4 addresses
        SOCK_STREAM, // TCP 
        0
    );
    if (!server_sock_fd) 
        exit_with_error(ERR_SOC_CREATE);

    struct sockaddr_in addr_in = {.sin_family = AF_INET,
                                  .sin_addr.s_addr = INADDR_ANY,
                                  .sin_port = htons(DEFAULT_PORT)};
    memset(addr_in.sin_zero, '\0', sizeof(addr_in.sin_zero));

    int v = 1;
    setsockopt(server_sock_fd, SOL_SOCKET, SO_REUSEADDR, &v, sizeof(v));

    // Bind the socket to the address and port
    if (bind(server_sock_fd, (struct sockaddr *)&addr_in,
             sizeof(struct sockaddr)) == -1)
        exit_with_error(ERR_SOC_BIND);

    // Start listening for incoming connections
    if (listen(server_sock_fd, DEFAULT_BACKLOG) < 0)
        exit_with_error(ERR_SOC_LISTEN);   

    int client_sock_fd;
    int addr_in_len = sizeof(addr_in);
    for (;;) {
        // A cliet has made a request
        client_sock_fd = accept(server_sock_fd, (struct sockaddr *)&addr_in,
                                (socklen_t *)&addr_in_len);
        if (client_sock_fd == -1) {
            // TODO:	LOG ERROR BUT DON'T EXIT
            exit_with_error(ERR_SOC_ACCEPT);
        }
        pid_t proc = fork();
        if (proc < 0) {
            // TODO: log error
            // Close client
            close(client_sock_fd);
        } else if (proc == 0) {
            // We serve the request on a different 
            // subprocess
            server_proc_req(client_sock_fd);
        } else {
            // We keep track of the number of forks 
            // the parent is creating
            cur_forks++;
            printf("cur_forks: %d\n", cur_forks);
            // No reason to keep this open in the parent
            // We close it
            close(client_sock_fd);
        }
        // Clean up some finished sub-processes
        if (!(cur_forks<max_forks)) {
            while (waitpid(-1, NULL, WNOHANG) > 0) {
                cur_forks--;
                printf("cur_forks: %d\n", cur_forks);
            }
        }

    }
    close(server_sock_fd);
}

//------------------------------------
// Entry Point
// ------------------------------------
int main(void) {
    start_server();
    return EXIT_SUCCESS;
}
