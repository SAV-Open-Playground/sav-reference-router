#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <netdb.h>
#include <errno.h>
#include "nest/bird.h"
#include <lib/cJSON.h>
#include <nest/protocol.h>
#include <proto/bgp/bgp.h>
int msg_count = 0;
byte *
insert_u16(byte *buf, uint val)
{
    put_u16(buf, val);
    return buf + 2;
}
byte *
insert_u8(byte *buf, uint val)
{
    put_u8(buf, val);
    return buf + 1;
}
static void
put_af3(byte *buf, u32 id)
{
    put_u16(buf, id >> 16);
    buf[2] = id & 0xff;
}
byte *
insert_json_key(byte *pos, cJSON *input_json, char *key)
{
    char input[1024];
    bsprintf(input, cJSON_GetObjectItem(input_json, key)->valuestring);
    // log("inserting %s", input);
    char *token;
    token = strtok(input, ",");
    while (token != NULL)
    {
        pos = insert_u8(pos, atoi(token));
        token = strtok(NULL, ",");
    }
    return pos;
}
static inline int
bgp_put_attr_hdr(byte *buf, uint code, uint flags, uint len)
{
    if (len < 256)
    {
        *buf++ = flags & ~BAF_EXT_LEN;
        *buf++ = code;
        *buf++ = len;
        return 3;
    }
    else
    {
        *buf++ = flags | BAF_EXT_LEN;
        *buf++ = code;
        put_u16(buf, len);
        return 4;
    }
}
int bird_send(struct bgp_proto *p, cJSON *input_json)
{
    struct bgp_conn *conn = p->conn;
    if (conn == NULL)
    {
        log("no conn"); // connection not ready
        return 2;
    }
    int is_native_bgp = cJSON_GetObjectItem(input_json, "is_native_bgp")->valueint;
    if (1 == is_native_bgp)
        return bird_send_bgp(p, input_json);
    else
        return bird_send_sav(p, input_json);
}
int bird_send_bgp(struct bgp_proto *p, cJSON *input_json)
{
    log("bird_send_bgp");
    struct bgp_conn *conn = p->conn;
    byte *current, *end, *buf_start, *buf_end;
    uint type;
    sock *sk = conn->sk;
    buf_start = sk->tbuf;
    buf_end = buf_start + (bgp_max_packet_length(conn) - BGP_HEADER_LENGTH);
    current = buf_start + BGP_HEADER_LENGTH;
    type = conn->packets_to_send;
    struct lp_state tmpp;
    lp_save(tmp_linpool, &tmpp); // save local linpool state
    struct bgp_channel *c = proto_find_channel_by_name(p, "ipv4");
    struct bgp_write_state s = {
        .proto = p,
        .channel = c,
        .pool = tmp_linpool,
        .mp_reach = (c->afi != BGP_AF_IPV4) || c->ext_next_hop, // mutiple protocol reach
        .as4_session = p->as4_session,
        .add_path = c->add_path_tx,
        .mpls = c->desc->mpls,
    };

    current = insert_json_key(current, input_json, "withdraws");
    byte *attrs_start = current;
    insert_u8(attrs_start + 2, BAF_OPTIONAL | BAF_EXT_LEN); // flag
    insert_u8(attrs_start + 3, BA_MP_REACH_NLRI);           // code
    put_af3(attrs_start + 6, BGP_AF_IPV4);                  // afi (2 for AFI and 1 for SAFI)
    current = attrs_start + 9;
    current = insert_json_key(current, input_json, "next_hop");
    current = insert_u8(current, 0); // reserve

    int is_interior = cJSON_GetObjectItem(input_json, "is_interior")->valueint;
    if (is_interior == 0)
    {
        // TODO add intra path here
    }
    // insert nlri
    current = insert_json_key(current, input_json, "bgp_nlri");

    // end of standard mp reach nlri field
    put_u16(attrs_start + 4, (current - attrs_start) - 6);

    // insert origin
    current += bgp_put_attr_hdr(current, BA_ORIGIN, 64, 1);
    current = insert_u8(current, p->is_interior);
    // insert as_path
    if (is_interior == 1)
    {
        current += bgp_put_attr_hdr(current, BA_AS_PATH, 80, cJSON_GetObjectItem(input_json, "as_path_len")->valueint); // here set the length to 0 and overwite it latter
        current = insert_json_key(current, input_json, "as_path");
    }
    // end of SAV attribute

    // insert attr length
    put_u16(attrs_start, (current - attrs_start) - 2);

    // bgp tailing
    end = current;

    // log("bgp-update packet assembled");
    p->stats.tx_updates++;
    lp_restore(tmp_linpool, &tmpp);

    uint len = end - buf_start;

    // log("bgp packet len %d", len);

    conn->bgp->stats.tx_messages++;
    conn->bgp->stats.tx_bytes += len;
    memset(buf_start, 0xff, 16); /* Marker */
    put_u16(buf_start + 16, len);
    buf_start[18] = PKT_UPDATE;

    int socket_result = sk_send(sk, len);
    input_json = NULL;
    log("bgp-update send result, %d", socket_result);

    return 0;
}
int bird_send_sav(struct bgp_proto *p, cJSON *input_json)
{
    log("bird_send_sav");
    struct bgp_conn *conn = p->conn;
    byte *current, *end, *buf_start, *buf_end;
    uint type;
    sock *sk = conn->sk;
    buf_start = sk->tbuf;
    buf_end = buf_start + (bgp_max_packet_length(conn) - BGP_HEADER_LENGTH);
    current = buf_start + BGP_HEADER_LENGTH;
    type = conn->packets_to_send;
    struct lp_state tmpp;
    lp_save(tmp_linpool, &tmpp); // save local linpool state
    struct bgp_channel *c = proto_find_channel_by_name(p, "rpdp4");

    struct bgp_write_state s = {
        .proto = p,
        .channel = c,
        .pool = tmp_linpool,
        .mp_reach = (c->afi != BGP_AF_IPV4) || c->ext_next_hop, // mutiple protocol reach
        .as4_session = p->as4_session,
        .add_path = c->add_path_tx,
        .mpls = c->desc->mpls,
    };
    current = insert_json_key(current, input_json, "withdraws");
    byte *attrs_start = current;
    insert_u8(attrs_start + 2, BAF_OPTIONAL | BAF_EXT_LEN); // flag
    // start of  SAV attribute
    insert_u8(attrs_start + 3, BA_MP_REACH_NLRI); // code
    put_af3(attrs_start + 6, BGP_AF_RPDP4);       // afi (2 for AFI and 1 for SAFI)
    current = attrs_start + 9;
    // insert next_hop
    current = insert_json_key(current, input_json, "next_hop");
    current = insert_u8(current, 0); // reserve
    // begin of standard mp reach nlri field
    // //insert sav_origin
    current = insert_json_key(current, input_json, "sav_origin");
    // insert sav_scope
    current = insert_json_key(current, input_json, "sav_scope");
    int is_interior = cJSON_GetObjectItem(input_json, "is_interior")->valueint;
    if (is_interior == 0)
    {
        // TODO add intra path here
    }
    // insert nlri
    current = insert_json_key(current, input_json, "sav_nlri");

    // end of standard mp reach nlri field
    put_u16(attrs_start + 4, (current - attrs_start) - 6);

    // insert origin
    current += bgp_put_attr_hdr(current, BA_ORIGIN, 64, 1);
    current = insert_u8(current, p->is_interior);
    // insert as_path
    if (is_interior == 1)
    {
        current += bgp_put_attr_hdr(current, BA_AS_PATH, 80, cJSON_GetObjectItem(input_json, "as_path_len")->valueint); // here set the length to 0 and overwite it latter
        current = insert_json_key(current, input_json, "as_path");
    }
    // end of SAV attribute

    // insert attr length
    put_u16(attrs_start, (current - attrs_start) - 2);

    // bgp tailing
    end = current;

    log("sav-update packet assembled");
    p->stats.tx_updates++;
    lp_restore(tmp_linpool, &tmpp);

    uint len = end - buf_start;

    log("sav packet len %d", len);

    conn->bgp->stats.tx_messages++;
    conn->bgp->stats.tx_bytes += len;
    memset(buf_start, 0xff, 16); /* Marker */
    put_u16(buf_start + 16, len);
    buf_start[18] = PKT_UPDATE;

    int socket_result = sk_send(sk, len);
    input_json = NULL;
    log("sav-update send result, %d", socket_result);
    return 0;
}

// void  send_request(char info[], char reply[])
char *send_request(char info[])
{
    struct sockaddr_in server;
    struct timeval timeout = {10, 0};
    struct hostent *hp;
    char ip[20] = {0};
    char *hostname = "localhost";
    int sockfd;
    char header_str[512];
    int size_recv, total_size = 0;
    int len;
    char slen[32];
    char chunk[512];
    int header_len;
    int body_len;
    int request_len;
    char *req_str = NULL;
    cJSON *info_json = cJSON_Parse(info);
    int reply_size = 1024;
    char *reply = (char *)calloc(reply_size, sizeof(char));
    char *token;

    if (info_json == NULL)
    {
        cJSON_Delete(info_json);
        bsprintf(reply, "{\"code\":\"5005\",\"msg\":\"Invalid Json String\"}");
        return reply;
    }
    char *msg_type = cJSON_GetObjectItem(info_json, "msg_type")->valuestring;

    memset(header_str, 0x00, sizeof(header_str));
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1)
    {
        cJSON_Delete(info_json);
        bsprintf(reply, "{\"code\":\"5001\",\"msg\":\"could not create socket\"}");
        return reply;
    }
    if ((hp = gethostbyname(hostname)) == NULL)
    {
        close(sockfd);
        cJSON_Delete(info_json);
        bsprintf(reply, "{\"code\":\"5002\",\"msg\":\"could not get host name\"}");
        return reply;
    }

    strcpy(ip, inet_ntoa(*(struct in_addr *)hp->h_addr_list[0]));

    server.sin_addr.s_addr = inet_addr(ip);
    server.sin_family = AF_INET;
    server.sin_port = htons(8888);

    /*connect server*/
    if (connect(sockfd, (struct sockaddr *)&server, sizeof(server)) < 0)
    {
        cJSON_Delete(info_json);
        bsprintf(reply, "{\"code\":\"5003\",\"msg\":\"could not connect server\"}");
        return reply;
    }

    /*http POST request*/
    strcpy(header_str, "POST /bird_bgp_upload/ HTTP/1.1\r\n");
    strcat(header_str, "Host: localhost\r\n");
    strcat(header_str, "Content-Type: application/json\r\n");
    strcat(header_str, "Content-Length: ");
    len = strlen(info);
    sprintf(slen, "%d", len);
    strcat(header_str, slen);
    strcat(header_str, "\r\n");
    strcat(header_str, "\r\n");
    // strcat(req_str, info);

    header_len = strlen(header_str);
    body_len = strlen(info);
    request_len = header_len + body_len + 256;
    req_str = (char *)calloc(request_len, sizeof(char));
    strcpy(req_str, header_str);
    strcat(req_str, info);
    /*send data*/
    if (send(sockfd, req_str, strlen(req_str), 0) < 0)
    {
        close(sockfd);
        cJSON_Delete(info_json);
        bsprintf(reply, "{\"code\":\"5004\",\"req_str\":\"could not send data\"}");
        return reply;
    }
    free(req_str);
    req_str = NULL;

    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(struct timeval));
    while (1)
    {
        memset(chunk, 0x00, 512);
        /*receive data*/
        if ((size_recv = recv(sockfd, chunk, 512, 0)) == -1)
        {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
            {
                break;
            }
            else if (errno == EINTR)
            {
                continue;
            }
            else if (errno == ENOENT)
            {
                break;
            }
            else if (errno == EBADMSG)
            {
                close(sockfd);
                bsprintf(reply, "{\"code\":\"5006\",\"req_str\":\"could not receive data\",\"err_code\":%d}", errno);
                cJSON_Delete(info_json);
                return reply;
            }
            else
            {
                bsprintf(reply, "{\"code\":\"5006\",\"req_str\":\"could not receive data\",\"err_code\":%d}", errno);
                cJSON_Delete(info_json);
                return reply;
            }
        }
        else if (size_recv == 0)
        {
            break;
        }
        else
        {
            total_size += size_recv;
            if (total_size > 512)
            {
                reply_size = reply_size + 512;
                reply = (char *)realloc(reply, reply_size * sizeof(char));
            }
            if (chunk != NULL)
            {
                // log("start chunk");
                // log(chunk);
                // log("end chunk");
                strcat(reply, chunk);
            }
        }
    }
    close(sockfd);
    cJSON_Delete(info_json);
    if (reply == NULL)
    {
        bsprintf(reply, "{\"code\":\"5007\",\"req_str\":\"result\"}");
        return reply;
    }
    //char *head_s = strstr(reply, "HTTP");
    //char *tail_s = strstr(reply, "POST");
    //char *head_e = strstr(reply, "\n\r");
    //char *tail_e = strstr(reply, "HTTP/1.1");
    //while ((head_s != NULL) ||(tail_s != NULL))
    //{
    //    if (head_s != NULL)
    //        bsprintf(reply, head_e);
    //    if (tail_s != NULL)
    //        bsprintf(reply, tail_e);
    //    head_s = strstr(reply, "HTTP");
    //    head_e = strstr(reply, "\n\r");
    //    tail_s = strstr(reply, "POST");
    //    tail_e = strstr(reply, "HTTP/1.1");
    //}
    log("http_reply: %s", reply);
    char *body = (char *)calloc(total_size, sizeof(char));
    token = strtok(reply, "\r\n");
    while( token != NULL ) { 
        if(strstr(token, "HTTP/1.1") == token){
            token = strtok(NULL, "\r\n");
            continue;
        }
        if(strstr(token, "Server:") == token){
            token = strtok(NULL, "\r\n");
            continue;
        }
        if(strstr(token, "Date:") == token){
            token = strtok(NULL, "\r\n");
            continue;
        }
        if(strstr(token, "Connection:") == token){
            token = strtok(NULL, "\r\n");
            continue;
        }
        if(strstr(token, "Content-Type:") == token){
            token = strtok(NULL, "\r\n");
            continue;
        }
        if(strstr(token, "Content-Length:") == token){
            token = strtok(NULL, "\r\n");
            continue;
        }
        if(strstr(token, "Host:") == token){
            token = strtok(NULL, "\r\n");
            continue;
        }
        if(strstr(token, "POST") != NULL){
            char *fount = strstr(token, "POST");
            int offset = fount - token;
            strncat(body, token, offset);
            token = strtok(NULL, "\r\n");
            continue;
        }
        strcat(body, token);
        token = strtok(NULL, "\r\n");
    }
    log("http_body: %s", body);
    return body;
}

int rpdp_process(cJSON *msg_json)
{
    char proto_name[20] = "";
    bsprintf(proto_name, "%s", cJSON_GetObjectItem(msg_json, "protocol_name")->valuestring);
    struct proto *P;
    WALK_LIST(P, proto_list)
    {
        if ((P->proto == &proto_bgp) && (P->proto_state != PS_DOWN))
        {
            struct bgp_proto *p = (void *)P;
            if (strcmp(P->name, proto_name) == 0)
                return bird_send(p, msg_json);
        }
    }
    log("protocol not found: %s", proto_name);
}

void send_to_agent(char msg[])
{
    // 1: missing key code
    // 0: good
    char *server_reply = NULL;
    server_reply = send_request(msg);
    int return_code = 1;
    // log("22222222222222222222222");
    // log(msg);
    cJSON *reply_json = cJSON_Parse(server_reply);
    if (!cJSON_HasObjectItem(reply_json, "code"))
        goto done;
    char *msg_type = cJSON_GetObjectItem(reply_json, "code")->valuestring;
    if (strcmp(msg_type, "0000") == 0)
    {
        return_code = 0;
        goto done;
    }
    else if (strcmp(msg_type, "2000") == 0)
    {
        {
            log("SavAgent reply %s", server_reply);
            return_code = rpdp_process(cJSON_GetObjectItem(reply_json, "data"));
            goto done;
        }
    }
    else
    {
        return_code = 3;
        goto done;
    }
    free(server_reply);
    server_reply = NULL;
done:
    if (reply_json != NULL)
    {
        cJSON_Delete(reply_json);
    }
    switch (return_code)
    {
    case 0:
        return;
    default:
        log("error code: %d", return_code);
        log("sending: %s", msg);
        if (server_reply != NULL)
            log("rep_msg: [%s]", server_reply);
        return;
    }
    free(server_reply);
    server_reply = NULL;
}

void send_pkts(char *filename)
{
    // read file line by line and parse to json and send.
    FILE *fp = NULL;
    char *line = NULL;
    size_t len = 10000;
    int return_code = 1;
    fp = fopen(filename, "r");
    if (fp == NULL)
    {
        log("file not found");
        exit(EXIT_FAILURE);
    }
    while ((getline(&line, &len, fp)) != -1)
        return_code = rpdp_process(cJSON_Parse(line));
    fclose(fp);
    free(line);
}
