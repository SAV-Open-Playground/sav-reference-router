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
int get_json_int(cJSON *input_json, char *key)
{
    return cJSON_GetObjectItem(input_json, key)->valueint;
}
char *get_json_str(cJSON *input_json, char *key)
{
    return cJSON_GetObjectItem(input_json, key)->valuestring;
}
byte *
insert_json_key_str(byte *pos, cJSON *input_json, char *key)
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
byte *
insert_json_key_int(byte *pos, cJSON *input_json, char *key)
{
    cJSON *temp = NULL;
    temp = cJSON_GetObjectItem(input_json, key)->child;
    while (temp != NULL)
    {
        pos = insert_u8(pos, temp->valueint);
        temp = temp->next;
    }
    return pos;
}
static inline int
bgp_send(struct bgp_conn *conn, uint type, uint len)
{
    sock *sk = conn->sk;
    byte *buf = sk->tbuf;

    conn->bgp->stats.tx_messages++;
    conn->bgp->stats.tx_bytes += len;

    memset(buf, 0xff, 16); /* Marker */
    put_u16(buf + 16, len);
    buf[18] = type;

    return sk_send(sk, len);
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
        log("error: no conn"); // connection not ready
        return 2;
    }
    int is_native_bgp = get_json_int(input_json, "is_native_bgp");
    if (1 == is_native_bgp)
        return bird_send_bgp(p, input_json);
    else
        return bird_send_dsav(p, input_json);
}
int bird_send_bgp(struct bgp_proto *p, cJSON *input_json)
{
    log("bird_send_native_bgp");
    struct bgp_conn *conn = p->conn;
    byte *cur_pos, *end, *buf_start, *buf_end;
    uint type;
    sock *sk = conn->sk;
    buf_start = sk->tbuf;
    buf_end = buf_start + (bgp_max_packet_length(conn) - BGP_HEADER_LENGTH);
    cur_pos = buf_start + BGP_HEADER_LENGTH;
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

    cur_pos = insert_json_key_str(cur_pos, input_json, "withdraws");
    byte *attrs_start = cur_pos;
    insert_u8(attrs_start + 2, BAF_OPTIONAL | BAF_EXT_LEN); // flag
    insert_u8(attrs_start + 3, BA_MP_REACH_NLRI);           // code
    put_af3(attrs_start + 6, BGP_AF_IPV4);                  // afi (2 for AFI and 1 for SAFI)
    cur_pos = attrs_start + 9;
    cur_pos = insert_json_key_str(cur_pos, input_json, "next_hop");
    cur_pos = insert_u8(cur_pos, 0); // reserve

    int is_interior = get_json_int(input_json, "is_interior");
    // insert nlri
    cur_pos = insert_json_key_str(cur_pos, input_json, "bgp_nlri");

    // end of standard mp reach nlri field
    put_u16(attrs_start + 4, (cur_pos - attrs_start) - 6);

    // insert origin
    cur_pos += bgp_put_attr_hdr(cur_pos, BA_ORIGIN, 64, 1);
    // cur_pos = insert_json_key_str(cur_pos, input_json, "origin");
    cur_pos = insert_u8(cur_pos, ORIGIN_IGP);
    cur_pos = insert_u8(cur_pos, p->is_interior);
    // insert as_path
    if (is_interior == 1)
    {
        cur_pos += bgp_put_attr_hdr(cur_pos, BA_AS_PATH, 80, cJSON_GetObjectItem(input_json, "as_path_len")->valueint);
        cur_pos = insert_json_key_str(cur_pos, input_json, "as_path");
    }
    // end of SAV attribute
    // insert attr length
    put_u16(attrs_start, (cur_pos - attrs_start) - 2);
    // bgp tailing
    end = cur_pos;
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
void log_data(byte *data, int len, char *msg)
{
    int count = 0;
    log("===========================");
    while (count < len)
    {
        log("%s [%d]: %d", msg, count, get_u8(data));
        data += 1;
        count += 1;
    }
}
int bird_send_dsav(struct bgp_proto *p, cJSON *input_json)
{
    log("bird_send_dsav");
    struct bgp_conn *conn = p->conn;
    byte *cur_pos, *end, *buf_start, *buf_end;
    sock *sk = conn->sk;
    buf_start = sk->tbuf;
    buf_end = buf_start + (bgp_max_packet_length(conn) - BGP_HEADER_LENGTH);
    // log("bgp max len: %d", buf_end -buf_start);
    cur_pos = buf_start + BGP_HEADER_LENGTH;
    struct lp_state tmpp;
    lp_save(tmp_linpool, &tmpp); // save local linpool state
    // struct bgp_channel *c = proto_find_channel_by_name(p, "rpdp4");
    struct bgp_channel *c = proto_find_channel_by_name(p, cJSON_GetObjectItem(input_json, "channel")->string);
    // log("input_json: %s", cJSON_Print(input_json));
    char *msg_type = cJSON_GetObjectItem(input_json, "type")->valuestring;
    if (strcmp(msg_type, "spa") == 0)
        return send_rpdp_update(
            p, input_json, conn, cur_pos, end, buf_start, sk, tmpp, c);
    else if (strcmp(msg_type, "spd") == 0)
        return send_rpdp_refresh(
            p, input_json, conn, cur_pos, end, buf_start, sk, tmpp, c);
    else
        {
            log("ERROR: type not supported %s", msg_type);
            return -1;
        }
        
}

int send_rpdp_update(struct bgp_proto *p, cJSON *input_json, struct bgp_conn *conn,
                     byte *cur_pos, byte *end, byte *buf_start, sock *sk,
                     lp_state tmpp, struct bgp_channel *c)
{   
    log("send_rpdp_update");
    log("input_json: %s", cJSON_Print(input_json));
    struct bgp_bucket *buck;
    byte *res = NULL;
    struct bgp_write_state s = {
        .proto = p,
        .channel = c,
        .pool = tmp_linpool,
        .as4_session = p->as4_session,
        .add_path = c->add_path_tx,
        .mpls = c->desc->mpls,
    };
    int rpdp_version = get_json_int(input_json, "rpdp_version");
    int del_len = get_json_int(input_json, "del_len");
    int is_interior = get_json_int(input_json, "is_interior");
    int add_len = get_json_int(input_json, "add_len");
    cur_pos = insert_u16(cur_pos, 0); // bgp withdraw,fixed to 0
    byte *total_path_attr_len_pos = cur_pos;
    cur_pos += 2;
    byte *attrs_start = cur_pos;
    // insert origin
    cur_pos += bgp_put_attr_hdr(cur_pos, BA_ORIGIN, 64, 1);
    cur_pos = insert_u8(cur_pos, ORIGIN_IGP);
    if (is_interior==1){
        cur_pos += bgp_put_attr_hdr(cur_pos, BA_AS_PATH, 64, get_json_int(input_json, "as_path_len"));
        cur_pos = insert_json_key_int(cur_pos, input_json, "as_path");
    }
    if (rpdp_version == 4)
        {cur_pos += bgp_put_attr_hdr(cur_pos, BA_NEXT_HOP, 64, 4);
        cur_pos = insert_json_key_int(cur_pos, input_json, "next_hop");}
    // log("after next_hop as_path and origin");
    if (add_len > 0) {
        cur_pos += bgp_put_attr_hdr(cur_pos, BA_MP_REACH_NLRI, 128, 0);
        // put afi and SAFI
        byte *add_len_pos = cur_pos-1;
        byte *add_len_start = cur_pos;
        if (rpdp_version == 6)
            put_af3(cur_pos, BGP_AF_RPDP6);
        else if (rpdp_version == 4)
            put_af3(cur_pos, BGP_AF_RPDP4);
        cur_pos += 3;
        // insert next_hop
        if (rpdp_version == 4)
            cur_pos = insert_u8(cur_pos, 4); // length of next hop,for bird processing
        else if (rpdp_version == 6)
            cur_pos = insert_u8(cur_pos, 16); // length of next hop,for bird processing
        cur_pos = insert_json_key_int(cur_pos, input_json, "next_hop");
        cur_pos = insert_u8(cur_pos, 0); // reserve zero,for bird processing
        cur_pos = insert_json_key_int(cur_pos, input_json, "add");
        insert_u8(add_len_pos, cur_pos - add_len_start);
    }
    // log("after add");
    if (del_len > 0)
    {   
        cur_pos += bgp_put_attr_hdr(cur_pos, BA_MP_UNREACH_NLRI, 128, 0);
        byte *del_len_pos = cur_pos-1;
        byte *del_len_start = cur_pos;
        if (rpdp_version == 6)
            put_af3(cur_pos, BGP_AF_RPDP6);
        else if (rpdp_version == 4)
            put_af3(cur_pos, BGP_AF_RPDP4);
        cur_pos += 3;
        cur_pos = insert_u8(cur_pos, 4); // length of next hop,for bird processing
        cur_pos = insert_json_key_int(cur_pos, input_json, "next_hop");
        cur_pos = insert_u8(cur_pos, 0); // reserve zero,for bird processing
        cur_pos = insert_json_key_int(cur_pos, input_json, "del");
        insert_u8(del_len_pos, cur_pos - del_len_start);
    }
    log("after spa_del");
    // insert rpdp_add


    // log("origin pos: %d", (cur_pos - attrs_start) - 1);
    // cur_pos = insert_json_key_int(cur_pos, input_json, "origin");
    // log("after origin");
    // insert as_path
        // TODO porperly handle as_path
    // insert next_hop


    // insert attr length
    log("total_path_attr_len_pos: %d", (cur_pos - attrs_start));
    // put_u16(total_path_attr_len_pos, (cur_pos - total_path_attr_len_pos) - 2);
    put_u16(total_path_attr_len_pos, cur_pos - attrs_start);

    // bgp tailing
    end = cur_pos;
    // log("sav-update packet assembled");
    p->stats.tx_updates++;
    lp_restore(tmp_linpool, &tmpp);

    uint len = end - buf_start;

    // log("rpdp_update len %d", len);

    int socket_result = bgp_send(conn, PKT_UPDATE, len);
    input_json = NULL;
    // log_data(buf_start, len, "DSAV-update packet");
    log("sav-update send result, %d", socket_result);
    return socket_result;
}
int send_rpdp_refresh(struct bgp_proto *p, cJSON *input_json, struct bgp_conn *conn,
                      byte *cur_pos, byte *end, byte *buf_start, sock *sk,
                      lp_state tmpp, struct bgp_channel *c)
{
    // insert rpdp
    log("send_rpdp_refresh");
    log("input_json: %s", cJSON_Print(input_json));
    int rpdp_version = get_json_int(input_json, "rpdp_version");
    // log("inserting afi");
    if (rpdp_version == 6)
        cur_pos = insert_u16(cur_pos, 2);
    else if (rpdp_version == 4)
        cur_pos = insert_u16(cur_pos, 1);
    else
        log("rpdp version not supported!!!!!!! %d", rpdp_version);
    // log("inserting reserve");
    cur_pos = insert_u8(cur_pos, 0);
    // log("inserting safi");
    cur_pos = insert_u8(cur_pos, 251);
    // type (spd message indicator)
    cur_pos = insert_u16(cur_pos, 2);
    // subtype
    if (get_json_int(input_json, "is_interior") == 1)
        cur_pos = insert_u8(cur_pos, 2);
    else
        cur_pos = insert_u8(cur_pos, 1);

    byte *len_pos = cur_pos;
    cur_pos += 2;
    // SN
    put_u32(cur_pos, get_json_int(input_json, "SN"));
    cur_pos += 4;
    // log("inserting origin_router_id");
    cur_pos = insert_json_key_int(cur_pos, input_json, "origin_router_id");
    if (get_json_int(input_json, "is_interior") == 1)
    {
        // log("inserting origin_as");
        put_u32(cur_pos, get_json_int(input_json, "source_asn"));
        cur_pos += 4;
        // log("inserting validation_as");
        put_u32(cur_pos, get_json_int(input_json, "validate_asn"));
        cur_pos += 4;
    }
    // optional_data
    byte *optional_data_len_pos = cur_pos;
    cur_pos += 2;
    // log("inserting opt_data");
    cur_pos = insert_json_key_int(cur_pos, input_json, "opt_data");
    // address
    put_u16(optional_data_len_pos, (cur_pos - optional_data_len_pos) - 2);
    if (get_json_int(input_json, "is_interior") == 1)
    {
        // cJSON_AR = cJSON_GetObjectItem(input_json, "source_asn")->child;
        // cJSON *temp = NULL;
        // temp = cJSON_GetObjectItem(input_json, "neighbor_ases")->child;
        // while (temp != NULL)
        // {
        //     // log("inserting neighbor_ases");
        //     put_u32(cur_pos, temp->valueint);
        //     cur_pos += 4;
        //     temp = temp->next;
        // }
        cur_pos = insert_json_key_int(cur_pos, input_json, "neighbor_ases");
    }
    else
    {
        log("inserting addresses");
        cur_pos = insert_json_key_int(cur_pos, input_json, "addresses");
    }

    // insert lengths

    put_u16(len_pos, (cur_pos - len_pos) - 2);

    log("sav-refresh packet assembled");
    // log("pkt data:")
    int socket_result = bgp_send(conn, PKT_ROUTE_REFRESH, cur_pos - buf_start);
    log("sav-refresh send result, %d", socket_result);
    input_json = NULL;
    // log_data(buf_start, len, "DSAV-update packet");
    // log_data(buf_start, cur_pos - buf_start, "DSAV-refresh packet");
    return socket_result;
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
    // log("send_request: [%s]", info);
    cJSON *info_json = cJSON_Parse(info);
    // log("send_request: [%s]", cJSON_Print(info_json));
    int reply_size = 1024;
    char *reply = (char *)calloc(reply_size, sizeof(char));
    // char *token = NULL;

    if (info_json == NULL)
    {
        cJSON_Delete(info_json);
        bsprintf(reply, "{\"code\":\"5005\",\"msg\":\"Req:Invalid Json String\"}");
        return reply;
    }
    // char *msg_type = cJSON_GetObjectItem(info_json, "msg_type")->valuestring;

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
                // log("got chunk [%s]",chunk);
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
    // log("395 reply: [%s]", reply);
    // log("396 reply: [%d]", strlen(reply));
    char *head_s = strstr(reply, "HTTP/1.1 200 OK");
    char *head_e = strstr(reply, "\r\n\r\n");
    if (head_s != NULL)
        bsprintf(reply, head_e + 4);
    // log("401 reply_len: [%d]", strlen(reply));
    // log("402 reply: [%s]", reply);
    // OD =\r; OA =\n
    char *tail_s = strstr(reply, "POST /bird_bgp_upload/ HTTP/1.1");
    char *tail_e = strstr(reply, "\r\n\r\n");
    while (tail_s != NULL)
    {
        // log("4016 reply: [%s]", reply);
        bsprintf(tail_s, tail_e + 4);
        tail_s = strstr(reply, "POST /bird_bgp_upload/ HTTP/1.1");
        tail_e = strstr(reply, "\r\n\r\n");
    }
    reply[strlen(reply) - 1] = '\0';
    // log("414 reply: [%s]", reply);
    // log("http_reply: [%s]", reply);
    return reply;
}

int send_rpdp_pkt(cJSON *msg_json)
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
    return -1;
}

void send_to_agent(char msg[])
{
    // 1: missing key code
    // 0: good
    char *server_reply = NULL;
    server_reply = send_request(msg);
    int return_code = 1;
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
        log("SavAgent reply %s", server_reply);
        return_code = send_rpdp_pkt(cJSON_GetObjectItem(reply_json, "data"));
        goto done;
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
    {
        return_code = send_rpdp_pkt(cJSON_Parse(line));
        if (return_code != 0)
            log("send_rpdp_pkt failed");
    }
    fclose(fp);
    free(line);
}
