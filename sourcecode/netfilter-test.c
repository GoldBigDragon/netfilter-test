#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <errno.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

const char *url;

// ������ ����մϴ�.
void usage() {
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net\n");
}

// Linux ��ɾ �����Ű��, �� ����� ���ڿ��� �������� �Լ��Դϴ�.
// ���ڷδ� �����ų ��ɾ ���ϴ�.
char* exec(const char* cmd) {
    // 1024bytes ũ���� ���� �迭�� �غ��մϴ�.
    char buffer[1024];
    // ����� ���� string ������ �غ��մϴ�.
    std::string result = "";
    // cmd â�� ���� �б� ���� �����մϴ�.
    FILE* pipe = popen(cmd, "r");
    // ������ ���� ���
    if (!pipe) {
        // ������ �ս��ϴ�.
        return NULL;
    }
    try {
        // ��°��� NULL�� �ƴ� �� ���� ��ɾ� ��¹����� �����ɴϴ�.
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            // result ���� �ȿ� ���ۿ� ��� ������ ����ϴ�.
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    // ������� ���� char ���� ������ result ���ڿ� ũ�� ��ŭ �����մϴ�.
    char *cstr = new char[result.length() + 1];
    // ������� ĳ������ ������ ����ϴ�.
    strcpy(cstr, result.c_str());
    // char ������ cmd ��� ����� ��ȯ�մϴ�.
    return cstr;
}

/* returns packet id */
static u_int32_t print_pkt (struct nfq_data *tb) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *data;
    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    int ret = nfq_get_payload(tb, &data);
    if(ret >= 0) {
        struct iphdr *ip_info = (struct iphdr *)data;
        if(ip_info->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp = (struct tcphdr *)((char *)ip_info + ip_info->ihl * 4);
            if(tcp->th_dport == ntohs(80) || tcp->th_dport == ntohs(443)) {
                unsigned int data_len = ntohs(ip_info->tot_len);
                // ��� ��, �����Ͱ� ���۵Ǵ� �������� �˾Ƴ��ϴ�.
                unsigned int dataOffset = (tcp->doff * 4) + (ip_info->ihl * 4);
                if(data_len <= dataOffset)
                    return id;
                else
                    data_len -= dataOffset;

                char *hdata = (char *)tcp + (tcp->doff * 4);
                char *host = strstr(hdata, "Host: ");
                int hostLen = strlen(host);
                int urlLen = strlen(url);
                if(host == NULL || hostLen < urlLen) {
                    return id;
                }
                int returnId = 0;
                int i = 0;
                for (i = 0; i < urlLen; i++) {
                    if(host[i+6] == url[i]) {
                        returnId = 0;
                    } else {
                        returnId = 1;
                        break;
                    }
                }
                if(returnId == 0) {
                    id = -1;
                    printf("[Blocked!]\n");
                }
            }
        }
    }
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    u_int32_t id = print_pkt(nfa);
    if(id == -1)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    else
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    if(argc != 2) {
        usage();
        return 0;
    }
    printf("%s", argv[1]);
    url = argv[1];
    exec("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    exec("iptables -A INPUT -j NFQUEUE --queue-num 0");
    
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));

    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif
    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}
