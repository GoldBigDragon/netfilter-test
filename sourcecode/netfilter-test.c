// 기본 입/출력 라이브러리를 불러옵니다.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <errno.h>
// 네트워크 패킷 관련 라이브러리를 불러옵니다.
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/types.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

// 입력한 url을 등록 할 전역 변수를 선언합니다.
const char *url;

// 사용법을 출력합니다.
void usage() {
    printf("syntax : netfilter-test <host>\n");
    printf("sample : netfilter-test test.gilgil.net\n");
}

// Linux 명령어를 실행시키고, 그 결과를 문자열로 가져오는 함수입니다.
// 인자로는 실행시킬 명령어가 들어갑니다.
char* exec(const char* cmd) {
    // 1024bytes 크기의 버퍼 배열을 준비합니다.
    char buffer[1024];
    // 결과를 담을 string 변수를 준비합니다.
    std::string result = "";
    // cmd 창을 열고 읽기 모드로 연결합니다.
    FILE* pipe = popen(cmd, "r");
    // 에러가 났을 경우
    if (!pipe) {
        // 에러를 뿜습니다.
        return NULL;
    }
    try {
        // 출력값이 NULL이 아닐 때 까지 명령어 출력문구를 가져옵니다.
        while (fgets(buffer, sizeof buffer, pipe) != NULL) {
            // result 변수 안에 버퍼에 담긴 내용을 담습니다.
            result += buffer;
        }
    } catch (...) {
        pclose(pipe);
        throw;
    }
    pclose(pipe);
    // 결과물을 담을 char 형식 변수를 result 문자열 크기 만큼 생성합니다.
    char *cstr = new char[result.length() + 1];
    // 결과물을 캐릭터형 변수에 담습니다.
    strcpy(cstr, result.c_str());
    // char 형태의 cmd 출력 결과를 반환합니다.
    return cstr;
}

// 차단 대상 URL 접근 시도 시 -1,
// 이외 대상 URL 접근 시도 시 패킷 ID를 반환하는 함수입니다.
static u_int32_t print_pkt (struct nfq_data *tb) {
    // 초기 반환 값은 0입니다.
    int id = 0;
    // 전달받은 패킷을 쪼개어 패킷 ID를 획득합니다.
    struct nfqnl_msg_packet_hdr *ph;
    unsigned char *data;
    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    // 뒤이어 오는 값의 전체 길이를 구합니다.
    int ret = nfq_get_payload(tb, &data);
    // 만일 뒤 이은 값이 존재 할 경우
    if(ret >= 0) {
        // IP 헤더를 구합니다.
        struct iphdr *ip_info = (struct iphdr *)data;
        // IP헤더 속 프로토콜이 TCP일 경우
        if(ip_info->protocol == IPPROTO_TCP) {
            // TCP 헤더를 구합니다.
            struct tcphdr *tcp = (struct tcphdr *)((char *)ip_info + ip_info->ihl * 4);
            // 통신 대상이 80포트(http)이거나 443포트(https)일 경우
            if(tcp->th_dport == ntohs(80) || tcp->th_dport == ntohs(443)) {
                
                unsigned int data_len = ntohs(ip_info->tot_len);
                // 헤더 중, 데이터가 시작되는 오프셋을 알아냅니다.
                unsigned int dataOffset = (tcp->doff * 4) + (ip_info->ihl * 4);
                if(data_len <= dataOffset)
                    return id;
                else
                    data_len -= dataOffset;

                
                
                // 데이터가 시작되는 위치를 포인터로 주시합니다.
                char *hdata = (char *)tcp + (tcp->doff * 4);
                // 주시된 위치부터의 내용 속에 Host: 문자열이 포함되는 부분을 포인터로 주시합니다.
                char *host = strstr(hdata, "Host: ");
                // 호스트(URL)의 전체 길이를 구합니다.
                int hostLen = strlen(host);
                // 등록했던 URL의 전체 길이를 구합니다.
                int urlLen = strlen(url);
                // 호스트가 비어있거나, 호스트의 길이가 등록한 URL보다 짧을 경우
                if(host == NULL || hostLen < urlLen) {
                    // 해당 패킷을 통과 시킵니다.
                    return id;
                }
                // 검사용 변수를 생성합니다.
                int returnId = 0;
                int i = 0;
                // 등록한 URL의 길이만큼 아래 구문을 반복합니다.
                for (i = 0; i < urlLen; i++) {
                    // Host: 글자 이후에 나오는 문자열과, 등록된 URL의 문자열을 비교합니다.
                    if(host[i+6] == url[i]) {
                        // 동일할 경우, 계속합니다.
                        returnId = 0;
                    // 다를 경우 검사용 변수에 '통과'를 뜻하는 1을 표기하고 반복을 종료합니다.
                    } else {
                        returnId = 1;
                        break;
                    }
                }
                // 검사용 변수 값이 0일 경우
                if(returnId == 0) {
                    // -1을 반환하여 사이트 접근을 막습니다.
                    id = -1;
                    printf("[Blocked!]\n");
                }
            }
        }
    }
    return id;
}

// 사이트 접근을 제어하는 함수입니다.
static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    // 패킷에 대한 ID값을 가져옵니다.
    u_int32_t id = print_pkt(nfa);
    // ID값이 -1일 경우 접근을 막고, 아닐 경우 허용합니다.
    if(id == -1)
        return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
    else
        return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

// 프로그램 시작 시 실행되는 MAIN 함수입니다.
int main(int argc, char **argv) {
    // 입력된 파라미터가 2개가 아닐 경우, 사용법을 알려주고 종료합니다.
    if(argc != 2) {
        usage();
        return 0;
    }
    // 입력된 데이터 중, 2번째로 입력한 값을 차단 대상으로 지정합니다.
    url = argv[1];
    // 오가는 패킷을 모두 NFQUEUE를 거치도록 합니다.
    exec("iptables -A OUTPUT -j NFQUEUE --queue-num 0");
    exec("iptables -A INPUT -j NFQUEUE --queue-num 0");
    
    // 패킷 수집 서비스를 준비합니다.
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

    // 패킷 수집을 반복합니다.
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
