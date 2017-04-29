/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_


#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Host.hpp>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>

#define TCP_FLAG(tcphdr) (tcphdr.fin | tcphdr.syn << 1 | tcphdr.rst << 2 | tcphdr.psh << 3 | tcphdr.ack << 4 | tcphdr.urg << 5)
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

struct SocketInfo
{
	int pid;
	int sockfd;
	//for blocking
	E::UUID uuid;
	//0-> closed, 1-> listen 2-> SYN_RCVD 3-> SYN_SENT 4->ESTABLISHED
	//5-> FIN_WAIT_1 6-> FIN_WAIT2 7->TIMED_WAIT 8->CLOSE_WAIT 9->LAST_ACK
	int state;
	unsigned int backlog;
	uint32_t saddr;
	uint32_t daddr;
	uint32_t sport;
	uint32_t dport;
	uint32_t seq;
	struct sockaddr* cliaddr;
	socklen_t* addrlen;
	std::list<struct SocketInfo*> wait_table;
};

struct BindInfo
{
	int pid;
	int sockfd;
	uint32_t address;
	uint16_t port;
	short family;
	socklen_t socklen;
};

struct ethdr
{
	char Dmac[6];
	char Smac[6];
	uint16_t Etype;
};

struct hdr
{
	struct ethdr eth;
	struct iphdr iph;
	struct tcphdr tcph;
} __attribute__((packed));

#include <E/E_TimerModule.hpp>
using namespace std;
namespace E
{

class TCPAssignment : public HostModule, public NetworkModule, public SystemCallInterface, private NetworkLog, private TimerModule
{
private:

private:
	virtual void timerCallback(void* payload) final;

public:
	TCPAssignment(Host* host);
	virtual void initialize();
	virtual void finalize();
	virtual ~TCPAssignment();
	virtual void syscall_socket(UUID syscallUUID, int pid, int sc_family, int sc_type);
	virtual void syscall_close(UUID syscallUUID, int pid, int socket_fd);
	virtual void syscall_bind(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	virtual void syscall_getsockname(UUID syscallUUID, int pid, int sock_fd, struct sockaddr *addr, socklen_t *addrlen);
	virtual void syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog);
	virtual void syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *cliaddr, socklen_t *addrlen);
	virtual void syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *servaddr, socklen_t addrlen);
	virtual void syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	list<struct SocketInfo> socket_table;
	//pid, fd -> address, port, family, socklen
	list<struct BindInfo> bind_table;
	
	list<struct SocketInfo*> estab_table;
	list<struct SocketInfo*> accept_table; 


protected:
	virtual void systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param) final;
	virtual void packetArrived(std::string fromModule, Packet* packet) final;
};

class TCPAssignmentProvider
{
private:
	TCPAssignmentProvider() {}
	~TCPAssignmentProvider() {}
public:
	static HostModule* allocate(Host* host) { return new TCPAssignment(host); }
};

}


#endif /* E_TCPASSIGNMENT_HPP_ */
