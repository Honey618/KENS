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

struct SocketInfo
{
	int pid;
	int sockfd;
	//for blocking
	E::UUID uuid;
	//0 -> closed, 1-> listen
	int state;
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


	list<struct SocketInfo> socket_table;
	//pid, fd -> address, port, family, socklen
	list<struct BindInfo> bind_table;


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
