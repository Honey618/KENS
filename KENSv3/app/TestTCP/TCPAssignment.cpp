/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: 근홍
 */


#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <cerrno>
#include <E/Networking/E_Packet.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include "TCPAssignment.hpp"

using namespace std;

namespace E
{

TCPAssignment::TCPAssignment(Host* host) : HostModule("TCP", host),
		NetworkModule(this->getHostModuleName(), host->getNetworkSystem()),
		SystemCallInterface(AF_INET, IPPROTO_TCP, host),
		NetworkLog(host->getNetworkSystem()),
		TimerModule(host->getSystem())
{

}

TCPAssignment::~TCPAssignment()
{

}

void TCPAssignment::initialize()
{

}

void TCPAssignment::finalize()
{

}
//socket family , socket_type
void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int sc_family, int sc_type)
{
	struct SocketInfo sock;
	int newsocket;
	newsocket = createFileDescriptor (pid);	
	sock.pid = pid;
	sock.sockfd = newsocket;
	sock.uuid = syscallUUID;
	sock.state = 0;
	socket_table.push_back(sock);
	return returnSystemCall(syscallUUID, newsocket);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int socket_fd)
{
	list<struct SocketInfo>::iterator it;
	list<struct BindInfo>::iterator jt;
	for(it = socket_table.begin(); it!=socket_table.end();it++)
	{
		if(it->pid == pid && it->sockfd == socket_fd)
			break;
	}
	
	//tuple<int, int> key(pid, socket_fd);
	
	if(it == socket_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}
	
	socket_table.erase(it);

	for(jt = bind_table.begin(); jt!=bind_table.end();jt++)
	{
		if(jt->pid == pid && jt->sockfd == socket_fd)
			break;
	}

	if(jt != bind_table.end())
	{
		bind_table.erase(jt);
	}
	removeFileDescriptor (pid, socket_fd);
	return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, const  struct sockaddr *addr, socklen_t addrlen)
{

	list<struct SocketInfo>::iterator it;
	list<struct BindInfo>::iterator jt;
	list<struct BindInfo>::iterator kt;

	struct sockaddr_in * addr_in = (struct sockaddr_in *)addr;
	uint32_t address = (addr_in->sin_addr.s_addr);
	uint16_t port = (addr_in->sin_port);
	short family = addr_in->sin_family;
	struct BindInfo bindinfo;
	bindinfo.pid = pid;
	bindinfo.sockfd = sockfd;
	bindinfo.address = address;
	bindinfo.port = port;
	bindinfo.family = family;
	bindinfo.socklen = addrlen;

	//tuple<int, int> key(pid, sockfd);
	//tuple<uint32_t, uint16_t, short, socklen_t> value(address, port, family, addrlen);
	//not in socket_table
	
	for(it = socket_table.begin(); it!=socket_table.end();it++)
	{
		if(it->pid == pid && it->sockfd == sockfd)
			break;
	}

	if(it == socket_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}

	for(jt = bind_table.begin(); jt!=bind_table.end();jt++)
	{
		if(jt->pid == pid && jt->sockfd == sockfd)
			break;
	}

	//already bind.
	if(jt != bind_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}

	//bind rule
	/*for(map<tuple<int,int>,tuple<uint32_t, uint16_t, short, socklen_t>>::iterator it = bind_table.begin(); it!=bind_table.end();it++)
	{
		if(get<1>(it->second) == port && ((get<0>(it->second) == address)|| addr == INADDR_ANY||get<0>(it->second) == INADDR_ANY))
		{
			return returnSystemCall(syscallUUID, -1);
		}
	}*/

	for(kt = bind_table.begin(); kt!=bind_table.end();kt++)
	{
		if(kt->port == port && ((kt->address == address)||address == INADDR_ANY||kt->address == INADDR_ANY))
		{
			return returnSystemCall(syscallUUID, -1);
		}
	}

	bind_table.push_back(bindinfo);
	return returnSystemCall(syscallUUID, 0);
}


void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sock_fd, struct sockaddr *addr, socklen_t *addrlen)
{
	list<struct SocketInfo>::iterator it;
	list<struct BindInfo>::iterator jt;

	struct sockaddr_in* addr_in = (struct sockaddr_in *)addr;

	
	for(it = socket_table.begin(); it!=socket_table.end();it++)
	{
		if(it->pid == pid && it->sockfd == sock_fd)
			break;
	}

	if(it == socket_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}

	for(jt = bind_table.begin(); jt!=bind_table.end();jt++)
	{
		if(jt->pid == pid && jt->sockfd == sock_fd)
			break;
	}

	if(jt == bind_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}

	memset(addr_in, 0, sizeof(struct sockaddr_in));
	addr_in->sin_addr.s_addr = jt->address;
	addr_in->sin_port = jt->port;
	addr_in->sin_family = jt->family;
	*(addrlen) = jt->socklen;
	return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::systemCallback(UUID syscallUUID, int pid, const SystemCallParameter& param)
{
	switch(param.syscallNumber)
	{
	case SOCKET:
		this->syscall_socket(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case CLOSE:
		this->syscall_close(syscallUUID, pid, param.param1_int);
		break;
	case READ:
		//this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case WRITE:
		//this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr, param.param3_int);
		break;
	case CONNECT:
		//this->syscall_connect(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		//this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		//this->syscall_accept(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr*>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr *>(param.param2_ptr), (socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr *>(param.param2_ptr),	static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		//this->syscall_getpeername(syscallUUID, pid, param.param1_int,
		//		static_cast<struct sockaddr *>(param.param2_ptr),
		//		static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}

void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{

}

void TCPAssignment::timerCallback(void* payload)
{

}


}
