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
	int newsocket;
	newsocket = createFileDescriptor (pid);	
	socket_table.insert(make_tuple(pid, newsocket));
	return returnSystemCall(syscallUUID, newsocket);
}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int socket_fd)
{
	tuple<int, int> key(pid, socket_fd);
	if(socket_table.find(key) == socket_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}
	
	socket_table.erase(key);
	if(bind_table.find(key) != bind_table.end())
	{
		bind_table.erase(bind_table.find(key));
	}
	removeFileDescriptor (pid, socket_fd);
	return returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, const  struct sockaddr *addr, socklen_t addrlen)
{
	struct sockaddr_in * addr_in = (struct sockaddr_in *)addr;
	uint32_t address = (addr_in->sin_addr.s_addr);
	uint16_t port = (addr_in->sin_port);
	short family = addr_in->sin_family;
	tuple<int, int> key(pid, sockfd);
	tuple<uint32_t, uint16_t, short, socklen_t> value(address, port, family, addrlen);
	//not in socket_table
	if(socket_table.find(key) == socket_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}
	//already bind.
	if(bind_table.find(key) != bind_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}
	//bind rule
	for(map<tuple<int,int>,tuple<uint32_t, uint16_t, short, socklen_t>>::iterator it = bind_table.begin(); it!=bind_table.end();it++)
	{
		if(get<1>(it->second) == port && ((get<0>(it->second) == address)|| addr == INADDR_ANY||get<0>(it->second) == INADDR_ANY))
		{
			return returnSystemCall(syscallUUID, -1);
		}
	}

	bind_table[key]=value;
	return returnSystemCall(syscallUUID, 0);
}


void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int sock_fd, struct sockaddr *addr, socklen_t *addrlen)
{
	struct sockaddr_in* addr_in = (struct sockaddr_in *)addr;
	tuple<int, int>key(pid, sock_fd);
	if(socket_table.find(key)==socket_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}

	map<tuple<int,int>,tuple<uint32_t,uint16_t,short,socklen_t>>::iterator it = bind_table.find(key);
	if(it==bind_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}

	memset(addr_in, 0, sizeof(struct sockaddr_in));
	addr_in->sin_addr.s_addr = (get<0>(it->second));
	addr_in->sin_port = (get<1>(it->second));
	addr_in->sin_family = get<2>(it->second);
	*(addrlen) = get<3>(it->second);
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
