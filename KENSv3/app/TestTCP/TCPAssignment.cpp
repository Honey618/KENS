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
#include <stdlib.h>

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
	
	if(it == socket_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}
	if(it->state<10)
	{
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
	else
	{
		uint32_t saddr;
		uint32_t daddr;
		uint16_t sport;
		uint32_t dport;

		saddr = it->saddr;
		daddr = it->daddr;
		sport = it->sport;
		dport = it->dport;
		printf("closing phase : src: %x:%d, dst: %x:%d\n",saddr,sport, daddr,dport);
		it->seq = rand();
		if(it->state == 4)
			it->state = 5;
		else if(it->state == 8)
			it->state = 9;
		it->uuid = syscallUUID;

		Packet *newpacket = allocatePacket(sizeof(struct hdr));
		struct hdr* newhdr = (struct hdr*)malloc(sizeof(struct hdr));
		memset(newhdr, 0, sizeof(struct hdr));
		newhdr->iph.daddr = htonl(daddr);
		newhdr->iph.saddr = htonl(saddr);
		newhdr->tcph.source = htons(sport);
		newhdr->tcph.dest = htons(dport);
		/*newpacket->readData(0, newhdr, sizeof(struct hdr));
		newhdr->tcph.ack_seq = htonl(ack_seq);*/
		newhdr->tcph.seq = htonl(it->seq);
		newhdr->tcph.doff = sizeof(struct tcphdr) >> 2;
		newhdr->tcph.fin = 1;
		newhdr->tcph.syn = 0;
		newhdr->tcph.rst = 0;
		newhdr->tcph.psh = 0;
		newhdr->tcph.ack = 0;
		newhdr->tcph.urg = 0;
		newhdr->tcph.window = htons(51200);
		newhdr->tcph.check = 0;
		newhdr->tcph.check = htons(~NetworkUtil::tcp_sum(newhdr->iph.saddr, newhdr->iph.daddr, (uint8_t*)(&(newhdr->tcph)), 20));
		newpacket->writeData(0, newhdr, sizeof(struct hdr));
		this->sendPacket("IPv4",newpacket);
	
		free(newhdr);
		
	}
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int sockfd, const  struct sockaddr *addr, socklen_t addrlen)
{
	list<struct SocketInfo>::iterator it;
	list<struct BindInfo>::iterator jt;
	list<struct BindInfo>::iterator kt;

	struct sockaddr_in * addr_in = (struct sockaddr_in *)addr;
	uint32_t address = ntohl(addr_in->sin_addr.s_addr);
	uint16_t port = ntohs(addr_in->sin_port);
	short family = addr_in->sin_family;
	struct BindInfo bindinfo;
	bindinfo.pid = pid;
	bindinfo.sockfd = sockfd;
	bindinfo.address = address;
	bindinfo.port = port;
	bindinfo.family = family;
	bindinfo.socklen = addrlen;

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
	for(kt = bind_table.begin(); kt!=bind_table.end();kt++)
	{
		if(kt->port == port && ((kt->address == address)||address == INADDR_ANY||kt->address == INADDR_ANY))
		{
			it->saddr = address;
			it->sport = port;
			return returnSystemCall(syscallUUID, -1);
		}
	}

	printf("%x:%d, family: %d\n",address,port, family);

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
	addr_in->sin_addr.s_addr = htonl(jt->address);
	addr_in->sin_port = htons(jt->port);
	addr_in->sin_family = jt->family;
	*(addrlen) = jt->socklen;


	return returnSystemCall(syscallUUID, 0);
}

 void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int sockfd, int backlog)
{
	list<struct SocketInfo>::iterator it;
	list<struct BindInfo>::iterator jt;

	for(it = socket_table.begin(); it!=socket_table.end();it++)
	{
		if(it->pid == pid && it->sockfd == sockfd)
			break;
	}
	if(it == socket_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}
	for(jt = bind_table.begin();jt!=bind_table.end();jt++)
	{
		if(jt->pid == pid && jt->sockfd == sockfd)
			break;
	}
	if(jt == bind_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}

	//set listen state
	it->state = 1;

	//set backlog
	it->backlog = backlog;

	returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int sockfd, struct sockaddr *cliaddr, socklen_t *addrlen)
{
	if(estab_table.empty())
	{
		struct SocketInfo* accept_waiter = (struct SocketInfo*)malloc(sizeof(struct SocketInfo));
		accept_waiter->pid = pid;
		accept_waiter->uuid = syscallUUID;
		accept_waiter->cliaddr = cliaddr;
		accept_waiter->addrlen = addrlen;
		accept_table.push_back(accept_waiter);
		printf("!!!!!!!!!!!!!!blocked\n");
	}
	else
	{
		struct SocketInfo* estable = estab_table.front();
		struct sockaddr_in *addr_in = (struct sockaddr_in*)cliaddr;
		
		memset(addr_in, 0, sizeof(struct sockaddr_in));
		addr_in->sin_addr.s_addr = htonl(estable->saddr);
		addr_in->sin_port = htons(estable->sport);
		addr_in->sin_family = 2;

		printf("my: %8x:%d, to:  %8x:%d\n",estable->saddr, estable->sport, estable->daddr, estable->dport);

		*(addrlen) = sizeof(struct sockaddr);
		int newsocket = createFileDescriptor(pid);
		estab_table.pop_front();
		printf("!!!!!!!!!!!!!!!!!Not blocked uuid\n");
		struct SocketInfo sock;
		sock.pid = pid;
		sock.sockfd= newsocket;
		sock.uuid = syscallUUID;
		sock.daddr = estable->daddr;
		sock.saddr = estable->saddr;
		sock.dport = estable->dport;
		sock.sport = estable->sport;
		sock.state=4;
		socket_table.push_back(sock);
		struct BindInfo bindinfo;
		bindinfo.pid = pid;
		bindinfo.sockfd = newsocket;
		bindinfo.address = (estable->daddr);
		bindinfo.port = (estable->dport);
		bindinfo.family = 2;
		bindinfo.socklen = sizeof(struct sockaddr);
		bind_table.push_back(bindinfo);
		return returnSystemCall(syscallUUID, newsocket);
		
	}
}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int sockfd, const struct sockaddr *servaddr, socklen_t addrlen)
{
	uint32_t daddr;
	uint16_t dport;
//	short family;
	uint32_t saddr;
	uint16_t sport;
	list<struct SocketInfo>::iterator it;
	list<struct BindInfo>::iterator jt;

	for(it=socket_table.begin();it!=socket_table.end();it++)
	{
		if(it->pid == pid && it->sockfd == sockfd)
			break;
	}

	if(it==socket_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}
	
	struct sockaddr_in * addr_in = (struct sockaddr_in *)servaddr;
	daddr = ntohl(addr_in->sin_addr.s_addr);
	dport = ntohs(addr_in->sin_port);
	printf("DDDDDDDDDDDDDDDDDD : %x %d\n", daddr, dport);	
	for(jt=bind_table.begin();jt!=bind_table.end();jt++)
	{
		if((jt->pid == pid && jt->sockfd == sockfd))
			break;
	}
	
	if(jt==bind_table.end())
	{
		int inter=getHost()->getRoutingTable((const uint8_t*)&daddr);
	
		if(!getHost()->getIPAddr((uint8_t*)&saddr, inter))
		{
			return returnSystemCall(syscallUUID, -1);
		}
		
		saddr=ntohl(saddr);
		sport = (uint16_t)(rand() % (0x10000-0x400) + 0x400);
	}
	else
	{
		saddr = jt->address;
		sport = jt->port;
	}

	
	printf("src : %x:%d dst: %x:%d\n",saddr,sport,daddr,dport);
	it->saddr = saddr;
	it->daddr = daddr;
	it->sport = sport;
	it->dport = dport;
	it->seq = rand();
	it->state = 3;
	it->uuid = syscallUUID;

	short family = 0x02;
	struct BindInfo bindinfo;
	bindinfo.pid = pid;
	bindinfo.sockfd = sockfd;
	bindinfo.address = saddr;
	bindinfo.port = sport;
	bindinfo.family = family;
	bindinfo.socklen = sizeof(struct sockaddr_in);
	for(jt=bind_table.begin();jt!=bind_table.end();jt++)
	{
		if(jt->pid == pid && jt->sockfd == sockfd)
		{
			printf("already BIND!!!!!!!!!!!!!!\n");
			break;
		}
	}
	if(jt==bind_table.end())
		bind_table.push_back(bindinfo);
	
	/*else
	{
		printf("JJJJJJ saddr:%x sport:%d\n",jt->address, jt->port);
		saddr = jt->address;
		sport = jt->port;
		it->saddr = saddr;
		it->sport = sport;
		
	}*/

	printf("SSSSSSSSSSSSSSSSSS:= %x %d\n",saddr,sport);
	Packet *newpacket = allocatePacket(sizeof(struct hdr));
	struct hdr* newhdr = (struct hdr*)malloc(sizeof(struct hdr));
	memset(newhdr, 0, sizeof(struct hdr));
	newhdr->iph.daddr = htonl(daddr);
	newhdr->iph.saddr = htonl(saddr);
	newhdr->tcph.source = htons(sport);
	newhdr->tcph.dest = htons(dport);
	newhdr->tcph.seq = htonl(it->seq);
	newhdr->tcph.doff = sizeof(struct tcphdr) >> 2;
	newhdr->tcph.fin = 0;
	newhdr->tcph.syn = 1;
	newhdr->tcph.rst = 0;
	newhdr->tcph.psh = 0;
	newhdr->tcph.ack = 0;
	newhdr->tcph.urg = 0;
	newhdr->tcph.window = htons(51200);
	newhdr->tcph.check = 0;
	newhdr->tcph.check = htons(~NetworkUtil::tcp_sum(newhdr->iph.saddr, newhdr->iph.daddr, (uint8_t*)(&(newhdr->tcph)), 20));
	newpacket->writeData(0, newhdr, sizeof(struct hdr));
	this->sendPacket("IPv4",newpacket);

	free(newhdr);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int sockfd, struct sockaddr *addr, socklen_t *addrlen)
{
	list<struct SocketInfo>::iterator it;

	for(it=socket_table.begin();it!=socket_table.end();it++)
	{
		if(it->pid == pid && it->sockfd == sockfd)
			break;
	}
	if(it==socket_table.end())
	{
		return returnSystemCall(syscallUUID, -1);
	}
	struct sockaddr_in* addr_in = (struct sockaddr_in *)addr;

	memset(addr_in, 0, sizeof(struct sockaddr_in));
	addr_in->sin_addr.s_addr = htonl(it->daddr);
	addr_in->sin_port = htons(it->dport);
	addr_in->sin_family = 2;
	*(addrlen) = sizeof(struct sockaddr_in);


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
		this->syscall_connect(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr*>(param.param2_ptr), (socklen_t)param.param3_int);
		break;
	case LISTEN:
		this->syscall_listen(syscallUUID, pid, param.param1_int, param.param2_int);
		break;
	case ACCEPT:
		this->syscall_accept(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr*>(param.param2_ptr), static_cast<socklen_t*>(param.param3_ptr));
		break;
	case BIND:
		this->syscall_bind(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr *>(param.param2_ptr), (socklen_t) param.param3_int);
		break;
	case GETSOCKNAME:
		this->syscall_getsockname(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr *>(param.param2_ptr),	static_cast<socklen_t*>(param.param3_ptr));
		break;
	case GETPEERNAME:
		this->syscall_getpeername(syscallUUID, pid, param.param1_int, static_cast<struct sockaddr *>(param.param2_ptr),	static_cast<socklen_t*>(param.param3_ptr));
		break;
	default:
		assert(0);
	}
}


void TCPAssignment::packetArrived(std::string fromModule, Packet* packet)
{
	struct hdr hdr;
//	void* payload==NULL;
//	int size;
	list<struct BindInfo>::iterator jt;
	list<struct SocketInfo>::iterator it;
	//precondition	

//	size = packet->getSize()-sizeof(struct hdr);
//	if(size)
//		payload = malloc(size);
	packet->readData(0, &hdr, sizeof(struct hdr));
//	packet->readData(sizeof(struct hdr), payload, size);
	//SYNPACKET ARRIVED
	if(TCP_FLAG(hdr.tcph)==0x2)
	{
		uint32_t daddr=ntohl(hdr.iph.daddr);
		uint16_t dport=ntohs(hdr.tcph.dest);
		for(jt=bind_table.begin(); jt!=bind_table.end();jt++)
		{
			if((jt->address == daddr || jt->address == INADDR_ANY) && jt->port == dport)
			{
				break;
			}
		}
		if(jt==bind_table.end())
		{
			return;
		}
		int pid = jt->pid;
		int sockfd = jt->sockfd;
		for(it = socket_table.begin();it!=socket_table.end();it++)
		{
			if(it->pid == pid && it->sockfd == sockfd)
				break;
		}
		if(it==socket_table.end())
		{
			return;
		}

		if(it->state == 1)
		{
			struct SocketInfo* waiter = (struct SocketInfo*)malloc(sizeof(struct SocketInfo));
			//state 2 : SYN_RCVD
			waiter->state = 2;
			waiter->saddr = jt->address;
			waiter->sport = jt->port;
			if(it->backlog > it->wait_table.size())
				it->wait_table.push_back(waiter);
			else
			{
				return;
			}
			Packet *newpacket = clonePacket(packet);
			struct hdr* newhdr = (struct hdr*)malloc(sizeof(struct hdr));
			newpacket->readData(0, newhdr, sizeof(struct hdr));
			packet->readData(14+12, &(newhdr->iph.daddr), 4);
			packet->readData(14+16, &(newhdr->iph.saddr), 4);
			packet->readData(14+20, &(newhdr->tcph.dest), 2);
			packet->readData(14+22, &(newhdr->tcph.source), 2);
			newpacket->writeData(14+12, &(newhdr->iph.saddr), 4);
			newpacket->writeData(14+16, &(newhdr->iph.daddr), 4);
			newpacket->writeData(14+20, &(newhdr->tcph.source), 2);
			newpacket->writeData(14+22, &(newhdr->tcph.dest), 2);
			packet->readData(14+24, &(newhdr->tcph.seq), 4);
			uint32_t ack_seq = ntohl(hdr.tcph.seq);
			ack_seq++;
			newhdr->tcph.ack_seq = htonl(ack_seq);
			newhdr->tcph.doff = sizeof(struct tcphdr) >> 2;
			newhdr->tcph.fin = 0;
			newhdr->tcph.syn = 1;
			newhdr->tcph.rst = 0;
			newhdr->tcph.psh = 0;
			newhdr->tcph.ack = 1;
			newhdr->tcph.urg = 0;
			newhdr->tcph.window = htons(51200);
			newhdr->tcph.check = 0;
			newhdr->tcph.check = htons(~NetworkUtil::tcp_sum(newhdr->iph.saddr, newhdr->iph.daddr, (uint8_t*)(&(newhdr->tcph)), 20));
			newpacket->writeData(0, newhdr, sizeof(struct hdr));
	
			waiter->seq = ntohl(newhdr->tcph.seq);
			this->sendPacket("IPv4",newpacket);
			this->freePacket(packet);
			free(newhdr);
		}
		else if(it->state == 3)
		{
			it->state = 2;
			Packet *newpacket = clonePacket(packet);
			struct hdr* newhdr = (struct hdr*)malloc(sizeof(struct hdr));
			newpacket->readData(0, newhdr, sizeof(struct hdr));
			packet->readData(14+12, &(newhdr->iph.daddr), 4);
			packet->readData(14+16, &(newhdr->iph.saddr), 4);
			packet->readData(14+20, &(newhdr->tcph.dest), 2);
			packet->readData(14+22, &(newhdr->tcph.source), 2);
			newpacket->writeData(14+12, &(newhdr->iph.saddr), 4);
			newpacket->writeData(14+16, &(newhdr->iph.daddr), 4);
			newpacket->writeData(14+20, &(newhdr->tcph.source), 2);
			newpacket->writeData(14+22, &(newhdr->tcph.dest), 2);
			packet->readData(14+24, &(newhdr->tcph.seq), 4);
			uint32_t ack_seq = ntohl(hdr.tcph.seq);
			ack_seq++;
			newhdr->tcph.ack_seq = htonl(ack_seq);
			newhdr->tcph.doff = sizeof(struct tcphdr) >> 2;
			newhdr->tcph.fin = 0;
			newhdr->tcph.syn = 0;
			newhdr->tcph.rst = 0;
			newhdr->tcph.psh = 0;
			newhdr->tcph.ack = 1;
			newhdr->tcph.urg = 0;
			newhdr->tcph.window = htons(51200);
			newhdr->tcph.check = 0;
			newhdr->tcph.check = htons(~NetworkUtil::tcp_sum(newhdr->iph.saddr, newhdr->iph.daddr, (uint8_t*)(&(newhdr->tcph)), 20));
			newpacket->writeData(0, newhdr, sizeof(struct hdr));
	
			//waiter->seq = ntohl(newhdr->tcph.seq);
			this->sendPacket("IPv4",newpacket);
			this->freePacket(packet);
			free(newhdr);
		}
	}
	//ACK packet arrived.
	else if(TCP_FLAG(hdr.tcph)==0x10)
	{
		uint32_t daddr=ntohl(hdr.iph.daddr);
		uint16_t dport=ntohs(hdr.tcph.dest);
		uint32_t saddr=ntohl(hdr.iph.saddr);
		uint16_t sport=ntohs(hdr.tcph.source);
		list<struct SocketInfo*>::iterator kt;
		for(it=socket_table.begin();it!=socket_table.end();it++)
		{
			if(it->daddr == saddr && it->saddr == daddr && it->dport == sport && it->sport == dport)
				break;
		}
		if(it==socket_table.end())
		{
		
			for(jt=bind_table.begin(); jt!=bind_table.end();jt++)
			{
				if((jt->address == daddr || jt->address == INADDR_ANY) && jt->port == dport)
				{
					break;
				}
			}
			if(jt==bind_table.end())
			{
				return;
			}
			int pid = jt->pid;
			int sockfd = jt->sockfd;
			for(it = socket_table.begin();it!=socket_table.end();it++)
			{
				if(it->pid == pid && it->sockfd == sockfd)
					break;
			}
		}
		if(it==socket_table.end())
		{
			return;
		}
		if(it->state==5)
		{
			struct hdr* newhdr = (struct hdr*)malloc(sizeof(struct hdr));
			packet->readData(0, newhdr, sizeof(struct hdr));

			if((it->seq)+1 != ntohl(newhdr->tcph.ack_seq))
			{
				printf("JASALHAJA\n");
				return;
			}
			//accept table empty, saddr daddr setting see. please.
			it->state = 6;	
		}
		else if(it->state ==9)
		{
			struct hdr* newhdr = (struct hdr*)malloc(sizeof(struct hdr));
			packet->readData(0, newhdr, sizeof(struct hdr));

			if((it->seq)+1 != ntohl(newhdr->tcph.ack_seq))
			{
				printf("Please JASAL\n");
				return;
			}
			socket_table.erase(it);

			int pid = it->pid;
			int socket_fd = it->sockfd;

			for(jt = bind_table.begin();jt!=bind_table.end();jt++)
			{
				if(jt->pid == pid && jt->sockfd == socket_fd)
					break;
			}
		
			if(jt != bind_table.end())
			{
				bind_table.erase(jt);
			}
			removeFileDescriptor (pid, socket_fd);
			return returnSystemCall(it->uuid, 0);
		}

		
		else if(it->state == 1)
		{
			struct hdr* newhdr = (struct hdr*)malloc(sizeof(struct hdr));
			packet->readData(0, newhdr, sizeof(struct hdr));
			for(kt = it->wait_table.begin();kt!=it->wait_table.end();kt++)
			{
				if(((*kt)->seq)+1 == ntohl(newhdr->tcph.ack_seq))
					break;
			}
	
			if(kt == it->wait_table.end())
			{
				return;
			}
			else
			{
				if((*kt)->state != 2)
				{
					return;
				}
				(*kt)->state=4;
				if(accept_table.empty())
				{
					(*kt)->saddr = ntohl(newhdr->iph.saddr);
					(*kt)->daddr = ntohl(newhdr->iph.daddr);
					(*kt)->sport = ntohs(newhdr->tcph.source);
					(*kt)->dport = ntohs(newhdr->tcph.dest);
					printf("saddr: %8x, daddr: %8x, sport: %d, dport: %d\n",(*kt)->saddr,(*kt)->daddr,(*kt)->sport,(*kt)->dport);
					estab_table.push_back(*kt);
					it->wait_table.erase(kt);
					printf("?????????????????blocked\n");
				}
				else
				{
					it->wait_table.erase(kt);
					struct SocketInfo* target = accept_table.front();
					int pid = target->pid;
					UUID uuid = target->uuid;
					struct sockaddr_in *addr_in=(struct sockaddr_in*)(target->cliaddr);
					memset(addr_in, 0 , sizeof(struct sockaddr_in));
					addr_in->sin_addr.s_addr = htonl(newhdr->iph.saddr);
					addr_in->sin_port = htons(newhdr->tcph.source);
					addr_in->sin_family = 0x02;
		
					*(target->addrlen) = sizeof(struct sockaddr);
					int newsocket = createFileDescriptor(pid);
					accept_table.pop_front();
					struct SocketInfo sock;
					sock.pid = pid;
					sock.sockfd= newsocket;
					sock.uuid = uuid;
					sock.state=4;
					sock.saddr=htonl(newhdr->iph.daddr);
					sock.daddr=htonl(newhdr->iph.saddr);
					sock.sport=htons(newhdr->tcph.dest);
					sock.dport=htons(newhdr->tcph.source);
					socket_table.push_back(sock);
					struct BindInfo bindinfo;
					bindinfo.pid = pid;
					bindinfo.sockfd = newsocket;
					bindinfo.address =ntohl(newhdr->iph.daddr);
					bindinfo.port = ntohs(newhdr->tcph.dest);
					bindinfo.family = 2;
					bindinfo.socklen = sizeof(struct sockaddr);
					bind_table.push_back(bindinfo);	
					printf("??????????????????Not blocked\n");
					return returnSystemCall(uuid, newsocket);
				}
			}
		}
		//cli-cli
		else
		{
			if(it==socket_table.end())
			{
				return;
			}
			if(it->state == 2)
			{
				it->state = 4;
				return returnSystemCall(it->uuid, 0);
			}
		}
		//free(newhdr);
	}
	//SYNACK PACKET ARRIVED
	else if(TCP_FLAG(hdr.tcph)==0x12)
	{
		uint32_t daddr=ntohl(hdr.iph.daddr);
		uint32_t saddr=ntohl(hdr.iph.saddr);
		uint16_t dport=ntohs(hdr.tcph.dest);
		uint16_t sport=ntohs(hdr.tcph.source);
		/**/
		for(it = socket_table.begin();it!=socket_table.end();it++)
		{
			if(it->saddr == daddr && it->daddr == saddr && it->sport == dport && it->dport == sport)
				break;
		}
		
		if(it==socket_table.end())
		{
			for(jt=bind_table.begin(); jt!=bind_table.end();jt++)
			{
				if((jt->address == daddr || jt->address == INADDR_ANY) && jt->port == dport)
				{
					break;
				}
			}
			if(jt==bind_table.end())
			{
				return;
			}
			int pid = jt->pid;
			int sockfd = jt->sockfd;
			for(it = socket_table.begin();it!=socket_table.end();it++)
				if(it->pid == pid && it->sockfd == sockfd)
					break;
			if(it==socket_table.end())
				return;
		}
		if(it->state != 3)
		{
			return;
		}
		if((it->seq)+1 != ntohl(hdr.tcph.ack_seq))
			return;
		
		Packet *newpacket = clonePacket(packet);
		struct hdr* newhdr = (struct hdr*)malloc(sizeof(struct hdr));
		newpacket->readData(0, newhdr, sizeof(struct hdr));

		printf("src : %x:%d, dst : %x:%d\n", ntohl(newhdr->iph.saddr), ntohs(newhdr->tcph.source), ntohl(newhdr->iph.daddr), ntohs(newhdr->tcph.dest));
		packet->readData(14+12, &(newhdr->iph.daddr), 4);
		packet->readData(14+16, &(newhdr->iph.saddr), 4);
		packet->readData(14+20, &(newhdr->tcph.dest), 2);
		packet->readData(14+22, &(newhdr->tcph.source), 2);
		newpacket->writeData(14+12, &(newhdr->iph.saddr), 4);
		newpacket->writeData(14+16, &(newhdr->iph.daddr), 4);
		newpacket->writeData(14+20, &(newhdr->tcph.source), 2);
		newpacket->writeData(14+22, &(newhdr->tcph.dest), 2);
		packet->readData(14+24, &(newhdr->tcph.seq), 4);
		uint32_t ack_seq = ntohl(hdr.tcph.seq);
		ack_seq++;
		newhdr->tcph.ack_seq = htonl(ack_seq);
		newhdr->tcph.doff = sizeof(struct tcphdr) >> 2;
		newhdr->tcph.fin = 0;
		newhdr->tcph.syn = 0;
		newhdr->tcph.rst = 0;
		newhdr->tcph.psh = 0;
		newhdr->tcph.ack = 1;
		newhdr->tcph.urg = 0;
		newhdr->tcph.window = htons(51200);
		newhdr->tcph.check = 0;
		newhdr->tcph.check = htons(~NetworkUtil::tcp_sum(newhdr->iph.saddr, newhdr->iph.daddr, (uint8_t*)(&(newhdr->tcph)), 20));
		newpacket->writeData(0, newhdr, sizeof(struct hdr));	
		this->sendPacket("IPv4",newpacket);
		this->freePacket(packet);
		free(newhdr);
		it->state = 4;
		it->saddr = daddr;
		it->sport = dport;
		it->daddr = saddr;
		it->dport = sport;
		return returnSystemCall(it->uuid, 0);
	}
	//FIN ARRIVED
	else if(TCP_FLAG(hdr.tcph)==0x01)
	{
		uint32_t saddr=ntohl(hdr.iph.saddr);
		uint32_t daddr=ntohl(hdr.iph.daddr);
		uint16_t sport=ntohs(hdr.tcph.source);
		uint16_t dport=ntohs(hdr.tcph.dest);
		/*for(jt=bind_table.begin(); jt!=bind_table.end();jt++)
		{
			if((jt->address == daddr || jt->address == INADDR_ANY) && jt->port == dport)
			{
				break;
			}
		}
		if(jt==bind_table.end())
		{
			printf("LLLLLLLLLLLLLLLLLLLLLLLLL\n");
			return;
		}
		int pid = jt->pid;
		int sockfd = jt->sockfd;
		for(it = socket_table.begin();it!=socket_table.end();it++)
		{
			if(it->pid == pid && it->sockfd == sockfd)
				break;
		}
		if(it==socket_table.end())
		{
			printf("LILILILI EE\n");
			return;
		}
		while(it->state == 1|| it->state == 5)
		{
			printf("pid : %d sockfd : %d\n", it->pid, it->sockfd);
			jt++;
			for(;jt!=bind_table.end();jt++)
			{
				if((jt->address == daddr || jt->address == INADDR_ANY) && jt->port == dport)
					{
						break;
					}
			}
			if(jt==bind_table.end())
			{
				return;
			}
			pid = jt->pid;
			sockfd = jt->sockfd;
			printf("newpid : %d newsockfd: %d\n", pid, sockfd);
			for(it=socket_table.begin();it!=socket_table.end();it++)
			{
				if(it->pid == pid && it->sockfd == sockfd)
					break;
			}
			if(it==socket_table.end())
			{
				printf("JOJUTNE\n");
				return;
			}
			printf("even if???? it->state : %d\n", it->state);
		}
		printf("it->state : %d\n",it->state);*/
		for(it=socket_table.begin();it!=socket_table.end();it++)
		{
			if(it->saddr == daddr && it->sport == dport && it->daddr == saddr && it->dport == sport)
				break;
		}
		if(it==socket_table.end())
		{
			//printf("SIBALSIBALSIBAL\n");
			return;
		}
		while(it->state ==5)
		{
			it++;
			for(;it!=socket_table.end();it++)
			{
				if(it->saddr == daddr && it->sport == dport && it->daddr == saddr && it->dport == sport)
					break;
			}
			if(it==socket_table.end())
			{
				//printf("SIBAL!SIBAL!SIBAL!\n");
				return;
			}
		}
		if(it->state == 4)
		{
			it->state = 8;
			Packet *newpacket = clonePacket(packet);
			struct hdr* newhdr = (struct hdr*)malloc(sizeof(struct hdr));
			newpacket->readData(0, newhdr, sizeof(struct hdr));
			packet->readData(14+12, &(newhdr->iph.daddr), 4);
			packet->readData(14+16, &(newhdr->iph.saddr), 4);
			packet->readData(14+20, &(newhdr->tcph.dest), 2);
			packet->readData(14+22, &(newhdr->tcph.source), 2);
			newpacket->writeData(14+12, &(newhdr->iph.saddr), 4);
			newpacket->writeData(14+16, &(newhdr->iph.daddr), 4);
			newpacket->writeData(14+20, &(newhdr->tcph.source), 2);
			newpacket->writeData(14+22, &(newhdr->tcph.dest), 2);
			packet->readData(14+24, &(newhdr->tcph.seq), 4);
			uint32_t ack_seq = ntohl(hdr.tcph.seq);
			ack_seq++;
			newhdr->tcph.ack_seq = htonl(ack_seq);
			newhdr->tcph.doff = sizeof(struct tcphdr) >> 2;
			newhdr->tcph.fin = 0;
			newhdr->tcph.syn = 0;
			newhdr->tcph.rst = 0;
			newhdr->tcph.psh = 0;
			newhdr->tcph.ack = 1;
			newhdr->tcph.urg = 0;
			newhdr->tcph.window = htons(51200);
			newhdr->tcph.check = 0;
			newhdr->tcph.check = htons(~NetworkUtil::tcp_sum(newhdr->iph.saddr, newhdr->iph.daddr, (uint8_t*)(&(newhdr->tcph)), 20));
			newpacket->writeData(0, newhdr, sizeof(struct hdr));	
			this->sendPacket("IPv4",newpacket);
			this->freePacket(packet);
			free(newhdr);
		}
		else if(it->state == 6)
		{
			it->state = 7;
			Packet *newpacket = clonePacket(packet);
			struct hdr* newhdr = (struct hdr*)malloc(sizeof(struct hdr));
			newpacket->readData(0, newhdr, sizeof(struct hdr));
			packet->readData(14+12, &(newhdr->iph.daddr), 4);
			packet->readData(14+16, &(newhdr->iph.saddr), 4);
			packet->readData(14+20, &(newhdr->tcph.dest), 2);
			packet->readData(14+22, &(newhdr->tcph.source), 2);
			newpacket->writeData(14+12, &(newhdr->iph.saddr), 4);
			newpacket->writeData(14+16, &(newhdr->iph.daddr), 4);
			newpacket->writeData(14+20, &(newhdr->tcph.source), 2);
			newpacket->writeData(14+22, &(newhdr->tcph.dest), 2);
			packet->readData(14+24, &(newhdr->tcph.seq), 4);
			uint32_t ack_seq = ntohl(hdr.tcph.seq);
			ack_seq++;
			newhdr->tcph.ack_seq = htonl(ack_seq);
			newhdr->tcph.doff = sizeof(struct tcphdr) >> 2;
			newhdr->tcph.fin = 0;
			newhdr->tcph.syn = 0;
			newhdr->tcph.rst = 0;
			newhdr->tcph.psh = 0;
			newhdr->tcph.ack = 1;
			newhdr->tcph.urg = 0;
			newhdr->tcph.window = htons(51200);
			newhdr->tcph.check = 0;
			newhdr->tcph.check = htons(~NetworkUtil::tcp_sum(newhdr->iph.saddr, newhdr->iph.daddr, (uint8_t*)(&(newhdr->tcph)), 20));
			newpacket->writeData(0, newhdr, sizeof(struct hdr));	
			this->sendPacket("IPv4",newpacket);
			this->freePacket(packet);
			free(newhdr);
			socket_table.erase(it);
			
			int pid = it->pid;
			int socket_fd = it->sockfd;

			for(jt = bind_table.begin();jt!=bind_table.end();jt++)
			{
				if(jt->pid == pid && jt->sockfd == socket_fd)
					break;
			}
		
			if(jt != bind_table.end())
			{
				bind_table.erase(jt);
			}
			removeFileDescriptor (pid, socket_fd);
			return returnSystemCall(it->uuid, 0);
		}
	
	}
	
}

void TCPAssignment::timerCallback(void* payload)
{

}

}
