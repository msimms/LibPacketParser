//	MIT License
//
//  Copyright (c) 2018 Michael J Simms. All rights reserved.
//
//	Permission is hereby granted, free of charge, to any person obtaining a copy
//	of this software and associated documentation files (the "Software"), to deal
//	in the Software without restriction, including without limitation the rights
//	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
//	copies of the Software, and to permit persons to whom the Software is
//	furnished to do so, subject to the following conditions:
//
//	The above copyright notice and this permission notice shall be included in all
//	copies or substantial portions of the Software.
//
//	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
//	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//	SOFTWARE.

#include "PacketAnalyzer.h"

namespace PacketParser
{
	void ParseArpPacket(const uint8_t* data, size_t dataLen, HeaderList& headers)
	{
		headers.push_back(std::make_pair(HEADER_ARP, data));
	}

	void ParseIcmpV4Packet(const uint8_t* data, size_t dataLen, HeaderList& headers)
	{
		const IcmpV4Header* icmpHdr = (const IcmpV4Header*)(data);

		if (dataLen < sizeof(IcmpV4Header))
		{
			return;
		}

		headers.push_back(std::make_pair(HEADER_ICMPV4, data));
	}

	void ParseTcpPacket(const uint8_t* data, size_t dataLen, HeaderList& headers)
	{
		const TcpHeader* tcpHdr = (const TcpHeader*)(data);

		if (dataLen < sizeof(TcpHeader))
		{
			return;
		}

		headers.push_back(std::make_pair(HEADER_TCP, data));
	}

	void ParseUdpPacket(const uint8_t* data, size_t dataLen, HeaderList& headers)
	{
		const UdpHeader* udpHdr = (const UdpHeader*)(data);

		if (dataLen < sizeof(UdpHeader))
		{
			return;
		}

		headers.push_back(std::make_pair(HEADER_UDP, data));
	}

	void ParseIpV4Packet(const uint8_t* data, size_t dataLen, HeaderList& headers)
	{
		const IpHeaderV4* ipHdr = (const IpHeaderV4*)(data);

		uint8_t hdrVersion = IPV4_VERSION(ipHdr);
		uint8_t headerLen = IPV4_HDR_LEN(ipHdr);
		uint16_t totalLen = ntohs(ipHdr->totalLength);

		if (hdrVersion != 4)
		{
			return;
		}

		if (totalLen <= headerLen)
		{
			return;
		}

		headers.push_back(std::make_pair(HEADER_IPV4, data));

		const uint8_t* nextHdr = data + headerLen;
		size_t nextHdrLen = dataLen - headerLen;

		IpType ipType = (IpType)ipHdr->protocol;
		switch (ipType)
		{
		case IP_UNKNOWN:
			break;
		case IP_ICMP:
			ParseIcmpV4Packet(nextHdr, nextHdrLen, headers);
			break;
		case IP_TCP:
			ParseTcpPacket(nextHdr, nextHdrLen, headers);
			break;
		case IP_UDP:
			ParseUdpPacket(nextHdr, nextHdrLen, headers);
			break;
		default:
			break;
		}
	}

	void ParseIpV6Packet(const uint8_t* data, size_t dataLen, HeaderList& headers)
	{
		const IpHeaderV6* ipHdr = (const IpHeaderV6*)(data);

		if (dataLen < sizeof(IpHeaderV6))
		{
			return;
		}

		headers.push_back(std::make_pair(HEADER_IPV6, data));

		const uint8_t* nextHdr = data + sizeof(IpHeaderV6);
		size_t nextHdrLen = dataLen - sizeof(IpHeaderV6);

		IpType ipType = (IpType)ipHdr->nextHeader;
		switch (ipType)
		{
		case IP_UNKNOWN:
			break;
		case IP_ICMP:
			break;
		case IP_TCP:
			ParseTcpPacket(nextHdr, nextHdrLen, headers);
			break;
		case IP_UDP:
			ParseUdpPacket(nextHdr, nextHdrLen, headers);
			break;
		default:
			break;
		}
	}

	void ParseEtherPacket(const uint8_t* data, size_t dataLen, HeaderList& headers)
	{
		if (dataLen < sizeof(EthernetHeader))
		{
			return;
		}

		headers.push_back(std::make_pair(HEADER_ETHER, data));

		const EthernetHeader* etherHdr = (const EthernetHeader*)(data);
		const uint8_t* nextHdr = data + sizeof(EthernetHeader);
		size_t nextHdrLen = dataLen - sizeof(EthernetHeader);

		EtherType etherType = (EtherType)ntohs(etherHdr->etherType);
		switch (etherType)
		{
		case ETHER_TYPE_IP4:
			ParseIpV4Packet(nextHdr, nextHdrLen, headers);
			break;
		case ETHER_TYPE_ARP:
			ParseArpPacket(nextHdr, nextHdrLen, headers);
			break;
		case ETHER_TYPE_IP6:
			ParseIpV6Packet(nextHdr, nextHdrLen, headers);
			break;
		default:
			break;
		}
	}

	void ParsePacket(const uint8_t* data, size_t dataLen, HeaderList& headers)
	{
		ParseEtherPacket(data, dataLen, headers);
	}
}
