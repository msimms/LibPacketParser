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

#include <iostream>
#include <pcap.h>
#include "PacketParser.h"

int main(int argc, const char * argv[])
{
	if (argc < 2)
	{
		std::cerr << "A pcap file was not provided." << std::endl;
		return -1;
	}

	char errbuff[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr* header;
	pcap_t* reader = pcap_open_offline(argv[1], errbuff);
	const u_char* packet;

	while (pcap_next_ex(reader, &header, &packet) >= 0)
	{
		PacketParser::HeaderList headers;
		PacketParser::Parse(packet, header->len, headers);
		
		std::cout << "Next Packet:" << std::endl;
		std::cout << "------------" << std::endl;
		
		auto iter = headers.begin();
		while (iter != headers.end())
		{
			const PacketParser::HeaderRef& headerRef = (*iter);
			const char* headerStr = NULL;

			switch (headerRef.first)
			{
				case PacketParser::HEADER_ETHER:
					headerStr = "Ethernet";
					break;
				case PacketParser::HEADER_IPV4:
					headerStr = "IPv4";
					break;
				case PacketParser::HEADER_IPV6:
					headerStr = "IPv6";
					break;
				case PacketParser::HEADER_TCP:
					headerStr = "TCP";
					break;
				case PacketParser::HEADER_UDP:
					headerStr = "UDP";
					break;
				case PacketParser::HEADER_ARP:
					headerStr = "ARP";
					break;
				case PacketParser::HEADER_ICMPV4:
					headerStr = "ICMPv4";
					break;
				case PacketParser::HEADER_ICMPV6:
					headerStr = "ICMPv6";
					break;
				case PacketParser::HEADER_DNS:
					headerStr = "DNS";
					break;
				case PacketParser::HEADER_HTTP:
					headerStr = "HTTP";
					break;
				case PacketParser::HEADER_HTTPS:
					headerStr = "HTTPS";
					break;
				default:
					headerStr = "Unknown";
					break;
			}
			std::cout << "Found " << headerStr << " header at 0x" << std::hex << (size_t)headerRef.second << "." << std::endl;

			++iter;
		}
		
		std::cout << std::endl;
	}

	return 0;
}
