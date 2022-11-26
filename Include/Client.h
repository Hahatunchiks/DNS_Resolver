#pragma once
#include <netdb.h>
#include <unistd.h>
#include <cinttypes>
#include <cstring>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <vector>
#include "dns_protocol.h"

class Client {
 public:
  explicit Client(const std::string &port, const std::string &host,
                  std::size_t buffSize = 4096)
      : m_SockFd{-1}, m_BuffSize{buffSize} {
    m_Hints.ai_family = AF_INET;
    m_Hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(host.c_str(), port.c_str(), &m_Hints, &m_AddrInfo) != 0) {
      perror("getaddrinfo:");
      throw std::runtime_error{"getaddrinfo: cannot fill info from hints"};
    }

    addrinfo *p;
    for (p = m_AddrInfo; p != nullptr; p = p->ai_next) {
      if ((m_SockFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) ==
          -1) {
        continue;
      }
      break;
    }

    timeval timeout;
    timeout.tv_sec = 10;
    timeout.tv_usec = 0;
    setsockopt(m_SockFd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    m_Host = p;
    freeaddrinfo(m_AddrInfo);
  }

  int Send(const std::string &message) {
    DNS_HEADER request_header{};

    request_header.id = htons(228);
    request_header.tc = 0;
    request_header.qr = 0;      // it;s request
    request_header.opcode = 0;  // standard query
    request_header.rd = 1;

    request_header.q_count = htons(1);
    request_header.auth_count = htons(0);
    request_header.add_count = htons(0);
    request_header.ans_count = htons(0);

    QUESTION request_query{};
    request_query.qtype = htons(1);
    request_query.qclass = htons(1);

    std::vector<std::pair<unsigned short, std::string>> octets;
    std::string octet{};
    for (const auto &i : message) {
      if (i == '.') {
        octets.emplace_back(octet.size(), octet);
        octet.clear();
      } else {
        octet += i;
      }
    }
    if(!octet.empty()) {
      octets.emplace_back(octet.size(), octet);
    }

    std::stringstream ss;
    ss.write((char *)&request_header, sizeof(request_header));
    for (const auto &i : octets) {
      ss.write((char *)&i.first, sizeof(char));
      ss.write(i.second.c_str(), i.second.size());
    }
    if(!octet.empty()) {
      char ending = 0x0;
      ss.write((char *)&ending, sizeof(char));
    }
    ss.write((char *)&request_query, sizeof(request_query));

    ssize_t sent = sendto(m_SockFd, ss.str().c_str(), ss.str().size(), 0,
                          m_Host->ai_addr, m_Host->ai_addrlen);

    if (sent < 0) {
      std::cerr << errno << std::endl;
      throw std::runtime_error{"sendto: cannot send to host"};
    }

    return 0;
  }

  std::string Receive() const {
    sockaddr_storage newAddr{};
    unsigned int sinSize = sizeof(newAddr);

    std::string buffer(m_BuffSize, '\0');
    ssize_t recvBytes = recvfrom(m_SockFd, (char *)buffer.c_str(), m_BuffSize,
                                 0, (sockaddr *)&newAddr, &sinSize);

    if (recvBytes < 0) {
      throw std::runtime_error{"client recvfrom: cannot receive\n"};
    }

    DNS_HEADER resp{};
    memcpy(&resp, buffer.c_str(), sizeof(DNS_HEADER));
    resp.id = ntohs(resp.id);
    resp.q_count = htons(resp.q_count);
    resp.ans_count = htons(resp.ans_count);
    resp.auth_count = htons(resp.auth_count);
    resp.add_count = htons(resp.add_count);
    if(resp.ans_count == 0) {
      return "";
    }
    int it = sizeof(DNS_HEADER);

    std::stringstream ss;
    while (buffer[it] != 0x0) {
      char size = buffer[it];
      ss.write(buffer.c_str() + it + 1, size);
      it += size + 1;
      if (buffer[it] != 0x0) {
        ss << ".";
      }
    }


    ss.clear();
    ss.flush();

    it += sizeof(unsigned short) * 3 + 1;

    R_DATA rData{};
    memcpy(&rData, buffer.c_str() + it, sizeof(rData));
    rData.ttl = ntohl(rData.ttl);
    rData.data_len = ntohs(rData.data_len);
    rData._class = ntohs(rData._class);
    rData.type = ntohs(rData.type);

    it += sizeof(rData);

    std::string ip;

    for (int i = 0; i < rData.data_len; i++) {
      std::uint8_t x = buffer[it + i];
      ip += std::to_string(+x);
      if (i < rData.data_len - 1) {
        ip += ".";
      }
    }

    return ip;
  }

  ~Client() { close(m_SockFd); }

 private:
  int m_SockFd;
  const std::size_t m_BuffSize;
  addrinfo m_Hints{};
  addrinfo *m_AddrInfo{};
  addrinfo *m_Host;
};