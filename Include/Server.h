#pragma once
#include <netdb.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <sstream>

#include "dns_protocol.h"

struct DNS_REQ {
  DNS_HEADER m_header;
  std::string m_Url;
  QUESTION m_Question;
};
class Server {
 public:
  explicit Server(const std::string &port, size_t buffSize = 4096)
      : m_SockFd{-1}, m_BuffSize{buffSize} {
    m_Hints.ai_family = AF_INET;
    m_Hints.ai_socktype = SOCK_DGRAM;
    m_Hints.ai_flags = AI_PASSIVE;

    if (getaddrinfo(nullptr, port.c_str(), &m_Hints, &m_AddrInfo) != 0) {
      throw std::runtime_error{"getaddrinfo: cannot fill info from hints"};
    }

    for (struct addrinfo *p = m_AddrInfo; p != nullptr; p = p->ai_next) {
      if ((m_SockFd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) ==
          -1) {
        continue;
      }

      if (bind(m_SockFd, p->ai_addr, p->ai_addrlen) == -1) {
        close(m_SockFd);
        std::cerr << errno << std::endl;
        throw std::runtime_error{"bind: cannot bind socket"};
      }

      break;
    }
    freeaddrinfo(m_AddrInfo);
  }

  DNS_REQ ParseDNS(char **message) const {
    auto *head = (DNS_HEADER *) *message;
    head->qr = 1;
    head->ans_count = htons(1);
    head->rcode = 0;
    DNS_REQ req_header{};


    int iter = sizeof(DNS_HEADER);
    memcpy(&req_header.m_header, *message, iter);
    req_header.m_header.id = ntohs(req_header.m_header.id);
    req_header.m_header.q_count = htons(req_header.m_header.q_count);
    req_header.m_header.ans_count = htons(req_header.m_header.ans_count);
    req_header.m_header.auth_count = htons(req_header.m_header.auth_count);
    req_header.m_header.add_count = htons(req_header.m_header.add_count);

    std::stringstream ss;
    while ((*message)[iter] != 0x0) {
      char size = (*message)[iter];
      ss.write((*message) + iter + 1, size);
      iter += size + 1;
      if ((*message)[iter] != 0x0) {
        ss << ".";
      }
    }

    req_header.m_Url = ss.str();
    memcpy(&req_header.m_Question, *message + iter + 1,
           sizeof(req_header.m_Question));

    req_header.m_Question.qtype = ntohs(req_header.m_Question.qtype);
    req_header.m_Question.qclass = ntohs(req_header.m_Question.qclass);


    return req_header;
  }

  int Send( char *buf, int buffSize, sockaddr_storage *clt) {


    auto parsed = ParseDNS(&buf);

    unsigned char ip[4];
    ip[0] = 0;
    ip[1] = 0;
    ip[2] = 0;
    ip[3] = 0;
    for(const char &i : parsed.m_Url) {
      if(i != '.') {
        ip[3]++;
      }
    }

    unsigned short offset = htons(0xC00C);

    R_DATA rData{};
    rData.data_len = htons(4);
    rData.ttl = htonl(1000);
    rData._class = htons(1);
    rData.type = htons(1);
    std::stringstream answerStream;

    answerStream.write(buf, buffSize);
    answerStream.write((char *) &offset, sizeof(offset));
    answerStream.write((char *)&rData, sizeof(rData));
    answerStream.write((char *)ip, sizeof(unsigned  char ) * 4);

    ssize_t sent = sendto(m_SockFd, answerStream.str().c_str(), answerStream.str().size(), 0, (sockaddr*)clt, sizeof(*clt));


    if(sent < 0) {
      std::cerr << errno << std::endl;
      throw std::runtime_error {"sendto: cannot send"};
    }
    return 0;
  }

  [[nodiscard]] ssize_t Receive(sockaddr_storage **newClt, char **buffer) const {

    *newClt = new sockaddr_storage;
    sockaddr_storage newAddr{};
    unsigned int sinSize = sizeof(newAddr);

    *buffer = new char[m_BuffSize];
    memset(*buffer, '\0', m_BuffSize);

    ssize_t recvBytes = recvfrom(m_SockFd, *buffer, m_BuffSize, 0,
                                 (sockaddr *)&newAddr, &sinSize);

    if (recvBytes < 0) {
      throw std::runtime_error{"recvfrom: cannot receive\n"};
    }

    memcpy(*newClt, &newAddr, sizeof(newAddr));
    return recvBytes;
  }

 private:
  int m_SockFd;
  const std::size_t m_BuffSize;
  addrinfo m_Hints{};
  addrinfo *m_AddrInfo{};
};