#include "Include/Server.h"

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  if (argc > 2) {
    std::cerr << "Expected 1 or 2 arguments";
    return -1;
  }
  std::string port = argc == 1 ? "53" : argv[1];
  Server server{port};
  while (true) {
    sockaddr_storage *clt = nullptr;
    char *buffer = nullptr;
    auto received = server.Receive(&clt, &buffer);
    server.Send(buffer, received, clt);
  }

  return 0;
}
