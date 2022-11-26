#include "Include/Client.h"


int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  if(argc > 4 || argc < 2) {
    std::cerr << "Expected from 2 to 4  arguments" << std::endl;
    return -1;
  }

  std::string port = argc == 3 ? "53" : argv[3];
  std::string host = argc == 2 ? "localhost" : argv[2];
  Client client{port, host};
  std::string url{argv[1]};
  client.Send(url);
  std::string ip = client.Receive();
  std::cerr << ip << std::endl;
  return 0;
}