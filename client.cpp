#include "Include/Client.h"

int main(int argc, char *argv[]) {
  (void)argc;
  (void)argv;

  if (argc > 4 || argc < 2) {
    std::cerr << "Expected from 2 to 4  arguments" << std::endl;
    return -1;
  }

  std::string port = (argc == 3 || argc == 2) ? "53" : argv[3];
  std::string host = argc == 2 ? "127.0.0.1" : argv[2];
  try {
    Client client{port, host};
    std::string url{argv[1]};
    client.Send(url);
    std::string ip = client.Receive();
    std::cout << ip << std::endl;
  } catch (std::runtime_error &e) {
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      return -2;
    }
    return -1;
  }
  return 0;
}
