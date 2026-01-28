#include "../include/server.hpp"
#include "../include/client.hpp"

int main() {

    std::string mode = "client"; // Default mode
    if (mode == "server") {
        Server s;
        s.run();
    } else if (mode == "client") {
        Client c;
        c.run();
    } else {
        std::cerr << "Invalid mode" << std::endl;
    }

    return 0;
}
