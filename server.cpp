#include <iostream>
#include <cstring>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024
   
using namespace std;

int main()
{
    int server_fd, new_socket;
    struct sockaddr_in address;
    int opt = 1;
    int addrlen = sizeof(address);
    char buffer[BUFFER_SIZE] = {0};

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) <= 0) {
        perror("Socket failed");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        perror("setsockopt");
        exit(EXIT_FAILURE);
    }

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 3) < 0) {
        perror("Listen");
        exit(EXIT_FAILURE);
    }
    
    cout << "Server is listening on port " << PORT << "...\n";

    while (true)
    {
        if ((new_socket = accept(server_fd, (struct sockaddr*)&address, (socklen_t*)&addrlen)) < 0) {
            perror("Accept");
            continue;
        }

        cout << "New client connected!" << endl;

        while (true)
        {
            memset(buffer, 0, BUFFER_SIZE); 

            int valread = read(new_socket, buffer, BUFFER_SIZE - 1); // -1 leaves room for \0
            
            if (valread == 0) {
                cout << "Client disconnected gracefully." << endl;
                break;
            } else if (valread < 0) {
                perror("Read error");
                break; 
            }

            buffer[valread] = '\0'; 
            
            cout << "Client: " << buffer << endl;
            string clnt(buffer);
            string snd = "Hello client";

            if (clnt == "1")
                snd = "One";
            else if (clnt == "2")
                snd = "Two";
            else if (clnt == "3")
                snd = "Three";
            else if (clnt == "quit") {
                cout << "Client requested to quit." << endl;
                break;
            }

            send(new_socket, snd.data(), snd.size(), 0);
            cout << "Server: " << snd << endl;
        }
        close(new_socket);
    }

    close(server_fd);
    return 0;
}