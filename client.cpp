#include <iostream>
#include <cstring>
#include <string>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#define PORT 8080
#define BUFFER_SIZE 1024

using namespace std;

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        cerr << "\n Socket creation error \n";
        return -1;
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &serv_addr.sin_addr) <= 0) {
        cerr << "\nInvalid address / Address not supported \n";
        return -1;
    }

    if (connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0) {
        cerr << "\nConnection Failed \n";
        return -1;
    }

    string inp;

    while (true)
    {
        cout << "Client: ";
        getline(cin, inp);

        send(sock, inp.data(), inp.size(), 0);

        if (inp == "quit")
        {
            cout << "Disconnecting..." << endl;
            break;
        }

        memset(buffer, 0, BUFFER_SIZE);
    
        int valread = read(sock, buffer, BUFFER_SIZE - 1);
        
        if (valread <= 0) {
            cout << "\nServer dropped the connection." << endl;
            break;
        }
        
        buffer[valread] = '\0';
        cout << "Server: " << buffer << endl;
    }

    close(sock);
    return 0;
}