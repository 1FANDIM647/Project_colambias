// DVS.cpp : Этот файл содержит функцию "main". Здесь начинается и заканчивается выполнение программы.
//


#undef   UNICODE
#define  WIN32_LEAN_AND_MEAN
#define  DEFAULT_PORT   "8080"// Номер порта 
#define  DEFAULT_BUFLEN  1024 // Размер буфера  
#define  MAX_SIZ_ZAP     1024 // Максиальный размер запроса 
#define  MAX_SIZ_OTV     1024 // Максиальный размер Ответа  
#define  MAX_KOL_POT     1024 // Максимальнео количество потоков  
#include <windows.h>
#include <iostream>
#include <winsock2.h>
#include <ws2tcpip.h> 
#include <iostream> 
#pragma comment (lib, "Ws2_32.lib")
//#pragma comment (lib, "Mswsock.lib")
using namespace std;
struct TPot {
    bool   SVO; // Свободен ли поток 
    SOCKET SOC; // сокет     
    char   ZAP[MAX_SIZ_ZAP]; // ЗАПРОС  
    char   OTV[MAX_SIZ_OTV]; // ОТВЕТ 
};

TPot POTS[MAX_KOL_POT];// Масив с потоками 


DWORD  WINAPI  ObrZap(LPVOID lpParam)
{  //-----------------------------------------------------------------------


 // Чтение данных в большой масив из сокета  
 // Ожидание ответа 
 // Вывод ответа в сокет 

    char* Zap = new char[DEFAULT_BUFLEN];// Буфер запроса 
    int ZapSi;// Количество поступивших данных из интернета 
    int OtpSi;// Колчиество отправленых байт клиенту 
    SOCKET ClientSocket = (SOCKET)lpParam;
    ZapSi = recv(
        ClientSocket,
        Zap,
        DEFAULT_BUFLEN,// Максимальное количество данных  
        0);// Читаем данные 

    char Otv[] =
        "HTTP/1.1 200 OK\r\n"
        "Content-Language: ru\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: 6\r\nConnection: close\r\n\r\n"
        "Privet"
        "\r\n\r\n\0";

    OtpSi = send(ClientSocket, Otv, sizeof(Otv), 0);   // Отдаем данные 
    closesocket(ClientSocket);
    return 0;
}  //---------------------------------------


int main()
{
    WSADATA wsaData;
    int iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    SOCKET ListenSocket = INVALID_SOCKET;
    SOCKET ClientSocket = INVALID_SOCKET;

    struct addrinfo* result = NULL;
    struct addrinfo hints;

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    // Resolve the server address and port
    iResult =
        getaddrinfo(NULL, DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed with error: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    // Create a SOCKET for connecting to server
    ListenSocket =
        socket(
            result->ai_family,
            result->ai_socktype,
            result->ai_protocol
        );
    if (ListenSocket == INVALID_SOCKET) {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }


    // Setup the TCP listening socket
    iResult = bind(
        ListenSocket,
        result->ai_addr,
        (int)result->ai_addrlen);

    if (iResult == SOCKET_ERROR) {
        printf("bind failed with error: %d\n", WSAGetLastError());
        freeaddrinfo(result);
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    freeaddrinfo(result);

    iResult = listen(ListenSocket, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed with error: %d\n", WSAGetLastError());
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }


    do {
        // Accept a client socket
        ClientSocket = accept(ListenSocket, NULL, NULL);



        if (ClientSocket == INVALID_SOCKET)  closesocket(ClientSocket);
        else {

            CreateThread(
                NULL,         // атрибуты безопасности по умолчанию
                0,            // размер стека используется по умолчанию
                ObrZap,       // функция потока
                (LPVOID)ClientSocket,         // аргумент функции потока
                0,            // флажки создания используются по умолчанию
                NULL);        // возвращает идентификатор потока



        }

    } while (true);


    closesocket(ClientSocket);
    WSACleanup();

}

// Запуск программы: CTRL+F5 или меню "Отладка" > "Запуск без отладки"
// Отладка программы: F5 или меню "Отладка" > "Запустить отладку"

// Советы по началу работы 
//   1. В окне обозревателя решений можно добавлять файлы и управлять ими.
//   2. В окне Team Explorer можно подключиться к системе управления версиями.
//   3. В окне "Выходные данные" можно просматривать выходные данные сборки и другие сообщения.
//   4. В окне "Список ошибок" можно просматривать ошибки.
//   5. Последовательно выберите пункты меню "Проект" > "Добавить новый элемент", чтобы создать файлы кода, или "Проект" > "Добавить существующий элемент", чтобы добавить в проект существующие файлы кода.
//   6. Чтобы снова открыть этот проект позже, выберите пункты меню "Файл" > "Открыть" > "Проект" и выберите SLN-файл.
