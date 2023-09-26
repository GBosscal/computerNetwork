#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <map>
#include <vector>
#include <ctime>
#include <sys/stat.h>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <sys/select.h>

#include "httpd.h"

using namespace std;

struct ThreadArgs {
    int clientSocket;
    std::string doc_root;
};

std::map<std::string, std::string> contentTypes = {
    {".html", "text/html"},
    {".htm", "text/html"},
    {".txt", "text/plain"},
    {".css", "text/css"},
    {".js", "application/javascript"},
    {".jpg", "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".png", "image/png"},
};

std::map<int, std::string> code2msg = {
    {200, "OK"},
    {400, ""},
    {403, ""},
    {404, "Not Found"},
};

std::string getDefaultFilePath(const std::string& path) {
    // 如果路径以'/'结尾，则追加index.html"
    if (path.back() == '/') {
        return path + "index.html";
    }
    return path;
}

std::string readFile(const std::string& filename) {
    std::ifstream file(filename);
    std::string content;

    if (file.is_open()) {
        std::ostringstream contentStream;
        contentStream << file.rdbuf();
        content = contentStream.str();
        file.close();
    }

    return content;
}

class HTTPMessage {
public:

    // request相关
    std::string msg;
    std::string method;
    std::string path;
    std::string protocol;
    std::string headers;
    std::string body;
    std::vector<std::pair<std::string, std::string>> request_headers;
    

    // response相关
    int response_code=0;
    std::string response_msg;
    int content_length;
    std::string content_type;
    std::vector<std::pair<std::string, std::string>> response_headers;
    std::string response_time;

    // 校验状态相关
    bool is_close=false;

    HTTPMessage() {}

    void parseRequest(const std::string& request) {
        size_t pos = request.find("\r\n\r\n");
        // 分离请求信息和请求体
        if (pos != std::string::npos) {
            msg = request.substr(0, pos);
            body = request.substr(pos + 4);
        }
        // 获取请求方式，请求路经，请求协议
        size_t requestLineEnd = request.find("\r\n");
        if (requestLineEnd != std::string::npos) {
            std::string requestLine = request.substr(0, requestLineEnd);
            size_t methodEnd = requestLine.find(' ');
            if (methodEnd != std::string::npos) {
                method = requestLine.substr(0, methodEnd);
                size_t pathEnd = requestLine.find(' ', methodEnd + 1);
                if (pathEnd != std::string::npos) {
                    path = requestLine.substr(methodEnd + 1, pathEnd - methodEnd - 1);
                    protocol = requestLine.substr(pathEnd + 1);
                }
            }
        }
        // 获取请求头信息
        if (requestLineEnd != std::string::npos && pos != std::string::npos){
            headers = request.substr(requestLineEnd + 2, pos); // +2 是因为把请求方式那行的\r\n都去掉
        }
    }

    string parseResponse(int clientSocket) {
        // 获取当前服务的IP
        struct sockaddr_in serverAddr;
        socklen_t serverAddrLen = sizeof(serverAddr);
        getsockname(clientSocket, (struct sockaddr*)&serverAddr, &serverAddrLen);
        char serverIp[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(serverAddr.sin_addr), serverIp, INET_ADDRSTRLEN);
        // 如果是响应代码是400，404，403，500，则需要将固定的html页返回。
        switch (response_code){
            case 400:
                content_type = "text/html";
                body = readFile("error_400.html");
                break;
            case 403:
                content_type = "text/html";
                body = readFile("error_403.html");
                break;
            case 404:
                content_type = "text/html";
                body = readFile("error_404.html");
                break;
            case 500:
                content_type = "text/html";
                body = readFile("error_500.html");
                break;
            default:
                break;
        }
        // 根据msg构建响应
        std::string response = protocol + " " + std::to_string(response_code) + " " + response_msg + "\r\n"; // 响应协议，响应码，响应信息
        // 响应头信息
        response = response + "Server: " + std::string(serverIp) + "\r\n" + "Content-Type: " + content_type + "\r\n";
        if (!response_time.empty()){
            response = response + "Last-Modified: " + response_time + "\r\n";
        }
        // body内容
        if (!body.empty()){
            response = response + "Content-Length: " + std::to_string(body.size()) + "\r\n";
            response = response + "\r\n" + body;
        }else{
            response = response + "\r\n";
        }
        return response;
    }

};

string getErrorMsg(int code){
    auto it = code2msg.find(code);
    if (it != code2msg.end()) {
        return it->second;
    }else {
        return "unKown";
    }
}

HTTPMessage handlerRequestHeader(HTTPMessage http_msg){
    string header = http_msg.headers;
    size_t startPos = 0;
    size_t endPos;
    while ((endPos = header.find("\r\n", startPos)) != std::string::npos) {
        // 获取单个header
        std::string single_header = header.substr(startPos, endPos - startPos);
        std::cerr << "SingleHeader: " << single_header << std::endl;
        size_t colonPos = single_header.find(':');
        // 校验header,如果没有:的话，则直接返回异常
        if (colonPos == std::string::npos) {
            http_msg.response_code = 400;
            return http_msg;
        }else {
            // 获取Connection,判断是否为close
            std::string firstWord = single_header.substr(0, colonPos);
            firstWord.erase(0, firstWord.find_first_not_of(" "));  // 去除前导空格
            firstWord.erase(firstWord.find_last_not_of(" ") + 1);  // 去除尾部空格
            // 提取冒号后的内容（去除空格）
            std::string value = single_header.substr(colonPos + 1);
            value.erase(0, value.find_first_not_of(" "));  // 去除前导空格
            value.erase(value.find_last_not_of(" ") + 1);  // 去除尾部空格
            // 先存储到request_headers中，后续判断
            http_msg.request_headers.push_back(std::make_pair(firstWord, value));
        }
        startPos = endPos + 2;
    }
    return http_msg;
}

HTTPMessage CheckingHeader(HTTPMessage http_msg) {
    http_msg.response_code = 400;
    for (const auto& header : http_msg.request_headers) {
        std::cout << "解析后的请求头了啦: " << header.first << ": " << header.second << std::endl;
        if (header.first == "Host") {
            http_msg.response_code = 0;
        }else if (header.first == "Connection" && header.second == "close") {
            http_msg.is_close = true;
        }
    }
    return http_msg;
}

// 处理request并生成response
HTTPMessage handleHttpRequest(const std::string& request){
    HTTPMessage http_request;
    http_request.parseRequest(request);

    // HTTPMessage http_response;
    // http_response.protocol = http_request.protocol;
    // http_response.path = http_request.path;

    // 打印各项信息
    std::cerr << "Method: " << http_request.method << std::endl;
    std::cerr << "Path: " << http_request.path << std::endl;
    std::cerr << "protocol: " << http_request.protocol << std::endl;
    std::cerr << "headers: " << http_request.headers << std::endl;
    std::cerr << "body: " << http_request.body << std::endl;

    // 校验路经是否为 / ，如果为 / 则映射到 /index.html
    if (http_request.path == "/"){
        http_request.path = "/index.html";
    }

    // 校验请求头是否符合要求
    http_request = handlerRequestHeader(http_request);
    if (http_request.response_code != 0) {
        return http_request;
    }
    // 校验请求头是否含有特定的信息，比如是否含有主机信息，是否含有close等。
    http_request = CheckingHeader(http_request);
    if (http_request.response_code != 0) {
        return http_request;
    } else if (http_request.is_close) {
        http_request.is_close = true;
        return http_request;
    }

    return http_request;
}

// 处理路由，尝试打开文件了。
HTTPMessage handlerUrl(HTTPMessage http_msg, string doc_root){
    
    struct stat fileInfo;
    // 判断是否追加index.html
    http_msg.path = getDefaultFilePath(http_msg.path); 
    // 构建完整的文件路径
    std::string fullPath = doc_root + http_msg.path;
    // 打印文件路径
    std::cerr << "Path: " << http_msg.path << std::endl;
    std::cerr << "Fullpath: " << fullPath << std::endl;
    if (stat(fullPath.c_str(), &fileInfo) != 0){
        // 检查文件是否存在
        http_msg.response_code = 404;
        return http_msg;
    }else if (!(fileInfo.st_mode & S_IROTH)) {
        // 检查文件权限
        http_msg.response_code = 403;
        return http_msg;
    }
    // 打开文件
    std::ifstream file(fullPath, std::ios::binary);
    if (!file.is_open()) {
        // 文件无法打开，返回500响应
        http_msg.response_code = 500;
        return http_msg;
    }
    // 获取文件扩展名
    size_t dotPos = http_msg.path.find_last_of(".");
    if (dotPos != std::string::npos) {
        std::string fileExtension = http_msg.path.substr(dotPos);
        // 查找Content-Type
        auto contentTypeIt = contentTypes.find(fileExtension);
        if (contentTypeIt != contentTypes.end()) {
            http_msg.content_type = contentTypeIt->second;
        }else {
            http_msg.content_type = "text/plain";
        }
    }
    // 设置文件大小为响应大小
    std::string fileContent((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    http_msg.content_length = fileContent.size();
    http_msg.response_code = 200;
    http_msg.body = fileContent;
    return http_msg;
}


void* handleClient(void* arg){
    // 拿到传入的参数
    ThreadArgs* threadArgs = (ThreadArgs*)arg;
    int clientSocket = threadArgs->clientSocket;
    std::string doc_root = threadArgs->doc_root;
    std::time_t start_time = std::time(nullptr);
    while (true) {
        // 定义最大请求体
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        // 通过socket来强行中断链接
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        if (setsockopt(clientSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            std::cerr << "Error setting timeout" << std::endl;
            break;
        }
        // 从客户端套接字读取HTTP请求
        ssize_t bytesRead = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytesRead <= 0) {
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
                std::cerr << "Connection timed out" << std::endl;
            }else {
                std::cerr << "Read data error" << std::endl;
            }
            // 超时/读取数据异常都关掉客户端套接字
            break;
        }
        // 校验是否超时（但是好像recv会一直等到能拿数据，所以不会工作）
        std::time_t end_time = std::time(nullptr);
        double elapsed_seconds = std::difftime(end_time, start_time);
        if (elapsed_seconds > 5) {
            // 关闭客户端套接字
            break;
        }
        // 处理HTTP请求
        std::string request(buffer, bytesRead);
        HTTPMessage http_response = handleHttpRequest(request);
        // 校验链接是否要关闭
        if (http_response.is_close == true) {
            // 关闭客户端套接字
            std::cerr << "Connection close" << std::endl;
            break;
        }
        // 处理路由
        http_response = handlerUrl(http_response, doc_root);
        // 其他情况发送套接字
        std::string response_str = http_response.parseResponse(clientSocket);
        send(clientSocket, response_str.c_str(), response_str.size(), 0);
    }
    close(clientSocket);
    pthread_exit(NULL);
}


void start_httpd(unsigned short port, string doc_root) {
    int serverSocket, clientSocket;
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t clientAddrLen = sizeof(clientAddr);

    // 创建套接字
    serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == -1) {
        std::cerr << "Error creating socket" << std::endl;
        return;
    }

    // 设置服务器地址和端口
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(port);

    // 绑定套接字
    if (bind(serverSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) == -1) {
        std::cerr << "Error binding" << std::endl;
        close(serverSocket);
        return;
    }

    // 监听连接
    if (listen(serverSocket, 5) == -1) {
        std::cerr << "Error listening" << std::endl;
        close(serverSocket);
        return;
    }

    cerr << "Starting server (port: " << port <<
        ", doc_root: " << doc_root << ")" << endl;

    while (true) {
        // 接受客户端连接
        clientSocket = accept(serverSocket, (struct sockaddr*)&clientAddr, &clientAddrLen);
        if (clientSocket == -1) {
            std::cerr << "Error accepting connection" << std::endl;
            continue;
        }

        // 使用pthread创建一个新线程来处理客户端连接
        pthread_t clientThread;
        ThreadArgs args;
        args.clientSocket = clientSocket;
        args.doc_root = doc_root;

        if (pthread_create(&clientThread, NULL, handleClient, &args) != 0) {
            std::cerr << "Error creating thread" << std::endl;
            close(clientSocket);
            continue;
        }

        // 分离线程，不阻塞主线程
        pthread_detach(clientThread);
    }

    // 关闭服务器套接字
    close(serverSocket);
}
