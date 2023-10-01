#include <iostream>
#include <string>
#include <cstring>
#include <map>
#include <vector>
#include <ctime>
#include <fstream>
#include <sstream>
#include <thread>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <future>
#include <functional>
#include <sys/select.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include "httpd.h"

using namespace std;

// 读取文件的方法
std::string readFile(const std::string& filename) {
    std::ifstream file(filename);
    std::string content;

    if (file.is_open()) {
        std::ostringstream content_stream;
        content_stream << file.rdbuf();
        content = content_stream.str();
        file.close();
    }

    return content;
}

// HTTPMessage对象
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
        size_t request_line_end = request.find("\r\n");
        if (request_line_end != std::string::npos) {
            std::string request_line = request.substr(0, request_line_end);
            size_t methodEnd = request_line.find(' ');
            if (methodEnd != std::string::npos) {
                method = request_line.substr(0, methodEnd);
                size_t pathEnd = request_line.find(' ', methodEnd + 1);
                if (pathEnd != std::string::npos) {
                    path = request_line.substr(methodEnd + 1, pathEnd - methodEnd - 1);
                    protocol = request_line.substr(pathEnd + 1);
                }
            }
        }
        // 获取请求头信息
        if (request_line_end != std::string::npos && pos != std::string::npos){
            headers = msg.substr(request_line_end + 2, pos); // +2 是因为把请求方式那行的\r\n都去掉
        }
    }

    string parseResponse(int client_socket) {
        // 获取当前服务的IP
        struct sockaddr_in server_addr;
        socklen_t server_addr_len = sizeof(server_addr);
        getsockname(client_socket, (struct sockaddr*)&server_addr, &server_addr_len);
        char server_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(server_addr.sin_addr), server_ip, INET_ADDRSTRLEN);
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
        response = response + "Server: " + std::string(server_ip) + "\r\n" + "Content-Type: " + content_type + "\r\n";
        std::cerr << "response_time" << response_time << std::endl;
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

// 往多线程中传入数据的结构体
struct ThreadArgs {
    int client_socket;
    std::string doc_root;
};

// 定义一个线程池类
class ThreadPool {
public:
    ThreadPool(size_t num_threads);
    template <class F, class... Args>
    auto enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
    ~ThreadPool();
private:
    // 线程需要执行的任务类型
    using Task = std::function<void()>;

    // 线程池
    std::vector<std::thread> workers;
    // 任务队列
    std::queue<Task> tasks;

    // 互斥锁，用于保护任务队列
    std::mutex queue_mutex;
    // 条件变量，用于通知线程任务队列有任务可以执行
    std::condition_variable condition;
    // 是否停止线程池
    bool stop;
};

// 表示通行/拒绝规则的类
class AccessRule {
public:
    std::string type; // 规则类型，例如 "allow" 或 "deny"
    std::string cidr_ip; // CIDR格式的IP地址范围
    struct sockaddr_in range;

    AccessRule(const std::string& t, const std::string& ip)
        : type(t), cidr_ip(ip) {}

};

// 线程池构造函数
inline ThreadPool::ThreadPool(size_t num_threads) : stop(false) {
    for (size_t i = 0; i < num_threads; ++i) {
        workers.emplace_back(
            [this] {
                while (true) {
                    Task task;
                    // 从任务队列中取出任务
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this] { return this->stop || !this->tasks.empty(); });
                        if (this->stop && this->tasks.empty()) {
                            return;
                        }
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }
                    // 执行任务
                    task();
                }
            }
        );
    }
}

// 线程池析构函数
inline ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex);
        stop = true;
    }
    condition.notify_all();
    for (std::thread& worker : workers) {
        worker.join();
    }
}

// 提交任务到线程池
template <class F, class... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type> {
    using return_type = typename std::result_of<F(Args...)>::type;

    auto task = std::make_shared<std::packaged_task<return_type()>>(
        std::bind(std::forward<F>(f), std::forward<Args>(args)...)
    );

    std::future<return_type> res = task->get_future();

    {
        std::unique_lock<std::mutex> lock(queue_mutex);

        // 停止状态不接受新任务
        if (stop) {
            throw std::runtime_error("enqueue on stopped ThreadPool");
        }

        // 将任务加入队列
        tasks.emplace([task]() { (*task)(); });
    }

    condition.notify_one();
    return res;
}

// 响应对应的content-types
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

// 响应代码对应的错误信息
std::map<int, std::string> code2msg = {
    {200, "OK"},
    {400, "Bad Request"},
    {403, "Forbidden"},
    {404, "Not Found"},
};

// 获取异常的信息
string getErrorMsg(int code){
    auto it = code2msg.find(code);
    if (it != code2msg.end()) {
        return it->second;
    }else {
        return "unKown";
    }
}

// 校验路径是否以'/'结尾，如果是则追加index.html"
std::string getDefaultFilePath(const std::string& path) {
    if (path.back() == '/') {
        return path + "index.html";
    }
    return path;
}

// 校验是否为安全的路经
bool isPathSafe(const std::string& path) {
    // 检查路径是否包含 ..，如果包含则不安全
    if (path.find("..") != std::string::npos) {
        return false;
    }
    
    // 定义不安全的字符集
    const std::string unsafe_characters = "\\:*?\"<>|";
    // 检查路径中是否包含不安全字符
    for (char c : path) {
        if (unsafe_characters.find(c) != std::string::npos) {
            std::cerr << "Path: " << c << unsafe_characters.find(c) << std::endl;
            return false; // 发现不安全字符
        }
    }

    // 如果没有发现安全问题，返回 true
    return true;
}

// 获取规范化的路径
std::string normalizePath(string doc_root, const std::string& path) {
    // 确保路径以文档根开头
    std::string full_path = doc_root + path;

    // 如果路径不安全，返回一个默认路径或错误响应
    if (!isPathSafe(full_path)) {
        return "error_404.html";
    }

    // 返回规范化后的路径
    return full_path;
}

// 尝试打开.htaccess，读取数据并实例化AccessRule
std::vector<AccessRule> getRuleFromAccess() {
    std::ifstream htaccess_file(".htaccess"); // 尝试打开.htaccess文件
    std::vector<AccessRule> access_rules; // 存储规则的向量

    if (htaccess_file.is_open()) {
        std::string line;
        while (std::getline(htaccess_file, line)) {
            // 在此处解析每一行规则
            if (line.find("allow from") != std::string::npos) {
                // 如果包含"allow from"，将其视为allow规则
                std::string cidr_ip = line.substr(line.find("allow from") + 11);
                access_rules.push_back(AccessRule("allow", cidr_ip));
            } else if (line.find("deny from") != std::string::npos) {
                // 如果包含"deny from"，将其视为deny规则
                std::string cidr_ip = line.substr(line.find("deny from") + 10);
                access_rules.push_back(AccessRule("deny", cidr_ip));
            }
        }
        htaccess_file.close();
    } else {
        std::cout << ".htaccess 文件不存在或无法打开." << std::endl;
    }

    // 输出存储的规则
    for (const AccessRule& rule : access_rules) {
        std::cout << "Rule Type: " << rule.type << ", CIDR IP: " << rule.cidr_ip << std::endl;
    }

    return access_rules;
}

// 将IP地址转换为整数
unsigned int ipToUint(const std::string& ip) {
    std::vector<unsigned int> parts;
    std::stringstream ss(ip);
    std::string part;
    
    while (getline(ss, part, '.')) {
        parts.push_back(std::stoi(part));
    }
    
    unsigned int result = 0;
    for (int i = 0; i < 4; ++i) {
        result |= (parts[i] << (24 - (8 * i)));
    }
    
    return result;
}

// 检查IP是否在CIDR范围内
bool isIpInCidr(const std::string& ip, const std::string& cidr) {
    size_t slashPos = cidr.find('/');
    if (slashPos == std::string::npos) {
        std::cerr << "Invalid CIDR format: " << cidr << std::endl;
        return false;
    }
    
    std::string cidr_ip = cidr.substr(0, slashPos);
    std::string cidr_mask_str = cidr.substr(slashPos + 1);
    int cidrMask = std::stoi(cidr_mask_str);
    
    unsigned int ipInt = ipToUint(ip);
    unsigned int cidr_ip_int = ipToUint(cidr_ip);
    unsigned int cidr_mask_int = (0xFFFFFFFFU << (32 - cidrMask));
    
    return (ipInt & cidr_mask_int) == (cidr_ip_int & cidr_mask_int);
}

// 通过host校验是否符合access中的规则
bool CheckingHostByAccessRules(string host){
    bool all_block = false;
    // 获取htaccess的数据
    std::vector<AccessRule> access_rules = getRuleFromAccess();
    // 根据每一个规则进行搜索
    for (const AccessRule& rule : access_rules) {
        if (isIpInCidr(host,rule.cidr_ip)){
            if (rule.type == "deny"){
                return false;
            }else{
                return true;
            }
        }
        if (rule.cidr_ip == "0.0.0.0/0"){
            all_block  = (rule.type == "deny");
        }
    }
    if (all_block){
        return false;
    }else{
        return true;
    }
}

// 校验header是否符合规定
HTTPMessage CheckingHeader(HTTPMessage http_msg) {
    
    // 初始化响应时间为400
    http_msg.response_code = 400;
    for (const auto& header : http_msg.request_headers) {
        if (header.first == "Host") {
            // 通过CIRD校验规则
            if (CheckingHostByAccessRules(header.second)){
                http_msg.response_code = 0;
            }else{
                http_msg.response_code = 403;
            }
        }else if (header.first == "Connection" && header.second == "close") {
            http_msg.is_close = true;
        }
    }
    return http_msg;
}

// 处理请求中的header的方法
HTTPMessage handlerRequestHeader(HTTPMessage http_msg){
    string header = http_msg.headers;
    size_t start_pos = 0;
    size_t end_pos;
    while ((end_pos = header.find("\r\n", start_pos)) != std::string::npos) {
        // 获取单个header
        std::string single_header = header.substr(start_pos, end_pos - start_pos);
        size_t colonPos = single_header.find(':');
        // 校验header,如果没有:的话，则直接返回异常
        if (colonPos == std::string::npos) {
            http_msg.response_code = 400;
            return http_msg;
        }else {
            // 记录所有的header
            std::string first_word = single_header.substr(0, colonPos);
            first_word.erase(0, first_word.find_first_not_of(" "));  // 去除前导空格
            first_word.erase(first_word.find_last_not_of(" ") + 1);  // 去除尾部空格
            // 提取冒号后的内容（去除空格）
            std::string value = single_header.substr(colonPos + 1);
            value.erase(0, value.find_first_not_of(" "));  // 去除前导空格
            value.erase(value.find_last_not_of(" ") + 1);  // 去除尾部空格
            // 先存储到request_headers中，后续判断
            http_msg.request_headers.push_back(std::make_pair(first_word, value));
        }
        start_pos = end_pos + 2;
    }
    return http_msg;
}

// 处理路由，尝试打开文件了。
HTTPMessage handlerUrl(HTTPMessage http_msg, string doc_root){
    
    struct stat file_info;
    // 判断是否追加index.html
    http_msg.path = getDefaultFilePath(http_msg.path); 
    // 判断路经是否安全
    std::string full_path = normalizePath(doc_root, http_msg.path);
    // 打印文件路径
    std::cerr << "Path: " << http_msg.path << std::endl;
    std::cerr << "full_path: " << full_path << std::endl;
    if (stat(full_path.c_str(), &file_info) != 0){
        // 检查文件是否存在
        http_msg.response_code = 404;
        return http_msg;
    }else if (!(file_info.st_mode & S_IROTH)) {
        // 检查文件权限
        http_msg.response_code = 403;
        return http_msg;
    }
    // 打开文件
    std::ifstream file(full_path, std::ios::binary);
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
    std::string file_content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    http_msg.content_length = file_content.size();
    http_msg.response_code = 200;
    http_msg.body = file_content;
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

// 处理客户端的方法（多线程）
// void* handleClient(void* arg){
//     // 拿到传入的参数
//     ThreadArgs* thread_args = (ThreadArgs*)arg;
//     int client_socket = thread_args->client_socket;
//     std::string doc_root = thread_args->doc_root;
//     std::time_t last_time = std::time(nullptr);

//     while (true) {
//         // 定义最大请求体
//         char buffer[4096];
//         memset(buffer, 0, sizeof(buffer));
//         // 通过socket来强行中断链接
//         struct timeval timeout;
//         timeout.tv_sec = 5;
//         timeout.tv_usec = 0;
//         if (setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
//             std::cerr << "Error setting timeout" << std::endl;
//             break;
//         }
//         // 从客户端套接字读取HTTP请求
//         ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer), 0);
//         if (bytes_read <= 0) {
//             if (errno == EWOULDBLOCK || errno == EAGAIN) {
//                 std::cerr << "Connection timed out" << std::endl;
//             }else {
//                 std::cerr << "Read data error" << std::endl;
//             }
//             // 超时/读取数据异常都关掉客户端套接字
//             break;
//         }
//         // 校验是否超时（但是好像recv会一直等到能拿数据，所以不会工作）
//         std::time_t end_time = std::time(nullptr);
//         double elapsed_seconds = std::difftime(end_time, last_time);
//         if (elapsed_seconds > 5) {
//             // 关闭客户端套接字
//             break;
//         }
//         // 处理HTTP请求
//         std::string request(buffer, bytes_read);
//         HTTPMessage http_response = handleHttpRequest(request);
//         // 校验链接是否要关闭
//         if (http_response.is_close == true) {
//             // 关闭客户端套接字
//             std::cerr << "Connection close" << std::endl;
//             break;
//         }else if (http_response.response_code != 0){
//             // 要是有响应代码的话，直接发送套接字
//             std::string response_str = http_response.parseResponse(client_socket);
//             send(client_socket, response_str.c_str(), response_str.size(), 0);
//             continue;
//         }
//         // 处理路由
//         http_response = handlerUrl(http_response, doc_root);
//         // 足够大以容纳格式化的时间字符串
//         char time_str[80]; 
//         // 使用strftime将time_t格式化为字符串
//         std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&last_time));
//         // 追加上次请求时间到响应中
//         http_response.response_time = time_str;
//         // 其他情况发送套接字
//         std::string response_str = http_response.parseResponse(client_socket);
//         send(client_socket, response_str.c_str(), response_str.size(), 0);
//         last_time = std::time(nullptr);
//     }
//     close(client_socket);
//     pthread_exit(NULL);
// }

// 处理客户端的方法（线程池）
void handlerWithThread(int client_socket, string doc_root) {
    std::time_t last_time = std::time(nullptr);
    while (true) {
        // 定义最大请求体
        char buffer[4096];
        memset(buffer, 0, sizeof(buffer));
        // 通过socket来强行中断链接
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        if (setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
            std::cerr << "Error setting timeout" << std::endl;
            break;
        }
        // 从客户端套接字读取HTTP请求
        ssize_t bytes_read = recv(client_socket, buffer, sizeof(buffer), 0);
        if (bytes_read <= 0) {
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
        double elapsed_seconds = std::difftime(end_time, last_time);
        if (elapsed_seconds > 5) {
            // 关闭客户端套接字
            break;
        }
        // 处理HTTP请求
        std::string request(buffer, bytes_read);
        HTTPMessage http_response = handleHttpRequest(request);
        // 校验链接是否要关闭
        if (http_response.is_close == true) {
            // 关闭客户端套接字
            std::cerr << "Connection close" << std::endl;
            break;
        }else if (http_response.response_code != 0){
            // 要是有响应代码的话，直接发送套接字
            std::string response_str = http_response.parseResponse(client_socket);
            send(client_socket, response_str.c_str(), response_str.size(), 0);
            continue;
        } 
        // 处理路由
        http_response = handlerUrl(http_response, doc_root);
        // 足够大以容纳格式化的时间字符串
        char time_str[80]; 
        // 使用strftime将time_t格式化为字符串
        std::strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", std::localtime(&last_time));
        // 追加上次请求时间到响应中
        http_response.response_time = time_str;
        // 其他情况发送套接字
        std::string response_str = http_response.parseResponse(client_socket);
        send(client_socket, response_str.c_str(), response_str.size(), 0);
        last_time = std::time(nullptr);
    }
    close(client_socket);
}

// 启动一个http的服务器
void start_httpd(unsigned short port, string doc_root, int thread_num) {
    // int server_socket, client_socket;
    int server_socket;
    struct sockaddr_in server_addr;
    // struct sockaddr_in server_addr, client_addr;
    // socklen_t clientAddrLen = sizeof(client_addr);

    // 创建套接字
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        std::cerr << "Error creating socket" << std::endl;
        return;
    }

    // 设置服务器地址和端口
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    // 绑定套接字
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        std::cerr << "Error binding" << std::endl;
        close(server_socket);
        return;
    }

    // 监听连接
    if (listen(server_socket, 5) == -1) {
        std::cerr << "Error listening" << std::endl;
        close(server_socket);
        return;
    }

    cerr << "Starting server (port: " << port <<
        ", doc_root: " << doc_root << "ThreadPool: " << thread_num << ")" << endl;

    // 多线程实现方式
    // while (true) {
    //     // 接受客户端连接Implemented thread pooling
    //     client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &clientAddrLen);
    //     if (client_socket == -1) {
    //         std::cerr << "Error accepting connection" << std::endl;
    //         continue;
    //     }

    //     // 使用pthread创建一个新线程来处理客户端连接
    //     pthread_t clientThread;
    //     ThreadArgs args;
    //     args.client_socket = client_socket;
    //     args.doc_root = doc_root;

    //     if (pthread_create(&clientThread, NULL, handleClient, &args) != 0) {
    //         std::cerr << "Error creating thread" << std::endl;
    //         close(client_socket);
    //         continue;
    //     }

    //     // 分离线程，不阻塞主线程
    //     pthread_detach(clientThread);
    // }

    // 创建线程池
    ThreadPool thread_pool(thread_num);
    // 线程池实现方式
    while (true) {
        struct sockaddr_in client_addr;
        socklen_t clientAddrLen = sizeof(client_addr);
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &clientAddrLen);
        if (client_socket == -1) {
            cerr << "Error accepting connection" << endl;
            continue;
        }
        thread_pool.enqueue(handlerWithThread, client_socket, doc_root);
    }

    // 关闭服务器套接字
    close(server_socket);
}
