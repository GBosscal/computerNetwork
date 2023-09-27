#ifndef HTTPD_H
#define HTTPD_H

#include <string>

using namespace std;

void start_httpd(unsigned short port, string doc_root, int thread_num);

#endif // HTTPD_H
