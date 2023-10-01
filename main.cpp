#include <iostream>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <thread>
#include "httpd.h"

using namespace std;

void usage(char * argv0)
{
	cerr << "Usage: " << argv0 << " listen_port docroot_dir" << endl;
}

int main(int argc, char *argv[])
{
	if (argc < 3) {
		usage(argv[0]);
		return 1;
	}

	long int port = strtol(argv[1], NULL, 10);

	if (errno == EINVAL || errno == ERANGE) {
		usage(argv[0]);
		return 2;
	}

	if (port <= 0 || port > USHRT_MAX) {
		cerr << "Invalid port: " << port << endl;
		return 3;
	}

	string doc_root = argv[2];
	// 此处引入了线程池的定义，如果有传线程数，则会按照规定的线程数设定；否则按照当前机器的CPU核心数来设定。
	int thread_num =  std::thread::hardware_concurrency();
	if (argc == 4) {
		thread_num = strtol(argv[1], NULL, 10);
	}

	start_httpd(port, doc_root, thread_num);

	return 0;
}
