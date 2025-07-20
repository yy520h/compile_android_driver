#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include "comm.h"
#include "memory.h"
#include "process.h"
#include <linux/module.h>
#include <linux/kallsyms.h>


static struct socket *sock = NULL;
static struct socket *client_sock = NULL;
static struct sockaddr_in server_addr;

#define SERVER_PORT_MIN 59000
#define SERVER_PORT_MAX 60000
#define SERVER_PORT_RANGE (SERVER_PORT_MAX - SERVER_PORT_MIN + 1) // 包括两端

// 处理用户空间的请求
static int handle_request(struct socket *client_sock) {
    struct msghdr msg;
    struct kvec iov;
    char buffer[1024];
    int ret;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    // 从用户空间接收请求
    ret = kernel_recvmsg(client_sock, &msg, &iov, 1, sizeof(buffer), 0);
    if (ret < 0) {
        return ret;
    }

    // 处理请求
    COPY_MEMORY cm;
    MODULE_BASE mb;
    char name[0x100];
    int cmd;

    cmd = buffer[0];

    switch (cmd) {
        case OP_READ_MEM:
            if (copy_from_user(&cm, buffer + 1, sizeof(cm)) != 0) {
                return -EFAULT;
            }
            if (read_process_memory(cm.pid, cm.addr, buffer + 1, cm.size)) {
                return -EFAULT;
            }
            break;
        case OP_WRITE_MEM:
            if (copy_from_user(&cm, buffer + 1, sizeof(cm)) != 0) {
                return -EFAULT;
            }
            if (write_process_memory(cm.pid, cm.addr, buffer + 1, cm.size)) {
                return -EFAULT;
            }
            break;
        case OP_MODULE_BASE:
            if (copy_from_user(&mb, buffer + 1, sizeof(mb)) != 0) {
                return -EFAULT;
            }
            if (copy_from_user(name, buffer + 1 + sizeof(mb), sizeof(name) - 1) != 0) {
                return -EFAULT;
            }
            mb.base = get_module_base(mb.pid, name);
            if (copy_to_user(buffer + 1, &mb, sizeof(mb)) != 0) {
                return -EFAULT;
            }
            break;
        case OP_GET_PROCESS_PID:
            if (copy_from_user(name, buffer + 1, sizeof(name) - 1) != 0) {
                return -EFAULT;
            }
            pid_t pid = get_process_pid(name);
            if (copy_to_user(buffer + 1, &pid, sizeof(pid)) != 0) {
                return -EFAULT;
            }
            break;
        case OP_CLOSE_PORT:
            return -ECANCELED; // 使用特殊返回码表示端口关闭
        default:
            return -EINVAL;
    }

    // 将响应发送回用户空间
    iov.iov_len = ret;
    ret = kernel_sendmsg(client_sock, &msg, &iov, 1, ret);
    if (ret < 0) {
        return ret;
    }

    return 0;
}

// 关闭 Socket
static void close_socket(void) {
    if (client_sock) {
        sock_release(client_sock);
        client_sock = NULL;
    }
    if (sock) {
        sock_release(sock);
        sock = NULL;
    }
}

// 打开一个新的 Socket
static int open_socket(void) {
    int ret;
    int server_port;

    // 在指定范围内随机选择一个端口
    get_random_bytes(&server_port, sizeof(server_port));
    server_port = SERVER_PORT_MIN + (server_port % SERVER_PORT_RANGE);

    // 创建 Socket
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, 0, &sock);
    if (ret < 0) {
        return ret;
    }

    // 绑定 Socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(server_port);

    ret = sock->ops->bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0) {
        close_socket();
        return ret;
    }

    // 监听
    ret = sock->ops->listen(sock, 5);
    if (ret < 0) {
        close_socket();
        return ret;
    }

    return 0;
}

// 模块初始化函数
static int __init socket_server_init(void) {
    int ret;

    // 在模块加载时打开一个新的 Socket
    ret = open_socket();
    if (ret < 0) {
        return ret;
    }

    // 接收连接并处理请求
    while (1) {
        struct socket *new_client_sock;
        ret = sock->ops->accept(sock, new_client_sock, 0, false);
        if (ret < 0) {
            break;
        }

        client_sock = new_client_sock;
        ret = handle_request(client_sock);
        if (ret == -ECANCELED) {
            close_socket();
            ret = open_socket();
            if (ret < 0) {
                break;
            }
        }
    }
    return 0;
}

// 模块卸载函数
static void __exit socket_server_exit(void) {
    close_socket();
}

module_init(socket_server_init);
module_exit(socket_server_exit);

MODULE_LICENSE("GPL");
//MODULE_DESCRIPTION("基于 Socket 的内核模块，用于进程内存操作");//模块描述
