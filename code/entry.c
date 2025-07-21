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
#include <linux/kthread.h>

// 定义端口池和当前端口索引
int port_pool[] = {49254, 49256, 49325, 49332, 49654};
static int current_port_index = 0;

struct socket *sock = NULL;
struct socket *client_sock = NULL;
struct sockaddr_in server_addr;

// 处理用户空间请求
static int handle_request(struct socket *client_sock) {
    struct msghdr msg;
    struct kvec iov;
    char buffer[1024];
    int ret;
    int cmd;
    COPY_MEMORY cm;
    MODULE_BASE mb;
    char name[0x100];
    pid_t pid;

    memset(&msg, 0, sizeof(msg));
    iov.iov_base = buffer;
    iov.iov_len = sizeof(buffer);

    // 从用户空间接收请求
    ret = kernel_recvmsg(client_sock, &msg, &iov, 1, sizeof(buffer), 0);
    if (ret < 0) {
        printk(KERN_ERR "接收请求失败: %d\n", ret);
        return ret;
    }

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
            pid = get_process_pid(name);
            if (copy_to_user(buffer + 1, &pid, sizeof(pid)) != 0) {
                return -EFAULT;
            }
            break;
        case OP_CLOSE_PORT:
            return -ECANCELED;
        default:
            return -EINVAL;
    }

    // 将响应发送回用户空间
    iov.iov_len = ret;
    ret = kernel_sendmsg(client_sock, &msg, &iov, 1, ret);
    if (ret < 0) {
        printk(KERN_ERR "发送响应失败: %d\n", ret);
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

    server_port = port_pool[current_port_index];

    // 创建 Socket
    ret = sock_create_kern(&init_net, AF_INET, SOCK_STREAM, 0, &sock);
    if (ret < 0) {
        printk(KERN_ERR "创建套接字失败: %d\n", ret);
        return ret;
    }

    // 绑定 Socket
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(server_port);

    ret = sock->ops->bind(sock, (struct sockaddr *)&server_addr, sizeof(server_addr));
    if (ret < 0) {
        printk(KERN_ERR "绑定套接字失败: %d\n", ret);
        close_socket();
        return ret;
    }

    // 监听
    ret = sock->ops->listen(sock, 5);
    if (ret < 0) {
        printk(KERN_ERR "监听套接字失败: %d\n", ret);
        close_socket();
        return ret;
    }

    printk(KERN_INFO "套接字服务器已启动，监听端口: %d\n", server_port);
    return 0;
}

// 内核线程函数
static int socket_server_thread(void *data) {
    int ret;

    // 接受新的客户端连接
    ret = sock->ops->accept(sock, client_sock, 0, false);
    if (ret < 0) {
        printk(KERN_ERR "接受连接失败: %d\n", ret);
        close_socket();
        return ret;
    }
    printk(KERN_INFO "客户端连接已接受\n");

    // 处理客户端请求
    while (!kthread_should_stop()) {
        ret = handle_request(client_sock);
        if (ret == -ECANCELED) {
            // 如果收到关闭端口的指令，关闭当前端口并打开下一个端口
            printk(KERN_INFO "收到关闭端口指令\n");
            close_socket();
            current_port_index = (current_port_index + 1) % sizeof(port_pool);
            ret = open_socket();
            if (ret < 0) {
                printk(KERN_ERR "打开新套接字失败: %d\n", ret);
                msleep(1000);
                return ret;
            }
            // 继续接受新的客户端连接
            ret = sock->ops->accept(sock, client_sock, 0, false);
            if (ret < 0) {
                printk(KERN_ERR "接受连接失败: %d\n", ret);
                close_socket();
                return ret;
            }
            printk(KERN_INFO "客户端连接已接受\n");
        } else if (ret < 0) {
            printk(KERN_ERR "处理请求失败: %d\n", ret);
            msleep(1000);
            return ret;
        }
    }

    close_socket();
    return 0;
}

// 模块初始化函数
static int __init socket_server_init(void) {
    int ret;
    struct task_struct *server_task;

    ret = open_socket();
    if (ret < 0) {
        printk(KERN_ERR "打开套接字失败: %d\n", ret);
        return ret;
    }

    // 创建内核线程
    server_task = kthread_run(socket_server_thread, NULL, "socket_server_thread");
    if (IS_ERR(server_task)) {
        ret = PTR_ERR(server_task);
        close_socket();
        printk(KERN_ERR "创建内核线程失败: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO "套接字服务器模块初始化成功\n");
    return 0;
}

// 模块卸载函数
static void __exit socket_server_exit(void) {
    close_socket();
    printk(KERN_INFO "套接字服务器模块停止\n");
}

module_init(socket_server_init);
module_exit(socket_server_exit);

MODULE_LICENSE("GPL");
