
#include <mysql.h>
#include <stdlib.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<time.h>
#include<string>

#include<iostream>

#include <winsock2.h>
#include <windows.h>
#include <winsock.h>
#include "standard.h"

using namespace std;

#pragma  comment(lib, "ws2_32.lib")     //链接Ws2_32.lib库

#define DNS_SERVER "10.3.9.4"       //外部DNS服务器地址
#define LOCAL_SERVER "127.0.0.1"       //本地DNS服务器地址
#define DNS_PORT 53                    //进行DNS服务的53号端口
#define TABLE_LENGTH 3000
#define DN_LENGTH 65
#define BUFFER_SIZE 512
#define TIMEOUT 1000
//待解析的域名请求表
typedef struct WaitingTable {               //中转表
    unsigned short original_ID;           //原有ID
    bool done;                           //标记是否完成解析
    SOCKADDR_IN client;                   //请求者套接字地址
    char domain_name[DN_LENGTH];       //客户查询的域名
    int dataLenth;                     //客户发送报文的字节数
    char recv[BUFFER_SIZE];
    clock_t time_t;
    int nak;
} WaitingTable;

/* 变量声明 */

WaitingTable waiting_table[TABLE_LENGTH];
int loacal_IDnum;                      //本地生成的ID个数

int GetDN(char *start, char *recvbuf, char *DN);

//获取DNS请求中的域名
int GetDN(char *start, char *recvbuf, char *DN) {          //也可以获得CNAME中的域名
    char domain_name[DN_LENGTH];                        //解析缓存得到的域名
    char DN1[DN_LENGTH];                             //存放要拼接的域名
    int pos = 0, DNlenth = 0, sum = 0;//pos为当前位置，partialen为局部域名长度，DNlenth为域名长度
    unsigned int partialen = 0;
    int flag = 0;
    while ((int) recvbuf[pos] != 0) {
        partialen = (unsigned int) recvbuf[pos];
        unsigned int y = 0xffffffc0;
        if (y == partialen) {
            int x = (int) recvbuf[pos + 1];
            x=x&255;
            GetDN(start, start + x, DN1);          //有可能遇到域名中一部分使用相对位置  使用递归
            if (DNlenth != 0) {
                domain_name[DNlenth] = '.';
                DNlenth++;
            }                     //x为相对位置
            flag = 1;
            break;
        }
        sum = sum + 1 + partialen;
        pos++;
        if (DNlenth != 0) {
            domain_name[DNlenth] = '.';
            DNlenth++;
        }
        for (int i = 0; i < partialen; i++) {
            domain_name[DNlenth] = recvbuf[pos];
            pos++;
            DNlenth++;
        }
    }
    if (flag == 0) {                                //对于有相对位置和没有的情况  长度计算方法不同
        domain_name[DNlenth] = '\0';                //要加结束符号  不然memcpy有问题
        memcpy(DN, domain_name, sizeof(domain_name));
        return sum + 1;
    } else {
        domain_name[DNlenth ] = '\0';
        strcat(domain_name, DN1);                   //将相对位置得到的域名拼接起来
        memcpy(DN, domain_name, sizeof(domain_name));
        return sum + 2;
    }

}

//注册本地服务器ID
unsigned short Generate_LocalID(unsigned short original, SOCKADDR_IN temp, bool ifdone) {
    srand(time(NULL));
    waiting_table[loacal_IDnum].original_ID = original;
    waiting_table[loacal_IDnum].client = temp;
    waiting_table[loacal_IDnum].done = ifdone;
    loacal_IDnum++;
    return (unsigned short) (loacal_IDnum - 1);    //以表中下标作为新的ID
}

void Info_help()
{
    cout << "dns 1 : 调试级别一 展示基础信息反馈" << endl;
    cout << "dns 2 : 调试级别二 展示本地DNS中继器详细处理过程" << endl;
    cout << "dns 1 X.X.X.X : 可指定外部DNS地址的调试级别一" << endl;
    cout << "dns 2 X.X.X.X : 可指定外部DNS地址的调试级别二"  << endl;
    cout << "实例 : dns 2 10.3.9.4" << endl;
}

void Generate_query(char Name[],char *addr,char *Type,char *expected,const char *preference,char *insert_code){
    strcat(insert_code, Name);
    strcat(insert_code, interval);
    strcat(insert_code, addr);
    strcat(insert_code, interval);
    strcat(insert_code, Type);
    strcat(insert_code, interval);
    strcat(insert_code, expected);
    strcat(insert_code, interval);
    strcat(insert_code, preference);
    strcat(insert_code, tail);
}

void Judge_type(int query_kind,char *expected){
    if (query_kind == 1) { strcpy(expected, A); }
    else if (query_kind == 28) { strcpy(expected, AAAA); }
    else if (query_kind == 5) { strcpy(expected, CNAME); }
    else if (query_kind == 15) { strcpy(expected, MX); }
    else if (query_kind == 12) { strcpy(expected, PTR); }
}

void Timeout(int &flag, SOCKET OUTER, SOCKADDR_IN OUTADDRESS)
{
    int i;
    int no_false=1;
    for(i = flag ;i <= loacal_IDnum-1;i++)
    {
        if(waiting_table[i].done == 0)
        {
            clock_t time=clock()-waiting_table[i].time_t;
            if(time >= TIMEOUT )
            {
                no_false=0;
                cout << "请求超时，重发本地ID为" << i << "的数据包" << endl;
                sendto(OUTER, waiting_table[i].recv, BUFFER_SIZE, 0, (SOCKADDR *) &OUTADDRESS, sizeof(OUTADDRESS));
            }
            if(time < TIMEOUT) return;
        }
        else if(no_false) flag = i;
    }
}


int main(int argc, char **argv) {
    //提供Windows Sockets API 的调用
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);            //初始化ws2_32.dll动态链接库

    int flag_t = 0;
    //变量初始化及声明
    char sendbuf[BUFFER_SIZE];          //发送缓存
    char recvbuf[BUFFER_SIZE];          //接收缓存
    char OUTER_DNS[20];                 //指定的外部DNS服务器
    char DN[DN_LENGTH];                  //解析缓存得到的域名

    for (int i = 0; i < TABLE_LENGTH; i++) {
        waiting_table[i].original_ID = 0;
        waiting_table[i].done = FALSE;
        waiting_table[i].dataLenth = 0;
        waiting_table[i].nak = 0;
        memset(&(waiting_table[i].client), 0, sizeof(SOCKADDR_IN));
        memset(&(waiting_table[i].domain_name), 0, DN_LENGTH * sizeof(char));
    }

    std::string query;

    //连接数据库
    MYSQL mysql;
    MYSQL_RES *res;
    MYSQL_ROW row;

    mysql_init(&mysql);
    if (!mysql_real_connect
            (&mysql, "localhost", "root", "wrx835368172", "MyTest", 3306, NULL, 0)) {
        printf("Failed to connect to Mysql!\n");
        return 0;
    }

    strcpy(OUTER_DNS, DNS_SERVER);
    int level = 2;
    //调试级别
    if (argc == 2 && strcmp(argv[1],"-help")==0) {
        Info_help();
        return 0;
    }
    else if (argc == 2 && (argv[1][0] - '0') == 1) {
        level = 1;
    }
    else if (argc == 2 && (argv[1][0] - '0') == 2) {
        level = 2;
    }

    if (argc == 3 && (argv[1][0] - '0') == 1) {
        strcpy(OUTER_DNS, argv[2]);
        level = 1;
    }

    if (argc == 3 && (argv[1][0] - '0') == 2) {
        strcpy(OUTER_DNS, argv[2]);
        level = 2;
    }

    //初始信息输出
    time_t curtime;
    time(&curtime);
    cout << "DNSRELAY is now running." << endl;
    printf("Start time: %s\n\n", ctime(&curtime));
    cout << "Outer DNS server " << OUTER_DNS << ",port : " << DNS_PORT << "." << endl;
    int debug_level = atoi(argv[1]);
    cout << "Debug level " << debug_level << endl;

    mysql_query(&mysql, "select count(type) from dns");     //找到行数
    res = mysql_store_result(&mysql);
    row = mysql_fetch_row(res);
    printf("数据库中共有%s行信息", row[0]);

    //socket套接字的声明及初始化
    SOCKET Outer, Local;                //本地DNS和外部DNS两个套接字
    SOCKADDR_IN LocalAdress, OuterAdress, TempAdress;    //本地DNS、外部DNS和请求端三个网络套接字地址

    //创建本地DNS和外部DNS套接字
    Outer = socket(AF_INET, SOCK_DGRAM, 0);
    Local = socket(AF_INET, SOCK_DGRAM, 0);
    if (Local == SOCKET_ERROR) {                        //检测是否创建成功
        cout << "创建错误" << endl;
        cout << "Failed: " << WSAGetLastError() << endl;
        return 2;
    }
    if (Outer == SOCKET_ERROR) {
        cout << "创建错误" << endl;
        cout << "Failed: " << WSAGetLastError() << endl;
        return 2;
    }
    unsigned long ul = 1;
    int ret1, ret2;
    ret1 = ioctlsocket(Outer, FIONBIO, (unsigned long *) &ul);//使用非阻塞方式连接
    ret2 = ioctlsocket(Local, FIONBIO, (unsigned long *) &ul);//使用非阻塞方式连接


    //设置本地DNS和外部DNS两个套接字
    LocalAdress.sin_family = AF_INET;//地址族
    LocalAdress.sin_port = htons(DNS_PORT);//端口号
    LocalAdress.sin_addr.s_addr = INADDR_ANY;//32位IPv4地址(inet_addr是一个计算机函数，功能是将一个点分十进制的IP转换成一个长整数型数（u_long类型）等同于inet_addr())
    //LocalAdress.sin_addr.s_addr = inet_addr(LOCAL_SERVER);
    OuterAdress.sin_family = AF_INET;//地址族
    OuterAdress.sin_port = htons(DNS_PORT);//端口号
    OuterAdress.sin_addr.s_addr = inet_addr(
            OUTER_DNS);//32位IPv4地址(inet_addr是一个计算机函数，功能是将一个点分十进制的IP转换成一个长整数型数（u_long类型）等同于inet_addr())


    //将本地地址与套接口绑定
    cout << "\nBinding Port 53 ...";
    if (::bind(Local, (SOCKADDR *) &LocalAdress, sizeof(LocalAdress)) == -1) {
        cout << "  failed!" << endl;
        exit(1);
    } else
        cout << "  succeed!" << endl;


    int RecvLen, SendLen;
    int TempSize = sizeof(TempAdress);


    while (1) {
        //判断是否有来自外部DNS服务器的应答
        memset(recvbuf, '\0', BUFFER_SIZE);
        RecvLen = recvfrom(Outer, recvbuf, BUFFER_SIZE, 0, (SOCKADDR *) &TempAdress, &TempSize);

        char *Reader = NULL;
        Reader = recvbuf;
        GetDN(recvbuf, recvbuf + 12, DN);               //获取query询问的域名
        Reader = Reader + 2 + 4 + 6 + strlen(DN) + 2;

        if (RecvLen > 0) {               //当有应答时
            if (level > 0) {
                cout << "\n收到来自外部DNS，IP为" << inet_ntoa(TempAdress.sin_addr) << "的Type: ";
                printf("%#X", ntohs(*(unsigned short *) Reader));
                cout << "回答" << " 的请求域名为" << DN << endl;
            }

            //获得answer个数
            unsigned short *answer_num = (unsigned short *) malloc(sizeof(unsigned short));
            memcpy(answer_num, recvbuf + 6, sizeof(unsigned short));
            int ip_num = ntohs(*answer_num);

            free(answer_num);

            //ID转换
            unsigned short *TID = (unsigned short *) malloc(sizeof(unsigned short));
            memcpy(TID, recvbuf, sizeof(unsigned short));
            int i = ntohs(*TID);                                 //找到转发表中对应的位置
            unsigned short LID = htons(waiting_table[i].original_ID);
            memcpy(recvbuf, &LID, sizeof(unsigned short));       //改为客户端发来的id
            waiting_table[i].done = TRUE;



            if (level > 0) cout << "本地ID为:" << i << ",客户端ID为:" << LID << endl;
            if (level > 1) cout << "报文中answer个数位" << ip_num << endl;

            //将不在本地缓存中的新查询到的域名及其IP加入本地缓存

            int dns_length = strlen(waiting_table[i].domain_name);
            char *type_pos = recvbuf + 2 + 4 + 6 + dns_length + 2 + 4 + 2;   //第一个答案的类型的位置
            char *pos = recvbuf + 2 + 4 + 6 + dns_length + 2 + 4 + 12;        //第一个答案的起始位置
            char *query_type = recvbuf + 2 + 4 + 6 + dns_length + 2;        //记录问题查询的类型
            int count = 0;


            char Name[100];                                     //询问的域名
            char IP[100];                                       //获得的答案 有可能是ipv4 ipv6 cname的域名
            char Type[7];                                       //记录答案的类型
            char expected[7];                                   //询问的类型


            //获得询问的类型
            unsigned short *type_char = (unsigned short *) malloc(sizeof(unsigned short));
            memcpy(type_char, query_type, sizeof(unsigned short));
            int query = ntohs(*type_char);

            Judge_type(query,expected);


            //十分重要！！！！
            //差错处理  有可能遇到  连续快速的询问了同样的问题 导致写了同样的答案两次 使得构造回应报文出错
            //以下处理可以避免answer重复
            int repeat_flag = 0;
            char repeat_query[200] = "select count(IP) from dns where name='";
            const char repeat_interval[30] = "' and expected='";
            const char repeat_tail[10] = "';";
            strcat(repeat_query, DN);
            strcat(repeat_query, repeat_interval);
            strcat(repeat_query, expected);
            strcat(repeat_query, repeat_tail);
            mysql_query(&mysql, repeat_query);
            if (level > 1) cout << "在数据库查询相关信息：" << repeat_query << endl;
            res = mysql_store_result(&mysql);
            row = mysql_fetch_row(res);
            if (atoi(row[0]) != 0&&level>0) {
                cout << "asnwer复写  跳过本次数据库存入" << endl;
                repeat_flag = 1;
            }

            //获得第一个答案的类型
            memcpy(type_char, type_pos, sizeof(unsigned short));

            //查询返回报文是否有error 即没查询到
            unsigned short *error_char = (unsigned short *) malloc(sizeof(unsigned short));
            memcpy(error_char, recvbuf + 3, sizeof(unsigned short));

            if (((int) *error_char) == 131) {                   //匹配0x8183

                char insert_code[250] = "INSERT INTO dns(name, IP, type,expected,preference) VALUES ('";

                strcpy(Name, DN);            //复制的name

                int type = ntohs(*type_char);           //获得类型
                // free(type_char);
                if (type == 1) { strcpy(Type, A); }
                else if (type == 28) { strcpy(Type, AAAA); }
                else if (type == 5) { strcpy(Type, CNAME); }
                else if (type == 15) { strcpy(Type, MX); }
                Generate_query(Name,"0.0.0.0",Type,expected,"0",insert_code);
                if(level>1){
                    cout << "接受到的报文头部标识error" << endl;
                    cout << "向数据库中写入信息：" << insert_code << endl;
                }
                mysql_query(&mysql, insert_code);              //存入数据库
            } else if (!repeat_flag) {                                          //有答案的报文
                strcpy(Name, DN);            //复制的name
                while (count < ip_num) {
                    struct in_addr ip_addr;                 //用于读取A类型答案
                    unsigned int ip = *(unsigned int *) pos;
                    memcpy(&ip_addr, &ip, 4);

                    char insert_code[300] = "INSERT INTO dns(name, IP, type,expected,preference) VALUES ('";

                    memcpy(type_char, type_pos, sizeof(unsigned short));
                    short type = ntohs(*type_char);           //获得类型

                    //读取答案  不同的type有不同的方式
                    if (type == 1) {
                        char *addr;
                        strcpy(Type, A);
                        addr = inet_ntoa(ip_addr);
                        Generate_query(Name,addr,Type,expected,"0",insert_code);
                        //4字节ipv4地址  12字节其他信息
                        pos = pos + 4 + 12;         //length需要计算
                        type_pos = type_pos + 10 + 4 + 2;
                    } else if (type == 28) {
                        strcpy(Type, AAAA);
                        char addr[40] = "\0";
                        unsigned int Byte;
                        char str[12];
                        char *zero = "00000000";
                        char *onezero = "0";
                        for (int i = 0; i < 4; i++) {
                            //每次读取四字节
                            memcpy(&Byte, pos + i * 4, sizeof(unsigned int));
                            Byte = ntohl(Byte);
                            //四字节16位
                            itoa(Byte, str, 16);
                            str[8] = '\0';      //变为字符串  不然strcat会出错
                            //itoa函数会省略前面的0  所以需要在不同情况下补零
                            if (Byte == 0) strcat(addr, zero);
                            else {
                                for (int i = 0; i < (8 - strlen(str)); i++) strcat(addr, onezero);
                                strcat(addr, str);
                            }
                        }
                        Generate_query(Name,addr,Type,expected,"0",insert_code);
                        cout << insert_code << endl;
                        //ipv6有16字节
                        pos = pos + 16 + 12;         //length需要计算
                        type_pos = type_pos + 16 + 12;
                    } else if (type == 5) {
                        //读取CNAME返回的域名
                        int datalength = GetDN(recvbuf, pos, IP);
                        strcpy(Type, CNAME);

                        Generate_query(Name,IP,Type,expected,"0",insert_code);
                        type_pos = type_pos + 10 + datalength + 2;
                        pos = pos + datalength + 12;         //length需要计算
                    } else if (type == 15) {
                        if (count == 0) pos += 2;
                        memcpy(type_char, pos - 2, sizeof(unsigned short));
                        short pre = ntohs(*type_char);           //获得preference
                        int datalength = GetDN(recvbuf, pos, IP);
                        strcpy(Type, MX);
                        Generate_query(Name,IP,Type,expected,to_string(pre).data(),insert_code);
                        type_pos = type_pos + 10 + datalength + 2 + 2; //多一个2字节的preferen
                        pos = pos + datalength + 12 + 2;         //length需要计算
                    } else if (type == 12) {
                        int datalength = GetDN(recvbuf, pos, IP);
                        strcpy(Type, PTR);
                        Generate_query(Name,IP,Type,expected,"0",insert_code);
                        type_pos = type_pos + 10 + datalength + 2;
                        pos = pos + datalength + 12;         //length需要计算
                    } else {                  //其他类型跳过
                        count++;
                        continue;
                    }

                    if (level > 1) cout << "向数据库写入" << insert_code << endl;
                    mysql_query(&mysql, insert_code);              //存入数据库

                    count++;
                }

            }
            free(type_char);
            free(error_char);
            SendLen = sendto(Local, recvbuf, BUFFER_SIZE, 0, (SOCKADDR *) &waiting_table[i].client,
                             sizeof(waiting_table[i].client));
            cout << expected << "查询已转发给请求者" << endl;
            if (SendLen == SOCKET_ERROR) {                  //检查是否正确发送

                cout << "sendto Failed: " << WSAGetLastError() << endl;
                continue;
            }
            free(TID);    //释放动态分配的内存


        }
        //处理客户端发出的请求
        memset(recvbuf, '\0', BUFFER_SIZE);
        RecvLen = recvfrom(Local, recvbuf, sizeof(recvbuf), 0, (SOCKADDR *) &TempAdress, &TempSize);
        Reader = recvbuf;
        GetDN(recvbuf, recvbuf + 12, DN);
        Reader = Reader + 2 + 4 + 6 + strlen(DN) + 2;
        if (RecvLen > 0) {
            cout << "有来自客户端的请求" << endl;
            if (level > 0) cout << "查询域名为：" << DN << endl;

            //记录报文希望得到的type
            char expected[7];
            unsigned short *type_char = (unsigned short *) malloc(sizeof(unsigned short));
            memcpy(type_char, recvbuf + 14 + strlen(DN), sizeof(unsigned short));
            int query_kind = ntohs(*type_char);
            Judge_type(query_kind,expected);

            //用于获取相应的answer和查看是否有期望的answer
            char query[200] = "select * from dns where name='";
            char count_query[100] = "select count(IP) from dns where name='";
            char and_condition[20] = "' and expected='";
            //char and_condition[20] = "' and type='";
            strcat(query, DN);
            strcat(query, and_condition);
            strcat(query, expected);
            strcat(query, new_tail);

            strcat(count_query, DN);
            strcat(count_query, and_condition);
            strcat(count_query, expected);
            strcat(count_query, new_tail);

            mysql_query(&mysql, count_query);     //首先查询是否有符合条件的ip
            res = mysql_store_result(&mysql);
            row = mysql_fetch_row(res);

            if (level > 1) {
                cout << "检索数据库信息" << endl;
                cout << query << endl;
            }
            //在本地的域名解析表中没有找到
            int ip_num = atoi(row[0]);

            mysql_query(&mysql, query);                 //获取answer
            res = mysql_store_result(&mysql);         //获得结果集
            row = mysql_fetch_row(res);

            //一个flag  如果查询的type和我拥有的所有answer的type不匹配  则等同于没有answer 出错
            int real_answer = 1;
            if (strcmp(AAAA, expected) == 0)
                real_answer = 0;  //对于AAAA的询问  可能只有CNAME类型的answer也是正确的  比如浏览网页 不能返回无answer情况
            while (row) {                   //寻找是否有匹配答案
                if (strcmp(row[2], expected) == 0) {
                    real_answer = 0;
                    break;
                }
                row = mysql_fetch_row(res);
            }

            if (ip_num == 0) {             //查找到零个数据
                //ID转换为请求报文的ID
                unsigned short *TID = (unsigned short *) malloc(sizeof(unsigned short));
                memcpy(TID, recvbuf, sizeof(unsigned short));
                unsigned short LID = htons(Generate_LocalID(ntohs(*TID), TempAdress, FALSE));//Local（本地）ID
                memcpy(recvbuf, &LID, sizeof(unsigned short));
                strcpy(waiting_table[loacal_IDnum - 1].domain_name, DN);
                waiting_table[loacal_IDnum - 1].dataLenth = RecvLen;
                waiting_table[loacal_IDnum - 1].time_t = clock();
                memcpy(waiting_table[loacal_IDnum - 1].recv,recvbuf,BUFFER_SIZE);


                cout << "转发给了外部DNS服务器" << endl;
                SendLen = sendto(Outer, recvbuf, BUFFER_SIZE, 0, (SOCKADDR *) &OuterAdress, sizeof(OuterAdress));

                Timeout(flag_t,Outer,OuterAdress);


                if (SendLen == SOCKET_ERROR) {
                    cout << "问题所在" << endl;
                    cout << "sendto Failed: " << WSAGetLastError() << endl;

                    continue;
                }
                free(TID);    //释放动态分配的内存
            }
                //在域名解析表中找到
            else {
                mysql_query(&mysql, query);
                res = mysql_store_result(&mysql);         //获得结果集
                row = mysql_fetch_row(res);

                //获取请求报文的ID
                char *reader = NULL;
                unsigned short *TID = (unsigned short *) malloc(sizeof(unsigned short));
                memcpy(TID, recvbuf, sizeof(unsigned short));
                //unsigned short LID = Generate_LocalID(ntohs(*TID), TempAdress, TRUE);
                if(level > 0) cout << "客户端ID：" << TID << endl;

                memcpy(sendbuf, recvbuf, BUFFER_SIZE);    //拷贝请求报文
                reader = sendbuf;                               //reader起始位置为回应报文的起始位置

                int type_flag = 0;       //0为A 1为CNAME 2为AAAA
                if (strcmp(row[1], "0.0.0.0") == 0 || real_answer) {
                    cout << "没有答案" << endl;
                    reader += 2;
                    //如果没有answer就设置为0x8583
                    *(unsigned short *) reader = htons(0x8583);
                    reader += 4;
                    *(unsigned short *) reader = htons(0x0000);//answer_count
                    reader += 6 + strlen(DN) + 2 + 4;    //2包括头部数字和尾部结束符,4包括type和class
                    *(unsigned short *) reader = htons(0xc00c);//Name指针形式
                    reader += 2;
                    if (!strcmp(row[3], "A")) *(unsigned short *) reader = htons(0x0001);             //type(A)}
                    else if (!strcmp(row[3], "AAAA")) *(unsigned short *) reader = htons(0x001c);//type(AAAA)
                    else if (!strcmp(row[3], "CNAME"))
                        *(unsigned short *) reader = htons(0x0005);             //type(CNAME)
                    else if (!strcmp(row[3], "MX")) *(unsigned short *) reader = htons(0x000f);
                    else if (!strcmp(row[3], "PTR")) *(unsigned short *) reader = htons(0x000c);
                    reader += 2;
                    *(unsigned short *) reader = htons(0x0001);//class(IN)
                    reader += 2;
                    *(unsigned int *) reader = htonl(0x000001d6);//TTL
                    reader += 4;
                    *(unsigned short *) reader = htons(0x0004);//datalength(IP值为4)
                    reader += 2;
                    *(unsigned int *) reader = inet_addr("0.0.0.0");//IP地址
                } else {
                    if(level>1) cout << "数据库检索到" << "域名为" << row[0] << " answer为" << row[1] << " 类型为" << row[2] << endl;
                    reader += 2;
                    *(unsigned short *) reader = htons(0x8180);//flag
                    reader += 4;
                    *(unsigned short *) reader = htons(ip_num);//answer_count
                    reader += 6 + strlen(DN) + 2 + 4;    //2包括头部数字和尾部结束符,4包括type和class
                    *(unsigned short *) reader = htons(0xc00c);//Name指针形式
                    reader += 2;
                    if (!strcmp(row[2], "A")) {
                        *(unsigned short *) reader = htons(0x0001); //type(A)
                        type_flag = 0;
                    } else if (!strcmp(row[2], "AAAA")) {
                        *(unsigned short *) reader = htons(0x001c); //type(AAAA)
                        type_flag = 2;
                    } else if (!strcmp(row[2], "CNAME")) {
                        *(unsigned short *) reader = htons(0x0005); //type(CNAME)
                        type_flag = 1;
                    } else if (!strcmp(row[2], "MX")) {
                        *(unsigned short *) reader = htons(0x000f); //type(MX)
                        type_flag = 3;
                    } else if (!strcmp(row[2], "PTR")) {
                        *(unsigned short *) reader = htons(0x000c); //type(PTR)
                        type_flag = 4;
                    }
                    reader += 2;
                    *(unsigned short *) reader = htons(0x0001);//class(IN)
                    reader += 2;
                    *(unsigned int *) reader = htonl(0x000001d6);//TTL
                    reader += 4;

                    if (type_flag == 0) {
                        *(unsigned short *) reader = htons(0x0004);//如果answer是A类型 则ip占用四字节
                        reader += 2;
                        *(unsigned int *) reader = inet_addr(row[1]);//IP地址
                        reader += 4;
                    } else if (type_flag == 1 || type_flag == 3 ||
                               type_flag == 4) {                  //如果answer是CNAME 则占据字节数取决于域名 回应报文不采用offset
                        unsigned short datalength = (unsigned short) (strlen(row[1]) + 2);


                        if (type_flag == 3) {
                            *(unsigned short *) reader = htons(datalength + 2);
                            reader += 2;
                            *(unsigned short *) reader = htons(atoi(row[4]));
                            reader += 2;
                        } else {
                            *(unsigned short *) reader = htons(datalength);
                            reader += 2;
                        }

                        int pt = 0;
                        unsigned short data;

                        while (pt < datalength - 3) {           //实则为pt<（datalength-2）-1
                            int count = 0;
                            int partlength;
                            while (row[1][pt] != '.' && row[1][pt] != '\0') {  //获取每段的长度
                                pt++;
                                count++;
                            }
                            partlength = count;
                            //奇数长和偶数长要区别处理  因为htons转变两字节 对于奇数长要特别处理
                            if ((partlength + 1) % 2 == 0) {
                                data = (unsigned short) (partlength << 8) +
                                       (unsigned short) (row[1][pt - count]);  //每个字母占一字节  但是htons转变两字节  因此两个字母合一起
                                *(unsigned short *) reader = htons(data);
                                reader += 2;
                                int i = 1;
                                while (i < count) {
                                    data = (unsigned short) (row[1][pt - count + i] << 8) +  //想靠前的数据在高8位
                                           ((unsigned short) row[1][pt - count + i + 1]);
                                    *(unsigned short *) reader = htons(data);
                                    reader += 2;
                                    i += 2;
                                }
                            } else {            //奇数长
                                data = (unsigned short) (partlength << 8);
                                *(unsigned short *) reader = htons(data);
                                reader += 1;        //只增加一字节  使得后续数据覆盖为了写入partlength而多写的一位
                                int i = 0;
                                while (i < count) {
                                    data = (unsigned short) (row[1][pt - count + i] << 8) +
                                           ((unsigned short) row[1][pt - count + i + 1]);
                                    *(unsigned short *) reader = htons(data);
                                    reader += 2;
                                    i += 2;
                                }
                            }
                            pt++;
                        }
                        *(unsigned short *) reader = htons(0x0000); //最后00结尾 最后只加一位  让后面覆盖多余的00
                        reader += 1;
                    }//一个转换函数
                    else if (type_flag == 2) {

                        *(unsigned short *) reader = htons(0x0010); //ipv6的ip地址长为16字节
                        reader += 2;
                        char temp_ch[9];
                        unsigned int temp_int;
                        for (int i = 0; i < 4; i++) {
                            strncpy(temp_ch, row[1] + i * 8, 8); //每四节写入一次

                            temp_int = strtoul(temp_ch, NULL, 16); //字符串=》整型

                            *(unsigned int *) reader = htonl(temp_int);
                            reader += 4;
                        }
                    }

                    if (ip_num > 1) {               //当有多个答案时
                        unsigned short temp;
                        for (int i = 1; i < ip_num; i++) {
                            unsigned short datalength = strlen(row[1]) + 2;
                            unsigned short distance;
                            row = mysql_fetch_row(res);
                            if(level>1) cout << "数据库检索到" << "域名为" << row[0] << " answer为" << row[1] << " 类型为" << row[2] << endl;
                            *(unsigned short *) reader = htons(0xc00c);//Name指针形式
                            reader += 1;
                            if (type_flag == 0) {                                  //连续的A  域名相对位置保持为最后一个CNAME的offset
                                *(unsigned short *) reader = htons(temp);
                            } else if (type_flag == 1) {
                                distance = (unsigned short) (((reader - sendbuf) - 1 - datalength) << 8); //计算offset
                                temp = distance;
                                *(unsigned short *) reader = htons(distance);
                            } else if (type_flag == 2) {     //存疑 当有多个AAAA时  处理应当同于A  没再抓到符合条件的response包
                                *(unsigned short *) reader = htons(temp);
                            } else if (type_flag == 3) {
                                *(unsigned short *) reader = htons(0x0c00);
                            }

                            //算出当前answer的type
                            if (!strcmp(row[2], "A")) {     //type(A)
                                type_flag = 0;
                            } else if (!strcmp(row[2], "AAAA")) {     //type(AAAA)
                                type_flag = 2;
                            } else if (!strcmp(row[2], "CNAME")) {     //type(CNAME)
                                type_flag = 1;
                            } else if (!strcmp(row[2], "MX")) {     //type(CNAME)
                                type_flag = 3;
                            }

                            reader += 1;

                            if (type_flag == 0) {
                                *(unsigned short *) reader = htons(0x0001);
                            }//type(A)
                            else if (type_flag == 2) {
                                *(unsigned short *) reader = htons(0x001c);
                            }//type(AAAA)
                            else if (type_flag == 1) {
                                *(unsigned short *) reader = htons(0x0005);//type(CNAME)
                            } else if (type_flag == 3) {
                                *(unsigned short *) reader = htons(0x000f);//type(MX)
                            }
                            reader += 2;
                            *(unsigned short *) reader = htons(0x0001);//class(IN)
                            reader += 2;
                            *(unsigned int *) reader = htonl(0x000001d6);//TTL
                            reader += 4;
                            if (type_flag == 0) {
                                *(unsigned short *) reader = htons(0x0004);//datalength(IP值为4)
                                reader += 2;
                                *(unsigned int *) reader = inet_addr(row[1]);//IP地址
                                reader += 4;
                            } else if (type_flag == 1 || type_flag == 3) {
                                unsigned short datalength = (unsigned short) (strlen(row[1]) + 2);   //整体要占的字节长度
                                if (type_flag == 3) {
                                    *(unsigned short *) reader = htons(
                                            datalength + 2);      //preference也算在datalength中！！！！
                                    reader += 2;
                                    *(unsigned short *) reader = htons(atoi(row[4]));
                                    reader += 2;
                                } else {
                                    unsigned short datalength = (unsigned short) (strlen(row[1]) + 2);   //整体要占的字节长度
                                    *(unsigned short *) reader = htons(datalength);
                                    reader += 2;
                                }
                                int pt = 0;
                                unsigned short data;
                                while (pt < datalength - 3) {
                                    int count = 0;
                                    int partlength;
                                    while (row[1][pt] != '.' && row[1][pt] != '\0') {
                                        pt++;
                                        count++;
                                    }
                                    partlength = count;
                                    if ((partlength + 1) % 2 ==
                                        0) {                    //字节分奇数偶数   对于整体（指明个数+正文）为奇数的 要单独处理
                                        // 因为最小的转换为两字节 让后一个覆盖
                                        data = (unsigned short) (partlength << 8) +
                                               (unsigned short) (row[1][pt - count]);  //区分大小端  主机与网络相反  想放前的在高8位
                                        *(unsigned short *) reader = htons(data);
                                        reader += 2;
                                        int i = 1;
                                        while (i < count) {
                                            data = (unsigned short) (row[1][pt - count + i] << 8) +
                                                   ((unsigned short) row[1][pt - count + i + 1]);
                                            *(unsigned short *) reader = htons(data);
                                            reader += 2;
                                            i += 2;
                                        }
                                    } else {
                                        data = (unsigned short) (partlength << 8);
                                        *(unsigned short *) reader = htons(data);
                                        reader += 1;
                                        int i = 0;
                                        while (i < count) {
                                            data = (unsigned short) (row[1][pt - count + i] << 8) +
                                                   ((unsigned short) row[1][pt - count + i + 1]);
                                            *(unsigned short *) reader = htons(data);
                                            reader += 2;
                                            i += 2;
                                        }
                                    }
                                    pt++;
                                }
                                *(unsigned short *) reader = htons(0x0000);   //最后00结尾 最后只加一位  让后面覆盖多余的00
                                reader += 1;
                            } else if (type_flag == 2) {
                                *(unsigned short *) reader = htons(0x0010);
                                reader += 2;
                                char temp_ch[9];
                                unsigned int temp_int;
                                for (int i = 0; i < 4; i++) {
                                    strncpy(temp_ch, row[1] + i * 8, 8);
                                    temp_int = strtoul(temp_ch, NULL, 16);
                                    *(unsigned int *) reader = htonl(temp_int);
                                    reader += 4;
                                }
                            }
                        }
                    }
                }
                sendto(Local, sendbuf, BUFFER_SIZE, 0, (SOCKADDR *) &TempAdress, sizeof(TempAdress));
                cout << "本地查询结果已发送给请求者" << endl;

            }
        }



    }
    closesocket(Outer);    //关闭套接字
    closesocket(Local);//关闭套接字
    WSACleanup();                //释放ws2_32.dll动态链接库初始化时分配的资源
    return 0;
}