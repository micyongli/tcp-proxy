
物联网调试助手

示例：

1、服务端：
  tcp-proxy -i 0.0.0.0:9000 -p xx.yy.zz.aa:9001

2、终端：
  tcp-proxy -t 127.0.0.1:9000 -p xx.yy.zz.aa:9001

注：传入服务端9000端口的数据会转发至终端的9000，双向传输。

