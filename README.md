url_recorder
===========

把HTTP请求的URL全部记录下来，我是在vps上用的~~
日志记录在 “/var/log/url_record.txt”
程序守护进程方式运行在后台

改进：不再网络出口抓包。

只支持pptp类型的vpn，每个vpn用户登录的时候，系统会创建一个虚拟网卡pppx，
程序捕获到事件后会自动一个线程针对这个虚拟网卡抓包

无vpn用户的时候不工作







<pre><code>
Debian/Ubuntu: apt-get install libpcap-dev -y
CentOS:yum install libpcap-devel -y

然后
gcc -o url_recorder url_recorder.c -lpcap -lpthread

需要root权限
./url_recorder 
</code></pre>
