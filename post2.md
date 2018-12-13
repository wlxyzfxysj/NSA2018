动态源路由协议DSR （Dynamic Source Routing）
DSR的特点在于使用了源路由的路由机制，在每一个分组的头部都携带整条路由的信息，路由器按照该路由纪录来转发分组。这种机制最初被IEEE802.5协议用在由桥互连的多个令牌环网中寻找路由。
DSR借鉴该机制，并结合了按需路由的思想。DSR协议使用源路由，采用Cache（缓冲器）存放路
由信息，且中间节点不必存储转发分组所需的路由信息，网络开销较少，但存在陈旧路由。


Dynamic Source Routing 按需路由
节点需要发送数据时才进行路由发现过程
反应型路由，仅维护活跃的路由


源路由
发送节点在分组中携带到达目的节点的路由信息（转发分组的完整的节点序列）– 不需要中间节点维护路由息
节点缓存到目的节点的多条路由– 避免了在每次路由中断时都需要进行路由发现，因此能够对拓扑变化作出更快的反应。


路由发现（Route Discovery）
只有在源节点需要发送数据时才启动
帮助源节点获得到达目的节点的路由


路由维护（Route Maintenance）
在源节点在给目的节点发送数据时监测当前路由的可用情况
当网络拓扑变化导致路由故障时切换到另一条路由或者重新发起路由发现过程


路由发现和路由维护都是按需进行的
不需要周期性路由公告
不需要感知链路状态
不需要邻居检测
DSR协议操作
（1）路由发现
当一个节点欲发送数据到目的节点时，它首先查询路由缓冲器是否有到目的节点的路由。如果
有，则按此路由发送数据；如果没有，源节点就开始启动路由发现程序。路由发现过程中使用
洪泛路由（Flooding Routing）。

路由发现的具体处理过程：
当节点S需要向节点D发送数据, 但不知到节点D的路由，于是节点S就开始路由发现过程。源节点S洪泛“路由请求”分组Route Request (RREQ)，每个请求分组通过序列号和源节点S标识唯一确定。

DSR路由发现：路由请求
源节点向邻居节点广播路由请求（RREQ：Route Request）目的节点地址
路由记录：纪录从源节点到目的节点路由中的中间节点请求ID
中间节点接收到RREQ后，将自己的地址附在路由纪录中



DSR路由发现：中间节点处理
中间节点维护<源节点地址、请求ID>序列对列表
重复RREQ检测
如果接收到的RREQ消息中的<源节点地址、请求ID>存在于本节点的序列对列表中
如果接收到的RREQ消息中的路由纪录中包含本节点的地址
如果检测到重复，则中间节点丢弃该RREQ消息



DSR路由发现：路由应答
目的节点收到RREQ后，给源节点返回路由应答（RREPRoute Reply）消息
拷贝RREQ消息中的路由纪录
源节点收到RREP后在本地路由缓存中缓存路由信息

 

 



总结：收到“路由请求”分组的节点，若满足：
1、该节点不是目的节点D；
2、请求分组头部的源路由序列中不包含该节点；
3、该节点没有接收过同样的路由请求分组；
4、节点的路由表中没有目的节点D的路由信息；节点将自己的地址附加到“路由请求”分组头部的路由纪录中，并将该分组转发给所有相邻节点。
若RREQ分组在最近收到的“历史RREQ列表”中存在、或路由纪录中包括本节点，此节点将删除该“路由请求”分组，防止循环处理和出现路由环路。
若该节点不是目的节点D，节点路由表中记录有到目的节点D的路由信息，节点将发送“路由应答”RREP分组给节点S，应答中包含了从节点S到节点D的路由。
若该节点就是目的节点D，则发送RREP分组给节点S。节点S获得路由后，使用源路由进行数据通信。


DSR路由维护
逐跳证实机制
链路层
确认
被动确认（监听其它节点间的数据发送）
其它高层
要求DSR软件返回确认
端到端证实机制
无法确定故障发生的位置
DSR 逐跳证实机制
DSR路由维护
如果数据分组被重发了最大次数仍然没有收到下一跳的确认，则节点向源端发送路由错误
（Route Error）消息，并且指明中断的链路
源端将该路由从路由缓存中删除
如果源端路由缓存中存在另一条到目的节点的路由则使用该路由重发分组
否则重新开始路由发现过程




DSR路由应答（链路为双向的）：
（1）当目的节点D一接到RREQ分组，就发送RREP分组
（2）RREP分组中包含有RREQ分组中从源节点S到目的节点的路由纪录（前向路）
（3）RREP分组按RREQ分组的路由纪录进行反向传送。
DSR路由应答（链路为单向的）：
此时，目的节点执行和源节点相同的路由发现过程，
所不同的的是，目的节点的RREQ分组捎带传送RREP分组。
DSR的路由缓存
（1）当源节点S接到RREP分组后，就将RREP分组中从源节点S到目的节点D的路由信息进行缓存
（2）当源节点S向目的节点D发送数据分组时，此路由信息就包含在每个分组的头部。
（3）所有的中间节点利用源路由信息进行分组转发。






DSR 协议特点
1）节点不需要周期性的发送路由广播分组，无需维护去往全网所有节点的路由信息，能自然而然的消除路由环路，而且能提供多条路由，可用于单向信道；
2）支持中间节点的应答，能使源节点快速获得路由，但会引起过时路由问题；
3）每个分组都需要携带完整的路由信息，造成开销较大，降低了网络带宽的利用率，不适合网络直径大的自组网，网络扩展性不强；
DSR优化：路由缓存
每个节点缓存它通过任何方式获得的新路由
转发RREQ
获得从本节点到RREQ路由记录中所有节点的路由，例如E转发RREQ(A-B-C)获得到到A的路由(C-B-A)
转发RREP
获得本节点到RREP路由纪录中所有节点的路由，例如B转发RREP(A-B-C-D)获得到D的路由(C-D)
转发数据分组
获得从本节点到数据分组节点列表中所有节点的路由，例如E转发数据分组(A-B-C)获得到A的路由(C-B-A)
监听相邻节点发送的分组
RREQ、RREP、数据分组等




中间节点使用缓存的到目的节点的路由响应RREQ
RREP中的路由纪录=RREQ中的路由纪录+缓存的到目的节点的路由



错误路由缓存
网络拓扑的变化使得缓存的路由失效
影响和感染其它节点，使用该路由缓存的路由将不可用
当节点根据路由缓存回应RREP时，其它监听到此RREP的节点会更改自己缓存的路由，从而感染错误路由缓存
设置缓存路由的有效期，过期即删除
RREP风暴
节点广播到某个目的节点的RREQ，当其邻居节点的路由缓存中都有到该目的节点的路由时，每个邻居节点都试图以自己缓存的路由响应，由此造成RREP风暴

RREP风暴将浪费网络带宽，并且加剧局部网络冲突



预防RREP风暴
每个节点延时D发送RREP

D=H *（h-1+r）
其中H是每条链路的传播延时h是自己返回的路径长度，即到目的节点的跳数r是0或者1
D与节点到目的节点的跳数成正比，使得到目的节点有最短路径的RREP最先发送
节点将接口设置成混杂模式(promiscuous)，监听是否存在有比自己更短的到目的节点的路径，如果有，则不发送本节点的RREP
DSR协议的优缺点
优点:
采用源路由机制、避免了路由环路。
它是一种按需路由协议、只有当两个节点间进行通信时，才会缓存路由纪录，因此相对主动路由来说，减小了路由维护的开销。
通过采用路由缓存技术，减少路由请求信息对信道的占用
缺点:
随着路经跳数的增加，分组头长度线性增加、开销大
路由请求分组RREQ采用洪泛发向全网扩散，导致网络负荷大
来自邻居节点的RREQ分组在某个节点可能会发生碰撞，解决办法是：在发送RREQ分组时引入随机时延
当源节点发送路由请求分组RREQ时，可能会收到多个节点缓存的到达目的节点的路由信息，引起竞争。解决办法：若某节点听到其它节点发出的RREQ分组中路由信息含有较少跳数，此节点停止发送。
当源节点发送路由请求分组RREQ时，可能会收到多个节点缓存的到达目的节点的路由信息，但有些路由信息可能是过时的。解决办法：引入定时器、链路断的情况应进行全网洪泛。