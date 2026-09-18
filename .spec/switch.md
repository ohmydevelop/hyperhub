这是一个模型网关，目标实现任意协议之间的转换，在 agent 到任意模型提供商之间的链接
实现协议 IR 协议
支持chat，response，message协议实现IR前后端，类似 LLVM IR思想

监听 127.0.0.1 http 端口

每种协议只需要实现IR编码和解码，这样就能实现任意协议之间的转换

交互

配置provider
api：
key：

配置模型bridge
input：模型名称
output：模型名称
upstream：选择一个provider，然后选择一个模型自动探测（api + key + 模型探测支持的协议类型）

新增
HTTP -> [message，response，chat]

协议栈需要传入数据，回调审计函数，
model_name --> provider --> model_name

将response和message、chat
进入serve协议栈

新增模型转换插件

