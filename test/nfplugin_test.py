from nfstream import NFStreamer, NFPlugin


class my_awesome_plugin(NFPlugin):
    # 瞎写用来测试怎么传递参数给super的
    def __init__(self, limit, **kwargs):
        super().__init__(**kwargs)
        if limit > 2:
            print(2)

    def on_init(self, packet, flow):
        # 创建新的属性使用 flow.udps.xxx
        # on_init进行属性初始化
        flow.udps.label = 0
        flow.udps.cate = 0
        # print(self.kk)

    def on_update(self, packet, flow):
        # on_update 进行属性值的更新，可以自己设定条件
        flow.udps.label = 0
        flow.udps.cate = 0
        # print("on_update",self.kk)


# 在下文中，我们实现了一个流切片器NFPlugin，
# 它将强制NFStream使每个达到数据包计数限制的流过期(即让expiration_id=-1)。
class FlowSlicer(NFPlugin):
    def on_init(self, packet, flow):
        if self.limit == 1:
           flow.expiration_id = -1

    def on_update(self, packet, flow):
        if self.limit == flow.bidirectional_packets:
           flow.expiration_id = -1 # -1 value force expiration


# streamer = NFStreamer(source="eth0", udps=FlowSlicer(limit=7))
# >7个packet，flow过期，限制一个flow中包的个数
# 在参数中写的limit=7，因为没有重定义__init__()所以使用父类里的__init__()
# 父类中setattr即设置新属性，在接下来的函数重写中可以使用self.limit进行调用


if __name__ == "__main__":
    streamer_awesome = NFStreamer(source='temp.pcap', udps=my_awesome_plugin(4,kk=2)).to_pandas()
    for flow in streamer_awesome:
        print(flow)  # see your dynamically created metric in generated flows