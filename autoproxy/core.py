from pwn import *
import time



class AutoProxy:
    def __init__(self):
        self.ProxyDic = "./venom/"
        self.FakePort = 4444
        self.CurrentNum=0
        self.CurrentNode = []
        self.TargetIp={}
        self.CurrentSocks={}
        self.log_file = time.strftime("log_%m%d-%H%M.txt", time.localtime())
        self.AdminProcess = self.SetUp()
        


    def Write(self,log_data):
        with open("./log/%s"%(self.log_file), "a") as f:
            log_data = str(log_data)
            localtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
            f.write("%s: %s"%(localtime, str(log_data)))
            f.write('\n')
            f.close()

    def StartFakeAgent(self):
        FakeAgentApp = "agent_linux_x64"
        FakeAgentAppAll = self.ProxyDic+FakeAgentApp

        FakeAgentProcess = process([FakeAgentAppAll,"-lport",str(self.FakePort)]) # start a process
        return FakeAgentProcess

    def StartAdmin(self,ip="127.0.0.1"):
        AdminApp = "admin_linux_x64"
        AdminAppAll = self.ProxyDic+AdminApp

        AdminProcess = process([AdminAppAll,"-rhost",ip,"-rport",str(self.FakePort)])
        self.CurrentNum += 1
        self.TargetIp[self.CurrentNum] = ip
        return AdminProcess
    
    def SetUp(self):
        self.StartFakeAgent()
        AdminProcess = self.StartAdmin()
        time.sleep(1)
        AdminProcess.recvuntil(">>> ") # recv a message from process
        AdminProcess.sendline("show")  # send a message to process
        AdminProcess.recvuntil("1")
        AdminProcess.recvuntil(">>> ")
        AdminProcess.sendline("goto 1")
        self.Write("Start AutoProxy")
        return AdminProcess
        
    def Show(self):
        self.AdminProcess.recvuntil(">>> ")
        self.AdminProcess.sendline("show")
        result = bytes.decode(self.AdminProcess.recvuntil("(")[:-1])
       
        
        CurrentNode = self.HandleInfo(result)
        self.NodeMonitor(CurrentNode)
        self.CurrentNode = CurrentNode

        self.Write(result)
        self.Write(str(self.TargetIp))
        print(result)
        print(self.TargetIp)
        return result

    def HandleInfo(self,info):
        result = []
        info = info.split("+ -- ")
        for i in info[1:]:
            result.append(int(i[0]))
        return result

    def Ip2Node(self,ip):
        result = -1
        for i in self.TargetIp:
            if self.TargetIp[i] == ip:
                result = i
                break
        if result == -1:
            print("Ip2Node failed: ip %s could not found"%(ip))
            pass
        return result
    
    def Node2Ip(self,node):
        result = self.TargetIp[node]
        return result

    def GotoNode(self,dest):
        if type(dest) == type("ip"):
            node = self.Ip2Node(dest)
            self.AdminProcess.recvuntil(">>> ")
            self.AdminProcess.sendline("goto %s"%(str(node)))
            self.Write("goto ip %s:%s"%(str(node),dest))
        elif type(dest) == type(1):
            self.AdminProcess.recvuntil(">>> ")
            self.AdminProcess.sendline("goto %s"%(str(dest)))
            self.Write("goto node %s:%s"%(str(dest),self.Node2Ip(dest)))

    def AddNode(self,srcip="127.0.0.1",desip="127.0.0.1",port=5555):
        self.GotoNode(srcip)
        self.AdminProcess.recvuntil(">>> ")
        self.AdminProcess.sendline("connect %s %s"%(desip, str(port)))
        connect_info = "connect %s %s"%(desip, str(port))
        self.CurrentNum += 1
        self.TargetIp[self.CurrentNum] = desip
        time.sleep(1)
        self.Write(connect_info)
        self.GotoNode(1)

    def NodeMonitor(self,Nodelist):
        if len(Nodelist) < len(self.CurrentNode):
            for i in self.CurrentNode:
                try:
                    Nodelist.index(i)
                except ValueError:
                    self.Write("[-] Lost node %s : %s"%(i,self.Node2Ip(i)))
                    self.TargetIp.pop(i)

    def Proxy(self,ip="192.168.254.132",port=5555):
        self.GotoNode(ip)
        self.AdminProcess.recvuntil(">>> ")
        self.AdminProcess.sendline("socks %s" % str(port))
        socks_info = "socks %s" % str(port)
        self.Write(socks_info)
        with open("./venom/proxychains.tmp", "r") as p1:
            content1 = p1.read()
            content2 = content1.replace("DEADBEEF",str(port))
            with open("/etc/proxychains.conf", "a") as p2:
                p2.write(str(content2))
                p2.close()
            p1.close()

if __name__ == '__main__':
    autoproxy = AutoProxy()
    autoproxy.Show()
    autoproxy.AddNode(desip="192.168.254.132")
    autoproxy.Show()
    print("debug")
    raw_input()
    autoproxy.Show()
    autoproxy.Proxy()
