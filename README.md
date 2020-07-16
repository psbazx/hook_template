# hook_template  
环境win10 vs2019  
## IAT HOOK  
简单来说就是修改IAT表地址  
最好配合dll注入来使用(这边用的是之前使用的远程线程注入)  
但是存在缺陷就是只能hook库函数不能hook所有函数  
## INLINE HOOK  
相对iat hook来说比较灵活可以hook任意函数  
修改机器码  
比如直接改jmp或者push|ret来实现跳转  
## X64 SSDT HOOK  
踩的坑还挺多。。。  像一般都是hook蓝屏函数，但是我的win10版本这个函数不在ssdt表里，超出了base周围哪4gb范围，只能换其他的hook，这边选择的是ZwAddBootEntry，经测试没啥大问题。  
绕pg是不可能的，虚拟机版本win10 1903 18362.959


