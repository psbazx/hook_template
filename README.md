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
踩的坑还挺多。。。  像一般都是hook蓝屏函数，但是我的win10版本这个函数不在ssdt表里，只能换其他的hook，找了半天没找到合适的只能hook自己。。。但是因为写保护导致存在多核切换情况。。。只能给虚拟机分配单核，总之问题很多，但是只要找到合适函数改一下就能hook，绕过pg代码不能发  


