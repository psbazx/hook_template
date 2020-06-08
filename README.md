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
//TO DO
