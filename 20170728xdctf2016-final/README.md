## 整数溢出 +　UAF
第一处整数溢出在判断dollar时触发，通过对buy和sell来溢出int 15，绕过对unsigned int的判断。  

UAF:func4 malloc了1024个字节后free。check函数中重用了堆块，先向堆块写入10个字节，后判断第十一个字节是否是'1'，传入第十二个字节处的地址作为system函数的参数。因此可以在func4处构造payload，造成在check中复用。