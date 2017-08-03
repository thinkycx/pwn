## 基础知识
<http://cb.drops.wiki/drops/tips-14465.html>   
<http://cb.drops.wiki/drops/tips-16063.html>  
<http://cb.drops.wiki/drops/tips-7326.html>  
<http://cb.drops.wiki/drops/tips-16610.html> 


## 思路
1. allocate chunk 1 2 3 4 (124 248 128 128 or 124 248 248 both ok)
2. forge in chunk 1 with a fake  freed chunk( **arrange fd bk to pass check in unlink**) and let \x00 overflow chunk 2 size 
3. free chunk 2 and unlink chunk 1 to change p[0](heap pointer array) setted to 0x804a094( also before &p[0] is ok)
4. edit chunk 1 and rewrite p[0] setted to free_got
5. edit chunk 1 and write free_got setted to system_addr
6. edit chunk 3 with /bin/sh
7. free chunk 3 to call system(/bin/sh) (chunk 4 size flag P must be 1)

## 分析

利用fsb计算libc的加载基址，可得libc中函数的实际地址，如system。

程序可分配最多5个堆块，chunk malloc大小可以是124（chunk size 0x80）和248（chunk size 0x100）。   
查看chunk size的大小，需要结合chunk结构看，8*n+4，是否满足，如果是，chunk size则为8*n。
EDIT函数在编辑chunk时，scanf函数可以输入124byte或者248byte。

edit 124chunk时，输出的长度可以溢出next chunk的presize。  
scanf溢出的一个字节"\x00"有可能溢出next chunk size的低两位个字节，造成当前chunk被认为是free的。  
edit 248 chunk时，无法溢出到下一个堆块。  

chunk的指针都保存在p数组中。edit函数，根据p来定位chunk，并进行修改。  
如果可以修改例如p[0]的内容也就是first chunk的指针，就可以造成p[0]位置的任意写。  
例如，修改p[0]为free_got addr，edit时就可以劫持了free函数，修改为另一个函数的实际地址，如system。  
下次调用free时，就相当于执行了system。  

如何修改p[0]的内容呢？free chunk时的unlink操作可以实现固定地址写。  
指向first chunk的ptr的地址为0x804a0a0。在first chunk 伪造堆块并溢出next chunk 再free next chunk 就可以unlink first chunk。  

通过free chunk2 来unlink chunk 1伪造first chunk的fd和bk为 ptr-0xc ptr-x0x8。free时unlink函数中在if条件的check时，赋值之后的FD和BK，FD->bk == BK->fd 都是0x804a0a0。
```
        FD->bk = BK;							      
        BK->fd = FD;	
```
因此0x804a0a0处的值为FD，也就是0x804a094。即，p[0]=0x804a094。  
注，由于free chunk2，p[1]=0x0，对解题无影响。

继续edit时，修改first chunk为 'a'*0x12 + got addr。此时，p[0]=got addr。  
继续edit first chunk，即完成向got addr写数据。

在first chunk伪造一个free的堆块（注意修改size、fd、bk和next chunk的presize），同时溢出second chunk的size的低两位字节（因此first 和second chunk size只能是 0x80 和0x100，同时third chunk不能为free，要求forth chunk size的P为1）。这时free second时，才会对first chunk unlink。因此，申请三个chunk。edit first chunk 伪造一个free的chunk，同时溢出下一个free的chunk。之后free second chunk，由于first chunk是伪造的free chunk。因此，会对first chunk unlink。

