set pagination off
set confirm off
target remote :1234
hbreak *0x803d189c
continue
set $alt = *(unsigned long *)($r0 + 4)
set $eps = *(unsigned long *)($alt + 20)
printf "eps=%#x chunk25=%#x\n", $eps, $eps + 25*44
x/16xw $eps + 25*44
hbreak *($eps + 25*44)
continue
info registers r4 pc
x/xw $r4 + 0x180
stepi
info registers pc
stepi
info registers pc
