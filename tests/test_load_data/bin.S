.section .data          /* the .data section is dynamically created and its addresses cannot be easily predicted */
    var1: .int 0x870      /* variable 1 in memory */




.section .text          /* start of the text (code) section */ 
    .global main

main:
    ldr x0, var1
    mov x1, x0






