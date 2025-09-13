# Test code in the Cent OS
.section .data
message:
    .asciz "Hello, World!\n"

.section .text
.global _start

_start:
    # Write system call
    mov $1, %rax                # syscall: write
    mov $1, %rdi                # file descriptor: stdout
    lea message(%rip), %rsi     # pointer to the message
    mov $14, %rdx               # length of the message
    syscall

    # Exit system call
    mov $60, %rax               # syscall: exit
    xor %rdi, %rdi              # exit code: 0
    syscall
