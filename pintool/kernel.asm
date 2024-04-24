bits 64
global _start

%define PINOP (0xbaddecaf << 32)
%define OP_SET_REG     0
%define OP_GET_CPUPATH 1
%define OP_GET_MEMPATH 2
%define OP_ABORT       3
%define OP_EXIT        4

%define SYS_read 0
%define SYS_write 1
%define SYS_open 2
%define SYS_close 3
%define SYS_mmap 9
%define SYS_munmap 11

%define O_RDWR 2

	; Puts the result in RAX.
%define INVOKE_PINOP(cmd) mov byte [rbx + cmd], 0

	; void get_cpupath(void *data, size_t size);

section .text
_start:
	; %rbx will always hold the PINOP base.
	mov rbx, PINOP

	; Get the CPU communication file path.
	mov rsi, 256
	sub rsp, rsi
	mov rdi, rsp
	INVOKE_PINOP(OP_GET_CPUPATH)

	; Open CPU comm file.
	mov eax, SYS_open
	mov rdi, rsp
	mov rsi, O_RDWR
	syscall
	cmp eax, 0
	jl abort
	mov [rel cpu_fd], eax
	add rsp, rsi

	; exit for now
	INVOKE_PINOP(OP_EXIT)
	int3

abort:
	INVOKE_PINOP(OP_ABORT)
	int3

section .bss
cpu_fd: dd 0
