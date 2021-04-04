#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <mach/mach.h>
#include <pthread.h>
#include <signal.h>

#include "beaengine/BeaEngine.h"

/*****************************************************************************/ 
/*  Copyright:                                                               */
/*  Portcullis Computer Security Limited <labs@portcullis-security.com>      */
/*                                                                           */
/*  Author:                                                                  */
/*  Matthieu Bonetti - Twitter: @_frego_                                     */
/*  Security Consultant - Portcullis Computer Security Limited.              */
/*                                                                           */
/* This program is free software: you can redistribute it and/or modify      */
/* it under the terms of the GNU General Public License as published by      */
/* the Free Software Foundation, either version 3 of the License, or         */
/* (at your option) any later version.                                       */
/*                                                                           */
/* This program is distributed in the hope that it will be useful,           */
/* but WITHOUT ANY WARRANTY; without even the implied warranty of            */
/* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             */
/* GNU General Public License for more details.                              */
/*                                                                           */
/* You should have received a copy of the GNU General Public License         */
/* along with this program.  If not, see <http://www.gnu.org/licenses/>.     */
/*                                                                           */
/*                                                                           */
/* This program aims to catch crashes from OSX applications and print        */
/* debugging information such as registers, disassembled code and a memory   */
/* dump of the stack.                                                        */
/*                                                                           */
/* It works on both x86 and x86_64 architectures.                            */
/*****************************************************************************/

#define APP_NAME "crash"
#define APP_VERSION "1.0"

/*****************************************************************************/
/* Definitions.                                                              */
/*****************************************************************************/

/* Configuration */
typedef struct 
{
    int timeout;
    pid_t pid;
} config_t;
config_t config;

/* Exception port for the debuggee. */
mach_port_t debuggee_port = MACH_PORT_NULL;

/* There is no public header for this function. */
extern boolean_t exc_server(mach_msg_header_t *, mach_msg_header_t *);

void
die(int code)
{
    kill(config.pid, 9);
    exit(code);
}

#define exit_error() { perror("[-] error"); die(255); }
#define EXIT_ON_MACH_ERROR(m, r) \
if(r != KERN_SUCCESS) { mach_error(m ":", r); die(255); }
#define EXIT_ON_MSG_ERROR(m, r) \
if(r != MACH_MSG_SUCCESS) { mach_error(m ":", r); die(255); }

/*****************************************************************************/
/* Debugger.                                                                 */
/*****************************************************************************/

vm_size_t
dbg_read_memory(mach_port_t port, 
                vm_address_t address,
                pointer_t buf,
                int size)
{
    kern_return_t err;
    vm_size_t nread;

    err = vm_read_overwrite(port, address, size, buf, &nread);
    if (err != KERN_SUCCESS)
    {
        printf("[-] Could not read memory at 0x%lx.\n", address);
        mach_error("", err);
        return 0;
    }

    return nread;
}

void
dbg_get_regs_x86(mach_port_t port, x86_thread_state32_t *state)
{
    kern_return_t err = -1;
    
    
    mach_msg_type_number_t state_count = x86_THREAD_STATE32_COUNT;
    
    err= thread_get_state(port,
                          x86_THREAD_STATE32,
                          (thread_state_t)state,
                          &state_count);
    EXIT_ON_MACH_ERROR("thread_get_state", err);

    return;
}

void
dbg_get_regs_x86_64(mach_port_t port, x86_thread_state64_t *state)
{
    kern_return_t err = -1;
    
    mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
    
    err= thread_get_state(port,
                          x86_THREAD_STATE64,
                          (thread_state_t)state,
                          &state_count);
    EXIT_ON_MACH_ERROR("thread_get_state", err);

    return;
}

vm_address_t
dbg_get_esp(mach_port_t port)
{
    x86_thread_state32_t state;
    dbg_get_regs_x86(port, &state);
    return state.__esp;
}

vm_address_t
dbg_get_eip(mach_port_t port)
{
    x86_thread_state32_t state;
    dbg_get_regs_x86(port, &state);
    return state.__eip;
}

vm_address_t
dbg_get_rsp(mach_port_t port)
{
    x86_thread_state64_t state;
    dbg_get_regs_x86_64(port, &state);
    return state.__rsp;
}

vm_address_t
dbg_get_rip(mach_port_t port)
{
    x86_thread_state64_t state;
    dbg_get_regs_x86_64(port, &state);
    return state.__rip;
}

/*****************************************************************************/
/* Output.                                                                   */
/*****************************************************************************/

#define STACK_LINES 8

void
dump_stack(mach_port_t port, mach_port_t task, int archi)
{
    vm_address_t sp = 0;
    char *buffer = NULL;
    unsigned long int *ptr = NULL;
    vm_size_t size = STACK_LINES * archi / 4;
    vm_size_t nread = 0;
    int i = 0;
    int j = 0;

    sp = (archi == 32) ? dbg_get_esp(port) : dbg_get_rsp(port);
    buffer = malloc(size);
    if (buffer == NULL)
        return;

    nread = dbg_read_memory(task, sp, (pointer_t)buffer, size);

    printf("Stack:\n");
   
    ptr = (unsigned long int *)buffer;
    for (i = 0 ; i < STACK_LINES ; i++)
    {
        unsigned char *c = (unsigned char *)ptr;

        if (archi == 64)
            printf("%.16lx: %.16lx  ", sp, *ptr);
        else
            printf("%.08x: %08x  ", (unsigned int)sp, (unsigned int)*ptr);

        for (j=0;j<archi/8;j++)
        {
            if (*c < 0x20 || *c > 0x7e)
                printf(".");
            else
                printf("%c", *c); 
            c++;
        }    

        printf("\n");

        ptr++;
        if (ptr > (unsigned long int *)(buffer+size))
            break;
    }

    free(buffer);

    return;
}

void
dump_register_x86_64(mach_port_t port)
{
    x86_thread_state64_t state;
    dbg_get_regs_x86_64(port, &state);

    printf("[ RAX: %.16lx  RBX: %.16lx  RCX: %.16lx  RDX: %.16lx ]\n", 
                                            (long unsigned int)state.__rax, 
                                            (long unsigned int)state.__rbx, 
                                            (long unsigned int)state.__rcx, 
                                            (long unsigned int)state.__rdx);
    printf("[ RSI: %.16lx  RDI: %.16lx  RBP: %.16lx  RSP: %.16lx ]\n", 
                                            (long unsigned int)state.__rsi, 
                                            (long unsigned int)state.__rdi, 
                                            (long unsigned int)state.__rbp, 
                                            (long unsigned int)state.__rsp);
    printf("[ R08: %.16lx  R09: %.16lx  R10: %.16lx  R11: %.16lx ]\n", 
                                            (long unsigned int)state.__r8, 
                                            (long unsigned int)state.__r9, 
                                            (long unsigned int)state.__r10, 
                                            (long unsigned int)state.__r11);
    printf("[ R12: %.16lx  R13: %.16lx  R14: %.16lx  R15: %.16lx ]\n",
                                            (long unsigned int)state.__r12, 
                                            (long unsigned int)state.__r13, 
                                            (long unsigned int)state.__r14, 
                                            (long unsigned int)state.__r15);

    printf("[     CS: %.4x      FS: %.4x      GS: %.4x      ", 
                                            (unsigned int)state.__cs, 
                                            (unsigned int)state.__fs,
                                            (unsigned int)state.__gs);  

    printf("RIP: %.16lx    %c %c %c %c %c %c %c %c %c   ]\n",
                    (long unsigned int)state.__rip,
                    (((unsigned int)state.__rflags >> 0xB) & 1) ? 'O' : 'o',
                    (((unsigned int)state.__rflags >> 0xA) & 1) ? 'D' : 'd',
                    (((unsigned int)state.__rflags >> 0x9) & 1) ? 'I' : 'i',
                    (((unsigned int)state.__rflags >> 0x8) & 1) ? 'T' : 't',
                    (((unsigned int)state.__rflags >> 0x7) & 1) ? 'S' : 's',
                    (((unsigned int)state.__rflags >> 0x6) & 1) ? 'Z' : 'Z',
                    (((unsigned int)state.__rflags >> 0x4) & 1) ? 'A' : 'a',
                    (((unsigned int)state.__rflags >> 0x2) & 1) ? 'P' : 'p',
                    (((unsigned int)state.__rflags >> 0x1) & 1) ? 'C' : 'c');

    printf("\n");   

    return;
}

void
dump_register_x86(mach_port_t port)
{
    x86_thread_state32_t state;
    dbg_get_regs_x86(port, &state);

    printf("[ EAX: %.8x  EBX: %.8x  ECX: %.8x  EDX: %.8x ]\n", 
                                            (unsigned int)state.__eax, 
                                            (unsigned int)state.__ebx, 
                                            (unsigned int)state.__ecx, 
                                            (unsigned int)state.__edx);
    printf("[ ESI: %.8x  EDI: %.8x  EBP: %.8x  ESP: %.8x ]\n", 
                                            (unsigned int)state.__esi,
                                            (unsigned int)state.__edi,
                                            (unsigned int)state.__ebp, 
                                            (unsigned int)state.__esp);
                                            
    printf("[ ES: %.4x  CS: %.4x  SS: %.4x  DS: %.4x  FS: %.4x  GS: %.4x ]\n", 
                                            (unsigned int)state.__es, 
                                            (unsigned int)state.__cs, 
                                            (unsigned int)state.__ss,
                                            (unsigned int)state.__ds,
                                            (unsigned int)state.__fs,
                                            (unsigned int)state.__gs);  

    printf("[ EIP: %.08x                            %c %c %c %c %c %c %c %c %c ]\n",
                    (unsigned int)state.__eip,
                    (((unsigned int)state.__eflags >> 0xB) & 1) ? 'O' : 'o',
                    (((unsigned int)state.__eflags >> 0xA) & 1) ? 'D' : 'd',
                    (((unsigned int)state.__eflags >> 0x9) & 1) ? 'I' : 'i',
                    (((unsigned int)state.__eflags >> 0x8) & 1) ? 'T' : 't',
                    (((unsigned int)state.__eflags >> 0x7) & 1) ? 'S' : 's',
                    (((unsigned int)state.__eflags >> 0x6) & 1) ? 'Z' : 'Z',
                    (((unsigned int)state.__eflags >> 0x4) & 1) ? 'A' : 'a',
                    (((unsigned int)state.__eflags >> 0x2) & 1) ? 'P' : 'p',
                    (((unsigned int)state.__eflags >> 0x1) & 1) ? 'C' : 'c');
                                              
    printf("\n");

    return;
}

/*****************************************************************************/
/* BeaEngine.                                                                */
/*****************************************************************************/

#define DISAS_BUFFER_SIZE 0x100
#define DISAS_LINE_COUNT 6

void disassemble_beaengine(vm_address_t address, 
                           pointer_t buf, 
                           vm_size_t size, 
                           int archi)
{
    DISASM MyDisasm;
    int len;
    int i = 0;

    /* Use BeaEngine to disassemble the code. */
    memset(&MyDisasm, 0, sizeof(DISASM));
    MyDisasm.EIP = (UIntPtr)buf;
    MyDisasm.VirtualAddr = address;
    MyDisasm.Archi = archi;
    MyDisasm.Options = Tabulation + NasmSyntax + PrefixedNumeral;
    
    for (i = 0; i < DISAS_LINE_COUNT ; i++)
    {
        MyDisasm.SecurityBlock = address + size - MyDisasm.EIP;
        len = Disasm(&MyDisasm);
        if (len == OUT_OF_BLOCK)
        {
            printf("out of block\n");
            break;
        }
        else if (len == UNKNOWN_OPCODE)
        {
            printf("unknown opcode\n");
            break;
        }
        else
        {
            printf("%.*lx: %s\n", 
                   archi/4,
                   MyDisasm.VirtualAddr, 
                   MyDisasm.CompleteInstr);
            MyDisasm.EIP += (UIntPtr)len;
            MyDisasm.VirtualAddr += len;
        }
    }

    return;
}

void
disassemble32(mach_port_t port, mach_port_t task)
{
    char buf[DISAS_BUFFER_SIZE];
    vm_size_t nread = 0;

    vm_address_t pc = dbg_get_eip(port);

    nread = dbg_read_memory(task, pc, (vm_address_t)&buf, DISAS_BUFFER_SIZE);
    if (nread == 0)
        return;

    disassemble_beaengine(pc, (pointer_t)&buf, DISAS_BUFFER_SIZE, 32);

    return;
}

void
disassemble64(mach_port_t port, mach_port_t task)
{
    char buf[DISAS_BUFFER_SIZE];
    vm_size_t nread = 0;

    vm_address_t pc = dbg_get_rip(port);

    nread = dbg_read_memory(task, pc, (vm_address_t)&buf, DISAS_BUFFER_SIZE);
    if (nread == 0)
        return;

    disassemble_beaengine(pc, (pointer_t)&buf, DISAS_BUFFER_SIZE, 64);

    return;
}

/*****************************************************************************/
/* Debugger.                                                                 */
/*****************************************************************************/

/* Return the debuggee's architecture. */
thread_state_flavor_t
arch_flavor(mach_port_t port)
{
    kern_return_t err = -1;
    mach_msg_type_number_t state_count = x86_THREAD_STATE_COUNT;
    x86_thread_state_t state;
    
    err = thread_get_state(port,
                           x86_THREAD_STATE,
                           (thread_state_t)&state,
                           &state_count);
    EXIT_ON_MACH_ERROR("thread_get_state", err);
    
    return state.tsh.flavor;
}

/* Catch Mach exceptions. */
kern_return_t
catch_exception_raise(mach_port_t port,
                      mach_port_t victim,
                      mach_port_t task,
                      exception_type_t exception,
                      exception_data_t code,
                      mach_msg_type_number_t code_count)
{
    /* This should not happen. */
    if (code_count < 1)
        die(255);

    printf("[+] Exception: ");
    switch(code[0])
    {
        case KERN_INVALID_ADDRESS:
            printf("KERN_INVALID_ADDRESS.\n");
            break;
        case KERN_PROTECTION_FAILURE:
            printf("KERN_PROTECTION_FAILURE.\n");
            break;
        default:
            printf("unknown exception code 0x%x.\n", code[0]);
            break;
    }

    switch(arch_flavor(victim))
    {
        case x86_THREAD_STATE64:
            printf("----------------------------------------------------------------------------------------------\n");
            dump_register_x86_64(victim);
            disassemble64(victim, task);
            printf("\n");
            dump_stack(victim, task, 64);
            printf("----------------------------------------------------------------------------------------------\n");
            break;
        case x86_THREAD_STATE32:
            printf("--------------------------------------------------------------\n");
            dump_register_x86(victim);
            disassemble32(victim, task);
            printf("\n");
            dump_stack(victim, task, 32);
            printf("--------------------------------------------------------------\n");
            break;
        default:
            printf("[-] Target architecture is not supported.");
            break;
    }

    return KERN_SUCCESS;
}

/* Standard Mach exception handler. It calls catch_exception_raise(). */
void
exception_handler(void)
{
    mach_msg_return_t err = -1;

    struct
    {
        mach_msg_header_t head;
        char data[256];
    } reply;

    struct 
    {
        mach_msg_header_t head;
        mach_msg_body_t msgh_body;
        char data[1024];
    } msg;


    err = mach_msg(&msg.head,
                   MACH_RCV_MSG | MACH_RCV_LARGE,
                   0,
                   sizeof(msg),
                   debuggee_port,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);
    EXIT_ON_MSG_ERROR("mach_msg", err);

    /* This calls catch_exception_raise(). */
    err = exc_server(&msg.head, &reply.head);

    /* We should die here. */
    if (err != KERN_SUCCESS)
        die(255);
    
    /* Send the reply */
    err = mach_msg(&reply.head,
                   MACH_SEND_MSG,
                   reply.head.msgh_size,
                   0,
                   MACH_PORT_NULL,
                   MACH_MSG_TIMEOUT_NONE,
                   MACH_PORT_NULL);
    EXIT_ON_MSG_ERROR("mach_msg", err);

    pthread_exit((void *)NULL);

    return;
}   

/* The debugger is a special thread that is being attached to the debuggee. */
void
setup_debugger(pid_t pid)
{
    kern_return_t err = -1;
    mach_port_t self = MACH_PORT_NULL;
    mach_port_t target = MACH_PORT_NULL;
    pthread_t exception_thread;

    self = mach_task_self();
    
    /* Allocate port for exceptions. */
    err = mach_port_allocate(self, 
                             MACH_PORT_RIGHT_RECEIVE, 
                             &debuggee_port);
    EXIT_ON_MACH_ERROR("mach_port_allocate", err);

    err = mach_port_insert_right(self, 
                                 debuggee_port,
                                 debuggee_port,
                                 MACH_MSG_TYPE_MAKE_SEND);
    EXIT_ON_MACH_ERROR("mach_port_insert_right", err);

    /* Set the exception port for pid. */
    err = task_for_pid(self, pid, &target);
    EXIT_ON_MACH_ERROR("task_for_pid", err);

    err = task_set_exception_ports(target, 
                                   EXC_MASK_ALL,
                                   debuggee_port,
                                   EXCEPTION_DEFAULT,
                                   THREAD_STATE_NONE);
    EXIT_ON_MACH_ERROR("mach_set_exception_ports", err);
    
    /* Create the exception handler thread. */
    if (pthread_create(&exception_thread, 
                        (pthread_attr_t *)NULL,
                        (void *(*)(void *))exception_handler, 
                        (void *)NULL) != 0)
    {
        exit_error();
    }

    return;
}

/*****************************************************************************/
/* Signal handling.                                                          */
/*****************************************************************************/

/* Wait for delay seconds before exiting. */
int
wait_until(int timeout)
{
    int status = -1;
    int retval = -1;
    struct timeval tv;

    while (1)
    {
        tv.tv_sec = timeout;
        tv.tv_usec = 0;

        retval = select(0, NULL, NULL, NULL, &tv);
        if (retval == -1)
        {
            int wpid = waitpid(-1, &status, WNOHANG);
            if (wpid < 0)
                return 1;
        }
        else if (retval == 0)
        {
            printf("[+] Timeout exceeded, exiting.\n");
            die(0);        
        }
        else
            exit_error();
    }
}

/* Exit if the child has exited. */
void
sighandler_chld(int code)
{
    int status = -1;
    wait(&status);
    printf("[+] The child has exited with exit code: %d.\n", WEXITSTATUS(status));
    exit(WEXITSTATUS(status));
}

/*****************************************************************************/
/* MAIN                                                                      */
/*****************************************************************************/

void Usage()
{
    printf("Usage: crash [options] target arguments\n");
    printf("  -t seconds        timeout (default: 5).\n");
    printf("\n");
    printf("Using BeaEngine version %s-%s.\n", BeaEngineVersion(), BeaEngineRevision());
    exit(0);
}

int
main(int argc, char **argv)
{
    int c;
    extern char *optarg;
    extern int optind;

    if (argc == 1)
        Usage();
    
    /* Command line parsing. */    
    memset(&config, 0, sizeof(config));
    config.timeout = 5;

    while((c = getopt(argc, argv, "ht:")) != -1)
    {
        switch(c)
        {
            case 'h':
                Usage();
                break;
            case 't':
                config.timeout = strtol(optarg, NULL, 10);
                break;
        }
    }

    /* If the child exits, we need to terminate. */
    signal(SIGCHLD, sighandler_chld);

    /* Launch the target application with its arguments and watches for eventual crashes. */
    config.pid = fork();
    if (config.pid == 0)
    {        
        execve(argv[optind], &argv[optind], NULL);
        exit_error();
    }
    else if (config.pid > 0)
    {
        printf("[+] PID: %d. Executing: ", config.pid);
        for (; optind < argc; optind++)
            printf("%s ", argv[optind]);
        printf("\n");

        setup_debugger(config.pid);
        wait_until(config.timeout);
    }
    else
        exit_error();

    return 0;
}
