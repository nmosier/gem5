#include <cstdlib>
#include <iostream>
#include <string>
#include <fstream>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "pin.H"

static const char *prog;
static KNOB<std::string> comm_path(KNOB_MODE_WRITEONCE, "pintool", "fifo", "", "specify path to file used for communication");
static NATIVE_FD comm_fd;
static KNOB<std::string> log_path(KNOB_MODE_WRITEONCE, "pintool", "log", "", "specify path to log file");
static std::ofstream log;
static KNOB<std::string> shm_name(KNOB_MODE_WRITEONCE, "pintool", "shm", "", "specify name of gem5 physmem");
static NATIVE_FD shm_fd;
static NATIVE_PID app_pid;

#define ENTRY_ADDR ((ADDRINT) 0xdeadbeef0000000)
#define SYSCALL_ADDR ((ADDRINT) 0xdeadbeef000000a)

static void
Abort()
{
    log.close();
    std::abort();
}

static void
Instruction(INS ins, void *)
{
    // TODO
}

static void
usage(std::ostream &os)
{
    std::cerr << prog << ": gem5 pin CPU client\n";
    std::cerr << KNOB_BASE::StringKnobSummary() << "\n";
}

static void Fini(int32_t code, void *) {
    OS_CloseFD(comm_fd);
    std::cerr << "Exiting: code = " << code << "\n";
    log << prog << "Finished running the program, Pin exiting!\n";
    log.close();
}

int
main(int argc, char *argv[])
{
    prog = argv[0];
    if (PIN_Init(argc, argv)) {
        usage(std::cerr);
        return EXIT_FAILURE;
    }

    if (log_path.Value().empty()) {
        std::cerr << "error: required option: -log\n";
        return EXIT_FAILURE;
    }

    log.open(log_path.Value());

    if (comm_path.Value().empty()) {
        std::cerr << "error: required option: -fifo\n";
        return EXIT_FAILURE;
    }

    if (OS_OpenFD(comm_path.Value().c_str(), OS_FILE_OPEN_TYPE_READ | OS_FILE_OPEN_TYPE_WRITE, 0, &comm_fd).generic_err != OS_RETURN_CODE_NO_ERROR) {
        std::cerr << "error: failed to open communication file: " << comm_path.Value() << "\n";
        return EXIT_FAILURE;
    }

    if (log_path.Value().empty()) {
        std::cerr << "error: required option: -shm\n";
        return EXIT_FAILURE;
    }

    if (OS_OpenFD(shm_name.Value().c_str(), OS_FILE_OPEN_TYPE_READ | OS_FILE_OPEN_TYPE_WRITE, 0, &shm_fd).generic_err != OS_RETURN_CODE_NO_ERROR) {
        std::cerr << "error: failed to open physmem file: " << shm_name.Value() << "\n";
        return EXIT_FAILURE;
    }

    if (OS_GetPid(&app_pid).generic_err != OS_RETURN_CODE_NO_ERROR) {
        std::cerr << "error: OS_GetPid failed\n";
        return EXIT_FAILURE;
    }

    INS_AddInstrumentFunction(Instruction, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);

    std::cerr << "runtime: starting program\n";

    PIN_StartProgram();
}
