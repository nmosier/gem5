#include <cstdlib>
#include <iostream>
#include <string>

#include "pin.H"

#include "cpu/pin/message.hh"

static const char *prog;
static KNOB<std::string> comm_path(KNOB_MODE_WRITEONCE, "pintool", "fifo", "", "specify path to file used for communication");
static NATIVE_FD comm_fd;

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
    std::cerr << prog << "Finished running the program, Pin exiting!\n";
}

int
main(int argc, char *argv[])
{
    prog = argv[0];
    if (PIN_Init(argc, argv)) {
        usage(std::cerr);
        return EXIT_FAILURE;
    }

    if (comm_path.Value().empty()) {
        std::cerr << "error: required option: -fifo\n";
        return EXIT_FAILURE;
    }

    if (OS_OpenFD(comm_path.Value().c_str(), OS_FILE_OPEN_TYPE_READ | OS_FILE_OPEN_TYPE_WRITE, 0, &comm_fd).generic_err != OS_RETURN_CODE_NO_ERROR) {
        std::cerr << "error: failed to open communication file: " << comm_path.Value() << "\n";
        return EXIT_FAILURE;
    }

    INS_AddInstrumentFunction(Instruction, nullptr);
    PIN_AddFiniFunction(Fini, nullptr);
    PIN_StartProgram();
}
