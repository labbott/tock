//! Kernel-userland system call interface for RISC-V architecture.

use core::fmt::Write;

use kernel;
use crate::csr::mcause;

/// This holds all of the state that the kernel must keep for the process when
/// the process is not executing.
#[derive(Copy, Clone, Default)]
#[repr(C)]
pub struct RiscvimacStoredState {
    /// Store all of the app registers.
    regs: [usize; 31],

    /// This holds the PC value of the app when the exception/syscall/interrupt
    /// occurred. We also use this to set the PC that the app should start
    /// executing at when it is resumed/started.
    pc: usize,

    /// We need to store the mcause CSR between when the trap occurs and after
    /// we exit the trap handler and resume the context switching code.
    mcause: usize,
}

// Named offsets into the stored state registers.  These needs to be kept in
// sync with the register save logic in _start_trap() as well as the register
// restore logic in switch_to_process() below.
const R_RA: usize = 0;
const R_SP: usize = 1;
const R_A0: usize = 9;
const R_A1: usize = 10;
const R_A2: usize = 11;
const R_A3: usize = 12;
const R_A4: usize = 13;

/// Implementation of the `UserspaceKernelBoundary` for the RISC-V architecture.
pub struct SysCall(());

impl SysCall {
    pub const unsafe fn new() -> SysCall {
        SysCall(())
    }
}

impl kernel::syscall::UserspaceKernelBoundary for SysCall {
    type StoredState = RiscvimacStoredState;

    unsafe fn initialize_process(
        &self,
        stack_pointer: *const usize,
        _stack_size: usize,
        state: &mut Self::StoredState,
    ) -> Result<*const usize, ()> {
        // Need to clear the stored state when initializing.
        state.regs.iter_mut().for_each(|x| *x = 0);
        state.pc = 0;
        state.mcause = 0;

        // The first time the process runs we need to set the initial stack
        // pointer in the sp register.
        state.regs[R_SP] = stack_pointer as usize;

        // Just return the stack pointer. For the RISC-V arch we do not need
        // to make a stack frame to start the process.
        Ok(stack_pointer as *mut usize)
    }

    unsafe fn set_syscall_return_value(
        &self,
        _stack_pointer: *const usize,
        state: &mut Self::StoredState,
        return_value: isize,
    ) {
        // Just need to put the return value in the a0 register for when the
        // process resumes executing.
        state.regs[R_A0] = return_value as usize; // a0 = return value
    }

    unsafe fn set_process_function(
        &self,
        stack_pointer: *const usize,
        _remaining_stack_memory: usize,
        state: &mut RiscvimacStoredState,
        callback: kernel::procs::FunctionCall,
    ) -> Result<*mut usize, *mut usize> {
        // Set the register state for the application when it starts
        // executing. These are the argument registers.
        state.regs[R_A0] = callback.argument0;
        state.regs[R_A1] = callback.argument1;
        state.regs[R_A2] = callback.argument2;
        state.regs[R_A3] = callback.argument3;

        // We also need to set the return address (ra) register so that the new
        // function that the process is running returns to the correct location.
        // Note, however, that if this function happens to be the first time the
        // process is executing then `state.pc` is invalid/useless, but the
        // application must ignore it anyway since there is nothing logically
        // for it to return to. So this doesn't hurt anything.
        state.regs[R_RA] = state.pc;

        // Save the PC we expect to execute.
        state.pc = callback.pc;

        Ok(stack_pointer as *mut usize)
    }

    // Mock implementation for tests on Travis-CI.
    #[cfg(not(any(target_arch = "riscv32", target_os = "none")))]
    unsafe fn switch_to_process(
        &self,
        _stack_pointer: *const usize,
        _state: &mut RiscvimacStoredState,
    ) -> (*mut usize, kernel::syscall::ContextSwitchReason) {
        unimplemented!()
    }

    #[cfg(all(target_arch = "riscv32", target_os = "none"))]
    unsafe fn switch_to_process(
        &self,
        _stack_pointer: *const usize,
        state: &mut RiscvimacStoredState,
    ) -> (*mut usize, kernel::syscall::ContextSwitchReason) {
        asm! ("
          // Before switching to the app we need to save the kernel registers to
          // the kernel stack. We then save the stack pointer in the mscratch
          // CSR (0x340) so we can retrieve it after returning to the kernel
          // from the app.
          //
          // A few values get saved to the kernel stack, including an app
          // register temporarily after entering the trap handler. Here is a
          // memory map to make it easier to keep track:
          //
          // ```
          // 34*4(sp):          <- original stack pointer
          // 33*4(sp):
          // 32*4(sp): x31
          // 31*4(sp): x30
          // 30*4(sp): x29
          // 29*4(sp): x28
          // 28*4(sp): x27
          // 27*4(sp): x26
          // 26*4(sp): x25
          // 25*4(sp): x24
          // 24*4(sp): x23
          // 23*4(sp): x22
          // 22*4(sp): x21
          // 21*4(sp): x20
          // 20*4(sp): x19
          // 19*4(sp): x18
          // 18*4(sp): x17
          // 17*4(sp): x16
          // 16*4(sp): x15
          // 15*4(sp): x14
          // 14*4(sp): x13
          // 13*4(sp): x12
          // 12*4(sp): x11
          // 11*4(sp): x10
          // 10*4(sp): x9
          //  9*4(sp): x8
          //  8*4(sp): x7
          //  7*4(sp): x6
          //  6*4(sp): x5
          //  5*4(sp): x4
          //  4*4(sp): x3
          //  3*4(sp): x1
          //  2*4(sp): _return_to_kernel (address to resume after trap)
          //  1*4(sp): *state   (Per-process StoredState struct)
          //  0*4(sp): app s0   <- new stack pointer
          // ```

          addi sp, sp, -34*4  // Move the stack pointer down to make room.

          sw   x1,  3*4(sp)    // Save all of the registers on the kernel stack.
          sw   x3,  4*4(sp)
          sw   x4,  5*4(sp)
          sw   x5,  6*4(sp)
          sw   x6,  7*4(sp)
          sw   x7,  8*4(sp)
          sw   x8,  9*4(sp)
          sw   x9,  10*4(sp)
          sw   x10, 11*4(sp)
          sw   x11, 12*4(sp)
          sw   x12, 13*4(sp)
          sw   x13, 14*4(sp)
          sw   x14, 15*4(sp)
          sw   x15, 16*4(sp)
          sw   x16, 17*4(sp)
          sw   x17, 18*4(sp)
          sw   x18, 19*4(sp)
          sw   x19, 20*4(sp)
          sw   x20, 21*4(sp)
          sw   x21, 22*4(sp)
          sw   x22, 23*4(sp)
          sw   x23, 24*4(sp)
          sw   x24, 25*4(sp)
          sw   x25, 26*4(sp)
          sw   x26, 27*4(sp)
          sw   x27, 28*4(sp)
          sw   x28, 29*4(sp)
          sw   x29, 30*4(sp)
          sw   x30, 31*4(sp)
          sw   x31, 32*4(sp)

          sw   $0, 1*4(sp)    // Store process state pointer on stack as well.
                              // We need to have the available for after the app
                              // returns to the kernel so we can store its
                              // registers.

          // Store the address to jump back to on the stack so that the trap
          // handler knows where to return to after the app stops executing.
          lui  t0, %hi(_return_to_kernel)
          addi t0, t0, %lo(_return_to_kernel)
          sw   t0, 2*4(sp)

          csrw 0x340, sp      // Save stack pointer in mscratch. This allows
                              // us to find it when the app returns back to
                              // the kernel.

          // Read current mstatus CSR and then modify it so we switch to
          // user mode when running the app.
          csrr t0, 0x300      // Read mstatus=0x300 CSR
          // Set the mode to user mode and set MPIE.
          li   t1, 0x1808     // t1 = MSTATUS_MPP & MSTATUS_MIE
          not  t1, t1         // t1 = ~(MSTATUS_MPP & MSTATUS_MIE)
          and  t0, t0, t1     // t0 = mstatus & ~(MSTATUS_MPP & MSTATUS_MIE)
          ori  t0, t0, 0x80   // t0 = t0 | MSTATUS_MPIE
          csrw 0x300, t0      // Set mstatus CSR so that we switch to user mode.

          // We have to set the mepc CSR with the PC we want the app to start
          // executing at. This has been saved in RiscvimacStoredState for us
          // (either when the app returned back to the kernel or in the
          // `set_process_function()` function).
          lw   t0, 31*4($0)   // Retrieve the PC from RiscvimacStoredState
          csrw 0x341, t0      // Set mepc CSR. This is the PC we want to go to.

          // Restore all of the app registers from what we saved. If this is the
          // first time running the app then most of these values are
          // irrelevant, However we do need to set the four arguments to the
          // `_start_ function in the app. If the app has been executing then this
          // allows the app to correctly resume.
          mv   t0,  $0       // Save the state pointer to a specific register.
          lw   x1,  0*4(t0)  // ra
          lw   x2,  1*4(t0)  // sp
          lw   x3,  2*4(t0)  // gp
          lw   x4,  3*4(t0)  // tp
          lw   x6,  5*4(t0)  // t1
          lw   x7,  6*4(t0)  // t2
          lw   x8,  7*4(t0)  // s0,fp
          lw   x9,  8*4(t0)  // s1
          lw   x10, 9*4(t0)  // a0
          lw   x11, 10*4(t0) // a1
          lw   x12, 11*4(t0) // a2
          lw   x13, 12*4(t0) // a3
          lw   x14, 13*4(t0) // a4
          lw   x15, 14*4(t0) // a5
          lw   x16, 15*4(t0) // a6
          lw   x17, 16*4(t0) // a7
          lw   x18, 17*4(t0) // s2
          lw   x19, 18*4(t0) // s3
          lw   x20, 19*4(t0) // s4
          lw   x21, 20*4(t0) // s5
          lw   x22, 21*4(t0) // s6
          lw   x23, 22*4(t0) // s7
          lw   x24, 23*4(t0) // s8
          lw   x25, 24*4(t0) // s9
          lw   x26, 25*4(t0) // s10
          lw   x27, 26*4(t0) // s11
          lw   x28, 27*4(t0) // t3
          lw   x29, 28*4(t0) // t4
          lw   x30, 29*4(t0) // t5
          lw   x31, 30*4(t0) // t6
          lw   x5,  4*4(t0)  // t0. Do last since we overwrite our pointer.

          // Call mret to jump to where mepc points, switch to user mode, and
          // start running the app.
          mret




          // This is where the trap handler jumps back to after the app stops
          // executing.
        _return_to_kernel:

          // We have already stored the app registers in the trap handler. We
          // can restore the kernel registers before resuming kernel code.
          lw   x1,  3*4(sp)
          lw   x3,  4*4(sp)
          lw   x4,  5*4(sp)
          lw   x5,  6*4(sp)
          lw   x6,  7*4(sp)
          lw   x7,  8*4(sp)
          lw   x8,  9*4(sp)
          lw   x9,  10*4(sp)
          lw   x10, 11*4(sp)
          lw   x11, 12*4(sp)
          lw   x12, 13*4(sp)
          lw   x13, 14*4(sp)
          lw   x14, 15*4(sp)
          lw   x15, 16*4(sp)
          lw   x16, 17*4(sp)
          lw   x17, 18*4(sp)
          lw   x18, 19*4(sp)
          lw   x19, 20*4(sp)
          lw   x20, 21*4(sp)
          lw   x21, 22*4(sp)
          lw   x22, 23*4(sp)
          lw   x23, 24*4(sp)
          lw   x24, 25*4(sp)
          lw   x25, 26*4(sp)
          lw   x26, 27*4(sp)
          lw   x27, 28*4(sp)
          lw   x28, 29*4(sp)
          lw   x29, 30*4(sp)
          lw   x30, 31*4(sp)
          lw   x31, 32*4(sp)

          addi sp, sp, 34*4   // Reset kernel stack pointer
          "

          :
          : "r"(state as *mut RiscvimacStoredState)
          : "memory"
          : "volatile");

        let ret = match mcause::Trap::from(state.mcause as u32) {
            mcause::Trap::Interrupt(_intr) => {
                // An interrupt occurred while the app was running.
                kernel::syscall::ContextSwitchReason::Interrupted
            }
            mcause::Trap::Exception(excp) => {
                match excp {
                    // Apparently the SiFive board only supports m-mode?
                    mcause::Exception::UserEnvCall
                    | mcause::Exception::MachineEnvCall => {
                        // Need to increment the PC so when we return we start at the correct
                        // instruction. The hardware does not do this for us.
                        state.pc += 4;

                        let syscall = kernel::syscall::arguments_to_syscall(
                            state.regs[R_A0] as u8,
                            state.regs[R_A1],
                            state.regs[R_A2],
                            state.regs[R_A3],
                            state.regs[R_A4],
                        );
                        match syscall {
                            Some(s) => kernel::syscall::ContextSwitchReason::SyscallFired { syscall: s },
                            None => kernel::syscall::ContextSwitchReason::Fault,
                        }
                    }
                    _ => {
                        // All other exceptions result in faulted state
                        kernel::syscall::ContextSwitchReason::Fault
                    }
                }
            }
        };
        let new_stack_pointer = state.regs[R_SP];
        (new_stack_pointer as *mut usize, ret)
    }

    unsafe fn fault_fmt(&self, _writer: &mut dyn Write) {}

    unsafe fn process_detail_fmt(
        &self,
        _stack_pointer: *const usize,
        _state: &RiscvimacStoredState,
        _writer: &mut dyn Write,
    ) {
          let x1 =  _state.regs[0];
          let x2 =  _state.regs[1];
          let x3 =  _state.regs[2];
          let x4 =  _state.regs[3];
          let x5 =  _state.regs[4];
          let x6 =  _state.regs[5];
          let x7 =  _state.regs[6];
          let x8 =  _state.regs[7];
          let x9 =  _state.regs[8];
          let x10 =  _state.regs[9];
          let x11 =  _state.regs[10];
          let x12 =  _state.regs[11];
          let x13 =  _state.regs[12];
          let x14 =  _state.regs[13];
          let x15 =  _state.regs[14];
          let x16 =  _state.regs[15];
          let x17 =  _state.regs[16];
          let x18 =  _state.regs[17];
          let x19 =  _state.regs[18];
          let x20 =  _state.regs[19];
          let x21 =  _state.regs[20];
          let x22 =  _state.regs[21];
          let x23 =  _state.regs[22];
          let x24 =  _state.regs[23];
          let x25 =  _state.regs[24];
          let x26 =  _state.regs[25];
          let x27 =  _state.regs[26];
          let x28 =  _state.regs[27];
          let x29 =  _state.regs[28];
          let x30 =  _state.regs[29];
          let x31 =  _state.regs[30];
          let _ = _writer.write_fmt(format_args!(
            "\
            \r\n pc = {:#010x}  a6 = {:#010x}\
            \r\n ra = {:#010x}  a7 = {:#010x}\
            \r\n sp = {:#010x}  s2 = {:#010x}\
            \r\n gp = {:#010x}  s3 = {:#010x}\
            \r\n tp = {:#010x}  s4 = {:#010x}\
            \r\n t0 = {:#010x}  s5 = {:#010x}\
            \r\n t1 = {:#010x}  s6 = {:#010x}\
            \r\n t2 = {:#010x}  s7 = {:#010x}\
            \r\n s0 = {:#010x}  s8 = {:#010x}\
            \r\n s1 = {:#010x}  s9 = {:#010x}\
            \r\n a0 = {:#010x}  s10 = {:#010x}\
            \r\n a1 = {:#010x}  s11 = {:#010x}\
            \r\n a2 = {:#010x}  t3 = {:#010x}\
            \r\n a3 = {:#010x}  t4 = {:#010x}\
            \r\n a4 = {:#010x}  t5 = {:#010x}\
            \r\n a5 = {:#010x}  t6 = {:#010x}\
            \r\n mcause = {:#010x}",
            _state.pc,
            x16,
            x1,
            x17,
            x2,
            x18,
            x3,
            x19,
            x4,
            x20,
            x5,
            x21,
            x6,
            x22,
            x7,
            x23,
            x8,
            x24,
            x9,
            x25,
            x10,
            x26,
            x11,
            x27,
            x12,
            x28,
            x13,
            x29,
            x14,
            x30,
            x15,
            x31,
            _state.mcause));


    }
}
