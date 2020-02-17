//! Support for the AES hardware block on OpenTitan
//!
//! https://docs.opentitan.org/hw/ip/aes/doc/

use kernel::common::cells::{OptionalCell, TakeCell};
use kernel::common::registers::{
    register_bitfields, register_structs, ReadOnly, ReadWrite, WriteOnly,
};
use kernel::common::StaticRef;
use kernel::debug;
use kernel::hil;
use kernel::hil::symmetric_encryption;
use kernel::hil::symmetric_encryption::{AES128_BLOCK_SIZE, AES128_KEY_SIZE};
use kernel::ReturnCode;

const MAX_LENGTH: usize = 128;

#[repr(C)]
register_structs! {
    pub AesRegisters {
        (0x00 => key0: WriteOnly<u32, Key::Register>),
        (0x04 => key1: WriteOnly<u32, Key::Register>),
        (0x08 => key2: WriteOnly<u32, Key::Register>),
        (0x0c => key3: WriteOnly<u32, Key::Register>),
        (0x10 => key4: WriteOnly<u32, Key::Register>),
        (0x14 => key5: WriteOnly<u32, Key::Register>),
        (0x18 => key6: WriteOnly<u32, Key::Register>),
        (0x1c => key7: WriteOnly<u32, Key::Register>),
        (0x20 => data_in0: WriteOnly<u32, Key::Register>),
        (0x24 => data_in1: WriteOnly<u32, Key::Register>),
        (0x28 => data_in2: WriteOnly<u32, Key::Register>),
        (0x2c => data_in3: WriteOnly<u32, Key::Register>),
        (0x30 => data_out0: ReadOnly<u32, Key::Register>),
        (0x34 => data_out1: ReadOnly<u32, Key::Register>),
        (0x38 => data_out2: ReadOnly<u32, Key::Register>),
        (0x3c => data_out3: ReadOnly<u32, Key::Register>),
        (0x40 => ctrl: ReadWrite<u32, CTRL::Register>),
        (0x44 => trigger: WriteOnly<u32, TRIGGER::Register>),
        (0x48 => status: ReadOnly<u32, STATUS::Register>),
        (0x4c => @END),
    }
}

register_bitfields![u32,
    Key [
        KEY OFFSET(0)  NUMBITS(32) []
    ],
    CTRL [
        OPERATION OFFSET(0) NUMBITS(1) [
            Encrypting = 0,
            Decrypting = 1
        ],
        KEY_LEN OFFSET(1) NUMBITS(3) [
            Key128 = 1,
            Key192 = 2,
            Key256 = 4
        ],
        MANUAL_OPERATION OFFSET(4) NUMBITS(1) []
    ],
    TRIGGER [
        START OFFSET(0) NUMBITS(1) [],
        KEY_CLEAR OFFSET(1) NUMBITS(1) [],
        DATA_IN_CLEAR OFFSET(2) NUMBITS(1) [],
        DATA_OUT_CLEAR OFFSET(3) NUMBITS(1) []
    ],
    STATUS [
        IDLE 0,
        STALL 1,
        OUTPUT_VALID 2,
        INPUT_READY 3
    ]
];

// https://docs.opentitan.org/hw/top_earlgrey/doc/
const AES_BASE: StaticRef<AesRegisters> =
    unsafe { StaticRef::new(0x40110000 as *const AesRegisters) };

pub struct Aes<'a> {
    registers: StaticRef<AesRegisters>,

    client: OptionalCell<&'a dyn hil::symmetric_encryption::Client<'a>>,
    source: TakeCell<'a, [u8]>,
    dest: TakeCell<'a, [u8]>,
}

impl Aes<'a> {
    const fn new() -> Aes<'a> {
        Aes {
            registers: AES_BASE,
            client: OptionalCell::empty(),
            source: TakeCell::empty(),
            dest: TakeCell::empty(),
        }
    }

    fn clear(&self) {
        let regs: &AesRegisters = &*self.registers;
        regs.trigger.write(
            TRIGGER::KEY_CLEAR.val(1)
                + TRIGGER::DATA_IN_CLEAR.val(1)
                + TRIGGER::DATA_OUT_CLEAR.val(1),
        );
    }

    fn configure(&self, encrypting: bool) {
        let regs: &AesRegisters = &*self.registers;
        let e = if encrypting {
            CTRL::OPERATION::Encrypting
        } else {
            CTRL::OPERATION::Decrypting
        };
        // Set this in manual mode for the moment since automatic block mode does not appear
        // to be working

        regs.ctrl
            .write(e + CTRL::KEY_LEN::Key128 + CTRL::MANUAL_OPERATION.val(1));
    }

    fn idle(&self) -> bool {
        let regs: &AesRegisters = &*self.registers;
        return regs.status.read(STATUS::IDLE) == 1;
    }

    fn input_ready(&self) -> bool {
        let regs: &AesRegisters = &*self.registers;
        return regs.status.read(STATUS::INPUT_READY) == 1;
    }

    fn output_valid(&self) -> bool {
        let regs: &AesRegisters = &*self.registers;
        return regs.status.read(STATUS::OUTPUT_VALID) == 1;
    }

    fn trigger(&self) {
        let regs: &AesRegisters = &*self.registers;
        regs.trigger.write(TRIGGER::START.val(1));
    }

    fn read_block(&self, blocknum: usize) -> bool {
        let regs: &AesRegisters = &*self.registers;
        let blocknum = blocknum * AES128_BLOCK_SIZE;

        loop {
            if self.output_valid() {
                break;
            }
        }

        self.dest.map_or_else(
            || {
                debug!("Called read_block() with no data");
                false
            },
            |dest| {
                for i in 0..4 {
                    // we work off an array of u8 so we need to assemble those back into
                    // a u32
                    let mut v = 0;
                    match i {
                        0 => v = regs.data_out0.get(),
                        1 => v = regs.data_out1.get(),
                        2 => v = regs.data_out2.get(),
                        3 => v = regs.data_out3.get(),
                        _ => {}
                    }
                    dest[blocknum + (i * 4) + 0] = (v >> 0) as u8;
                    dest[blocknum + (i * 4) + 1] = (v >> 8) as u8;
                    dest[blocknum + (i * 4) + 2] = (v >> 16) as u8;
                    dest[blocknum + (i * 4) + 3] = (v >> 24) as u8;
                }
                true
            },
        );
        true
    }

    fn write_block(&self, blocknum: usize) -> bool {
        let regs: &AesRegisters = &*self.registers;
        let blocknum = blocknum * AES128_BLOCK_SIZE;

        loop {
            if self.input_ready() {
                break;
            }
        }

        self.source.map_or_else(
            || {
                // This is the case that dest = source
                self.dest.map_or_else(
                    || {
                        debug!("Called write_block() with no data");
                        false
                    },
                    |dest| {
                        for i in 0..4 {
                            // we work off an array of u8 so we need to assemble those back into
                            // a u32
                            let mut v = dest[blocknum + (i * 4) + 0] as usize;
                            v |= (dest[blocknum + (i * 4) + 1] as usize) << 8;
                            v |= (dest[blocknum + (i * 4) + 2] as usize) << 16;
                            v |= (dest[blocknum + (i * 4) + 3] as usize) << 24;
                            match i {
                                0 => regs.data_in0.set(v as u32),
                                1 => regs.data_in1.set(v as u32),
                                2 => regs.data_in2.set(v as u32),
                                3 => regs.data_in3.set(v as u32),
                                _ => {}
                            }
                        }
                        true
                    },
                )
            },
            |source| {
                for i in 0..4 {
                    // we work off an array of u8 so we need to assemble those back into
                    // a u32
                    let mut v = source[blocknum + (i * 4) + 0] as usize;
                    v |= (source[blocknum + (i * 4) + 1] as usize) << 8;
                    v |= (source[blocknum + (i * 4) + 2] as usize) << 16;
                    v |= (source[blocknum + (i * 4) + 3] as usize) << 24;
                    match i {
                        0 => regs.data_in0.set(v as u32),
                        1 => regs.data_in1.set(v as u32),
                        2 => regs.data_in2.set(v as u32),
                        3 => regs.data_in3.set(v as u32),
                        _ => {}
                    }
                }
                true
            },
        );
        true
    }

    fn set_key(&self, key: &[u8]) -> ReturnCode {
        let regs: &AesRegisters = &*self.registers;

        loop {
            if self.idle() {
                break;
            }
        }

        if key.len() != AES128_KEY_SIZE {
            return ReturnCode::EINVAL;
        }

        for i in 0..4 {
            let mut k = key[i * 4 + 0] as usize;
            k |= (key[i * 4 + 1] as usize) << 8;
            k |= (key[i * 4 + 2] as usize) << 16;
            k |= (key[i * 4 + 3] as usize) << 24;
            match i {
                0 => regs.key0.set(k as u32),
                1 => regs.key1.set(k as u32),
                2 => regs.key2.set(k as u32),
                3 => regs.key3.set(k as u32),
                _ => {}
            }
        }

        // We must write the rest of the registers as well
        regs.key4.set(0);
        regs.key5.set(0);
        regs.key6.set(0);
        regs.key7.set(0);
        ReturnCode::SUCCESS
    }

    fn crypt(&self, start_index: usize, stop_index: usize, wr_start_index: usize) -> bool {
        // convert our start_indexes in the array to block numbers
        let start_block = start_index / AES128_BLOCK_SIZE;
        let end_block = stop_index / AES128_BLOCK_SIZE;
        let mut wr_block = wr_start_index / AES128_BLOCK_SIZE;
        for i in start_block..end_block {
            self.write_block(wr_block);
            self.trigger();
            self.read_block(i);
            wr_block = wr_block + 1;
        }
        return true;
    }
}

impl hil::symmetric_encryption::AES128<'a> for Aes<'a> {
    fn enable(&self) {
        self.configure(true);
    }

    fn disable(&self) {
        self.clear();
    }

    fn set_client(&'a self, client: &'a dyn symmetric_encryption::Client<'a>) {
        self.client.set(client);
    }

    fn set_iv(&self, _iv: &[u8]) -> ReturnCode {
        // nothing because this is ECB
        ReturnCode::SUCCESS
    }

    fn start_message(&self) {
        return;
    }

    fn set_key(&self, key: &[u8]) -> ReturnCode {
        return self.set_key(key);
    }

    fn crypt(
        &'a self,
        source: Option<&'a mut [u8]>,
        dest: &'a mut [u8],
        start_index: usize,
        stop_index: usize,
    ) -> Option<(ReturnCode, Option<&'a mut [u8]>, &'a mut [u8])> {
        if stop_index - start_index > MAX_LENGTH {
            return Some((ReturnCode::EINVAL, source, dest));
        }
        self.dest.replace(dest);
        match source {
            None => {
                self.crypt(start_index, stop_index, start_index);
            }
            Some(src) => {
                self.source.replace(src);
                self.crypt(start_index, stop_index, 0);
            }
        }
        self.client.map(|client| {
            client.crypt_done(self.source.take(), self.dest.take().unwrap());
        });
        None
    }
}

pub static mut AES: Aes<'static> = Aes::new();

impl kernel::hil::symmetric_encryption::AES128ECB for Aes<'a> {
    fn set_mode_aes128ecb(&self, encrypting: bool) {
        self.configure(encrypting);
        ()
    }
}
