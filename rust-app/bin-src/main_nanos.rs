use core::pin::Pin;
use rust_app::implementation::*;

use nanos_sdk::buttons::{ButtonEvent};
use nanos_sdk::io;
use nanos_ui::ui;
use core::cell::RefCell;
use ledger_async_block::*;

nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

use rust_app::*;

static mut COMM_CELL : Option<RefCell<io::Comm>> = None;

static mut HOST_IO_STATE : Option<RefCell<HostIOState>> = None;

static mut STATES_BACKING : ParsersState<'static> = ParsersState::NoState;

#[inline(never)]
unsafe fn initialize() {
    COMM_CELL=Some(RefCell::new(io::Comm::new()));
    let comm = COMM_CELL.as_ref().unwrap();
    HOST_IO_STATE=Some(RefCell::new(HostIOState {
        comm: comm,
        requested_block: None,
        sent_command: None,
    }));
}

#[cfg(not(test))]
#[no_mangle]
extern "C" fn sample_main() {
    unsafe { initialize(); }
    let comm = unsafe { COMM_CELL.as_ref().unwrap() }; // io::Comm::new();
    let host_io = HostIO(unsafe { HOST_IO_STATE.as_ref().unwrap() });
    let mut states = unsafe { Pin::new_unchecked( &mut STATES_BACKING ) };

    info!("State struct uses {} bytes\n", core::mem::size_of::<ParsersState<'static>>()); // size_of_val(unsafe { states.into_inner_unchecked() }));

    loop {
        // Draw some 'welcome' screen
        ui::SingleMessage::new("W e l c o m e").show();

        // Wait for either a specific button push to exit the app
        // or an APDU command
        let evt = comm.borrow_mut().next_event(); // Need to do this outside of the match so we don't hold on to the reference during the body.
        match evt {
            io::Event::Button(ButtonEvent::RightButtonRelease) => nanos_sdk::exit_app(0),
            io::Event::Command(ins) => {
                trace!("Comm: {:?}", comm);
                match handle_apdu(host_io, ins, &mut states) {
                    Ok(()) => { comm.borrow_mut().reply_ok() },
                    Err(sw) => { trace!("Sending error {:?}", comm); comm.borrow_mut().reply(sw) },
                } }
            _ => (),
        }
    }
}

#[repr(u8)]
#[derive(Debug)]
enum Ins {
    GetPubkey,
    Sign,
    Exit,
}

impl From<u8> for Ins {
    fn from(ins: u8) -> Ins {
        match ins {
            2 => Ins::GetPubkey,
            3 => Ins::Sign,
            0xff => Ins::Exit,
            _ => panic!(),
        }
    }
}

// use arrayvec::ArrayVec;
use nanos_sdk::io::Reply;

#[inline(never)]
fn handle_apdu<'a: 'b, 'b>(io: HostIO, ins: Ins, state: &'b mut Pin<&'a mut ParsersState<'a>>) -> Result<(), Reply> {

    let comm = io.get_comm();
    if comm?.rx == 0 {
        return Err(io::StatusWords::NothingReceived.into());
    }

    match ins {
        Ins::GetPubkey => {
            poll_apdu_handler(state, io, GetAddress)?
        }
        Ins::Sign => {
            poll_apdu_handler(state, io, Sign)?
        }
        Ins::Exit => nanos_sdk::exit_app(0),
    }
    Ok(())
}
