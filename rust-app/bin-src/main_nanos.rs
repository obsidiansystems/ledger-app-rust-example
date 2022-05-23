use rust_app::crypto_helpers::*;
use rust_app::implementation::*;
use rust_app::interface::*;
mod utils;

use ledger_parser_combinators::interp_parser::set_from_thunk;

use core::str::from_utf8;
use nanos_sdk::io;
use nanos_ui::ui;

use prompts_ui::RootMenu;

nanos_sdk::set_panic!(nanos_sdk::exiting_panic);

/// Display public key in two separate
/// message scrollers
fn show_pubkey() {
    let pubkey = get_pubkey(&BIP32_PATH);
    match pubkey {
        Ok(pk) => {
            {
                let hex0 = utils::to_hex(&pk.W[1..33]).unwrap();
                let m = from_utf8(&hex0).unwrap();
                ui::MessageScroller::new(m).event_loop();
            }
            {
                let hex1 = utils::to_hex(&pk.W[33..65]).unwrap();
                let m = from_utf8(&hex1).unwrap();
                ui::MessageScroller::new(m).event_loop();
            }
        }
        Err(_) => ui::popup("Error"),
    }
}

/// Basic nested menu. Will be subject
/// to simplifications in the future.
#[allow(clippy::needless_borrow)]
fn menu_example() {
    loop {
        match ui::Menu::new(&[&"PubKey", &"Infos", &"Back", &"Exit App"]).show() {
            0 => show_pubkey(),
            1 => loop {
                match ui::Menu::new(&[&"Copyright", &"Authors", &"Back"]).show() {
                    0 => ui::popup("2020 Ledger"),
                    1 => ui::popup("???"),
                    _ => break,
                }
            },
            2 => return,
            3 => nanos_sdk::exit_app(2),
            _ => (),
        }
    }
}

use ledger_parser_combinators::interp_parser::OOB;
use rust_app::*;

const WELCOME_TEXT: &str = "W e l c o m e";

#[cfg(not(test))]
#[no_mangle]
extern "C" fn sample_main() {
    let mut comm = io::Comm::new();
    // let mut states = parser_states!();
    // let mut parsers = mk_parsers();
    let mut states = ParsersState::NoState;

    let mut idle_menu = RootMenu::new([ WELCOME_TEXT, "Exit"]);
    let mut busy_menu = RootMenu::new(["Working...", "Cancel"]);

    let menu = |states: &ParsersState, idle: &mut RootMenu<2>, busy: &mut RootMenu<2>| match states {
        ParsersState::NoState => idle.show(),
        _ => busy.show(),
    };

    menu(&states, &mut idle_menu, &mut busy_menu);

    use core::mem::size_of_val;
    info!("State struct uses {} bytes\n", size_of_val(&states));
    // with_parser_state!(parsers);

    loop {
        // Wait for either a specific button push to exit the app
        // or an APDU command
        match comm.next_event() {
            io::Event::Command(ins) => {
                trace!("Command recived");
                match handle_apdu(&mut comm, ins, &mut states) {
                    Ok(()) => comm.reply_ok(),
                    Err(sw) => comm.reply(sw),
                };
                menu(&states, & mut idle_menu, & mut busy_menu);
                trace!("Command done");
            },
            io::Event::Button(btn) => {
                trace!("Button recived");
                if let ParsersState::NoState = states {
                    if let Some(1) = idle_menu.update(btn) {
                        info!("Exiting app at user direction via root menu");
                        nanos_sdk::exit_app(0)
                    }
                } else if let Some(1) = busy_menu.update(btn) {
                    info!("Resetting at user direction via busy menu");
                    set_from_thunk(&mut states, || ParsersState::NoState);
                };
                menu(&states, & mut idle_menu, & mut busy_menu);
                trace!("Button done");
            },
        }
    }
}

#[repr(u8)]
#[derive(Debug)]
enum Ins {
    GetPubkey,
    Sign,
    Menu,
    ShowPrivateKey,
    Exit,
}

impl From<u8> for Ins {
    fn from(ins: u8) -> Ins {
        match ins {
            2 => Ins::GetPubkey,
            3 => Ins::Sign,
            4 => Ins::Menu,
            0xfe => Ins::ShowPrivateKey,
            0xff => Ins::Exit,
            _ => panic!(),
        }
    }
}

use arrayvec::ArrayVec;
use nanos_sdk::io::Reply;

use ledger_parser_combinators::interp_parser::InterpParser;
fn run_parser_apdu<P: InterpParser<A, Returning = ArrayVec<u8, 260>>, A>(
    states: &mut ParsersState,
    get_state: fn(&mut ParsersState) -> &mut <P as InterpParser<A>>::State,
    parser: &P,
    comm: &mut io::Comm,
) -> Result<(), Reply> {
    let cursor = comm.get_data()?;

    loop {
        trace!("Parsing APDU input: {:?}\n", cursor);
        let mut parse_destination = None;
        let parse_rv = <P as InterpParser<A>>::parse(parser, get_state(states), cursor, &mut parse_destination);
        trace!("Parser result: {:?}\n", parse_rv);
        match parse_rv {
            // Explicit rejection; reset the parser. Possibly send error message to host?
            Err((Some(OOB::Reject), _)) => {
                *states = ParsersState::NoState;
                break Err(io::StatusWords::Unknown.into());
            }
            // Deliberately no catch-all on the Err((Some case; we'll get error messages if we
            // add to OOB's out-of-band actions and forget to implement them.
            //
            // Finished the chunk with no further actions pending, but not done.
            Err((None, [])) => break Ok(()),
            // Didn't consume the whole chunk; reset and error message.
            Err((None, _)) => {
                *states = ParsersState::NoState;
                break Err(io::StatusWords::Unknown.into());
            }
            // Consumed the whole chunk and parser finished; send response.
            Ok([]) => {
                trace!("Parser finished, resetting state\n");
                match parse_destination.as_ref() {
                    Some(rv) => comm.append(&rv[..]),
                    None => break Err(io::StatusWords::Unknown.into()),
                }
                // Parse finished; reset.
                *states = ParsersState::NoState;
                break Ok(());
            }
            // Parse ended before the chunk did; reset.
            Ok(_) => {
                *states = ParsersState::NoState;
                break Err(io::StatusWords::Unknown.into());
            }
        }
    }
}

// fn handle_apdu<P: for<'a> FnMut(ParserTag, &'a [u8]) -> RX<'a, ArrayVec<u8, 260> > >(comm: &mut io::Comm, ins: Ins, parser: &mut P) -> Result<(), Reply> {
#[inline(never)]
fn handle_apdu(comm: &mut io::Comm, ins: Ins, parser: &mut ParsersState) -> Result<(), Reply> {
    info!("entering handle_apdu with command {:?}", ins);
    if comm.rx == 0 {
        return Err(io::StatusWords::NothingReceived.into());
    }

    match ins {
        Ins::GetPubkey => {
            run_parser_apdu::<_, Bip32Key>(parser, get_get_address_state, &GET_ADDRESS_IMPL, comm)?
        }
        Ins::Sign => {
            run_parser_apdu::<_, SignParameters>(parser, get_sign_state, &SIGN_IMPL, comm)?
        }

        Ins::Menu => menu_example(),
        Ins::ShowPrivateKey => comm.append(&bip32_derive_secp256k1(&BIP32_PATH)?),
        Ins::Exit => nanos_sdk::exit_app(0),
        // _ => nanos_sdk::exit_app(0)
    }
    Ok(())
}
