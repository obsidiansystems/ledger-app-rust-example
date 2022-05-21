use crate::crypto_helpers::{detecdsa_sign, get_pkh, get_private_key, get_pubkey, Hasher};
use crate::interface::*;
use arrayvec::ArrayVec;
use core::fmt::Write;
use ledger_parser_combinators::interp_parser::{
    Action, DefaultInterp, DropInterp, ObserveBytes, SubInterp
};
use pin_project::pin_project;
use core::future::Future;
use ledger_parser_combinators::async_parser::*;

use crate::ui::write_scroller;

use core::convert::TryFrom;
use core::task::*;
use ledger_async_block::*;

// A couple type ascription functions to help the compiler along.
const fn mkfn<A,B,C>(q: fn(&A,&mut B)->C) -> fn(&A,&mut B)->C {
    q
}
const fn mkfinfun(a: fn(ArrayVec<u32, 10>) -> Option<ArrayVec<u8, 128>>) -> fn(ArrayVec<u32, 10>) -> Option<ArrayVec<u8, 128>> {
    a
}


pub type GetAddressImplT = impl AsyncParser<Bip32Key, ByteStream> + HasOutput<Bip32Key, Output=ArrayVec<u8, 128>>; // Returning = ArrayVec<u8, 260_usize>>;

pub static GET_ADDRESS_IMPL: GetAddressImplT =
    Action(SubInterp(DefaultInterp), mkfinfun(|path: ArrayVec<u32, 10>| -> Option<ArrayVec<u8, 128>> {
        let key = get_pubkey(&path).ok()?;

        let pkh = get_pkh(key);

        // At this point we have the value to send to the host; but there's a bit more to do to
        // ask permission from the user.
        write_scroller("Provide Public Key", |w| Ok(write!(w, "{}", pkh)?))?;

        let mut p = ArrayVec::new();
        p.try_push(u8::try_from(key.W_len).ok()?).ok()?;
        p.try_extend_from_slice(&key.W[1..key.W_len as usize]).ok()?;
        Some(p)
    }));

#[derive(Copy, Clone)]
pub struct GetAddress; // (pub GetAddressImplT);

impl AsyncAPDU for GetAddress {
    // const MAX_PARAMS : usize = 1;
    type State<'c> = impl Future<Output = ()>;

    fn run<'c>(self, io: HostIO, input: ArrayVec<ByteStream, MAX_PARAMS >) -> Self::State<'c> {
        let mut param = input[0].clone();
        async move {
            let address = GET_ADDRESS_IMPL.parse(&mut param).await;
            io.result_final(&address).await;
        }
    }
}

impl<'d> AsyncAPDUStated<ParsersStateCtr> for GetAddress {
    #[inline(never)]
    fn init<'a, 'b: 'a>(
        self,
        s: &mut core::pin::Pin<&'a mut ParsersState<'a>>,
        io: HostIO,
        input: ArrayVec<ByteStream, MAX_PARAMS>
    ) -> () {
        s.set(ParsersState::GetAddressState(self.run(io, input)));
    }

    /*
    #[inline(never)]
    fn get<'a, 'b>(self, s: &'b mut core::pin::Pin<&'a mut ParsersState<'a>>) -> Option<&'b mut core::pin::Pin<&'a mut Self::State<'a>>> {
        match s.as_mut().project() {
            ParsersStateProjection::GetAddressState(ref mut s) => Some(s),
            _ => panic!("Oops"),
        }
    }*/

    #[inline(never)]
    fn poll<'a, 'b>(self, s: &mut core::pin::Pin<&'a mut ParsersState>) -> core::task::Poll<()> {
        let waker = unsafe { Waker::from_raw(RawWaker::new(&(), &RAW_WAKER_VTABLE)) };
        let mut ctxd = Context::from_waker(&waker);
        match s.as_mut().project() {
            ParsersStateProjection::GetAddressState(ref mut s) => s.as_mut().poll(&mut ctxd),
            _ => panic!("Ooops"),
        }
    }
}


#[derive(Copy, Clone)]
pub struct Sign;

// Transaction parser; this should prompt the user a lot more than this.

const TXN_PARSER : impl AsyncParser<Transaction, ByteStream> + HasOutput<Transaction, Output = [u8; 32]> = Action(ObserveBytes(Hasher::new, Hasher::update, DropInterp),
mkfn(|(hash, _): &(Hasher, Option<() /*ArrayVec<(), { usize::MAX }>*/>), destination: &mut _| {
    let the_hash = hash.clone().finalize();

    write_scroller("Sign Hash?", |w| Ok(write!(w, "{}", the_hash)?))?;

    *destination = Some(the_hash.0.into());
    Some(())
}));


const PRIVKEY_PARSER : impl AsyncParser<Bip32Key, ByteStream> + HasOutput<Bip32Key, Output=nanos_sdk::bindings::cx_ecfp_private_key_t>= Action(
    SubInterp(DefaultInterp),
    // And ask the user if this is the key the meant to sign with:
    mkfn(|path: &ArrayVec<u32, 10>, destination: &mut _| {
        let privkey = get_private_key(path).ok()?;
        let pubkey = get_pubkey(path).ok()?; // Redoing work here; fix.
        let pkh = get_pkh(pubkey);

        write_scroller("With PKH", |w| Ok(write!(w, "{}", pkh)?))?;

        *destination = Some(privkey);
        Some(())
    }));

impl AsyncAPDU for Sign {
    // const MAX_PARAMS : usize = 2;

    type State<'c> = impl Future<Output = ()>;

    fn run<'c>(self, io: HostIO, mut input: ArrayVec<ByteStream, MAX_PARAMS>) -> Self::State<'c> {
        async move {
            let hash = TXN_PARSER.parse(&mut input[0]).await;

            let privkey = PRIVKEY_PARSER.parse(&mut input[1]).await;

            let (sig, len) = detecdsa_sign(&hash[..], &privkey).unwrap();

            io.result_final(&sig[0..len as usize]).await;
        }
    }
}

impl<'d> AsyncAPDUStated<ParsersStateCtr> for Sign {
    #[inline(never)]
    fn init<'a, 'b: 'a>(
        self,
        s: &mut core::pin::Pin<&'a mut ParsersState<'a>>,
        io: HostIO,
        input: ArrayVec<ByteStream, MAX_PARAMS>
    ) -> () {
        s.set(ParsersState::SignState(self.run(io, input)));
    }

    #[inline(never)]
    fn poll<'a>(self, s: &mut core::pin::Pin<&'a mut ParsersState>) -> core::task::Poll<()> {
        let waker = unsafe { Waker::from_raw(RawWaker::new(&(), &RAW_WAKER_VTABLE)) };
        let mut ctxd = Context::from_waker(&waker);
        match s.as_mut().project() {
            ParsersStateProjection::SignState(ref mut s) => s.as_mut().poll(&mut ctxd),
            _ => panic!("Ooops"),
        }
    }
}

// The global parser state enum; any parser above that'll be used as the implementation for an APDU
// must have a field here.

// type GetAddressStateType = impl Future;
// type SignStateType = impl Future<Output = ()>;

#[pin_project(project = ParsersStateProjection)]
pub enum ParsersState<'a> {
    NoState,
    GetAddressState(#[pin] <GetAddress as AsyncAPDU>::State<'a>), // <GetAddressImplT<'a> as AsyncParser<Bip32Key, ByteStream<'a>>>::State<'a>),
    SignState(#[pin] <Sign as AsyncAPDU>::State<'a>),
    // SignState(#[pin] <SignImplT<'a> as AsyncParser<SignParameters, ByteStream<'a>>>::State<'a>),
}

impl<'a> Default for ParsersState<'a> {
    fn default() -> Self {
        ParsersState::NoState
    }
}

// we need to pass a type constructor for ParsersState to various places, so that we can give it
// the right lifetime; this is a bit convoluted, but works.

pub struct ParsersStateCtr;
impl StateHolderCtr for ParsersStateCtr {
    type StateCtr<'a> = ParsersState<'a>;
}

