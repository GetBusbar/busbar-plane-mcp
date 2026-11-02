// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! Typed refusal slots for unused operations of test-only doors.

use busbar_contract::abi::mechanism::call::Outcome;
use busbar_contract::abi::sdk::door::{AbiIn, AbiOut};
use busbar_contract::abi::sdk::{Instance, Lent, Out, SafeSlot};

pub(crate) struct Idle<I, O>(std::marker::PhantomData<fn(I) -> O>);
impl<I: AbiIn, O: AbiOut> SafeSlot for Idle<I, O> {
    type State = crate::plane_door::McpDoor;
    type In = I;
    type Out = O;
    fn call(_: Instance<'_, Self::State>, _: Lent<'_, I>, _: Out<'_, O>) -> Outcome {
        Outcome::Refused
    }
}
