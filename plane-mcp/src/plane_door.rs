// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! THE PLANE'S DOOR, SERVED: the slots the kernel calls over the plane ABI, on the SDK's safe

include!("plane_door_impl.rs");

#[path = "door_legacy.rs"]
mod door_legacy;
