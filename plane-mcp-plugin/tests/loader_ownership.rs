// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

//! MCP-owned declarations and snapshots formerly asserted by core loader witnesses.
use busbar_plugin_loader::dispatch::kinds::plane::{open_door, refresh_door, retire_door, Plane};
use busbar_plugin_loader::dispatch::{
    load_dropped, load_linked, rendering_of, Bind, ConnTable, LinkedRow, NoSink, Plugin,
};
use std::sync::Arc;
fn binding() -> Bind {
    Bind {
        instance: "mcp-owner-lifecycle".into(),
        max_inflight_cap: 8,
        sink: Arc::new(NoSink),
        dispatcher: {
            static DISPATCHER: std::sync::OnceLock<busbar_plugin_loader::dispatch::Dispatcher> =
                std::sync::OnceLock::new();
            DISPATCHER
                .get_or_init(|| {
                    busbar_plugin_loader::dispatch::Dispatcher::new(
                        Default::default(),
                        busbar_contract::services::test_caller_binding(),
                    )
                })
                .adopter()
        },
        conns: ConnTable::Probe,
    }
}
fn linked() -> Plugin<Plane> {
    load_linked::<Plane>(&LinkedRow::of(busbar_plane_mcp::door).unwrap(), binding()).unwrap()
}
fn dropped() -> Plugin<Plane> {
    let image = std::path::PathBuf::from(
        std::env::var_os("BUSBAR_PLUGIN_CDYLIB").expect("fresh MCP cdylib"),
    );
    assert!(image.is_absolute() && image.is_file());
    load_dropped::<Plane>(
        &image,
        &rendering_of(busbar_plane_mcp::door).unwrap(),
        binding(),
    )
    .unwrap()
}
#[test]
fn mcp_declared_registry_facts_agree_through_both_origins() {
    let check = |make: fn() -> Plugin<Plane>| {
        let facts = make();
        let served = facts.served();
        let declared = facts.declared();
        let reg =
            busbar_plugin_loader::dispatch::kinds::plane::registration(Arc::new(
                move || Ok(make()),
            ))
            .unwrap();
        assert_eq!(reg.key, "mcp");
        assert_eq!(reg.section, "tools");
        assert_eq!(
            (reg.label, reg.subject_noun, reg.admin_noun, reg.audit_kind),
            ("MCP", "MCP server", "mcp-server", "mcp_server")
        );
        assert_eq!(reg.dialects, vec!["jsonrpc"]);
        assert_eq!(reg.record_kinds, declared.record_kinds);
        assert_eq!(reg.record_kinds.len(), 4);
        assert!(!served.op_classes.is_empty());
        assert_eq!(reg.scope_kinds, declared.scope_kinds);
        assert_eq!(reg.trust_keys, declared.trust_keys);
        assert_eq!(reg.signing, declared.signing);
        assert!(reg.signing.is_some());
        assert_eq!(
            reg.billable_classes,
            served
                .billable_classes
                .iter()
                .copied()
                .zip(served.billable_families.iter().copied())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            reg.caller_credential_refusal,
            Some(served.caller_credential_refusal)
        );
        assert_eq!((reg.validate)(b"{}"), Ok(()));
        assert!((reg.validate)(b"{").is_err());
        let first = (reg.facing)(b"{}", b"", None, &[]).unwrap();
        assert_eq!((reg.facing)(b"{}", b"", None, &[]).unwrap(), first);
        format!("{reg:?}")
    };
    assert_eq!(check(linked), check(dropped));
}
#[test]
fn mcp_snapshot_routes_survive_refresh_retirement_and_close() {
    for p in [linked(), dropped()] {
        let first = open_door(&p, b"{}", b"{}", None).unwrap();
        let published = first.clone();
        assert_eq!(first.generation, 1);
        assert_eq!(refresh_door(&p, b"{}", b"{}", 2).unwrap().generation, 2);
        retire_door(&p, 1);
        drop(p);
        assert_eq!(first, published);
        assert_eq!(first.generation, 1);
        assert!(first.claims.is_empty());
        let routes = first
            .admin_routes
            .iter()
            .map(|route| {
                (
                    route.verb.as_str(),
                    route.target.as_str(),
                    route.audit_verb.as_str(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            routes,
            [
                ("POST", "/tools/{name}/connect", "connect"),
                ("GET", "/tools/{name}/changes", ""),
                ("GET", "/tools/{name}/health", "")
            ]
        );
    }
}

#[test]
fn mcp_function_macro_and_loaded_rows_preserve_the_same_door_and_statement() {
    use busbar_plugin_loader::dispatch::{
        rendering_of, rendering_of_loaded, rendering_of_macro, LinkedRow, LoadedDoor,
    };
    let door = busbar_plane_mcp::door;
    let macro_door = busbar_plane_mcp::MACRO_DOOR;
    let restated = unsafe { LoadedDoor::from_raw(busbar_plugin_loader::dispatch::load::raw(door)) };
    assert_eq!(door as *const () as usize, macro_door.door_fn() as usize);
    let by_fn = LinkedRow::of(door).expect("actual function door states itself");
    let by_macro = LinkedRow::of_macro(macro_door).expect("actual macro handle states itself");
    let by_loaded = LinkedRow::of_loaded(restated).expect("actual loaded door states itself");
    assert_eq!(by_fn.statement, by_macro.statement);
    assert_eq!(by_fn.statement, by_loaded.statement);
    assert_eq!(by_fn.door as usize, by_macro.door as usize);
    assert_eq!(by_fn.door as usize, by_loaded.door as usize);
    assert_eq!(
        rendering_of(door).unwrap(),
        rendering_of_macro(macro_door).unwrap()
    );
    assert_eq!(
        rendering_of(door).unwrap(),
        rendering_of_loaded(restated).unwrap()
    );

    use busbar_plugin_loader::dispatch::kinds::plane::Plane;
    use busbar_plugin_loader::dispatch::{
        load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
    };
    use std::sync::Arc;
    let dispatcher = Dispatcher::new(
        DispatchConfig::default(),
        busbar_contract::services::test_caller_binding(),
    );
    let bind = |row: &LinkedRow| {
        load_linked::<Plane>(
            row,
            Bind {
                instance: "mcp-owner-identity".into(),
                max_inflight_cap: 8,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::Probe,
            },
        )
        .expect("the actual plane descriptor binds")
    };
    let linked = bind(&by_fn);
    let linked_macro = bind(&by_macro);
    let linked_loaded = bind(&by_loaded);
    let shape = |plugin: &busbar_plugin_loader::dispatch::Plugin<Plane>| {
        (
            plugin.name().to_string(),
            plugin.kind(),
            plugin.max_inflight(),
        )
    };
    assert_eq!(shape(&linked), shape(&linked_macro));
    assert_eq!(shape(&linked), shape(&linked_loaded));
}
