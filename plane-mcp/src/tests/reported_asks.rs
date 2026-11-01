use super::*;

#[test]
fn a_later_rounds_key_cannot_complete_or_preempt_an_earlier_round() {
    let rounds = vec![
        round(&[("first", crate::tools_config::ASK_ELICITATION)]),
        round(&[("later", crate::tools_config::ASK_ELICITATION)]),
    ];
    let mut seal = Plain::default();
    let AskDecision::Ask {
        request_state: first,
        ..
    } = decide(
        &rounds,
        3,
        &caps(),
        Retry::default(),
        bind("k"),
        "d",
        Some(&mut seal),
    )
    else {
        panic!("first ask")
    };
    let premature = json!({"later":"premature"});
    assert!(matches!(
        decide(
            &rounds,
            3,
            &caps(),
            Retry {
                responses: Some(&premature),
                state: Some(&first)
            },
            bind("k"),
            "d",
            Some(&mut seal)
        ),
        AskDecision::Refuse(AskRefusal::Unanswered { .. })
    ));
    let mixed = json!({"first":"accepted", "later":"premature"});
    let AskDecision::Ask {
        request_state: second,
        ..
    } = decide(
        &rounds,
        3,
        &caps(),
        Retry {
            responses: Some(&mixed),
            state: Some(&first),
        },
        bind("k"),
        "d",
        Some(&mut seal),
    )
    else {
        panic!("next ask")
    };
    let final_answer = json!({"later":"current"});
    let AskDecision::Answered(answers) = decide(
        &rounds,
        3,
        &caps(),
        Retry {
            responses: Some(&final_answer),
            state: Some(&second),
        },
        bind("k"),
        "d",
        Some(&mut seal),
    ) else {
        panic!("answered")
    };
    assert_eq!(answers["first"], "accepted");
    assert_eq!(answers["later"], "current");
}
