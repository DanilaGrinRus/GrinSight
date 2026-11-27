use super::*;
use slint::Model;

const HEIGHT: u64 = 4_122_001;
const CONFIRMED_TIME: u64 = 1_800_000_000;
const CONFIRMATIONS: u64 = 19;
const BALANCE: u64 = 1_000_000_000;
const POSITIVE_REPORT: &str = "the tip is confirmed by public nodes";
const NEGATIVE_REPORT: &str = "the time is not confirmed: too few public nodes answered";

#[derive(Clone, Copy, Debug)]
enum Wallet {
    Confirmed,
    QuorumLost,
    TimeLost,
    BothLost,
    NoReply,
}

fn refresh(app: &App, history: &str, host_report: &str, wallet: Wallet) {
    let report = format!("headers verified to {HEIGHT} from {history}; blocks applied to the tip, {HEIGHT}; {host_report}");
    let mut wallet_reads = 0;
    let view = gather_from(None, Some(false), |method, _| {
        Ok(match method {
            "host.status" => {
                json!({"network":"main","chain":{"configured":true,"phase":"ready","problem":report}})
            }
            "paycore.wallet.chain_status" => {
                wallet_reads += 1;
                let (selected, timestamp) = match wallet {
                    Wallet::Confirmed => (true, Some(CONFIRMED_TIME)),
                    Wallet::QuorumLost => (false, Some(CONFIRMED_TIME)),
                    // An incomplete reply still naming a tip must fail closed.
                    Wallet::TimeLost => (true, None),
                    Wallet::BothLost => (false, None),
                    Wallet::NoReply => return Err(CallError::Timeout),
                };
                json!({
                    "state": if selected {"at_tip"} else {"behind"},
                    "tip_height":HEIGHT, "selected_height":selected.then_some(HEIGHT),
                    "confirmed_time":timestamp, "k_conf":CONFIRMATIONS,
                    "balance":{"spendable":BALANCE.to_string(),"reserved":"0","immature":"0","incomplete":false}
                })
            }
            "paycore.chain.status" | "paycore.balance" => {
                panic!("split wallet refresh through {method}")
            }
            "paycore.search.status" => json!({"state":"done"}),
            _ => Value::Null,
        })
    });
    assert_eq!(
        wallet_reads, 1,
        "each refresh must read one wallet snapshot"
    );
    apply(app, view);
}

fn assert_window(app: &App, wallet: Wallet) {
    let verified = matches!(wallet, Wallet::Confirmed);
    let clock_confirmed = matches!(wallet, Wallet::Confirmed | Wallet::QuorumLost);
    let no_reply = matches!(wallet, Wallet::NoReply);
    let stage = |label: &str| {
        app.get_sync_stages()
            .iter()
            .find(|s| s.label == label)
            .unwrap()
    };
    let detail = |label: &str| {
        app.get_sync_rows()
            .iter()
            .find(|r| r.label == label)
            .unwrap()
    };

    assert_eq!(app.get_verified_good(), verified, "{wallet:?}: banner");
    assert_eq!(app.get_sync_readiness() == tr("Ready to use", "Готово к работе"), verified);
    if !verified {
        assert!(app.get_sync_readiness().starts_with(app.get_verified_chip().as_str()));
    }
    assert_eq!(
        app.get_verified().contains(&fill(tr("Your wallet is ready to use. Public nodes verified the tip at block {}.", "Кошельком можно пользоваться. Публичные ноды подтвердили вершину на блоке {}."), &[&HEIGHT.to_string()])),
        verified,
        "the readiness message must disappear as soon as verification is lost"
    );
    assert_eq!(
        app.get_verified_chip() == tr("VERIFIED", "ПРОВЕРЕНО"),
        verified
    );
    if no_reply {
        assert_eq!(app.get_balance(), "—");
    } else {
        assert_eq!(app.get_balance().as_str(), amount(BALANCE));
        assert!(detail(tr("Confirmation", "Подтверждение"))
            .value
            .contains("19"));
    }
    let blocks = stage(tr("Blocks", "Блоки"));
    assert!(blocks.value.contains("4 122 001"));
    assert_eq!(
        blocks.tone, 1,
        "local block progress survives a lost quorum"
    );
    let tip = stage(tr("Tip", "Вершина"));
    assert_eq!(tip.tone == 1, verified, "{wallet:?}: tip: {}", tip.value);
    if verified {
        assert_ne!(
            tip.value,
            tr(
                NEGATIVE_REPORT,
                "время не подтверждено: ответило слишком мало публичных нод"
            )
        );
    } else {
        assert_ne!(
            tip.value,
            tr(
                "confirmed by public nodes",
                "подтверждена публичными нодами"
            )
        );
    }
    let chosen = detail(tr("Chosen tip", "Выбранная вершина"));
    assert_eq!(
        chosen.tone == 1,
        verified,
        "{wallet:?}: chosen tip: {}",
        chosen.value
    );
    if verified {
        assert!(chosen.value.contains("4 122 001"));
    }
    let wallet_detail = detail(tr("Wallet", "Кошелёк"));
    assert_eq!(
        wallet_detail.tone == 1,
        verified,
        "{wallet:?}: wallet: {}",
        wallet_detail.value
    );
    let time = detail(tr("Time", "Время"));
    assert_eq!(
        time.tone == 1,
        clock_confirmed,
        "{wallet:?}: time: {}",
        time.value
    );
    if clock_confirmed {
        assert!(time.value.contains("08:00 UTC"));
    }
    let words = app.get_sync_words();
    if verified {
        assert!(!words.iter().any(|line| line.as_str() == NEGATIVE_REPORT));
    } else {
        assert!(!words.iter().any(|line| line.as_str() == POSITIVE_REPORT));
    }
    println!(
        "{wallet:?}: {} | {} | {} | {}",
        app.get_verified_chip(),
        blocks.value,
        tip.value,
        time.value
    );
}

#[test]
fn fresh_and_returning_profiles_show_local_blocks_separately_from_quorum_and_time(
) -> Result<(), Box<dyn std::error::Error>> {
    const CHILD: &str = "GRINSIGHT_UI_FRESHNESS_TEST_LOCALE";
    // Language and the Slint platform belong to the process. Isolate both
    // locales from other window tests running in the same suite.
    let Ok(locale) = std::env::var(CHILD) else {
        let test = "live::freshness_tests::fresh_and_returning_profiles_show_local_blocks_separately_from_quorum_and_time";
        for locale in ["en", "ru"] {
            let run = std::process::Command::new(std::env::current_exe()?)
                .args(["--exact", test, "--nocapture"])
                .env(CHILD, locale)
                .output()?;
            let log = String::from_utf8_lossy(&run.stdout);
            assert!(
                run.status.success() && log.contains("1 passed"),
                "{log}\n{}",
                String::from_utf8_lossy(&run.stderr)
            );
            print!("{log}");
        }
        return Ok(());
    };
    assert!(locale == "ru" || locale == "en");
    let window = slint::platform::software_renderer::MinimalSoftwareWindow::new(
        slint::platform::software_renderer::RepaintBufferType::NewBuffer,
    );
    slint::platform::set_platform(Box::new(crate::keys_tests::Plain(window)))?;
    let release = "a release starting point (4115520)";
    let returning = "a locally saved point: headers checked from network genesis (4122000)";
    for history in [release, returning] {
        let app = App::new()?;
        crate::set_language(&app, &locale);
        println!("{locale}, {history}");
        if history == returning {
            refresh(&app, history, POSITIVE_REPORT, Wallet::Confirmed);
            assert_window(&app, Wallet::Confirmed);
        }
        for lost in [
            Wallet::QuorumLost,
            Wallet::TimeLost,
            Wallet::BothLost,
            Wallet::NoReply,
        ] {
            refresh(&app, history, POSITIVE_REPORT, lost);
            assert_window(&app, lost);
            refresh(&app, history, NEGATIVE_REPORT, Wallet::Confirmed);
            assert_window(&app, Wallet::Confirmed);
        }
        refresh(&app, history, "public nodes did not confirm the tip (1 answered, 3 needed, 1 named it)", Wallet::QuorumLost);
        let tip = app.get_sync_stages().iter().find(|s| s.label == tr("Tip", "Вершина")).unwrap();
        assert!(tip.value.starts_with(tr("public nodes did not confirm the tip", "публичные ноды не подтвердили вершину")));
        assert!(tip.value.contains('3'));
        // Selection alone cannot mark the wallet ready when the balance reply is missing.
        refresh_balance_fixture(&app, false);
        assert_eq!(app.get_balance(), "—");
        assert!(!app.get_verified_good());
        assert_ne!(app.get_verified_chip(), tr("VERIFIED", "ПРОВЕРЕНО"));
    }
    Ok(())
}
