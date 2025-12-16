// The check thread has the unfortunate job of jumping in and out of async worlds,
// unlike the other threads which can remain purely async or purely sync

use std::{
    collections::HashMap,
    io::{PipeReader, PipeWriter, Read, Write},
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    thread::Scope,
};

use nix::sys::{signal, wait};
use tokio::sync::{broadcast, mpsc};

use crate::checks::CheckResultType;

#[allow(dead_code)]
pub enum OutboundMessage {
    Start,
    Stop,
    Die,
    PromptResponse(String),
    TriggerNow,
}

fn update_stats<F>(
    daemon: &RwLock<super::RuntimeDaemonConfig>,
    id: &super::CheckId,
    update_func: F,
) -> eyre::Result<()>
where
    F: Fn(&super::RuntimeCheckHandle),
{
    let Ok(read) = daemon.read() else {
        eyre::bail!("Could not acquire read lock to update statistics");
    };

    let Some(checks) = read.checks.get(&id.0) else {
        eyre::bail!("Could not find host `{}` in runtime configuration", &id.0);
    };

    let Some(check) = checks.get(&id.1) else {
        eyre::bail!(
            "Could not find check `{}.{}` in runtime configuration",
            &id.0,
            &id.1
        );
    };

    (update_func)(&check.1);

    Ok(())
}

pub fn register_check<'scope, 'env: 'scope>(
    daemon: &'env RwLock<super::RuntimeDaemonConfig>,
    (check_id, check): (super::CheckId, super::CheckCommands),
    scope: &'scope Scope<'scope, 'env>,
    prompt_writer: mpsc::Sender<(super::CheckId, String)>,
    log_writer: PipeWriter,
    shutdown: broadcast::Receiver<()>,
    autostart: bool,
) -> eyre::Result<()> {
    let (message_sender, message_receiver) = tokio::sync::mpsc::channel(128);

    scope.spawn({
        let check_id = check_id.clone();
        let check = check.clone();
        move || {
            if let Err(e) = check_thread(
                daemon,
                (check_id, check),
                prompt_writer,
                &log_writer,
                shutdown,
                message_receiver,
                autostart,
            ) {
                eprintln!("Failed to run check thread! {e}");
            }
        }
    });

    {
        let Ok(mut checks) = daemon.write() else {
            eyre::bail!("Could not acquire write lock to register check");
        };

        let host = checks.checks.entry(Arc::clone(&check_id.0)).or_default();

        if host.contains_key(&check_id.1) {
            eyre::bail!(
                "Check `{}.{}` is already registered!",
                &check_id.0,
                &check_id.1
            );
        }

        host.insert(
            Arc::clone(&check_id.1),
            (
                check,
                super::RuntimeCheckHandle {
                    message_sender,
                    currently_running: AtomicBool::from(false),
                    started: AtomicBool::from(autostart),
                },
            ),
        );
    }

    Ok(())
}

fn check_thread<'scope, 'env: 'scope>(
    daemon: &'env RwLock<super::RuntimeDaemonConfig>,
    (check_id, check): (super::CheckId, super::CheckCommands),
    mut prompt_writer: mpsc::Sender<(super::CheckId, String)>,
    log_writer: &PipeWriter,
    mut shutdown: broadcast::Receiver<()>,
    mut message_receiver: mpsc::Receiver<OutboundMessage>,
    autostart: bool,
) -> eyre::Result<()> {
    let mut paused = !autostart;
    let mut check_prompt_values = HashMap::new();

    loop {
        update_stats(daemon, &check_id, |h| {
            h.currently_running.store(false, Ordering::Relaxed);
            h.started.store(!paused, Ordering::Relaxed);
        })?;

        if wait_for_trigger(
            daemon,
            &check_id,
            &mut message_receiver,
            &mut shutdown,
            &mut paused,
        )? {
            return Ok(());
        }

        update_stats(daemon, &check_id, |h| {
            h.currently_running.store(true, Ordering::Relaxed);
            h.started.store(!paused, Ordering::Relaxed);
        })?;

        let (prompt_reader_raw, prompt_writer_raw) = std::io::pipe()?;
        let (answer_reader_raw, answer_writer_raw) = std::io::pipe()?;
        let log_writer = log_writer.try_clone()?;

        match unsafe { nix::unistd::fork() }? {
            nix::unistd::ForkResult::Parent { child } => {
                if let Err(e) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?
                    .block_on(async {
                        Box::pin(run_parent(
                            &check_id,
                            prompt_reader_raw,
                            answer_writer_raw,
                            &mut prompt_writer,
                            &mut message_receiver,
                            &mut check_prompt_values,
                            child,
                        ))
                        .await
                    })
                {
                    eprintln!("Could not manage check child process: {e}");
                }
            }
            nix::unistd::ForkResult::Child => {
                if let Err(e) = run_child(
                    check_id,
                    check,
                    prompt_writer_raw,
                    answer_reader_raw,
                    log_writer,
                ) {
                    eprintln!("Could not run check process: {e}");
                }
                std::process::exit(0);
            }
        }
    }
}

fn wait_for_trigger(
    daemon: &RwLock<super::RuntimeDaemonConfig>,
    check_id: &super::CheckId,
    message_receiver: &mut mpsc::Receiver<OutboundMessage>,
    shutdown: &mut broadcast::Receiver<()>,
    paused: &mut bool,
) -> eyre::Result<bool> {
    let timeout = {
        let Ok(read) = daemon.read() else {
            eyre::bail!("Could not acquire lock to read interval time!");
        };

        read.check_interval
    };

    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let sleep = tokio::time::sleep(timeout);
            tokio::pin!(sleep);

            loop {
                if *paused {
                    while let Some(msg) = tokio::select! {
                        _ = shutdown.recv() => {
                            return Ok(true)
                        }
                        msg = message_receiver.recv() => msg
                    } {
                        match msg {
                            OutboundMessage::Die => return Ok(true),
                            OutboundMessage::Start => {
                                *paused = false;
                                return Ok(false);
                            }
                            OutboundMessage::PromptResponse(_) => {}
                            OutboundMessage::Stop => {
                                *paused = true;
                            }
                            OutboundMessage::TriggerNow => {
                                return Ok(false);
                            }
                        }
                    }
                } else {
                    while let Some(msg) = tokio::select! {
                        () = &mut sleep => {
                            return Ok(false)
                        }
                        _ = shutdown.recv() => {
                            return Ok(true)
                        }
                        msg = message_receiver.recv() => msg
                    } {
                        match msg {
                            OutboundMessage::Die => return Ok(true),
                            OutboundMessage::Start => {
                                *paused = false;
                                return Ok(false);
                            }
                            OutboundMessage::PromptResponse(_) => {}
                            OutboundMessage::Stop => {
                                *paused = true;
                                update_stats(daemon, check_id, |h| {
                                    h.currently_running.store(true, Ordering::Relaxed);
                                    h.started.store(false, Ordering::Relaxed);
                                })?;
                                break;
                            }
                            OutboundMessage::TriggerNow => {
                                return Ok(false);
                            }
                        }
                    }
                }
            }
        })
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum ChildToParentMsg {
    Done,
    Prompt(String),
}

#[derive(serde::Serialize, serde::Deserialize)]
pub enum ParentToChildMsg {
    Answer(String),
}

// This is intended to be run on a thread dedicated to running the parent of the
// check process. As such, it is ok to use blocking APIs
async fn run_parent(
    check_id: &super::CheckId,
    mut prompt_reader_raw: PipeReader,
    mut answer_writer_raw: PipeWriter,
    prompt_writer: &mut mpsc::Sender<(super::CheckId, String)>,
    message_receiver: &mut mpsc::Receiver<OutboundMessage>,
    check_prompt_values: &mut HashMap<String, String>,
    child: nix::unistd::Pid,
) -> eyre::Result<()> {
    let mut message_buffer = [0u8; 16384];

    loop {
        let Ok(bytes) = prompt_reader_raw.read(&mut message_buffer) else {
            eprintln!("Could not receive message from check child!");
            continue;
        };

        // EOF
        if bytes == 0 {
            return Ok(());
        }

        let Ok(msg) = serde_json::from_slice::<ChildToParentMsg>(&message_buffer[..bytes]) else {
            eprintln!("Could not parse message from child");
            continue;
        };

        match msg {
            ChildToParentMsg::Done => {
                signal::kill(child, signal::SIGINT)?;
                break;
            }
            ChildToParentMsg::Prompt(p) => {
                let pr = if let Some(pr) = check_prompt_values.get(&p) {
                    pr.clone()
                } else {
                    prompt_writer.send((check_id.clone(), p.clone())).await?;

                    loop {
                        let Some(m) = message_receiver.recv().await else {
                            eyre::bail!("Did not receive prompt response message");
                        };
                        let OutboundMessage::PromptResponse(r) = m else {
                            continue;
                        };

                        break r;
                    }
                }
                .trim()
                .to_string();

                check_prompt_values.insert(p.clone(), pr.clone());

                let resp_json = serde_json::to_string(&ParentToChildMsg::Answer(pr))?;
                answer_writer_raw.write_all(resp_json.as_bytes())?;
            }
        }
    }

    wait::waitpid(child, Some(wait::WaitPidFlag::empty()))?;

    Ok(())
}

fn run_child(
    check_id: super::CheckId,
    check: super::CheckCommands,
    mut prompt_writer_raw: PipeWriter,
    answer_reader_raw: PipeReader,
    log_writer: PipeWriter,
) -> eyre::Result<()> {
    if let Err(e) = run_troubleshooter(
        check_id,
        check,
        &mut prompt_writer_raw,
        answer_reader_raw,
        log_writer,
    ) {
        eprintln!("Could not run check! {e}");
    }

    let done_msg = serde_json::to_string(&ChildToParentMsg::Done)?;
    prompt_writer_raw.write_all(done_msg.as_bytes())?;

    Ok(())
}

fn run_troubleshooter(
    check_id: super::CheckId,
    check: super::CheckCommands,
    prompt_writer_raw: &mut PipeWriter,
    mut answer_reader_raw: PipeReader,
    mut log_writer: PipeWriter,
) -> eyre::Result<()> {
    let mut runner = crate::checks::DaemonTroubleshooter::new(move |prompt| {
        let prompt_msg = serde_json::to_string(&ChildToParentMsg::Prompt(prompt.to_string()))?;
        prompt_writer_raw.write_all(prompt_msg.as_bytes())?;

        let mut resp_buffer = vec![0u8; 32768];
        let bytes = answer_reader_raw.read(&mut resp_buffer)?;

        let ParentToChildMsg::Answer(answer) = serde_json::from_slice(&resp_buffer[..bytes])?;

        Ok(answer)
    });

    let t = check.troubleshooter();
    let checks = t.checks()?;

    let mut overall_result = CheckResultType::NotRun;

    let mut steps = HashMap::new();

    for (i, check) in checks.into_iter().enumerate() {
        let key = format!("step{i}");

        let value = check.run_check(&mut runner)?;

        overall_result &= value.result_type;

        steps.insert(key, (check.name().to_string(), value));
    }

    let result = super::logs::LogEvent::Result(super::TroubleshooterResult {
        timestamp: chrono::Utc::now(),
        check_id,
        overall_result,
        steps,
    });

    let result_json = serde_json::to_string(&result)?;
    log_writer.write_all(result_json.as_bytes())?;

    Ok(())
}
