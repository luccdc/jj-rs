use std::sync::{Arc, Mutex, RwLock};

use crate::commands::check::CheckCommands;

#[derive(Clone)]
pub struct RuntimeCheckStateHandle {
    state: Arc<Mutex<RuntimeCheckStateInternal>>,
}

struct RuntimeCheckStateInternal {
    state: RuntimeCheckState,
}

enum RuntimeCheckState {
    NotRunning,
    Running,
}

pub struct DaemonHandle<'scope> {
    logs: &'scope super::logs::LogHandler,
    checks: &'scope RwLock<super::RuntimeDaemonConfig>,
}

impl DaemonHandle<'_> {
    pub fn register_check(
        &self,
        host: String,
        service: String,
        check: CheckCommands,
    ) -> anyhow::Result<()> {
        let Ok(mut lock) = self.checks.write() else {
            anyhow::bail!("Could not acquire write lock on daemon config!");
        };

        let host_config = lock.checks.entry(host.clone()).or_default();

        if host_config.contains_key(&service) {
            anyhow::bail!("Service `{service}` already defined for host `{host}`");
        }

        host_config.insert(
            service,
            (
                check,
                RuntimeCheckStateHandle {
                    state: Arc::new(Mutex::new(RuntimeCheckStateInternal {
                        state: RuntimeCheckState::NotRunning,
                    })),
                },
            ),
        );

        Ok(())
    }

    pub fn import_config(&self, config: &super::DaemonConfig) -> anyhow::Result<()> {
        let Ok(mut lock) = self.checks.write() else {
            anyhow::bail!("Could not acquire write lock on daemon config!");
        };

        for (host, services) in &config.checks {
            let host_config = lock.checks.entry(host.clone()).or_default();

            for (service, check) in services {
                if host_config.contains_key(service) {
                    eprintln!("Duplicate service `{service}` found for host `{host}`");
                    continue;
                }

                host_config.insert(
                    service.to_string(),
                    (
                        check.clone(),
                        RuntimeCheckStateHandle {
                            state: Arc::new(Mutex::new(RuntimeCheckStateInternal {
                                state: RuntimeCheckState::NotRunning,
                            })),
                        },
                    ),
                );
            }
        }
        Ok(())
    }

    pub fn start_all_unstarted(&self) -> anyhow::Result<()> {
        todo!()
    }
}

pub fn spawn_daemon<'scope, 'env: 'scope>(
    logs: &'scope super::logs::LogHandler,
    checks: &'scope RwLock<super::RuntimeDaemonConfig>,
    _prompt_writer: std::io::PipeWriter,
    _answer_reader: std::io::PipeReader,
    _scope: &'scope std::thread::Scope<'scope, 'env>,
) -> DaemonHandle<'scope> {
    DaemonHandle { checks, logs }
}
