// SPDX-FileCopyrightText: 2025 Greenbone AG
//
// SPDX-License-Identifier: GPL-2.0-or-later WITH x11vnc-openssl-exception

use crate::models::{Parameter, Protocol, VTData};
use crate::nasl::interpreter::{ForkingInterpreter, InterpreterError};
use crate::nasl::utils::Register;
use crate::nasl::utils::ctx::TargetId;
use crate::nasl::utils::lookup_keys::SCRIPT_PARAMS;
use crate::scheduling::Stage;
use crate::storage::error::StorageError;
use crate::storage::items::kb::{self, KbContext, KbContextKey, KbItem, KbKey};
use tracing::{trace, warn};

use crate::nasl::prelude::*;

use super::ExecuteError;
use super::error::{ExecutionTiming, ScriptResult, ScriptResultKind};

/// Runs a single VT to completion on a single host.
pub struct VTRunner<'a> {
    target: TargetId,
    vt: &'a VTData,
    stage: Stage,
    param: Option<&'a Vec<Parameter>>,

    scan_ctx: &'a ScanCtx<'a>,
}

impl<'a> VTRunner<'a> {
    #[allow(clippy::too_many_arguments)]
    pub async fn run(
        target: TargetId,
        vt: &'a VTData,
        stage: Stage,
        param: Option<&'a Vec<Parameter>>,
        scan_ctx: &'a ScanCtx<'a>,
    ) -> Result<ScriptResult, ExecuteError> {
        let s = Self {
            target,
            vt,
            stage,
            param,

            scan_ctx,
        };
        s.execute().await
    }

    fn set_parameters(&mut self, register: &mut Register) -> Result<(), ExecuteError> {
        if let Some(params) = &self.param {
            for p in params.iter() {
                register.add_global_var(
                    format!("{}_{}", SCRIPT_PARAMS, p.id).as_str(),
                    NaslValue::String(p.value.clone()),
                );
            }
        }
        Ok(())
    }

    async fn check_key<A, B, C>(
        &self,
        key: &KbContextKey,
        result_none: A,
        result_some: B,
        result_err: C,
    ) -> Result<(), ScriptResultKind>
    where
        A: Fn() -> Option<ScriptResultKind>,
        B: Fn(Vec<KbItem>) -> Option<ScriptResultKind>,
        C: Fn(StorageError) -> Option<ScriptResultKind>,
    {
        let result = match self.scan_ctx.storage().retrieve(key).await {
            Ok(x) => {
                if let Some(x) = x {
                    result_some(x)
                } else {
                    trace!("not found");
                    result_none()
                }
            }
            Err(e) => {
                warn!(error=%e, "storage error");
                result_err(e)
            }
        };
        match result {
            None => Ok(()),
            Some(x) => Err(x),
        }
    }

    async fn check_keys(&self, vt: &VTData) -> Result<(), ScriptResultKind> {
        let key = self.generate_key();
        for k in &vt.required_keys {
            self.check_key(
                &KbContextKey(key.clone(), k.into()),
                || Some(ScriptResultKind::MissingRequiredKey(k.into())),
                |_| None,
                |_| Some(ScriptResultKind::MissingRequiredKey(k.into())),
            )
            .await?
        }

        for k in &vt.mandatory_keys {
            self.check_key(
                &KbContextKey(key.clone(), k.into()),
                || Some(ScriptResultKind::MissingMandatoryKey(k.into())),
                |_| None,
                |_| Some(ScriptResultKind::MissingMandatoryKey(k.into())),
            )
            .await?
        }

        for k in &vt.excluded_keys {
            self.check_key(
                &KbContextKey(key.clone(), k.into()),
                || None,
                |_| Some(ScriptResultKind::ContainsExcludedKey(k.into())),
                |_| None,
            )
            .await?
        }

        // script_require_ports() receives alternatives, not a list of ports
        // that must all be open. For example, a VT may declare
        // ("Services/ftp", 21, 6200), where any one matching service/port is
        // sufficient to run the check. Requiring every entry made nearly all
        // vulnerability VTs exit before their NASL body executed.
        check_required_ports(&self.scan_ctx, &key, Protocol::TCP, &vt.required_ports).await?;
        check_required_ports(&self.scan_ctx, &key, Protocol::UDP, &vt.required_udp_ports).await?;

        Ok(())
    }

    // TODO: probably better to enhance ContextKey::Scan to contain target and scan_id?
    fn generate_key(&self) -> KbContext {
        let target_ip = self.scan_ctx.target_by_id(self.target).ip_addr();
        (
            self.scan_ctx.scan().clone(),
            crate::storage::Target(target_ip.to_string()),
        )
    }

    async fn execute_inner(
        &self,
        code: Code,
        register: Register,
    ) -> (ScriptResultKind, ExecutionTiming) {
        let mut timing = ExecutionTiming::default();
        let started = std::time::Instant::now();
        if let Err(e) = self.check_keys(self.vt).await {
            timing.prerequisites = started.elapsed();
            return (e, timing);
        }
        timing.prerequisites = started.elapsed();
        let script_ctx = ScriptCtx::new(self.scan_ctx, self.target, self.vt.clone());
        let parse_started = std::time::Instant::now();
        let ast = code.parse().emit_errors();
        timing.parse = parse_started.elapsed();
        if let Err(errs) = ast {
            return (
                ScriptResultKind::Error(InterpreterError::syntax_error(errs)),
                timing,
            );
        }
        let ast = ast.unwrap();

        let mut interpreter = ForkingInterpreter::new(ast, register, self.scan_ctx, script_ctx);
        let interpreter_started = std::time::Instant::now();
        while let Some(r) = interpreter.next().await {
            match r {
                Ok(NaslValue::Exit(x)) => {
                    timing.interpreter = interpreter_started.elapsed();
                    return (ScriptResultKind::ReturnCode(x), timing);
                }
                Err(e) => {
                    timing.interpreter = interpreter_started.elapsed();
                    return (ScriptResultKind::Error(e), timing);
                }
                Ok(x) => {
                    trace!(statement_result=?x);
                }
            }
        }
        timing.interpreter = interpreter_started.elapsed();
        (ScriptResultKind::ReturnCode(0), timing)
    }

    async fn execute(mut self) -> Result<ScriptResult, ExecuteError> {
        let load_started = std::time::Instant::now();
        let code = Code::load(self.scan_ctx.loader(), &self.vt.filename)?;
        let source_load = load_started.elapsed();
        let mut register = Register::default();
        self.set_parameters(&mut register)?;

        // currently scans are limited to the target as well as the id.
        tracing::info!(oid = %self.vt.oid, filename = %self.vt.filename, "running VT");
        let (kind, mut timing) = self.execute_inner(code, register).await;
        timing.source_load = source_load;
        tracing::debug!(result=?kind, "finished");
        Ok(ScriptResult {
            oid: self.vt.oid.clone(),
            filename: self.vt.filename.clone(),
            stage: self.stage,
            kind,
            target: self
                .scan_ctx
                .target_by_id(self.target)
                .original_target_str()
                .into(),
            timing,
        })
    }
}

async fn check_required_ports(
    scan_ctx: &ScanCtx<'_>,
    key: &KbContext,
    protocol: Protocol,
    requirements: &[String],
) -> Result<(), ScriptResultKind> {
    if requirements.is_empty() {
        return Ok(());
    }

    for requirement in requirements {
        let kb_key = if let Some(service) = requirement.strip_prefix("Services/") {
            KbKey::Service(kb::Service::Custom(service.to_string()))
        } else if requirement.contains('/') {
            KbKey::Custom(requirement.clone())
        } else {
            match protocol {
                Protocol::TCP => KbKey::Port(kb::Port::Tcp(requirement.clone())),
                Protocol::UDP => KbKey::Port(kb::Port::Udp(requirement.clone())),
            }
        };
        let context_key = KbContextKey(key.clone(), kb_key);
        match scan_ctx.storage().retrieve(&context_key).await {
            Ok(Some(values)) => {
                if values.into_iter().any(bool::from) {
                    return Ok(());
                }
            }
            Ok(None) => {}
            Err(error) => {
                warn!(%error, requirement, "failed to read required port key");
            }
        }
    }

    Err(ScriptResultKind::MissingPort(
        protocol,
        requirements.join(", "),
    ))
}
