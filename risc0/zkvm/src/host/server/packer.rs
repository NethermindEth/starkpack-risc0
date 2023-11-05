use anyhow::{Ok, Result};
use risc0_binfmt::MemoryImage;
use risc0_circuit_rv32im::CircuitImpl;
use risc0_core::field::baby_bear::BabyBear;
use risc0_zkp::prove::{adapter::ProveAdapter, executor::Executor};

use crate::{
    host::{receipt::ExitCode, server::prove::exec::MachineContext, CIRCUIT},
    Executor as SessionExec, ExecutorEnv, Loader, Segment, SegmentRef, Session, SessionEvents,
};

pub struct PackSession {
    pub pack_segments: Vec<Vec<Box<dyn SegmentRef>>>,
    pub pack_journals: Vec<Vec<u8>>,
    pub pack_exit_codes: Vec<ExitCode>,
    pub pack_hooks: Vec<Option<Vec<Box<dyn SessionEvents>>>>,
}

impl PackSession {
    pub fn new_from_envs(envs: Vec<ExecutorEnv<'_>>, image: MemoryImage) -> Result<Self> {
        assert!(envs.is_empty() == false, "No execution enviroments found");
        let mut sessions = Vec::new();
        for env in envs {
            let mut exec = SessionExec::new(env, image.clone())?;
            let sub_session = exec.run()?;
            sessions.push(sub_session);
        }
        Ok(PackSession::join_segments(sessions))
    }

    pub fn join_segments(sessions: Vec<Session>) -> PackSession {
        let mut pack_segments = Vec::<Vec<_>>::with_capacity(sessions.len());
        let mut pack_journals = Vec::new();
        let mut pack_exit_codes = Vec::new();
        let mut pack_hooks = Vec::new();
        for session in sessions {
            for (i, segment) in session.segments.iter().enumerate() {
                if pack_segments.len() <= i {
                    pack_segments.push(vec![]);
                }
                pack_segments[i].push(segment.copy_box());
            }
            pack_journals.push(session.journal);
            pack_exit_codes.push(session.exit_code);
            if session.hooks.is_empty() {
                pack_hooks.push(None);
            } else {
                pack_hooks.push(Some(session.hooks))
            }
        }
        PackSession {
            pack_segments,
            pack_journals,
            pack_exit_codes,
            pack_hooks,
        }
    }

    pub fn resolve_packed_segments(&self) -> Result<Vec<Vec<Segment>>> {
        let mut resolved_packed_segments: Vec<Vec<Segment>> = Vec::new();
        for pack_segment in self.pack_segments.iter() {
            let mut ith_pack_segments = Vec::new();
            for segment in pack_segment {
                let resolved_seg = segment.resolve()?;
                ith_pack_segments.push(resolved_seg);
            }
            resolved_packed_segments.push(ith_pack_segments);
        }
        Ok(resolved_packed_segments)
    }

    pub fn generate_machine_executors(
        pack_segment: Vec<&Segment>,
    ) -> Vec<Executor<BabyBear, CircuitImpl, MachineContext>> {
        let mut ios = Vec::new();
        let mut executors = Vec::new();
        let max_po2_in_segments = pack_segment
            .iter()
            .map(|segment| segment.po2)
            .max()
            .unwrap();
        for segment in pack_segment.iter() {
            let io = segment.prepare_globals();
            ios.push(io.clone());
            let machine = MachineContext::new(segment);
            let executor = Executor::new(
                &CIRCUIT,
                machine,
                max_po2_in_segments,
                max_po2_in_segments,
                &io,
            );
            executors.push(executor);
        }
        executors
    }

    pub fn generate_adapters(
        executors: &mut Vec<Executor<BabyBear, CircuitImpl, MachineContext>>,
    ) -> Result<Vec<ProveAdapter<'_, BabyBear, CircuitImpl, MachineContext>>> {
        let mut adapters = Vec::new();
        for executor in executors.iter_mut() {
            let loader = Loader::new();
            loader.load(|chunk, fini| executor.step(chunk, fini))?;
            executor.finalize();
            let adapter = ProveAdapter::new(executor);
            adapters.push(adapter);
        }
        Ok(adapters)
    }
}
