//! The recent jobs a connection can still submit against.

use std::collections::VecDeque;
use std::sync::Arc;

use super::template::ActiveTemplate;

/// Jobs kept per connection. A share for an older job is stale.
pub const JOB_HISTORY: usize = 8;

/// A job as issued: the template and the difficulty it was issued at.
///
/// The share target travels with the job, not the connection, so a
/// difficulty change does not retroactively reject work the miner is still
/// hashing on an earlier job.
#[derive(Clone)]
pub struct Job {
    pub template: Arc<ActiveTemplate>,
    pub difficulty: u64,
    pub share_target: [u8; 32],
}

/// A ring of the last [`JOB_HISTORY`] jobs, keyed by job id.
pub struct JobManager {
    jobs: VecDeque<Job>,
    next_id: u32,
}

impl Default for JobManager {
    fn default() -> Self {
        Self::new()
    }
}

impl JobManager {
    pub fn new() -> Self {
        Self { jobs: VecDeque::with_capacity(JOB_HISTORY), next_id: 1 }
    }

    /// Allocate the id for the next job.
    pub fn next_job_id(&mut self) -> u32 {
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1).max(1);
        id
    }

    /// Record a newly issued job, evicting the oldest past the cap.
    pub fn push(&mut self, job: Job) {
        if self.jobs.len() == JOB_HISTORY {
            self.jobs.pop_front();
        }
        self.jobs.push_back(job);
    }

    pub fn get(&self, job_id: u32) -> Option<&Job> {
        self.jobs.iter().find(|j| j.template.job_id == job_id)
    }

    /// The most recently issued job.
    pub fn latest(&self) -> Option<&Job> {
        self.jobs.back()
    }

    /// Make every job accept shares at `target` if that is easier than the
    /// target it was issued with.
    ///
    /// Stratum V2 sets one target per channel, and a miner applies a new one
    /// to the jobs it already holds. When the target gets easier, shares on
    /// those jobs arrive at the new target at once; judging them by the old
    /// one would reject honest work. When it gets harder nothing changes: a
    /// share that met the old target was valid when the miner found it.
    pub fn relax_share_targets(&mut self, target: &[u8; 32], difficulty: u64) {
        for job in &mut self.jobs {
            if *target > job.share_target {
                job.share_target = *target;
                job.difficulty = difficulty;
            }
        }
    }

    /// Forget every job: the chain tip moved and none of them can make a
    /// block any more.
    pub fn mark_all_stale(&mut self) {
        self.jobs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stratum::template::tests::work_with;

    fn job(mgr: &mut JobManager) -> Job {
        let id = mgr.next_job_id();
        let template = ActiveTemplate::build(
            work_with(0, 0x207fffff),
            id,
            bitcoin::ScriptBuf::new_op_return([1]),
            8,
        )
        .unwrap();
        Job { template: Arc::new(template), difficulty: 1, share_target: [0xff; 32] }
    }

    #[test]
    fn old_jobs_are_evicted_and_a_tip_change_forgets_all() {
        let mut mgr = JobManager::new();
        let ids: Vec<u32> = (0..JOB_HISTORY + 2)
            .map(|_| {
                let j = job(&mut mgr);
                let id = j.template.job_id;
                mgr.push(j);
                id
            })
            .collect();
        assert!(mgr.get(ids[0]).is_none());
        assert!(mgr.get(ids[1]).is_none());
        assert!(mgr.get(ids[2]).is_some());
        assert_eq!(mgr.latest().unwrap().template.job_id, *ids.last().unwrap());
        mgr.mark_all_stale();
        assert!(mgr.get(*ids.last().unwrap()).is_none());
        assert!(mgr.latest().is_none());
    }
}
