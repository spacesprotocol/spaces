use std::collections::BTreeMap;

use anyhow::anyhow;
use spaces_protocol::{
    Covenant, RevokeReason, SpaceOut,
    bitcoin::{OutPoint, Transaction},
    hasher::{KeyHasher, SpaceKey},
    prepare::{SpacesSource, TxContext},
    validate::{TxChangeSet, UpdateKind, Validator},
};

use crate::store::Sha256;
use crate::store::chain::Chain;

pub struct TxChecker<'a> {
    pub original: &'a mut Chain,
    pub spaces: BTreeMap<SpaceKey, Option<OutPoint>>,
    pub spaceouts: BTreeMap<OutPoint, Option<SpaceOut>>,
}

impl<'a> TxChecker<'a> {
    pub fn new(snap: &'a mut Chain) -> Self {
        Self {
            original: snap,
            spaces: Default::default(),
            spaceouts: Default::default(),
        }
    }

    pub fn apply_package(
        &mut self,
        height: u32,
        txs: Vec<Transaction>,
    ) -> anyhow::Result<Vec<Option<TxChangeSet>>> {
        let mut sets = Vec::with_capacity(txs.len());
        for tx in txs {
            sets.push(self.apply_tx(height, &tx)?);
        }
        Ok(sets)
    }

    pub fn check_apply_tx(
        &mut self,
        height: u32,
        tx: &Transaction,
    ) -> anyhow::Result<Option<TxChangeSet>> {
        let changeset = self.apply_tx(height, tx)?;
        if let Some(changeset) = changeset.as_ref() {
            Self::check(changeset)?;
        }
        Ok(changeset)
    }

    pub fn apply_tx(
        &mut self,
        height: u32,
        tx: &Transaction,
    ) -> anyhow::Result<Option<TxChangeSet>> {
        let ctx = match { TxContext::from_tx::<Self, Sha256>(self, tx)? } {
            None => return Ok(None),
            Some(ctx) => ctx,
        };
        let validator = Validator::new();
        let changeset = validator.process(height, tx, ctx);
        let changeset2 = changeset.clone();

        let txid = tx.compute_txid();
        for spend in changeset.spends {
            let outpoint = tx.input[spend.n].previous_output;
            self.spaceouts.insert(outpoint, None);
        }
        for create in changeset.creates {
            let outpoint = OutPoint {
                txid,
                vout: create.n as _,
            };
            if let Some(space) = create.space.as_ref() {
                let key = SpaceKey::from(Sha256::hash(space.name.as_ref()));
                self.spaces.insert(key, Some(outpoint));
            }
            self.spaceouts.insert(outpoint, Some(create));
        }
        for update in changeset.updates {
            let space = SpaceKey::from(Sha256::hash(
                update
                    .output
                    .spaceout
                    .space
                    .as_ref()
                    .expect("space")
                    .name
                    .as_ref(),
            ));
            match update.kind {
                UpdateKind::Revoke(_) => {
                    self.spaces.insert(space, None);
                    self.spaceouts.insert(update.output.outpoint(), None);
                }
                _ => {
                    let outpoint = update.output.outpoint();
                    self.spaces.insert(space, Some(outpoint));
                    self.spaceouts
                        .insert(outpoint, Some(update.output.spaceout));
                }
            }
        }
        Ok(Some(changeset2))
    }

    pub fn check(changset: &TxChangeSet) -> anyhow::Result<()> {
        if changset
            .spends
            .iter()
            .any(|spend| spend.script_error.is_some())
        {
            return Err(anyhow!(
                "tx-check: transaction not broadcasted as it may have an open that will be rejected"
            ));
        }
        for create in changset.creates.iter() {
            if let Some(space) = create.space.as_ref()
                && matches!(space.covenant, Covenant::Reserved)
            {
                return Err(anyhow!(
                    "tx-check: transaction not broadcasted as it may cause spaces to use a reserved covenant"
                ));
            }
        }
        for update in changset.updates.iter() {
            if let UpdateKind::Revoke(kind) = update.kind
                && !matches!(kind, RevokeReason::Expired)
            {
                return Err(anyhow!(
                    "tx-check: transaction not broadcasted as it may cause a space to be revoked (code: {:?})",
                    kind
                ));
            }
        }
        Ok(())
    }
}

impl SpacesSource for TxChecker<'_> {
    fn get_space_outpoint(
        &mut self,
        space_hash: &SpaceKey,
    ) -> spaces_protocol::errors::Result<Option<OutPoint>> {
        match self.spaces.get(space_hash) {
            None => self.original.get_space_outpoint(space_hash),
            Some(res) => Ok(*res),
        }
    }

    fn get_spaceout(
        &mut self,
        outpoint: &OutPoint,
    ) -> spaces_protocol::errors::Result<Option<SpaceOut>> {
        match self.spaceouts.get(outpoint) {
            None => self.original.get_spaceout(outpoint),
            Some(space_out) => Ok(space_out.clone()),
        }
    }
}
