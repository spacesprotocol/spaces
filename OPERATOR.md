  operate                 Initialize a space or numeric for operation of off-chain subspaces
  commit                  Commit a new root
  rollback                Rollback the last pending commitment
  delegate                Delegate operation of a space or numeric to someone else
  getdelegator            Get the current space a num id is responsible for
  getdelegation           Get the current num id responsible for a space or numeric
  getcommitment           Get a commitment for a space or numeric

spaces operate --help
Initialize a space or numeric for operation of off-chain subspaces

Usage: space-cli operate [OPTIONS] <SUBJECT>

spaces commit --help
Commit a new root

Usage: space-cli commit [OPTIONS] <SUBJECT> <ROOT>

Arguments:
  <SUBJECT>  Space name, numeric, or num id
  <ROOT>     The new state root


spaces delegate --help
Delegate operation of a space or numeric to someone else

Usage: space-cli delegate [OPTIONS] --to <TO> <SUBJECT>

Arguments:
  <SUBJECT>  Space name, numeric, or num id

      --to <TO>              Recipient space name or address (must be a space address)

spaces getdelegator --help
Get the current space a num id is responsible for

Usage: space-cli getdelegator [OPTIONS] <SUBJECT>

Arguments:
  <SUBJECT>  A num id (e.g., num1...) or numeric (e.g., #800000-3)

getdelegation --help
Get the current num id responsible for a space or numeric

Usage: space-cli getdelegation [OPTIONS] <SUBJECT>

Arguments:
  <SUBJECT>  Space name, numeric, or num id

