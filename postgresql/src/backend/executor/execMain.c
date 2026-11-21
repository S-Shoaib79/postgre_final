/*-------------------------------------------------------------------------
 *
 * execMain.c
 *	  top level executor interface routines
 *
 * INTERFACE ROUTINES
 *	ExecutorStart()
 *	ExecutorRun()
 *	ExecutorFinish()
 *	ExecutorEnd()
 *
 *	These four procedures are the external interface to the executor.
 *	In each case, the query descriptor is required as an argument.
 *
 *	ExecutorStart must be called at the beginning of execution of any
 *	query plan and ExecutorEnd must always be called at the end of
 *	execution of a plan (unless it is aborted due to error).
 *
 *	ExecutorRun accepts direction and count arguments that specify whether
 *	the plan is to be executed forwards, backwards, and for how many tuples.
 *	In some cases ExecutorRun may be called multiple times to process all
 *	the tuples for a plan.  It is also acceptable to stop short of executing
 *	the whole plan (but only if it is a SELECT).
 *
 *	ExecutorFinish must be called after the final ExecutorRun call and
 *	before ExecutorEnd.  This can be omitted only in case of EXPLAIN,
 *	which should also omit ExecutorRun.
 *
 * Portions Copyright (c) 1996-2026, PostgreSQL Global Development Group
 * Portions Copyright (c) 1994, Regents of the University of California
 *
 *
 * IDENTIFICATION
 *	  src/backend/executor/execMain.c
 *
 *-------------------------------------------------------------------------
 */
#include "postgres.h"

#include "access/sysattr.h"
#include "access/table.h"
#include "access/tableam.h"
#include "access/tupconvert.h"
#include "access/xact.h"
#include "catalog/namespace.h"
#include "catalog/partition.h"
#include "commands/matview.h"
#include "commands/trigger.h"
#include "executor/executor.h"
#include "executor/execPartition.h"
#include "executor/instrument.h"
#include "executor/nodeSubplan.h"
#include "foreign/fdwapi.h"
#include "mb/pg_wchar.h"
#include "miscadmin.h"
#include "nodes/queryjumble.h"
#include "parser/parse_relation.h"
#include "pgstat.h"
#include "rewrite/rewriteHandler.h"
#include "tcop/utility.h"
#include "utils/acl.h"
#include "utils/backend_status.h"
#include "utils/lsyscache.h"
#include "utils/partcache.h"
#include "utils/rls.h"
#include "utils/snapmgr.h"
/* #include "executor/discreet_hooks.h" -- R1 now lives in this file (see _PGS_Discreet_R1_Intercept) */
#include "utils/guc.h"
#include "utils/builtins.h"
#include "executor/cpp_logger.h"
#include "catalog/pg_type.h"
#include "executor/am_client.h"
#include "executor/spi.h"
#include "utils/memutils.h"
#include "executor/runtime_security.h"

/* Runtime security: defined at the end of this file */
static void _PGS_RuntimeSecurity_StatementEnd(EState *estate);


/* Hooks for plugins to get control in ExecutorStart/Run/Finish/End */
ExecutorStart_hook_type ExecutorStart_hook = NULL;
ExecutorRun_hook_type ExecutorRun_hook = NULL;
ExecutorFinish_hook_type ExecutorFinish_hook = NULL;
ExecutorEnd_hook_type ExecutorEnd_hook = NULL;

/* Hook for plugin to get control in ExecCheckPermissions() */
ExecutorCheckPerms_hook_type ExecutorCheckPerms_hook = NULL;

/* decls for local routines only used within this module */
static void InitPlan(QueryDesc *queryDesc, int eflags);
static void CheckValidRowMarkRel(Relation rel, RowMarkType markType);
static void ExecPostprocessPlan(EState *estate);
static void ExecEndPlan(PlanState *planstate, EState *estate);
static void ExecutePlan(QueryDesc *queryDesc,
						CmdType operation,
						bool sendTuples,
						uint64 numberTuples,
						ScanDirection direction,
						DestReceiver *dest);
static bool ExecCheckPermissionsModified(Oid relOid, Oid userid,
										 Bitmapset *modifiedCols,
										 AclMode requiredPerms);
static void ExecCheckXactReadOnly(PlannedStmt *plannedstmt);
static void EvalPlanQualStart(EPQState *epqstate, Plan *planTree);
static void ReportNotNullViolationError(ResultRelInfo *resultRelInfo,
										TupleTableSlot *slot,
										EState *estate, int attnum);

/* end of local decls */


/* ----------------------------------------------------------------
 *		ExecutorStart
 *
 *		This routine must be called at the beginning of any execution of any
 *		query plan
 *
 * Takes a QueryDesc previously created by CreateQueryDesc (which is separate
 * only because some places use QueryDescs for utility commands).  The tupDesc
 * field of the QueryDesc is filled in to describe the tuples that will be
 * returned, and the internal fields (estate and planstate) are set up.
 *
 * eflags contains flag bits as described in executor.h.
 *
 * NB: the CurrentMemoryContext when this is called will become the parent
 * of the per-query context used for this Executor invocation.
 *
 * We provide a function hook variable that lets loadable plugins
 * get control when ExecutorStart is called.  Such a plugin would
 * normally call standard_ExecutorStart().
 *
 * ----------------------------------------------------------------
 */
void
ExecutorStart(QueryDesc *queryDesc, int eflags)
{
	/*
	 * In some cases (e.g. an EXECUTE statement or an execute message with the
	 * extended query protocol) the query_id won't be reported, so do it now.
	 *
	 * Note that it's harmless to report the query_id multiple times, as the
	 * call will be ignored if the top level query_id has already been
	 * reported.
	 */
	pgstat_report_query_id(queryDesc->plannedstmt->queryId, false);

	if (ExecutorStart_hook)
		(*ExecutorStart_hook) (queryDesc, eflags);
	else
		standard_ExecutorStart(queryDesc, eflags);
}

void
standard_ExecutorStart(QueryDesc *queryDesc, int eflags)
{
	EState	   *estate;
	MemoryContext oldcontext;

	/* sanity checks: queryDesc must not be started already */
	Assert(queryDesc != NULL);
	Assert(queryDesc->estate == NULL);

	/* caller must ensure the query's snapshot is active */
	Assert(GetActiveSnapshot() == queryDesc->snapshot);

	/*
	 * If the transaction is read-only, we need to check if any writes are
	 * planned to non-temporary tables.  EXPLAIN is considered read-only.
	 *
	 * Don't allow writes in parallel mode.  Supporting UPDATE and DELETE
	 * would require (a) storing the combo CID hash in shared memory, rather
	 * than synchronizing it just once at the start of parallelism, and (b) an
	 * alternative to heap_update()'s reliance on xmax for mutual exclusion.
	 * INSERT may have no such troubles, but we forbid it to simplify the
	 * checks.
	 *
	 * We have lower-level defenses in CommandCounterIncrement and elsewhere
	 * against performing unsafe operations in parallel mode, but this gives a
	 * more user-friendly error message.
	 */
	if ((XactReadOnly || IsInParallelMode()) &&
		!(eflags & EXEC_FLAG_EXPLAIN_ONLY))
		ExecCheckXactReadOnly(queryDesc->plannedstmt);

	/*
	 * Build EState, switch into per-query memory context for startup.
	 */
	estate = CreateExecutorState();
	queryDesc->estate = estate;

	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	/*
	 * Fill in external parameters, if any, from queryDesc; and allocate
	 * workspace for internal parameters
	 */
	estate->es_param_list_info = queryDesc->params;

	if (queryDesc->plannedstmt->paramExecTypes != NIL)
	{
		int			nParamExec;

		nParamExec = list_length(queryDesc->plannedstmt->paramExecTypes);
		estate->es_param_exec_vals = (ParamExecData *)
			palloc0_array(ParamExecData, nParamExec);
	}

	/* We now require all callers to provide sourceText */
	Assert(queryDesc->sourceText != NULL);
	estate->es_sourceText = queryDesc->sourceText;

	/*
	 * Fill in the query environment, if any, from queryDesc.
	 */
	estate->es_queryEnv = queryDesc->queryEnv;

	/*
	 * If non-read-only query, set the command ID to mark output tuples with
	 */
	switch (queryDesc->operation)
	{
		case CMD_SELECT:

			/*
			 * SELECT FOR [KEY] UPDATE/SHARE and modifying CTEs need to mark
			 * tuples
			 */
			if (queryDesc->plannedstmt->rowMarks != NIL ||
				queryDesc->plannedstmt->hasModifyingCTE)
				estate->es_output_cid = GetCurrentCommandId(true);

			/*
			 * A SELECT without modifying CTEs can't possibly queue triggers,
			 * so force skip-triggers mode. This is just a marginal efficiency
			 * hack, since AfterTriggerBeginQuery/AfterTriggerEndQuery aren't
			 * all that expensive, but we might as well do it.
			 */
			if (!queryDesc->plannedstmt->hasModifyingCTE)
				eflags |= EXEC_FLAG_SKIP_TRIGGERS;
			break;

		case CMD_INSERT:
		case CMD_DELETE:
		case CMD_UPDATE:
		case CMD_MERGE:
			estate->es_output_cid = GetCurrentCommandId(true);
			break;

		default:
			elog(ERROR, "unrecognized operation code: %d",
				 (int) queryDesc->operation);
			break;
	}

	/*
	 * Copy other important information into the EState
	 */
	estate->es_snapshot = RegisterSnapshot(queryDesc->snapshot);
	estate->es_crosscheck_snapshot = RegisterSnapshot(queryDesc->crosscheck_snapshot);
	estate->es_top_eflags = eflags;
	estate->es_instrument = queryDesc->instrument_options;
	estate->es_jit_flags = queryDesc->plannedstmt->jitFlags;

	/*
	 * Set up query-level instrumentation if extensions have requested it via
	 * query_instr_options. Ensure an extension has not allocated query_instr
	 * itself.
	 */
	Assert(queryDesc->query_instr == NULL);
	if (queryDesc->query_instr_options)
		queryDesc->query_instr = InstrAlloc(queryDesc->query_instr_options);

	/*
	 * Set up an AFTER-trigger statement context, unless told not to, or
	 * unless it's EXPLAIN-only mode (when ExecutorFinish won't be called).
	 */
	if (!(eflags & (EXEC_FLAG_SKIP_TRIGGERS | EXEC_FLAG_EXPLAIN_ONLY)))
		AfterTriggerBeginQuery();

	/*
	 * Initialize the plan state tree
	 */
	InitPlan(queryDesc, eflags);

	MemoryContextSwitchTo(oldcontext);
}

/* ----------------------------------------------------------------
 *		ExecutorRun
 *
 *		This is the main routine of the executor module. It accepts
 *		the query descriptor from the traffic cop and executes the
 *		query plan.
 *
 *		ExecutorStart must have been called already.
 *
 *		If direction is NoMovementScanDirection then nothing is done
 *		except to start up/shut down the destination.  Otherwise,
 *		we retrieve up to 'count' tuples in the specified direction.
 *
 *		Note: count = 0 is interpreted as no portal limit, i.e., run to
 *		completion.  Also note that the count limit is only applied to
 *		retrieved tuples, not for instance to those inserted/updated/deleted
 *		by a ModifyTable plan node.
 *
 *		There is no return value, but output tuples (if any) are sent to
 *		the destination receiver specified in the QueryDesc; and the number
 *		of tuples processed at the top level can be found in
 *		estate->es_processed.  The total number of tuples processed in all
 *		the ExecutorRun calls can be found in estate->es_total_processed.
 *
 *		We provide a function hook variable that lets loadable plugins
 *		get control when ExecutorRun is called.  Such a plugin would
 *		normally call standard_ExecutorRun().
 *
 * ----------------------------------------------------------------
 */
void
ExecutorRun(QueryDesc *queryDesc,
			ScanDirection direction, uint64 count)
{
	if (ExecutorRun_hook)
		(*ExecutorRun_hook) (queryDesc, direction, count);
	else
		standard_ExecutorRun(queryDesc, direction, count);
}

void
standard_ExecutorRun(QueryDesc *queryDesc,
					 ScanDirection direction, uint64 count)
{
	EState	   *estate;
	CmdType		operation;
	DestReceiver *dest;
	bool		sendTuples;
	MemoryContext oldcontext;

	/* sanity checks */
	Assert(queryDesc != NULL);

	estate = queryDesc->estate;

	Assert(estate != NULL);
	Assert(!(estate->es_top_eflags & EXEC_FLAG_EXPLAIN_ONLY));

	/* caller must ensure the query's snapshot is active */
	Assert(GetActiveSnapshot() == estate->es_snapshot);

	/*
	 * Switch into per-query memory context
	 */
	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	/* Allow instrumentation of Executor overall runtime */
	if (queryDesc->query_instr)
		InstrStart(queryDesc->query_instr);

	/* Discreet: logger hook, one line per table in the plan */
	/* Disabled (replaced by the in-file R1 hook): _PGS_Discreet_LogExecutorRun(queryDesc); */

	/*
	 * extract information from the query descriptor and the query feature.
	 */
	operation = queryDesc->operation;
	dest = queryDesc->dest;

	/*
	 * startup tuple receiver, if we will be emitting tuples
	 */
	estate->es_processed = 0;

	sendTuples = (operation == CMD_SELECT ||
				  queryDesc->plannedstmt->hasReturning);

	if (sendTuples)
		dest->rStartup(dest, operation, queryDesc->tupDesc);

	/*
	 * Run plan, unless direction is NoMovement.
	 *
	 * Note: pquery.c selects NoMovement if a prior call already reached
	 * end-of-data in the user-specified fetch direction.  This is important
	 * because various parts of the executor can misbehave if called again
	 * after reporting EOF.  For example, heapam.c would actually restart a
	 * heapscan and return all its data afresh.  There is also some doubt
	 * about whether a parallel plan would operate properly if an additional,
	 * necessarily non-parallel execution request occurs after completing a
	 * parallel execution.  (That case should work, but it's untested.)
	 */
	if (!ScanDirectionIsNoMovement(direction))
		ExecutePlan(queryDesc,
					operation,
					sendTuples,
					count,
					direction,
					dest);

	/*
	 * Update es_total_processed to keep track of the number of tuples
	 * processed across multiple ExecutorRun() calls.
	 */
	estate->es_total_processed += estate->es_processed;

	/*
	 * shutdown tuple receiver, if we started it
	 */
	if (sendTuples)
		dest->rShutdown(dest);

	if (queryDesc->query_instr)
		InstrStop(queryDesc->query_instr);

	MemoryContextSwitchTo(oldcontext);
}

/* ----------------------------------------------------------------
 *		ExecutorFinish
 *
 *		This routine must be called after the last ExecutorRun call.
 *		It performs cleanup such as firing AFTER triggers.  It is
 *		separate from ExecutorEnd because EXPLAIN ANALYZE needs to
 *		include these actions in the total runtime.
 *
 *		We provide a function hook variable that lets loadable plugins
 *		get control when ExecutorFinish is called.  Such a plugin would
 *		normally call standard_ExecutorFinish().
 *
 * ----------------------------------------------------------------
 */
void
ExecutorFinish(QueryDesc *queryDesc)
{
	if (ExecutorFinish_hook)
		(*ExecutorFinish_hook) (queryDesc);
	else
		standard_ExecutorFinish(queryDesc);
}

void
standard_ExecutorFinish(QueryDesc *queryDesc)
{
	EState	   *estate;
	MemoryContext oldcontext;

	/* sanity checks */
	Assert(queryDesc != NULL);

	estate = queryDesc->estate;

	Assert(estate != NULL);
	Assert(!(estate->es_top_eflags & EXEC_FLAG_EXPLAIN_ONLY));

	/* This should be run once and only once per Executor instance */
	Assert(!estate->es_finished);

	/* Switch into per-query memory context */
	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	/* Allow instrumentation of Executor overall runtime */
	if (queryDesc->query_instr)
		InstrStart(queryDesc->query_instr);

	/* Run ModifyTable nodes to completion */
	ExecPostprocessPlan(estate);

	/* Execute queued AFTER triggers, unless told not to */
	if (!(estate->es_top_eflags & EXEC_FLAG_SKIP_TRIGGERS))
		AfterTriggerEndQuery(estate);

	if (queryDesc->query_instr)
		InstrStop(queryDesc->query_instr);

	MemoryContextSwitchTo(oldcontext);

	estate->es_finished = true;

	/* Runtime security: handle the tenant, user and role-asset rows written */
	_PGS_RuntimeSecurity_StatementEnd(estate);
}

/* ----------------------------------------------------------------
 *		ExecutorEnd
 *
 *		This routine must be called at the end of execution of any
 *		query plan
 *
 *		We provide a function hook variable that lets loadable plugins
 *		get control when ExecutorEnd is called.  Such a plugin would
 *		normally call standard_ExecutorEnd().
 *
 * ----------------------------------------------------------------
 */
void
ExecutorEnd(QueryDesc *queryDesc)
{
	if (ExecutorEnd_hook)
		(*ExecutorEnd_hook) (queryDesc);
	else
		standard_ExecutorEnd(queryDesc);
}

void
standard_ExecutorEnd(QueryDesc *queryDesc)
{
	EState	   *estate;
	MemoryContext oldcontext;

	/* sanity checks */
	Assert(queryDesc != NULL);

	estate = queryDesc->estate;

	Assert(estate != NULL);

	if (estate->es_parallel_workers_to_launch > 0)
		pgstat_update_parallel_workers_stats((PgStat_Counter) estate->es_parallel_workers_to_launch,
											 (PgStat_Counter) estate->es_parallel_workers_launched);

	/*
	 * Check that ExecutorFinish was called, unless in EXPLAIN-only mode. This
	 * Assert is needed because ExecutorFinish is new as of 9.1, and callers
	 * might forget to call it.
	 */
	Assert(estate->es_finished ||
		   (estate->es_top_eflags & EXEC_FLAG_EXPLAIN_ONLY));

	/*
	 * Switch into per-query memory context to run ExecEndPlan
	 */
	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	ExecEndPlan(queryDesc->planstate, estate);

	/* do away with our snapshots */
	UnregisterSnapshot(estate->es_snapshot);
	UnregisterSnapshot(estate->es_crosscheck_snapshot);

	/*
	 * Must switch out of context before destroying it
	 */
	MemoryContextSwitchTo(oldcontext);

	/*
	 * Release EState and per-query memory context.  This should release
	 * everything the executor has allocated.
	 */
	FreeExecutorState(estate);

	/* Reset queryDesc fields that no longer point to anything */
	queryDesc->tupDesc = NULL;
	queryDesc->estate = NULL;
	queryDesc->planstate = NULL;
	queryDesc->query_instr = NULL;
}

/* ----------------------------------------------------------------
 *		ExecutorRewind
 *
 *		This routine may be called on an open queryDesc to rewind it
 *		to the start.
 * ----------------------------------------------------------------
 */
void
ExecutorRewind(QueryDesc *queryDesc)
{
	EState	   *estate;
	MemoryContext oldcontext;

	/* sanity checks */
	Assert(queryDesc != NULL);

	estate = queryDesc->estate;

	Assert(estate != NULL);

	/* It's probably not sensible to rescan updating queries */
	Assert(queryDesc->operation == CMD_SELECT);

	/*
	 * Switch into per-query memory context
	 */
	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	/*
	 * rescan plan
	 */
	ExecReScan(queryDesc->planstate);

	MemoryContextSwitchTo(oldcontext);
}


/*
 * ExecCheckPermissions
 *		Check access permissions of relations mentioned in a query
 *
 * Returns true if permissions are adequate.  Otherwise, throws an appropriate
 * error if ereport_on_violation is true, or simply returns false otherwise.
 *
 * Note that this does NOT address row-level security policies (aka: RLS).  If
 * rows will be returned to the user as a result of this permission check
 * passing, then RLS also needs to be consulted (and check_enable_rls()).
 *
 * See rewrite/rowsecurity.c.
 *
 * NB: rangeTable is no longer used by us, but kept around for the hooks that
 * might still want to look at the RTEs.
 */
bool
ExecCheckPermissions(List *rangeTable, List *rteperminfos,
					 bool ereport_on_violation)
{
	ListCell   *l;
	bool		result = true;

#ifdef USE_ASSERT_CHECKING
	Bitmapset  *indexset = NULL;

	/* Check that rteperminfos is consistent with rangeTable */
	foreach(l, rangeTable)
	{
		RangeTblEntry *rte = lfirst_node(RangeTblEntry, l);

		if (rte->perminfoindex != 0)
		{
			/* Sanity checks */

			/*
			 * Only relation RTEs and subquery RTEs that were once relation
			 * RTEs (views) have their perminfoindex set.
			 */
			Assert(rte->rtekind == RTE_RELATION ||
				   (rte->rtekind == RTE_SUBQUERY &&
					rte->relkind == RELKIND_VIEW));

			(void) getRTEPermissionInfo(rteperminfos, rte);
			/* Many-to-one mapping not allowed */
			Assert(!bms_is_member(rte->perminfoindex, indexset));
			indexset = bms_add_member(indexset, rte->perminfoindex);
		}
	}

	/* All rteperminfos are referenced */
	Assert(bms_num_members(indexset) == list_length(rteperminfos));
#endif

	foreach(l, rteperminfos)
	{
		RTEPermissionInfo *perminfo = lfirst_node(RTEPermissionInfo, l);

		Assert(OidIsValid(perminfo->relid));
		result = ExecCheckOneRelPerms(perminfo);
		if (!result)
		{
			if (ereport_on_violation)
				aclcheck_error(ACLCHECK_NO_PRIV,
							   get_relkind_objtype(get_rel_relkind(perminfo->relid)),
							   get_rel_name(perminfo->relid));
			return false;
		}
	}

	if (ExecutorCheckPerms_hook)
		result = (*ExecutorCheckPerms_hook) (rangeTable, rteperminfos,
											 ereport_on_violation);
	return result;
}

/*
 * ExecCheckOneRelPerms
 *		Check access permissions for a single relation.
 */
bool
ExecCheckOneRelPerms(RTEPermissionInfo *perminfo)
{
	AclMode		requiredPerms;
	AclMode		relPerms;
	AclMode		remainingPerms;
	Oid			userid;
	Oid			relOid = perminfo->relid;

	requiredPerms = perminfo->requiredPerms;
	Assert(requiredPerms != 0);

	/*
	 * userid to check as: current user unless we have a setuid indication.
	 *
	 * Note: GetUserId() is presently fast enough that there's no harm in
	 * calling it separately for each relation.  If that stops being true, we
	 * could call it once in ExecCheckPermissions and pass the userid down
	 * from there.  But for now, no need for the extra clutter.
	 */
	userid = OidIsValid(perminfo->checkAsUser) ?
		perminfo->checkAsUser : GetUserId();

	/*
	 * We must have *all* the requiredPerms bits, but some of the bits can be
	 * satisfied from column-level rather than relation-level permissions.
	 * First, remove any bits that are satisfied by relation permissions.
	 */
	relPerms = pg_class_aclmask(relOid, userid, requiredPerms, ACLMASK_ALL);
	remainingPerms = requiredPerms & ~relPerms;
	if (remainingPerms != 0)
	{
		int			col = -1;

		/*
		 * If we lack any permissions that exist only as relation permissions,
		 * we can fail straight away.
		 */
		if (remainingPerms & ~(ACL_SELECT | ACL_INSERT | ACL_UPDATE))
			return false;

		/*
		 * Check to see if we have the needed privileges at column level.
		 *
		 * Note: failures just report a table-level error; it would be nicer
		 * to report a column-level error if we have some but not all of the
		 * column privileges.
		 */
		if (remainingPerms & ACL_SELECT)
		{
			/*
			 * When the query doesn't explicitly reference any columns (for
			 * example, SELECT COUNT(*) FROM table), allow the query if we
			 * have SELECT on any column of the rel, as per SQL spec.
			 */
			if (bms_is_empty(perminfo->selectedCols))
			{
				if (pg_attribute_aclcheck_all(relOid, userid, ACL_SELECT,
											  ACLMASK_ANY) != ACLCHECK_OK)
					return false;
			}

			while ((col = bms_next_member(perminfo->selectedCols, col)) >= 0)
			{
				/* bit #s are offset by FirstLowInvalidHeapAttributeNumber */
				AttrNumber	attno = col + FirstLowInvalidHeapAttributeNumber;

				if (attno == InvalidAttrNumber)
				{
					/* Whole-row reference, must have priv on all cols */
					if (pg_attribute_aclcheck_all(relOid, userid, ACL_SELECT,
												  ACLMASK_ALL) != ACLCHECK_OK)
						return false;
				}
				else
				{
					if (pg_attribute_aclcheck(relOid, attno, userid,
											  ACL_SELECT) != ACLCHECK_OK)
						return false;
				}
			}
		}

		/*
		 * Basically the same for the mod columns, for both INSERT and UPDATE
		 * privilege as specified by remainingPerms.
		 */
		if (remainingPerms & ACL_INSERT &&
			!ExecCheckPermissionsModified(relOid,
										  userid,
										  perminfo->insertedCols,
										  ACL_INSERT))
			return false;

		if (remainingPerms & ACL_UPDATE &&
			!ExecCheckPermissionsModified(relOid,
										  userid,
										  perminfo->updatedCols,
										  ACL_UPDATE))
			return false;
	}
	return true;
}

/*
 * ExecCheckPermissionsModified
 *		Check INSERT or UPDATE access permissions for a single relation (these
 *		are processed uniformly).
 */
static bool
ExecCheckPermissionsModified(Oid relOid, Oid userid, Bitmapset *modifiedCols,
							 AclMode requiredPerms)
{
	int			col = -1;

	/*
	 * When the query doesn't explicitly update any columns, allow the query
	 * if we have permission on any column of the rel.  This is to handle
	 * SELECT FOR UPDATE as well as possible corner cases in UPDATE.
	 */
	if (bms_is_empty(modifiedCols))
	{
		if (pg_attribute_aclcheck_all(relOid, userid, requiredPerms,
									  ACLMASK_ANY) != ACLCHECK_OK)
			return false;
	}

	while ((col = bms_next_member(modifiedCols, col)) >= 0)
	{
		/* bit #s are offset by FirstLowInvalidHeapAttributeNumber */
		AttrNumber	attno = col + FirstLowInvalidHeapAttributeNumber;

		if (attno == InvalidAttrNumber)
		{
			/* whole-row reference can't happen here */
			elog(ERROR, "whole-row update is not implemented");
		}
		else
		{
			if (pg_attribute_aclcheck(relOid, attno, userid,
									  requiredPerms) != ACLCHECK_OK)
				return false;
		}
	}
	return true;
}

/*
 * Check that the query does not imply any writes to non-temp tables;
 * unless we're in parallel mode, in which case don't even allow writes
 * to temp tables.
 *
 * Note: in a Hot Standby this would need to reject writes to temp
 * tables just as we do in parallel mode; but an HS standby can't have created
 * any temp tables in the first place, so no need to check that.
 */
static void
ExecCheckXactReadOnly(PlannedStmt *plannedstmt)
{
	ListCell   *l;

	/*
	 * Fail if write permissions are requested in parallel mode for table
	 * (temp or non-temp), otherwise fail for any non-temp table.
	 */
	foreach(l, plannedstmt->permInfos)
	{
		RTEPermissionInfo *perminfo = lfirst_node(RTEPermissionInfo, l);

		if ((perminfo->requiredPerms & (~ACL_SELECT)) == 0)
			continue;

		if (isTempNamespace(get_rel_namespace(perminfo->relid)))
			continue;

		PreventCommandIfReadOnly(CreateCommandName((Node *) plannedstmt));
	}

	if (plannedstmt->commandType != CMD_SELECT || plannedstmt->hasModifyingCTE)
		PreventCommandIfParallelMode(CreateCommandName((Node *) plannedstmt));
}


/* ----------------------------------------------------------------
 *		InitPlan
 *
 *		Initializes the query plan: open files, allocate storage
 *		and start up the rule manager
 * ----------------------------------------------------------------
 */
static void
InitPlan(QueryDesc *queryDesc, int eflags)
{
	CmdType		operation = queryDesc->operation;
	PlannedStmt *plannedstmt = queryDesc->plannedstmt;
	Plan	   *plan = plannedstmt->planTree;
	List	   *rangeTable = plannedstmt->rtable;
	EState	   *estate = queryDesc->estate;
	PlanState  *planstate;
	TupleDesc	tupType;
	ListCell   *l;
	int			i;

	/*
	 * Do permissions checks
	 */
	ExecCheckPermissions(rangeTable, plannedstmt->permInfos, true);

	/*
	 * initialize the node's execution state
	 */
	ExecInitRangeTable(estate, rangeTable, plannedstmt->permInfos,
					   bms_copy(plannedstmt->unprunableRelids));

	estate->es_plannedstmt = plannedstmt;
	estate->es_part_prune_infos = plannedstmt->partPruneInfos;

	/*
	 * Perform runtime "initial" pruning to identify which child subplans,
	 * corresponding to the children of plan nodes that contain
	 * PartitionPruneInfo such as Append, will not be executed. The results,
	 * which are bitmapsets of indexes of the child subplans that will be
	 * executed, are saved in es_part_prune_results.  These results correspond
	 * to each PartitionPruneInfo entry, and the es_part_prune_results list is
	 * parallel to es_part_prune_infos.
	 */
	ExecDoInitialPruning(estate);

	/*
	 * Next, build the ExecRowMark array from the PlanRowMark(s), if any.
	 */
	if (plannedstmt->rowMarks)
	{
		estate->es_rowmarks = (ExecRowMark **)
			palloc0_array(ExecRowMark *, estate->es_range_table_size);
		foreach(l, plannedstmt->rowMarks)
		{
			PlanRowMark *rc = (PlanRowMark *) lfirst(l);
			RangeTblEntry *rte = exec_rt_fetch(rc->rti, estate);
			Oid			relid;
			Relation	relation;
			ExecRowMark *erm;

			/* ignore "parent" rowmarks; they are irrelevant at runtime */
			if (rc->isParent)
				continue;

			/*
			 * Also ignore rowmarks belonging to child tables that have been
			 * pruned in ExecDoInitialPruning().
			 */
			if (rte->rtekind == RTE_RELATION &&
				!bms_is_member(rc->rti, estate->es_unpruned_relids))
				continue;

			/* get relation's OID (will produce InvalidOid if subquery) */
			relid = rte->relid;

			/* open relation, if we need to access it for this mark type */
			switch (rc->markType)
			{
				case ROW_MARK_EXCLUSIVE:
				case ROW_MARK_NOKEYEXCLUSIVE:
				case ROW_MARK_SHARE:
				case ROW_MARK_KEYSHARE:
				case ROW_MARK_REFERENCE:
					relation = ExecGetRangeTableRelation(estate, rc->rti, false);
					break;
				case ROW_MARK_COPY:
					/* no physical table access is required */
					relation = NULL;
					break;
				default:
					elog(ERROR, "unrecognized markType: %d", rc->markType);
					relation = NULL;	/* keep compiler quiet */
					break;
			}

			/* Check that relation is a legal target for marking */
			if (relation)
				CheckValidRowMarkRel(relation, rc->markType);

			erm = palloc_object(ExecRowMark);
			erm->relation = relation;
			erm->relid = relid;
			erm->rti = rc->rti;
			erm->prti = rc->prti;
			erm->rowmarkId = rc->rowmarkId;
			erm->markType = rc->markType;
			erm->strength = rc->strength;
			erm->waitPolicy = rc->waitPolicy;
			erm->ermActive = false;
			ItemPointerSetInvalid(&(erm->curCtid));
			erm->ermExtra = NULL;

			Assert(erm->rti > 0 && erm->rti <= estate->es_range_table_size &&
				   estate->es_rowmarks[erm->rti - 1] == NULL);

			estate->es_rowmarks[erm->rti - 1] = erm;
		}
	}

	/*
	 * Initialize the executor's tuple table to empty.
	 */
	estate->es_tupleTable = NIL;

	/* signal that this EState is not used for EPQ */
	estate->es_epq_active = NULL;

	/*
	 * Initialize private state information for each SubPlan.  We must do this
	 * before running ExecInitNode on the main query tree, since
	 * ExecInitSubPlan expects to be able to find these entries.
	 */
	Assert(estate->es_subplanstates == NIL);
	i = 1;						/* subplan indices count from 1 */
	foreach(l, plannedstmt->subplans)
	{
		Plan	   *subplan = (Plan *) lfirst(l);
		PlanState  *subplanstate;
		int			sp_eflags;

		/*
		 * A subplan will never need to do BACKWARD scan nor MARK/RESTORE. If
		 * it is a parameterless subplan (not initplan), we suggest that it be
		 * prepared to handle REWIND efficiently; otherwise there is no need.
		 */
		sp_eflags = eflags
			& ~(EXEC_FLAG_REWIND | EXEC_FLAG_BACKWARD | EXEC_FLAG_MARK);
		if (bms_is_member(i, plannedstmt->rewindPlanIDs))
			sp_eflags |= EXEC_FLAG_REWIND;

		subplanstate = ExecInitNode(subplan, estate, sp_eflags);

		estate->es_subplanstates = lappend(estate->es_subplanstates,
										   subplanstate);

		i++;
	}

	/*
	 * Initialize the private state information for all the nodes in the query
	 * tree.  This opens files, allocates storage and leaves us ready to start
	 * processing tuples.
	 */
	planstate = ExecInitNode(plan, estate, eflags);

	/*
	 * Get the tuple descriptor describing the type of tuples to return.
	 */
	tupType = ExecGetResultType(planstate);

	/*
	 * Initialize the junk filter if needed.  SELECT queries need a filter if
	 * there are any junk attrs in the top-level tlist.
	 */
	if (operation == CMD_SELECT)
	{
		bool		junk_filter_needed = false;
		ListCell   *tlist;

		foreach(tlist, plan->targetlist)
		{
			TargetEntry *tle = (TargetEntry *) lfirst(tlist);

			if (tle->resjunk)
			{
				junk_filter_needed = true;
				break;
			}
		}

		if (junk_filter_needed)
		{
			JunkFilter *j;
			TupleTableSlot *slot;

			slot = ExecInitExtraTupleSlot(estate, NULL, &TTSOpsVirtual);
			j = ExecInitJunkFilter(planstate->plan->targetlist,
								   slot);
			estate->es_junkFilter = j;

			/* Want to return the cleaned tuple type */
			tupType = j->jf_cleanTupType;
		}
	}

	queryDesc->tupDesc = tupType;
	queryDesc->planstate = planstate;
}

/*
 * Check that a proposed result relation is a legal target for the operation
 *
 * Generally the parser and/or planner should have noticed any such mistake
 * already, but let's make sure.
 *
 * For INSERT ON CONFLICT, the result relation is required to support the
 * onConflictAction, regardless of whether a conflict actually occurs.
 *
 * For MERGE, mergeActions is the list of actions that may be performed.  The
 * result relation is required to support every action, regardless of whether
 * or not they are all executed.
 *
 * Note: when changing this function, you probably also need to look at
 * CheckValidRowMarkRel.
 */
void
CheckValidResultRel(ResultRelInfo *resultRelInfo, CmdType operation,
					OnConflictAction onConflictAction, List *mergeActions)
{
	Relation	resultRel = resultRelInfo->ri_RelationDesc;
	FdwRoutine *fdwroutine;

	/* Expect a fully-formed ResultRelInfo from InitResultRelInfo(). */
	Assert(resultRelInfo->ri_needLockTagTuple ==
		   IsInplaceUpdateRelation(resultRel));

	switch (resultRel->rd_rel->relkind)
	{
		case RELKIND_RELATION:
		case RELKIND_PARTITIONED_TABLE:

			/*
			 * For MERGE, check that the target relation supports each action.
			 * For other operations, just check the operation itself.
			 */
			if (operation == CMD_MERGE)
				foreach_node(MergeAction, action, mergeActions)
					CheckCmdReplicaIdentity(resultRel, action->commandType);
			else
				CheckCmdReplicaIdentity(resultRel, operation);

			/*
			 * For INSERT ON CONFLICT DO UPDATE, additionally check that the
			 * target relation supports UPDATE.
			 */
			if (onConflictAction == ONCONFLICT_UPDATE)
				CheckCmdReplicaIdentity(resultRel, CMD_UPDATE);
			break;
		case RELKIND_SEQUENCE:
			ereport(ERROR,
					(errcode(ERRCODE_WRONG_OBJECT_TYPE),
					 errmsg("cannot change sequence \"%s\"",
							RelationGetRelationName(resultRel))));
			break;
		case RELKIND_TOASTVALUE:
			ereport(ERROR,
					(errcode(ERRCODE_WRONG_OBJECT_TYPE),
					 errmsg("cannot change TOAST relation \"%s\"",
							RelationGetRelationName(resultRel))));
			break;
		case RELKIND_VIEW:

			/*
			 * Okay only if there's a suitable INSTEAD OF trigger.  Otherwise,
			 * complain, but omit errdetail because we haven't got the
			 * information handy (and given that it really shouldn't happen,
			 * it's not worth great exertion to get).
			 */
			if (!view_has_instead_trigger(resultRel, operation, mergeActions))
				error_view_not_updatable(resultRel, operation, mergeActions,
										 NULL);
			break;
		case RELKIND_MATVIEW:
			if (!MatViewIncrementalMaintenanceIsEnabled())
				ereport(ERROR,
						(errcode(ERRCODE_WRONG_OBJECT_TYPE),
						 errmsg("cannot change materialized view \"%s\"",
								RelationGetRelationName(resultRel))));
			break;
		case RELKIND_FOREIGN_TABLE:
			/* Okay only if the FDW supports it */
			fdwroutine = resultRelInfo->ri_FdwRoutine;
			switch (operation)
			{
				case CMD_INSERT:
					if (fdwroutine->ExecForeignInsert == NULL)
						ereport(ERROR,
								(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
								 errmsg("cannot insert into foreign table \"%s\"",
										RelationGetRelationName(resultRel))));
					if (fdwroutine->IsForeignRelUpdatable != NULL &&
						(fdwroutine->IsForeignRelUpdatable(resultRel) & (1 << CMD_INSERT)) == 0)
						ereport(ERROR,
								(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
								 errmsg("foreign table \"%s\" does not allow inserts",
										RelationGetRelationName(resultRel))));
					break;
				case CMD_UPDATE:
					if (fdwroutine->ExecForeignUpdate == NULL)
						ereport(ERROR,
								(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
								 errmsg("cannot update foreign table \"%s\"",
										RelationGetRelationName(resultRel))));
					if (fdwroutine->IsForeignRelUpdatable != NULL &&
						(fdwroutine->IsForeignRelUpdatable(resultRel) & (1 << CMD_UPDATE)) == 0)
						ereport(ERROR,
								(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
								 errmsg("foreign table \"%s\" does not allow updates",
										RelationGetRelationName(resultRel))));
					break;
				case CMD_DELETE:
					if (fdwroutine->ExecForeignDelete == NULL)
						ereport(ERROR,
								(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
								 errmsg("cannot delete from foreign table \"%s\"",
										RelationGetRelationName(resultRel))));
					if (fdwroutine->IsForeignRelUpdatable != NULL &&
						(fdwroutine->IsForeignRelUpdatable(resultRel) & (1 << CMD_DELETE)) == 0)
						ereport(ERROR,
								(errcode(ERRCODE_OBJECT_NOT_IN_PREREQUISITE_STATE),
								 errmsg("foreign table \"%s\" does not allow deletes",
										RelationGetRelationName(resultRel))));
					break;
				default:
					elog(ERROR, "unrecognized CmdType: %d", (int) operation);
					break;
			}
			break;
		default:
			ereport(ERROR,
					(errcode(ERRCODE_WRONG_OBJECT_TYPE),
					 errmsg("cannot change relation \"%s\"",
							RelationGetRelationName(resultRel))));
			break;
	}

	/*
	 * Conflict log tables are managed by the system to record logical
	 * replication conflicts.  We allow DELETE and TRUNCATE to permit users to
	 * manually prune these logs, but manual data insertion or modification
	 * (INSERT, UPDATE, MERGE) is prohibited to maintain the integrity of the
	 * system-generated logs.
	 *
	 * Since TRUNCATE is handled as a separate utility command, we only need
	 * to explicitly permit CMD_DELETE here.
	 */
	if (IsConflictLogTableNamespace(RelationGetNamespace(resultRel)) &&
		operation != CMD_DELETE)
		ereport(ERROR,
				(errcode(ERRCODE_WRONG_OBJECT_TYPE),
				 errmsg("cannot modify or insert data into conflict log table \"%s\"",
						RelationGetRelationName(resultRel)),
				 errdetail("Conflict log tables are system-managed and only support cleanup using DELETE or TRUNCATE.")));
}

/*
 * Check that a proposed rowmark target relation is a legal target
 *
 * In most cases parser and/or planner should have noticed this already, but
 * they don't cover all cases.
 */
static void
CheckValidRowMarkRel(Relation rel, RowMarkType markType)
{
	FdwRoutine *fdwroutine;

	switch (rel->rd_rel->relkind)
	{
		case RELKIND_RELATION:
		case RELKIND_PARTITIONED_TABLE:
			/* OK */
			break;
		case RELKIND_SEQUENCE:
			/* Must disallow this because we don't vacuum sequences */
			ereport(ERROR,
					(errcode(ERRCODE_WRONG_OBJECT_TYPE),
					 errmsg("cannot lock rows in sequence \"%s\"",
							RelationGetRelationName(rel))));
			break;
		case RELKIND_TOASTVALUE:
			/* We could allow this, but there seems no good reason to */
			ereport(ERROR,
					(errcode(ERRCODE_WRONG_OBJECT_TYPE),
					 errmsg("cannot lock rows in TOAST relation \"%s\"",
							RelationGetRelationName(rel))));
			break;
		case RELKIND_VIEW:
			/* Should not get here; planner should have expanded the view */
			ereport(ERROR,
					(errcode(ERRCODE_WRONG_OBJECT_TYPE),
					 errmsg("cannot lock rows in view \"%s\"",
							RelationGetRelationName(rel))));
			break;
		case RELKIND_MATVIEW:
			/* Allow referencing a matview, but not actual locking clauses */
			if (markType != ROW_MARK_REFERENCE)
				ereport(ERROR,
						(errcode(ERRCODE_WRONG_OBJECT_TYPE),
						 errmsg("cannot lock rows in materialized view \"%s\"",
								RelationGetRelationName(rel))));
			break;
		case RELKIND_FOREIGN_TABLE:
			/* Okay only if the FDW supports it */
			fdwroutine = GetFdwRoutineForRelation(rel, false);
			if (fdwroutine->RefetchForeignRow == NULL)
				ereport(ERROR,
						(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
						 errmsg("cannot lock rows in foreign table \"%s\"",
								RelationGetRelationName(rel))));
			break;
		default:
			ereport(ERROR,
					(errcode(ERRCODE_WRONG_OBJECT_TYPE),
					 errmsg("cannot lock rows in relation \"%s\"",
							RelationGetRelationName(rel))));
			break;
	}

	/*
	 * Conflict log tables are managed by the system to record logical
	 * replication conflicts.
	 */
	if (IsConflictLogTableNamespace(RelationGetNamespace(rel)))
		ereport(ERROR,
				(errcode(ERRCODE_WRONG_OBJECT_TYPE),
				 errmsg("cannot lock rows in the conflict log table \"%s\"",
						RelationGetRelationName(rel))));
}

/*
 * Initialize ResultRelInfo data for one result relation
 *
 * Caution: before Postgres 9.1, this function included the relkind checking
 * that's now in CheckValidResultRel, and it also did ExecOpenIndices if
 * appropriate.  Be sure callers cover those needs.
 */
void
InitResultRelInfo(ResultRelInfo *resultRelInfo,
				  Relation resultRelationDesc,
				  Index resultRelationIndex,
				  ResultRelInfo *partition_root_rri,
				  int instrument_options)
{
	MemSet(resultRelInfo, 0, sizeof(ResultRelInfo));
	resultRelInfo->type = T_ResultRelInfo;
	resultRelInfo->ri_RangeTableIndex = resultRelationIndex;
	resultRelInfo->ri_RelationDesc = resultRelationDesc;
	resultRelInfo->ri_NumIndices = 0;
	resultRelInfo->ri_IndexRelationDescs = NULL;
	resultRelInfo->ri_IndexRelationInfo = NULL;
	resultRelInfo->ri_needLockTagTuple =
		IsInplaceUpdateRelation(resultRelationDesc);
	/* make a copy so as not to depend on relcache info not changing... */
	resultRelInfo->ri_TrigDesc = CopyTriggerDesc(resultRelationDesc->trigdesc);
	if (resultRelInfo->ri_TrigDesc)
	{
		int			n = resultRelInfo->ri_TrigDesc->numtriggers;

		resultRelInfo->ri_TrigFunctions = (FmgrInfo *)
			palloc0_array(FmgrInfo, n);
		resultRelInfo->ri_TrigWhenExprs = (ExprState **)
			palloc0_array(ExprState *, n);
		if (instrument_options)
			resultRelInfo->ri_TrigInstrument = InstrAllocTrigger(n, instrument_options);
	}
	else
	{
		resultRelInfo->ri_TrigFunctions = NULL;
		resultRelInfo->ri_TrigWhenExprs = NULL;
		resultRelInfo->ri_TrigInstrument = NULL;
	}
	if (resultRelationDesc->rd_rel->relkind == RELKIND_FOREIGN_TABLE)
		resultRelInfo->ri_FdwRoutine = GetFdwRoutineForRelation(resultRelationDesc, true);
	else
		resultRelInfo->ri_FdwRoutine = NULL;

	/* The following fields are set later if needed */
	resultRelInfo->ri_RowIdAttNo = 0;
	resultRelInfo->ri_extraUpdatedCols = NULL;
	resultRelInfo->ri_projectNew = NULL;
	resultRelInfo->ri_newTupleSlot = NULL;
	resultRelInfo->ri_oldTupleSlot = NULL;
	resultRelInfo->ri_projectNewInfoValid = false;
	resultRelInfo->ri_FdwState = NULL;
	resultRelInfo->ri_usesFdwDirectModify = false;
	resultRelInfo->ri_CheckConstraintExprs = NULL;
	resultRelInfo->ri_GenVirtualNotNullConstraintExprs = NULL;
	resultRelInfo->ri_GeneratedExprsI = NULL;
	resultRelInfo->ri_GeneratedExprsU = NULL;
	resultRelInfo->ri_projectReturning = NULL;
	resultRelInfo->ri_onConflictArbiterIndexes = NIL;
	resultRelInfo->ri_onConflict = NULL;
	resultRelInfo->ri_ReturningSlot = NULL;
	resultRelInfo->ri_TrigOldSlot = NULL;
	resultRelInfo->ri_TrigNewSlot = NULL;
	resultRelInfo->ri_AllNullSlot = NULL;
	resultRelInfo->ri_MergeActions[MERGE_WHEN_MATCHED] = NIL;
	resultRelInfo->ri_MergeActions[MERGE_WHEN_NOT_MATCHED_BY_SOURCE] = NIL;
	resultRelInfo->ri_MergeActions[MERGE_WHEN_NOT_MATCHED_BY_TARGET] = NIL;
	resultRelInfo->ri_MergeJoinCondition = NULL;

	/*
	 * Only ExecInitPartitionInfo() and ExecInitPartitionDispatchInfo() pass
	 * non-NULL partition_root_rri.  For child relations that are part of the
	 * initial query rather than being dynamically added by tuple routing,
	 * this field is filled in ExecInitModifyTable().
	 */
	resultRelInfo->ri_RootResultRelInfo = partition_root_rri;
	/* Set by ExecGetRootToChildMap */
	resultRelInfo->ri_RootToChildMap = NULL;
	resultRelInfo->ri_RootToChildMapValid = false;
	/* Set by ExecInitRoutingInfo */
	resultRelInfo->ri_PartitionTupleSlot = NULL;
	resultRelInfo->ri_ChildToRootMap = NULL;
	resultRelInfo->ri_ChildToRootMapValid = false;
	resultRelInfo->ri_CopyMultiInsertBuffer = NULL;
}

/*
 * ExecGetTriggerResultRel
 *		Get a ResultRelInfo for a trigger target relation.
 *
 * Most of the time, triggers are fired on one of the result relations of the
 * query, and so we can just return a suitable one we already made and stored
 * in the es_opened_result_relations or es_tuple_routing_result_relations
 * Lists.
 *
 * However, it is sometimes necessary to fire triggers on other relations;
 * this happens mainly when an RI update trigger queues additional triggers
 * on other relations, which will be processed in the context of the outer
 * query.  For efficiency's sake, we want to have a ResultRelInfo for those
 * triggers too; that can avoid repeated re-opening of the relation.  (It
 * also provides a way for EXPLAIN ANALYZE to report the runtimes of such
 * triggers.)  So we make additional ResultRelInfo's as needed, and save them
 * in es_trig_target_relations.
 */
ResultRelInfo *
ExecGetTriggerResultRel(EState *estate, Oid relid,
						ResultRelInfo *rootRelInfo)
{
	ResultRelInfo *rInfo;
	ListCell   *l;
	Relation	rel;
	MemoryContext oldcontext;

	/*
	 * Before creating a new ResultRelInfo, check if we've already made and
	 * cached one for this relation.  We must ensure that the given
	 * 'rootRelInfo' matches the one stored in the cached ResultRelInfo as
	 * trigger handling for partitions can result in mixed requirements for
	 * what ri_RootResultRelInfo is set to.
	 */

	/* Search through the query result relations */
	foreach(l, estate->es_opened_result_relations)
	{
		rInfo = lfirst(l);
		if (RelationGetRelid(rInfo->ri_RelationDesc) == relid &&
			rInfo->ri_RootResultRelInfo == rootRelInfo)
			return rInfo;
	}

	/*
	 * Search through the result relations that were created during tuple
	 * routing, if any.
	 */
	foreach(l, estate->es_tuple_routing_result_relations)
	{
		rInfo = (ResultRelInfo *) lfirst(l);
		if (RelationGetRelid(rInfo->ri_RelationDesc) == relid &&
			rInfo->ri_RootResultRelInfo == rootRelInfo)
			return rInfo;
	}

	/* Nope, but maybe we already made an extra ResultRelInfo for it */
	foreach(l, estate->es_trig_target_relations)
	{
		rInfo = (ResultRelInfo *) lfirst(l);
		if (RelationGetRelid(rInfo->ri_RelationDesc) == relid &&
			rInfo->ri_RootResultRelInfo == rootRelInfo)
			return rInfo;
	}
	/* Nope, so we need a new one */

	/*
	 * Open the target relation's relcache entry.  We assume that an
	 * appropriate lock is still held by the backend from whenever the trigger
	 * event got queued, so we need take no new lock here.  Also, we need not
	 * recheck the relkind, so no need for CheckValidResultRel.
	 */
	rel = table_open(relid, NoLock);

	/*
	 * Make the new entry in the right context.
	 */
	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);
	rInfo = makeNode(ResultRelInfo);
	InitResultRelInfo(rInfo,
					  rel,
					  0,		/* dummy rangetable index */
					  rootRelInfo,
					  estate->es_instrument);
	estate->es_trig_target_relations =
		lappend(estate->es_trig_target_relations, rInfo);
	MemoryContextSwitchTo(oldcontext);

	/*
	 * Currently, we don't need any index information in ResultRelInfos used
	 * only for triggers, so no need to call ExecOpenIndices.
	 */

	return rInfo;
}

/*
 * Return the ancestor relations of a given leaf partition result relation
 * up to and including the query's root target relation.
 *
 * These work much like the ones opened by ExecGetTriggerResultRel, except
 * that we need to keep them in a separate list.
 *
 * These are closed by ExecCloseResultRelations.
 */
List *
ExecGetAncestorResultRels(EState *estate, ResultRelInfo *resultRelInfo)
{
	ResultRelInfo *rootRelInfo = resultRelInfo->ri_RootResultRelInfo;
	Relation	partRel = resultRelInfo->ri_RelationDesc;
	Oid			rootRelOid;

	if (!partRel->rd_rel->relispartition)
		elog(ERROR, "cannot find ancestors of a non-partition result relation");
	Assert(rootRelInfo != NULL);
	rootRelOid = RelationGetRelid(rootRelInfo->ri_RelationDesc);
	if (resultRelInfo->ri_ancestorResultRels == NIL)
	{
		ListCell   *lc;
		List	   *oids = get_partition_ancestors(RelationGetRelid(partRel));
		List	   *ancResultRels = NIL;

		foreach(lc, oids)
		{
			Oid			ancOid = lfirst_oid(lc);
			Relation	ancRel;
			ResultRelInfo *rInfo;

			/*
			 * Ignore the root ancestor here, and use ri_RootResultRelInfo
			 * (below) for it instead.  Also, we stop climbing up the
			 * hierarchy when we find the table that was mentioned in the
			 * query.
			 */
			if (ancOid == rootRelOid)
				break;

			/*
			 * All ancestors up to the root target relation must have been
			 * locked by the planner or AcquireExecutorLocks().
			 */
			ancRel = table_open(ancOid, NoLock);
			rInfo = makeNode(ResultRelInfo);

			/* dummy rangetable index */
			InitResultRelInfo(rInfo, ancRel, 0, NULL,
							  estate->es_instrument);
			ancResultRels = lappend(ancResultRels, rInfo);
		}
		ancResultRels = lappend(ancResultRels, rootRelInfo);
		resultRelInfo->ri_ancestorResultRels = ancResultRels;
	}

	/* We must have found some ancestor */
	Assert(resultRelInfo->ri_ancestorResultRels != NIL);

	return resultRelInfo->ri_ancestorResultRels;
}

/* ----------------------------------------------------------------
 *		ExecPostprocessPlan
 *
 *		Give plan nodes a final chance to execute before shutdown
 * ----------------------------------------------------------------
 */
static void
ExecPostprocessPlan(EState *estate)
{
	ListCell   *lc;

	/*
	 * Make sure nodes run forward.
	 */
	estate->es_direction = ForwardScanDirection;

	/*
	 * Run any secondary ModifyTable nodes to completion, in case the main
	 * query did not fetch all rows from them.  (We do this to ensure that
	 * such nodes have predictable results.)
	 */
	foreach(lc, estate->es_auxmodifytables)
	{
		PlanState  *ps = (PlanState *) lfirst(lc);

		for (;;)
		{
			TupleTableSlot *slot;

			/* Reset the per-output-tuple exprcontext each time */
			ResetPerTupleExprContext(estate);

			slot = ExecProcNode(ps);

			if (TupIsNull(slot))
				break;
		}
	}
}

/* ----------------------------------------------------------------
 *		ExecEndPlan
 *
 *		Cleans up the query plan -- closes files and frees up storage
 *
 * NOTE: we are no longer very worried about freeing storage per se
 * in this code; FreeExecutorState should be guaranteed to release all
 * memory that needs to be released.  What we are worried about doing
 * is closing relations and dropping buffer pins.  Thus, for example,
 * tuple tables must be cleared or dropped to ensure pins are released.
 * ----------------------------------------------------------------
 */
static void
ExecEndPlan(PlanState *planstate, EState *estate)
{
	ListCell   *l;

	/*
	 * shut down the node-type-specific query processing
	 */
	ExecEndNode(planstate);

	/*
	 * for subplans too
	 */
	foreach(l, estate->es_subplanstates)
	{
		PlanState  *subplanstate = (PlanState *) lfirst(l);

		ExecEndNode(subplanstate);
	}

	/*
	 * destroy the executor's tuple table.  Actually we only care about
	 * releasing buffer pins and tupdesc refcounts; there's no need to pfree
	 * the TupleTableSlots, since the containing memory context is about to go
	 * away anyway.
	 */
	ExecResetTupleTable(estate->es_tupleTable, false);

	/*
	 * Close any Relations that have been opened for range table entries or
	 * result relations.
	 */
	ExecCloseResultRelations(estate);
	ExecCloseRangeTableRelations(estate);
}

/*
 * Close any relations that have been opened for ResultRelInfos.
 */
void
ExecCloseResultRelations(EState *estate)
{
	ListCell   *l;

	/*
	 * close indexes of result relation(s) if any.  (Rels themselves are
	 * closed in ExecCloseRangeTableRelations())
	 *
	 * In addition, close the stub RTs that may be in each resultrel's
	 * ri_ancestorResultRels.
	 */
	foreach(l, estate->es_opened_result_relations)
	{
		ResultRelInfo *resultRelInfo = lfirst(l);
		ListCell   *lc;

		ExecCloseIndices(resultRelInfo);
		foreach(lc, resultRelInfo->ri_ancestorResultRels)
		{
			ResultRelInfo *rInfo = lfirst(lc);

			/*
			 * Ancestors with RTI > 0 (should only be the root ancestor) are
			 * closed by ExecCloseRangeTableRelations.
			 */
			if (rInfo->ri_RangeTableIndex > 0)
				continue;

			table_close(rInfo->ri_RelationDesc, NoLock);
		}
	}

	/*
	 * Now close any relations that we opened for trigger target
	 * ResultRelInfos.
	 */
	ExecCloseTrigTargetRelations(estate);
}

/*
 * Close any relations that have been opened for ResultRelInfos opened
 * specifically for trigger target relations.
 */
void
ExecCloseTrigTargetRelations(EState *estate)
{
	ListCell   *l;

	/* Close any relations that have been opened by ExecGetTriggerResultRel(). */
	foreach(l, estate->es_trig_target_relations)
	{
		ResultRelInfo *resultRelInfo = (ResultRelInfo *) lfirst(l);

		/*
		 * Assert this is a "dummy" ResultRelInfo, see above.  Otherwise we
		 * might be issuing a duplicate close against a Relation opened by
		 * ExecGetRangeTableRelation.
		 */
		Assert(resultRelInfo->ri_RangeTableIndex == 0);

		/*
		 * Since ExecGetTriggerResultRel doesn't call ExecOpenIndices for
		 * these rels, we needn't call ExecCloseIndices either.
		 */
		Assert(resultRelInfo->ri_NumIndices == 0);

		table_close(resultRelInfo->ri_RelationDesc, NoLock);
	}
}

/*
 * Close all relations opened by ExecGetRangeTableRelation().
 *
 * We do not release any locks we might hold on those rels.
 */
void
ExecCloseRangeTableRelations(EState *estate)
{
	int			i;

	for (i = 0; i < estate->es_range_table_size; i++)
	{
		if (estate->es_relations[i])
			table_close(estate->es_relations[i], NoLock);
	}
}

/* 1. Helper to recursively find scan node types in the plan tree */
static NodeTag
_PGS_Discreet_FindScanNodeType(Plan *node)
{
	if (node == NULL)
		return T_Invalid;

	switch (nodeTag(node))
	{
		case T_SeqScan:
		case T_IndexScan:
		case T_IndexOnlyScan:
		case T_BitmapHeapScan:
		case T_BitmapIndexScan:
		case T_SubqueryScan:
		case T_FunctionScan:
		case T_NestLoop:
		case T_HashJoin:
		case T_MergeJoin:
			return nodeTag(node);
		default:
			break;
	}

	if (node->lefttree != NULL)
	{
		NodeTag tag = _PGS_Discreet_FindScanNodeType(node->lefttree);
		if (tag != T_Invalid)
			return tag;
	}

	if (node->righttree != NULL)
	{
		NodeTag tag = _PGS_Discreet_FindScanNodeType(node->righttree);
		if (tag != T_Invalid)
			return tag;
	}

	return T_Invalid;
}

/* 2. Helper to map node tags to readable strings */
static const char *
_PGS_Discreet_GetScanTypeFromTag(NodeTag tag)
{
	switch (tag)
	{
		case T_SeqScan:
			return "Sequential Scan";
		case T_IndexScan:
			return "Index Scan";
		case T_IndexOnlyScan:
			return "Index-Only Scan";
		case T_BitmapHeapScan:
			return "Bitmap Heap Scan";
		case T_BitmapIndexScan:
			return "Bitmap Index Scan";
		case T_SubqueryScan:
			return "Subquery Scan";
		case T_NestLoop:
			return "Nested Loop Join";
		case T_HashJoin:
			return "Hash Join";
		case T_MergeJoin:
			return "Merge Join";
		default:
			return "Projected / Execution Root";
	}
}

/* 3. Main Interception Function */

static void
_PGS_Discreet_R1_Intercept(QueryDesc *queryDesc, TupleTableSlot *slot, uint64 row_num)
{
    TupleDesc tupdesc = slot->tts_tupleDescriptor;
    PlannedStmt *stmt = queryDesc != NULL ? queryDesc->plannedstmt : NULL;
    StringInfoData buf;
    StringInfoData tables_buf;
    int i;
    const char *app_user = NULL;
    const char *tenant = NULL;
    const char *req_id = NULL;
    const char *scan_type = "Unknown Scan";

    initStringInfo(&buf);
    initStringInfo(&tables_buf);

    /* Determine scan/join type from plan tree traversal */
    if (stmt != NULL && stmt->planTree != NULL)
    {
        NodeTag scan_tag = _PGS_Discreet_FindScanNodeType(stmt->planTree);
        scan_type = _PGS_Discreet_GetScanTypeFromTag(scan_tag);
    }

    /* Retrieve application identity and request metadata */
    app_user = GetConfigOption("discreet.app_user", true, false);
    tenant = GetConfigOption("discreet.tenant", true, false);
    req_id = GetConfigOption("discreet.request_id", true, false);

    /* Determine target relation(s) from query plan */
    if (stmt != NULL && stmt->relationOids != NIL)
    {
        ListCell *lc;
        bool first = true;

        foreach(lc, stmt->relationOids)
        {
            Oid relOid = lfirst_oid(lc);
            char *rname = get_rel_name(relOid);

            if (!first)
                appendStringInfoString(&tables_buf, ", ");

            appendStringInfo(&tables_buf, "%s (OID: %u)",
                             rname ? rname : "unknown",
                             (unsigned int) relOid);

            first = false;

            if (rname != NULL)
                pfree(rname);
        }
    }
    else
    {
        appendStringInfoString(&tables_buf, "(Virtual/Expression)");
    }

    /* Ensure all slot attributes are available */
    slot_getallattrs(slot);

    /* Build row-level log header */
    appendStringInfo(&buf,
                     "[DISCREET_R1] READ row %llu | Scan Type: %s | Table: %s",
                     (unsigned long long) row_num,
                     scan_type,
                     tables_buf.data);

    /* Log each column's actual value */
    for (i = 0; i < tupdesc->natts; i++)
    {
        Form_pg_attribute attr = TupleDescAttr(tupdesc, i);
        bool isnull = slot->tts_isnull[i];
        char *typname = format_type_be(attr->atttypid);
        char *value_str;

        if (isnull)
        {
            value_str = pstrdup("NULL");
        }
        else
        {
            Oid typoutput;
            bool typisvarlena;

            getTypeOutputInfo(attr->atttypid, &typoutput, &typisvarlena);

            value_str = OidOutputFunctionCall(
                typoutput,
                slot->tts_values[i]
            );
        }

        /* Log BEFORE_READ only */
        if (app_user != NULL && app_user[0] != '\0')
        {
            ereport(LOG,
                    (errmsg("[DISCREET_R1] READ_OP\n"
                            "table: %s\n"
                            "attnum: %d\n"
                            "attribute: %s\n"
                            "type: %s\n"
                            "value: %s\n"
                            "app_user: %s\n"
                            "tenant: %s\n"
                            "request_id: %s\n"
                            "validated: true",
                            tables_buf.data,
                            i + 1,
                            NameStr(attr->attname),
                            typname,
                            value_str,
                            app_user,
                            tenant ? tenant : "none",
                            req_id ? req_id : "none")));
        }
        else
        {
            ereport(LOG,
                    (errmsg("[DISCREET_R1] READ_OP\n"
                            "table: %s\n"
                            "attnum: %d\n"
                            "attribute: %s\n"
                            "type: %s\n"
                            "value: %s\n"
                            "validated: false",
                            tables_buf.data,
                            i + 1,
                            NameStr(attr->attname),
                            typname,
                            value_str)));
        }

        /* Free allocated strings */
        if (value_str != NULL)
            pfree(value_str);

        pfree(typname);
    }

    /* Append application identity to the row-level log */
    if (app_user != NULL && app_user[0] != '\0')
    {
        appendStringInfo(&buf,
                         " | app_user: %s | tenant: %s | request_id: %s | validated: true",
                         app_user,
                         tenant ? tenant : "none",
                         req_id ? req_id : "none");
    }
    else
    {
        appendStringInfoString(&buf, " | validated: false");
    }

    /* Write row-level log */
    elog(LOG, "%s", buf.data);

    /* Release buffers */
    pfree(buf.data);
    pfree(tables_buf.data);
}

/* ----------------------------------------------------------------
 *		ExecutePlan
 *
 *		Processes the query plan until we have retrieved 'numberTuples' tuples,
 *		moving in the specified direction.
 *
 *		Runs to completion if numberTuples is 0
 * ----------------------------------------------------------------
 */
static void
ExecutePlan(QueryDesc *queryDesc,
			CmdType operation,
			bool sendTuples,
			uint64 numberTuples,
			ScanDirection direction,
			DestReceiver *dest)
{
	EState	   *estate = queryDesc->estate;
	PlanState  *planstate = queryDesc->planstate;
	bool		use_parallel_mode;
	TupleTableSlot *slot;
	uint64		current_tuple_count;

	/*
	 * initialize local variables
	 */
	current_tuple_count = 0;

	/*
	 * Set the direction.
	 */
	estate->es_direction = direction;

	/*
	 * Set up parallel mode if appropriate.
	 *
	 * Parallel mode only supports complete execution of a plan.  If we've
	 * already partially executed it, or if the caller asks us to exit early,
	 * we must force the plan to run without parallelism.
	 */
	if (queryDesc->already_executed || numberTuples != 0)
		use_parallel_mode = false;
	else
		use_parallel_mode = queryDesc->plannedstmt->parallelModeNeeded;
	queryDesc->already_executed = true;

	estate->es_use_parallel_mode = use_parallel_mode;
	if (use_parallel_mode)
		EnterParallelMode();

	/*
	 * Loop until we've processed the proper number of tuples from the plan.
	 */
	for (;;)
	{
		/* Reset the per-output-tuple exprcontext */
		ResetPerTupleExprContext(estate);

		/*
		 * Execute the plan and obtain a tuple
		 */
		slot = ExecProcNode(planstate);

		/*
		 * if the tuple is null, then we assume there is nothing more to
		 * process so we just end the loop...
		 */
		if (TupIsNull(slot))
			break;

		/*
		 * If we have a junk filter, then project a new tuple with the junk
		 * removed.
		 *
		 * Store this new "clean" tuple in the junkfilter's resultSlot.
		 * (Formerly, we stored it back over the "dirty" tuple, which is WRONG
		 * because that tuple slot has the wrong descriptor.)
		 */
		if (estate->es_junkFilter != NULL)
			slot = ExecFilterJunk(estate->es_junkFilter, slot);

		/*
		 * If we are supposed to send the tuple somewhere, do so. (In
		 * practice, this is probably always the case at this point.)
		 */
		if (sendTuples)
		{
			/* Discreet R1: inspect the result row before it is sent, then the C++ logger */
			/* Disabled (hooks off):
			if (slot && !TupIsNull(slot))
			{
				_PGS_Discreet_R1_Intercept(queryDesc, slot, current_tuple_count + 1);
				_PGS_myCppFunction((int) (current_tuple_count + 1));
			}
			*/

			/* Discreet R1: return integer columns -10, as the client wrote them */
			/* Disabled (integer shift off): _PGS_Discreet_R1_Unshift(queryDesc, slot, current_tuple_count + 1); */

			/*
			 * If we are not able to send the tuple, we assume the destination
			 * has closed and no more tuples can be sent. If that's the case,
			 * end the loop.
			 */
			if (!dest->receiveSlot(slot, dest))
				break;
		}

		/*
		 * Count tuples processed, if this is a SELECT.  (For other operation
		 * types, the ModifyTable plan node must count the appropriate
		 * events.)
		 */
		if (operation == CMD_SELECT)
			(estate->es_processed)++;

		/*
		 * check our tuple count.. if we've processed the proper number then
		 * quit, else loop again and process more tuples.  Zero numberTuples
		 * means no limit.
		 */
		current_tuple_count++;
		if (numberTuples && numberTuples == current_tuple_count)
			break;
	}

	/*
	 * If we know we won't need to back up, we can release resources at this
	 * point.
	 */
	if (!(estate->es_top_eflags & EXEC_FLAG_BACKWARD))
		ExecShutdownNode(planstate);

	if (use_parallel_mode)
		ExitParallelMode();
}


/*
 * ExecRelCheck --- check that tuple meets check constraints for result relation
 *
 * Returns NULL if OK, else name of failed check constraint
 */
static const char *
ExecRelCheck(ResultRelInfo *resultRelInfo,
			 TupleTableSlot *slot, EState *estate)
{
	Relation	rel = resultRelInfo->ri_RelationDesc;
	int			ncheck = rel->rd_att->constr->num_check;
	ConstrCheck *check = rel->rd_att->constr->check;
	ExprContext *econtext;
	MemoryContext oldContext;

	/*
	 * CheckNNConstraintFetch let this pass with only a warning, but now we
	 * should fail rather than possibly failing to enforce an important
	 * constraint.
	 */
	if (ncheck != rel->rd_rel->relchecks)
		elog(ERROR, "%d pg_constraint record(s) missing for relation \"%s\"",
			 rel->rd_rel->relchecks - ncheck, RelationGetRelationName(rel));

	/*
	 * If first time through for this result relation, build expression
	 * nodetrees for rel's constraint expressions.  Keep them in the per-query
	 * memory context so they'll survive throughout the query.
	 */
	if (resultRelInfo->ri_CheckConstraintExprs == NULL)
	{
		oldContext = MemoryContextSwitchTo(estate->es_query_cxt);
		resultRelInfo->ri_CheckConstraintExprs = palloc0_array(ExprState *, ncheck);
		for (int i = 0; i < ncheck; i++)
		{
			Expr	   *checkconstr;

			/* Skip not enforced constraint */
			if (!check[i].ccenforced)
				continue;

			checkconstr = stringToNode(check[i].ccbin);
			checkconstr = (Expr *) expand_generated_columns_in_expr((Node *) checkconstr, rel, 1);
			resultRelInfo->ri_CheckConstraintExprs[i] =
				ExecPrepareExpr(checkconstr, estate);
		}
		MemoryContextSwitchTo(oldContext);
	}

	/*
	 * We will use the EState's per-tuple context for evaluating constraint
	 * expressions (creating it if it's not already there).
	 */
	econtext = GetPerTupleExprContext(estate);

	/* Arrange for econtext's scan tuple to be the tuple under test */
	econtext->ecxt_scantuple = slot;

	/* And evaluate the constraints */
	for (int i = 0; i < ncheck; i++)
	{
		ExprState  *checkconstr = resultRelInfo->ri_CheckConstraintExprs[i];

		/*
		 * NOTE: SQL specifies that a NULL result from a constraint expression
		 * is not to be treated as a failure.  Therefore, use ExecCheck not
		 * ExecQual.
		 */
		if (checkconstr && !ExecCheck(checkconstr, econtext))
			return check[i].ccname;
	}

	/* NULL result means no error */
	return NULL;
}

/*
 * ExecPartitionCheck --- check that tuple meets the partition constraint.
 *
 * Returns true if it meets the partition constraint.  If the constraint
 * fails and we're asked to emit an error, do so and don't return; otherwise
 * return false.
 */
bool
ExecPartitionCheck(ResultRelInfo *resultRelInfo, TupleTableSlot *slot,
				   EState *estate, bool emitError)
{
	ExprContext *econtext;
	bool		success;

	/*
	 * If first time through, build expression state tree for the partition
	 * check expression.  (In the corner case where the partition check
	 * expression is empty, ie there's a default partition and nothing else,
	 * we'll be fooled into executing this code each time through.  But it's
	 * pretty darn cheap in that case, so we don't worry about it.)
	 */
	if (resultRelInfo->ri_PartitionCheckExpr == NULL)
	{
		/*
		 * Ensure that the qual tree and prepared expression are in the
		 * query-lifespan context.
		 */
		MemoryContext oldcxt = MemoryContextSwitchTo(estate->es_query_cxt);
		List	   *qual = RelationGetPartitionQual(resultRelInfo->ri_RelationDesc);

		resultRelInfo->ri_PartitionCheckExpr = ExecPrepareCheck(qual, estate);
		MemoryContextSwitchTo(oldcxt);
	}

	/*
	 * We will use the EState's per-tuple context for evaluating constraint
	 * expressions (creating it if it's not already there).
	 */
	econtext = GetPerTupleExprContext(estate);

	/* Arrange for econtext's scan tuple to be the tuple under test */
	econtext->ecxt_scantuple = slot;

	/*
	 * As in case of the cataloged constraints, we treat a NULL result as
	 * success here, not a failure.
	 */
	success = ExecCheck(resultRelInfo->ri_PartitionCheckExpr, econtext);

	/* if asked to emit error, don't actually return on failure */
	if (!success && emitError)
		ExecPartitionCheckEmitError(resultRelInfo, slot, estate);

	return success;
}

/*
 * ExecPartitionCheckEmitError - Form and emit an error message after a failed
 * partition constraint check.
 */
void
ExecPartitionCheckEmitError(ResultRelInfo *resultRelInfo,
							TupleTableSlot *slot,
							EState *estate)
{
	Oid			root_relid;
	TupleDesc	tupdesc;
	char	   *val_desc;
	Bitmapset  *modifiedCols;

	/*
	 * If the tuple has been routed, it's been converted to the partition's
	 * rowtype, which might differ from the root table's.  We must convert it
	 * back to the root table's rowtype so that val_desc in the error message
	 * matches the input tuple.
	 */
	if (resultRelInfo->ri_RootResultRelInfo)
	{
		ResultRelInfo *rootrel = resultRelInfo->ri_RootResultRelInfo;
		TupleDesc	old_tupdesc;
		AttrMap    *map;

		root_relid = RelationGetRelid(rootrel->ri_RelationDesc);
		tupdesc = RelationGetDescr(rootrel->ri_RelationDesc);

		old_tupdesc = RelationGetDescr(resultRelInfo->ri_RelationDesc);
		/* a reverse map */
		map = build_attrmap_by_name_if_req(old_tupdesc, tupdesc, false);

		/*
		 * Partition-specific slot's tupdesc can't be changed, so allocate a
		 * new one.
		 */
		if (map != NULL)
			slot = execute_attr_map_slot(map, slot,
										 MakeTupleTableSlot(tupdesc, &TTSOpsVirtual, 0));
		modifiedCols = bms_union(ExecGetInsertedCols(rootrel, estate),
								 ExecGetUpdatedCols(rootrel, estate));
	}
	else
	{
		root_relid = RelationGetRelid(resultRelInfo->ri_RelationDesc);
		tupdesc = RelationGetDescr(resultRelInfo->ri_RelationDesc);
		modifiedCols = bms_union(ExecGetInsertedCols(resultRelInfo, estate),
								 ExecGetUpdatedCols(resultRelInfo, estate));
	}

	val_desc = ExecBuildSlotValueDescription(root_relid,
											 slot,
											 tupdesc,
											 modifiedCols,
											 64);
	ereport(ERROR,
			(errcode(ERRCODE_CHECK_VIOLATION),
			 errmsg("new row for relation \"%s\" violates partition constraint",
					RelationGetRelationName(resultRelInfo->ri_RelationDesc)),
			 val_desc ? errdetail("Failing row contains %s.", val_desc) : 0,
			 errtable(resultRelInfo->ri_RelationDesc)));
}

/*
 * ExecConstraints - check constraints of the tuple in 'slot'
 *
 * This checks the traditional NOT NULL and check constraints.
 *
 * The partition constraint is *NOT* checked.
 *
 * Note: 'slot' contains the tuple to check the constraints of, which may
 * have been converted from the original input tuple after tuple routing.
 * 'resultRelInfo' is the final result relation, after tuple routing.
 */
void
ExecConstraints(ResultRelInfo *resultRelInfo,
				TupleTableSlot *slot, EState *estate)
{
	Relation	rel = resultRelInfo->ri_RelationDesc;
	TupleDesc	tupdesc = RelationGetDescr(rel);
	TupleConstr *constr = tupdesc->constr;
	Bitmapset  *modifiedCols;
	List	   *notnull_virtual_attrs = NIL;

	Assert(constr);				/* we should not be called otherwise */

	/*
	 * Verify not-null constraints.
	 *
	 * Not-null constraints on virtual generated columns are collected and
	 * checked separately below.
	 */
	if (constr->has_not_null)
	{
		for (AttrNumber attnum = 1; attnum <= tupdesc->natts; attnum++)
		{
			Form_pg_attribute att = TupleDescAttr(tupdesc, attnum - 1);

			if (att->attnotnull && att->attgenerated == ATTRIBUTE_GENERATED_VIRTUAL)
				notnull_virtual_attrs = lappend_int(notnull_virtual_attrs, attnum);
			else if (att->attnotnull && slot_attisnull(slot, attnum))
				ReportNotNullViolationError(resultRelInfo, slot, estate, attnum);
		}
	}

	/*
	 * Verify not-null constraints on virtual generated column, if any.
	 */
	if (notnull_virtual_attrs)
	{
		AttrNumber	attnum;

		attnum = ExecRelGenVirtualNotNull(resultRelInfo, slot, estate,
										  notnull_virtual_attrs);
		if (attnum != InvalidAttrNumber)
			ReportNotNullViolationError(resultRelInfo, slot, estate, attnum);
	}

	/*
	 * Verify check constraints.
	 */
	if (rel->rd_rel->relchecks > 0)
	{
		const char *failed;

		if ((failed = ExecRelCheck(resultRelInfo, slot, estate)) != NULL)
		{
			char	   *val_desc;
			Relation	orig_rel = rel;

			/*
			 * If the tuple has been routed, it's been converted to the
			 * partition's rowtype, which might differ from the root table's.
			 * We must convert it back to the root table's rowtype so that
			 * val_desc shown error message matches the input tuple.
			 */
			if (resultRelInfo->ri_RootResultRelInfo)
			{
				ResultRelInfo *rootrel = resultRelInfo->ri_RootResultRelInfo;
				TupleDesc	old_tupdesc = RelationGetDescr(rel);
				AttrMap    *map;

				tupdesc = RelationGetDescr(rootrel->ri_RelationDesc);
				/* a reverse map */
				map = build_attrmap_by_name_if_req(old_tupdesc,
												   tupdesc,
												   false);

				/*
				 * Partition-specific slot's tupdesc can't be changed, so
				 * allocate a new one.
				 */
				if (map != NULL)
					slot = execute_attr_map_slot(map, slot,
												 MakeTupleTableSlot(tupdesc, &TTSOpsVirtual, 0));
				modifiedCols = bms_union(ExecGetInsertedCols(rootrel, estate),
										 ExecGetUpdatedCols(rootrel, estate));
				rel = rootrel->ri_RelationDesc;
			}
			else
				modifiedCols = bms_union(ExecGetInsertedCols(resultRelInfo, estate),
										 ExecGetUpdatedCols(resultRelInfo, estate));
			val_desc = ExecBuildSlotValueDescription(RelationGetRelid(rel),
													 slot,
													 tupdesc,
													 modifiedCols,
													 64);
			ereport(ERROR,
					(errcode(ERRCODE_CHECK_VIOLATION),
					 errmsg("new row for relation \"%s\" violates check constraint \"%s\"",
							RelationGetRelationName(orig_rel), failed),
					 val_desc ? errdetail("Failing row contains %s.", val_desc) : 0,
					 errtableconstraint(orig_rel, failed)));
		}
	}
}

/*
 * Verify not-null constraints on virtual generated columns of the given
 * tuple slot.
 *
 * Return value of InvalidAttrNumber means all not-null constraints on virtual
 * generated columns are satisfied.  A return value > 0 means a not-null
 * violation happened for that attribute.
 *
 * notnull_virtual_attrs is the list of the attnums of virtual generated column with
 * not-null constraints.
 */
AttrNumber
ExecRelGenVirtualNotNull(ResultRelInfo *resultRelInfo, TupleTableSlot *slot,
						 EState *estate, List *notnull_virtual_attrs)
{
	Relation	rel = resultRelInfo->ri_RelationDesc;
	ExprContext *econtext;
	MemoryContext oldContext;

	/*
	 * We implement this by building a NullTest node for each virtual
	 * generated column, which we cache in resultRelInfo, and running those
	 * through ExecCheck().
	 */
	if (resultRelInfo->ri_GenVirtualNotNullConstraintExprs == NULL)
	{
		oldContext = MemoryContextSwitchTo(estate->es_query_cxt);
		resultRelInfo->ri_GenVirtualNotNullConstraintExprs =
			palloc0_array(ExprState *, list_length(notnull_virtual_attrs));

		foreach_int(attnum, notnull_virtual_attrs)
		{
			int			i = foreach_current_index(attnum);
			NullTest   *nnulltest;

			/* "generated_expression IS NOT NULL" check. */
			nnulltest = makeNode(NullTest);
			nnulltest->arg = (Expr *) build_generation_expression(rel, attnum);
			nnulltest->nulltesttype = IS_NOT_NULL;
			nnulltest->argisrow = false;
			nnulltest->location = -1;

			resultRelInfo->ri_GenVirtualNotNullConstraintExprs[i] =
				ExecPrepareExpr((Expr *) nnulltest, estate);
		}
		MemoryContextSwitchTo(oldContext);
	}

	/*
	 * We will use the EState's per-tuple context for evaluating virtual
	 * generated column not null constraint expressions (creating it if it's
	 * not already there).
	 */
	econtext = GetPerTupleExprContext(estate);

	/* Arrange for econtext's scan tuple to be the tuple under test */
	econtext->ecxt_scantuple = slot;

	/* And evaluate the check constraints for virtual generated column */
	foreach_int(attnum, notnull_virtual_attrs)
	{
		int			i = foreach_current_index(attnum);
		ExprState  *exprstate = resultRelInfo->ri_GenVirtualNotNullConstraintExprs[i];

		Assert(exprstate != NULL);
		if (!ExecCheck(exprstate, econtext))
			return attnum;
	}

	/* InvalidAttrNumber result means no error */
	return InvalidAttrNumber;
}

/*
 * Report a violation of a not-null constraint that was already detected.
 */
static void
ReportNotNullViolationError(ResultRelInfo *resultRelInfo, TupleTableSlot *slot,
							EState *estate, int attnum)
{
	Bitmapset  *modifiedCols;
	char	   *val_desc;
	Relation	rel = resultRelInfo->ri_RelationDesc;
	Relation	orig_rel = rel;
	TupleDesc	tupdesc = RelationGetDescr(rel);
	TupleDesc	orig_tupdesc = RelationGetDescr(rel);
	Form_pg_attribute att = TupleDescAttr(tupdesc, attnum - 1);

	Assert(attnum > 0);

	/*
	 * If the tuple has been routed, it's been converted to the partition's
	 * rowtype, which might differ from the root table's.  We must convert it
	 * back to the root table's rowtype so that val_desc shown error message
	 * matches the input tuple.
	 */
	if (resultRelInfo->ri_RootResultRelInfo)
	{
		ResultRelInfo *rootrel = resultRelInfo->ri_RootResultRelInfo;
		AttrMap    *map;

		tupdesc = RelationGetDescr(rootrel->ri_RelationDesc);
		/* a reverse map */
		map = build_attrmap_by_name_if_req(orig_tupdesc,
										   tupdesc,
										   false);

		/*
		 * Partition-specific slot's tupdesc can't be changed, so allocate a
		 * new one.
		 */
		if (map != NULL)
			slot = execute_attr_map_slot(map, slot,
										 MakeTupleTableSlot(tupdesc, &TTSOpsVirtual, 0));
		modifiedCols = bms_union(ExecGetInsertedCols(rootrel, estate),
								 ExecGetUpdatedCols(rootrel, estate));
		rel = rootrel->ri_RelationDesc;
	}
	else
		modifiedCols = bms_union(ExecGetInsertedCols(resultRelInfo, estate),
								 ExecGetUpdatedCols(resultRelInfo, estate));

	val_desc = ExecBuildSlotValueDescription(RelationGetRelid(rel),
											 slot,
											 tupdesc,
											 modifiedCols,
											 64);
	ereport(ERROR,
			errcode(ERRCODE_NOT_NULL_VIOLATION),
			errmsg("null value in column \"%s\" of relation \"%s\" violates not-null constraint",
				   NameStr(att->attname),
				   RelationGetRelationName(orig_rel)),
			val_desc ? errdetail("Failing row contains %s.", val_desc) : 0,
			errtablecol(orig_rel, attnum));
}

/*
 * ExecWithCheckOptions -- check that tuple satisfies any WITH CHECK OPTIONs
 * of the specified kind.
 *
 * Note that this needs to be called multiple times to ensure that all kinds of
 * WITH CHECK OPTIONs are handled (both those from views which have the WITH
 * CHECK OPTION set and from row-level security policies).  See ExecInsert()
 * and ExecUpdate().
 */
void
ExecWithCheckOptions(WCOKind kind, ResultRelInfo *resultRelInfo,
					 TupleTableSlot *slot, EState *estate)
{
	Relation	rel = resultRelInfo->ri_RelationDesc;
	TupleDesc	tupdesc = RelationGetDescr(rel);
	ExprContext *econtext;
	ListCell   *l1,
			   *l2;

	/*
	 * We will use the EState's per-tuple context for evaluating constraint
	 * expressions (creating it if it's not already there).
	 */
	econtext = GetPerTupleExprContext(estate);

	/* Arrange for econtext's scan tuple to be the tuple under test */
	econtext->ecxt_scantuple = slot;

	/* Check each of the constraints */
	forboth(l1, resultRelInfo->ri_WithCheckOptions,
			l2, resultRelInfo->ri_WithCheckOptionExprs)
	{
		WithCheckOption *wco = (WithCheckOption *) lfirst(l1);
		ExprState  *wcoExpr = (ExprState *) lfirst(l2);

		/*
		 * Skip any WCOs which are not the kind we are looking for at this
		 * time.
		 */
		if (wco->kind != kind)
			continue;

		/*
		 * WITH CHECK OPTION checks are intended to ensure that the new tuple
		 * is visible (in the case of a view) or that it passes the
		 * 'with-check' policy (in the case of row security). If the qual
		 * evaluates to NULL or FALSE, then the new tuple won't be included in
		 * the view or doesn't pass the 'with-check' policy for the table.
		 */
		if (!ExecQual(wcoExpr, econtext))
		{
			char	   *val_desc;
			Bitmapset  *modifiedCols;

			switch (wco->kind)
			{
					/*
					 * For WITH CHECK OPTIONs coming from views, we might be
					 * able to provide the details on the row, depending on
					 * the permissions on the relation (that is, if the user
					 * could view it directly anyway).  For RLS violations, we
					 * don't include the data since we don't know if the user
					 * should be able to view the tuple as that depends on the
					 * USING policy.
					 */
				case WCO_VIEW_CHECK:
					/* See the comment in ExecConstraints(). */
					if (resultRelInfo->ri_RootResultRelInfo)
					{
						ResultRelInfo *rootrel = resultRelInfo->ri_RootResultRelInfo;
						TupleDesc	old_tupdesc = RelationGetDescr(rel);
						AttrMap    *map;

						tupdesc = RelationGetDescr(rootrel->ri_RelationDesc);
						/* a reverse map */
						map = build_attrmap_by_name_if_req(old_tupdesc,
														   tupdesc,
														   false);

						/*
						 * Partition-specific slot's tupdesc can't be changed,
						 * so allocate a new one.
						 */
						if (map != NULL)
							slot = execute_attr_map_slot(map, slot,
														 MakeTupleTableSlot(tupdesc, &TTSOpsVirtual, 0));

						modifiedCols = bms_union(ExecGetInsertedCols(rootrel, estate),
												 ExecGetUpdatedCols(rootrel, estate));
						rel = rootrel->ri_RelationDesc;
					}
					else
						modifiedCols = bms_union(ExecGetInsertedCols(resultRelInfo, estate),
												 ExecGetUpdatedCols(resultRelInfo, estate));
					val_desc = ExecBuildSlotValueDescription(RelationGetRelid(rel),
															 slot,
															 tupdesc,
															 modifiedCols,
															 64);

					ereport(ERROR,
							(errcode(ERRCODE_WITH_CHECK_OPTION_VIOLATION),
							 errmsg("new row violates check option for view \"%s\"",
									wco->relname),
							 val_desc ? errdetail("Failing row contains %s.",
												  val_desc) : 0));
					break;
				case WCO_RLS_INSERT_CHECK:
				case WCO_RLS_UPDATE_CHECK:
					if (wco->polname != NULL)
						ereport(ERROR,
								(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
								 errmsg("new row violates row-level security policy \"%s\" for table \"%s\"",
										wco->polname, wco->relname)));
					else
						ereport(ERROR,
								(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
								 errmsg("new row violates row-level security policy for table \"%s\"",
										wco->relname)));
					break;
				case WCO_RLS_MERGE_UPDATE_CHECK:
				case WCO_RLS_MERGE_DELETE_CHECK:
					if (wco->polname != NULL)
						ereport(ERROR,
								(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
								 errmsg("target row violates row-level security policy \"%s\" (USING expression) for table \"%s\"",
										wco->polname, wco->relname)));
					else
						ereport(ERROR,
								(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
								 errmsg("target row violates row-level security policy (USING expression) for table \"%s\"",
										wco->relname)));
					break;
				case WCO_RLS_CONFLICT_CHECK:
					if (wco->polname != NULL)
						ereport(ERROR,
								(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
								 errmsg("new row violates row-level security policy \"%s\" (USING expression) for table \"%s\"",
										wco->polname, wco->relname)));
					else
						ereport(ERROR,
								(errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
								 errmsg("new row violates row-level security policy (USING expression) for table \"%s\"",
										wco->relname)));
					break;
				default:
					elog(ERROR, "unrecognized WCO kind: %u", wco->kind);
					break;
			}
		}
	}
}

/*
 * ExecBuildSlotValueDescription -- construct a string representing a tuple
 *
 * This is intentionally very similar to BuildIndexValueDescription, but
 * unlike that function, we truncate long field values (to at most maxfieldlen
 * bytes).  That seems necessary here since heap field values could be very
 * long, whereas index entries typically aren't so wide.
 *
 * Also, unlike the case with index entries, we need to be prepared to ignore
 * dropped columns.  We used to use the slot's tuple descriptor to decode the
 * data, but the slot's descriptor doesn't identify dropped columns, so we
 * now need to be passed the relation's descriptor.
 *
 * Note that, like BuildIndexValueDescription, if the user does not have
 * permission to view any of the columns involved, a NULL is returned.  Unlike
 * BuildIndexValueDescription, if the user has access to view a subset of the
 * column involved, that subset will be returned with a key identifying which
 * columns they are.
 */
char *
ExecBuildSlotValueDescription(Oid reloid,
							  TupleTableSlot *slot,
							  TupleDesc tupdesc,
							  Bitmapset *modifiedCols,
							  int maxfieldlen)
{
	StringInfoData buf;
	StringInfoData collist;
	bool		write_comma = false;
	bool		write_comma_collist = false;
	int			i;
	AclResult	aclresult;
	bool		table_perm = false;
	bool		any_perm = false;

	/*
	 * Check if RLS is enabled and should be active for the relation; if so,
	 * then don't return anything.  Otherwise, go through normal permission
	 * checks.
	 */
	if (check_enable_rls(reloid, InvalidOid, true) == RLS_ENABLED)
		return NULL;

	initStringInfo(&buf);

	appendStringInfoChar(&buf, '(');

	/*
	 * Check if the user has permissions to see the row.  Table-level SELECT
	 * allows access to all columns.  If the user does not have table-level
	 * SELECT then we check each column and include those the user has SELECT
	 * rights on.  Additionally, we always include columns the user provided
	 * data for.
	 */
	aclresult = pg_class_aclcheck(reloid, GetUserId(), ACL_SELECT);
	if (aclresult != ACLCHECK_OK)
	{
		/* Set up the buffer for the column list */
		initStringInfo(&collist);
		appendStringInfoChar(&collist, '(');
	}
	else
		table_perm = any_perm = true;

	/* Make sure the tuple is fully deconstructed */
	slot_getallattrs(slot);

	for (i = 0; i < tupdesc->natts; i++)
	{
		bool		column_perm = false;
		char	   *val;
		int			vallen;
		Form_pg_attribute att = TupleDescAttr(tupdesc, i);

		/* ignore dropped columns */
		if (att->attisdropped)
			continue;

		if (!table_perm)
		{
			/*
			 * No table-level SELECT, so need to make sure they either have
			 * SELECT rights on the column or that they have provided the data
			 * for the column.  If not, omit this column from the error
			 * message.
			 */
			aclresult = pg_attribute_aclcheck(reloid, att->attnum,
											  GetUserId(), ACL_SELECT);
			if (bms_is_member(att->attnum - FirstLowInvalidHeapAttributeNumber,
							  modifiedCols) || aclresult == ACLCHECK_OK)
			{
				column_perm = any_perm = true;

				if (write_comma_collist)
					appendStringInfoString(&collist, ", ");
				else
					write_comma_collist = true;

				appendStringInfoString(&collist, NameStr(att->attname));
			}
		}

		if (table_perm || column_perm)
		{
			if (att->attgenerated == ATTRIBUTE_GENERATED_VIRTUAL)
				val = "virtual";
			else if (slot->tts_isnull[i])
				val = "null";
			else
			{
				Oid			foutoid;
				bool		typisvarlena;

				getTypeOutputInfo(att->atttypid,
								  &foutoid, &typisvarlena);
				val = OidOutputFunctionCall(foutoid, slot->tts_values[i]);
			}

			if (write_comma)
				appendStringInfoString(&buf, ", ");
			else
				write_comma = true;

			/* truncate if needed */
			vallen = strlen(val);
			if (vallen <= maxfieldlen)
				appendBinaryStringInfo(&buf, val, vallen);
			else
			{
				vallen = pg_mbcliplen(val, vallen, maxfieldlen);
				appendBinaryStringInfo(&buf, val, vallen);
				appendStringInfoString(&buf, "...");
			}
		}
	}

	/* If we end up with zero columns being returned, then return NULL. */
	if (!any_perm)
		return NULL;

	appendStringInfoChar(&buf, ')');

	if (!table_perm)
	{
		appendStringInfoString(&collist, ") = ");
		appendBinaryStringInfo(&collist, buf.data, buf.len);

		return collist.data;
	}

	return buf.data;
}


/*
 * ExecUpdateLockMode -- find the appropriate UPDATE tuple lock mode for a
 * given ResultRelInfo
 */
LockTupleMode
ExecUpdateLockMode(EState *estate, ResultRelInfo *relinfo)
{
	Bitmapset  *keyCols;
	Bitmapset  *updatedCols;

	/*
	 * Compute lock mode to use.  If columns that are part of the key have not
	 * been modified, then we can use a weaker lock, allowing for better
	 * concurrency.
	 */
	updatedCols = ExecGetAllUpdatedCols(relinfo, estate);
	keyCols = RelationGetIndexAttrBitmap(relinfo->ri_RelationDesc,
										 INDEX_ATTR_BITMAP_KEY);

	if (bms_overlap(keyCols, updatedCols))
		return LockTupleExclusive;

	return LockTupleNoKeyExclusive;
}

/*
 * ExecFindRowMark -- find the ExecRowMark struct for given rangetable index
 *
 * If no such struct, either return NULL or throw error depending on missing_ok
 */
ExecRowMark *
ExecFindRowMark(EState *estate, Index rti, bool missing_ok)
{
	if (rti > 0 && rti <= estate->es_range_table_size &&
		estate->es_rowmarks != NULL)
	{
		ExecRowMark *erm = estate->es_rowmarks[rti - 1];

		if (erm)
			return erm;
	}
	if (!missing_ok)
		elog(ERROR, "failed to find ExecRowMark for rangetable index %u", rti);
	return NULL;
}

/*
 * ExecBuildAuxRowMark -- create an ExecAuxRowMark struct
 *
 * Inputs are the underlying ExecRowMark struct and the targetlist of the
 * input plan node (not planstate node!).  We need the latter to find out
 * the column numbers of the resjunk columns.
 */
ExecAuxRowMark *
ExecBuildAuxRowMark(ExecRowMark *erm, List *targetlist)
{
	ExecAuxRowMark *aerm = palloc0_object(ExecAuxRowMark);
	char		resname[32];

	aerm->rowmark = erm;

	/* Look up the resjunk columns associated with this rowmark */
	if (erm->markType != ROW_MARK_COPY)
	{
		/* need ctid for all methods other than COPY */
		snprintf(resname, sizeof(resname), "ctid%u", erm->rowmarkId);
		aerm->ctidAttNo = ExecFindJunkAttributeInTlist(targetlist,
													   resname);
		if (!AttributeNumberIsValid(aerm->ctidAttNo))
			elog(ERROR, "could not find junk %s column", resname);
	}
	else
	{
		/* need wholerow if COPY */
		snprintf(resname, sizeof(resname), "wholerow%u", erm->rowmarkId);
		aerm->wholeAttNo = ExecFindJunkAttributeInTlist(targetlist,
														resname);
		if (!AttributeNumberIsValid(aerm->wholeAttNo))
			elog(ERROR, "could not find junk %s column", resname);
	}

	/* if child rel, need tableoid */
	if (erm->rti != erm->prti)
	{
		snprintf(resname, sizeof(resname), "tableoid%u", erm->rowmarkId);
		aerm->toidAttNo = ExecFindJunkAttributeInTlist(targetlist,
													   resname);
		if (!AttributeNumberIsValid(aerm->toidAttNo))
			elog(ERROR, "could not find junk %s column", resname);
	}

	return aerm;
}


/*
 * EvalPlanQual logic --- recheck modified tuple(s) to see if we want to
 * process the updated version under READ COMMITTED rules.
 *
 * See backend/executor/README for some info about how this works.
 */


/*
 * Check the updated version of a tuple to see if we want to process it under
 * READ COMMITTED rules.
 *
 *	epqstate - state for EvalPlanQual rechecking
 *	relation - table containing tuple
 *	rti - rangetable index of table containing tuple
 *	inputslot - tuple for processing - this can be the slot from
 *		EvalPlanQualSlot() for this rel, for increased efficiency.
 *
 * This tests whether the tuple in inputslot still matches the relevant
 * quals. For that result to be useful, typically the input tuple has to be
 * last row version (otherwise the result isn't particularly useful) and
 * locked (otherwise the result might be out of date). That's typically
 * achieved by using table_tuple_lock() with the
 * TUPLE_LOCK_FLAG_FIND_LAST_VERSION flag.
 *
 * Returns a slot containing the new candidate update/delete tuple, or
 * NULL if we determine we shouldn't process the row.
 */
TupleTableSlot *
EvalPlanQual(EPQState *epqstate, Relation relation,
			 Index rti, TupleTableSlot *inputslot)
{
	TupleTableSlot *slot;
	TupleTableSlot *testslot;

	Assert(rti > 0);

	/*
	 * Need to run a recheck subquery.  Initialize or reinitialize EPQ state.
	 */
	EvalPlanQualBegin(epqstate);

	/*
	 * Callers will often use the EvalPlanQualSlot to store the tuple to avoid
	 * an unnecessary copy.
	 */
	testslot = EvalPlanQualSlot(epqstate, relation, rti);
	if (testslot != inputslot)
		ExecCopySlot(testslot, inputslot);

	/*
	 * Mark that an EPQ tuple is available for this relation.  (If there is
	 * more than one result relation, the others remain marked as having no
	 * tuple available.)
	 */
	epqstate->relsubs_done[rti - 1] = false;
	epqstate->relsubs_blocked[rti - 1] = false;

	/*
	 * Run the EPQ query.  We assume it will return at most one tuple.
	 */
	slot = EvalPlanQualNext(epqstate);

	/*
	 * If we got a tuple, force the slot to materialize the tuple so that it
	 * is not dependent on any local state in the EPQ query (in particular,
	 * it's highly likely that the slot contains references to any pass-by-ref
	 * datums that may be present in copyTuple).  As with the next step, this
	 * is to guard against early re-use of the EPQ query.
	 */
	if (!TupIsNull(slot))
		ExecMaterializeSlot(slot);

	/*
	 * Clear out the test tuple, and mark that no tuple is available here.
	 * This is needed in case the EPQ state is re-used to test a tuple for a
	 * different target relation.
	 */
	ExecClearTuple(testslot);
	epqstate->relsubs_blocked[rti - 1] = true;

	return slot;
}

/*
 * EvalPlanQualInit -- initialize during creation of a plan state node
 * that might need to invoke EPQ processing.
 *
 * If the caller intends to use EvalPlanQual(), resultRelations should be
 * a list of RT indexes of potential target relations for EvalPlanQual(),
 * and we will arrange that the other listed relations don't return any
 * tuple during an EvalPlanQual() call.  Otherwise resultRelations
 * should be NIL.
 *
 * Note: subplan/auxrowmarks can be NULL/NIL if they will be set later
 * with EvalPlanQualSetPlan.
 */
void
EvalPlanQualInit(EPQState *epqstate, EState *parentestate,
				 Plan *subplan, List *auxrowmarks,
				 int epqParam, List *resultRelations)
{
	Index		rtsize = parentestate->es_range_table_size;

	/* initialize data not changing over EPQState's lifetime */
	epqstate->parentestate = parentestate;
	epqstate->epqParam = epqParam;
	epqstate->resultRelations = resultRelations;

	/*
	 * Allocate space to reference a slot for each potential rti - do so now
	 * rather than in EvalPlanQualBegin(), as done for other dynamically
	 * allocated resources, so EvalPlanQualSlot() can be used to hold tuples
	 * that *may* need EPQ later, without forcing the overhead of
	 * EvalPlanQualBegin().
	 */
	epqstate->tuple_table = NIL;
	epqstate->relsubs_slot = palloc0_array(TupleTableSlot *, rtsize);

	/* ... and remember data that EvalPlanQualBegin will need */
	epqstate->plan = subplan;
	epqstate->arowMarks = auxrowmarks;

	/* ... and mark the EPQ state inactive */
	epqstate->origslot = NULL;
	epqstate->recheckestate = NULL;
	epqstate->recheckplanstate = NULL;
	epqstate->relsubs_rowmark = NULL;
	epqstate->relsubs_done = NULL;
	epqstate->relsubs_blocked = NULL;
}

/*
 * EvalPlanQualSetPlan -- set or change subplan of an EPQState.
 *
 * We used to need this so that ModifyTable could deal with multiple subplans.
 * It could now be refactored out of existence.
 */
void
EvalPlanQualSetPlan(EPQState *epqstate, Plan *subplan, List *auxrowmarks)
{
	/* If we have a live EPQ query, shut it down */
	EvalPlanQualEnd(epqstate);
	/* And set/change the plan pointer */
	epqstate->plan = subplan;
	/* The rowmarks depend on the plan, too */
	epqstate->arowMarks = auxrowmarks;
}

/*
 * Return, and create if necessary, a slot for an EPQ test tuple.
 *
 * Note this only requires EvalPlanQualInit() to have been called,
 * EvalPlanQualBegin() is not necessary.
 */
TupleTableSlot *
EvalPlanQualSlot(EPQState *epqstate,
				 Relation relation, Index rti)
{
	TupleTableSlot **slot;

	Assert(relation);
	Assert(rti > 0 && rti <= epqstate->parentestate->es_range_table_size);
	slot = &epqstate->relsubs_slot[rti - 1];

	if (*slot == NULL)
	{
		MemoryContext oldcontext;

		oldcontext = MemoryContextSwitchTo(epqstate->parentestate->es_query_cxt);
		*slot = table_slot_create(relation, &epqstate->tuple_table);
		MemoryContextSwitchTo(oldcontext);
	}

	return *slot;
}

/*
 * Fetch the current row value for a non-locked relation, identified by rti,
 * that needs to be scanned by an EvalPlanQual operation.  origslot must have
 * been set to contain the current result row (top-level row) that we need to
 * recheck.  Returns true if a substitution tuple was found, false if not.
 */
bool
EvalPlanQualFetchRowMark(EPQState *epqstate, Index rti, TupleTableSlot *slot)
{
	ExecAuxRowMark *earm = epqstate->relsubs_rowmark[rti - 1];
	ExecRowMark *erm;
	Datum		datum;
	bool		isNull;

	Assert(earm != NULL);
	Assert(epqstate->origslot != NULL);

	erm = earm->rowmark;

	if (RowMarkRequiresRowShareLock(erm->markType))
		elog(ERROR, "EvalPlanQual doesn't support locking rowmarks");

	/* if child rel, must check whether it produced this row */
	if (erm->rti != erm->prti)
	{
		Oid			tableoid;

		datum = ExecGetJunkAttribute(epqstate->origslot,
									 earm->toidAttNo,
									 &isNull);
		/* non-locked rels could be on the inside of outer joins */
		if (isNull)
			return false;

		tableoid = DatumGetObjectId(datum);

		Assert(OidIsValid(erm->relid));
		if (tableoid != erm->relid)
		{
			/* this child is inactive right now */
			return false;
		}
	}

	if (erm->markType == ROW_MARK_REFERENCE)
	{
		Assert(erm->relation != NULL);

		/* fetch the tuple's ctid */
		datum = ExecGetJunkAttribute(epqstate->origslot,
									 earm->ctidAttNo,
									 &isNull);
		/* non-locked rels could be on the inside of outer joins */
		if (isNull)
			return false;

		/* fetch requests on foreign tables must be passed to their FDW */
		if (erm->relation->rd_rel->relkind == RELKIND_FOREIGN_TABLE)
		{
			FdwRoutine *fdwroutine;
			bool		updated = false;

			fdwroutine = GetFdwRoutineForRelation(erm->relation, false);
			/* this should have been checked already, but let's be safe */
			if (fdwroutine->RefetchForeignRow == NULL)
				ereport(ERROR,
						(errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
						 errmsg("cannot lock rows in foreign table \"%s\"",
								RelationGetRelationName(erm->relation))));

			fdwroutine->RefetchForeignRow(epqstate->recheckestate,
										  erm,
										  datum,
										  slot,
										  &updated);
			if (TupIsNull(slot))
				elog(ERROR, "failed to fetch tuple for EvalPlanQual recheck");

			/*
			 * Ideally we'd insist on updated == false here, but that assumes
			 * that FDWs can track that exactly, which they might not be able
			 * to.  So just ignore the flag.
			 */
			return true;
		}
		else
		{
			/* ordinary table, fetch the tuple */
			if (!table_tuple_fetch_row_version(erm->relation,
											   (ItemPointer) DatumGetPointer(datum),
											   SnapshotAny, slot))
				elog(ERROR, "failed to fetch tuple for EvalPlanQual recheck");
			return true;
		}
	}
	else
	{
		Assert(erm->markType == ROW_MARK_COPY);

		/* fetch the whole-row Var for the relation */
		datum = ExecGetJunkAttribute(epqstate->origslot,
									 earm->wholeAttNo,
									 &isNull);
		/* non-locked rels could be on the inside of outer joins */
		if (isNull)
			return false;

		ExecStoreHeapTupleDatum(datum, slot);
		return true;
	}
}

/*
 * Fetch the next row (if any) from EvalPlanQual testing
 *
 * (In practice, there should never be more than one row...)
 */
TupleTableSlot *
EvalPlanQualNext(EPQState *epqstate)
{
	MemoryContext oldcontext;
	TupleTableSlot *slot;

	oldcontext = MemoryContextSwitchTo(epqstate->recheckestate->es_query_cxt);
	slot = ExecProcNode(epqstate->recheckplanstate);
	MemoryContextSwitchTo(oldcontext);

	return slot;
}

/*
 * Initialize or reset an EvalPlanQual state tree
 */
void
EvalPlanQualBegin(EPQState *epqstate)
{
	EState	   *parentestate = epqstate->parentestate;
	EState	   *recheckestate = epqstate->recheckestate;

	if (recheckestate == NULL)
	{
		/* First time through, so create a child EState */
		EvalPlanQualStart(epqstate, epqstate->plan);
	}
	else
	{
		/*
		 * We already have a suitable child EPQ tree, so just reset it.
		 */
		Index		rtsize = parentestate->es_range_table_size;
		PlanState  *rcplanstate = epqstate->recheckplanstate;

		/*
		 * Reset the relsubs_done[] flags to equal relsubs_blocked[], so that
		 * the EPQ run will never attempt to fetch tuples from blocked target
		 * relations.
		 */
		memcpy(epqstate->relsubs_done, epqstate->relsubs_blocked,
			   rtsize * sizeof(bool));

		/* Recopy current values of parent parameters */
		if (parentestate->es_plannedstmt->paramExecTypes != NIL)
		{
			int			i;

			/*
			 * Force evaluation of any InitPlan outputs that could be needed
			 * by the subplan, just in case they got reset since
			 * EvalPlanQualStart (see comments therein).
			 */
			ExecSetParamPlanMulti(rcplanstate->plan->extParam,
								  GetPerTupleExprContext(parentestate));

			i = list_length(parentestate->es_plannedstmt->paramExecTypes);

			while (--i >= 0)
			{
				/* copy value if any, but not execPlan link */
				recheckestate->es_param_exec_vals[i].value =
					parentestate->es_param_exec_vals[i].value;
				recheckestate->es_param_exec_vals[i].isnull =
					parentestate->es_param_exec_vals[i].isnull;
			}
		}

		/*
		 * Mark child plan tree as needing rescan at all scan nodes.  The
		 * first ExecProcNode will take care of actually doing the rescan.
		 */
		rcplanstate->chgParam = bms_add_member(rcplanstate->chgParam,
											   epqstate->epqParam);
	}
}

/*
 * Start execution of an EvalPlanQual plan tree.
 *
 * This is a cut-down version of ExecutorStart(): we copy some state from
 * the top-level estate rather than initializing it fresh.
 */
static void
EvalPlanQualStart(EPQState *epqstate, Plan *planTree)
{
	EState	   *parentestate = epqstate->parentestate;
	Index		rtsize = parentestate->es_range_table_size;
	EState	   *rcestate;
	MemoryContext oldcontext;
	ListCell   *l;

	epqstate->recheckestate = rcestate = CreateExecutorState();

	oldcontext = MemoryContextSwitchTo(rcestate->es_query_cxt);

	/* signal that this is an EState for executing EPQ */
	rcestate->es_epq_active = epqstate;

	/*
	 * Child EPQ EStates share the parent's copy of unchanging state such as
	 * the snapshot, rangetable, and external Param info.  They need their own
	 * copies of local state, including a tuple table, es_param_exec_vals,
	 * result-rel info, etc.
	 */
	rcestate->es_direction = ForwardScanDirection;
	rcestate->es_snapshot = parentestate->es_snapshot;
	rcestate->es_crosscheck_snapshot = parentestate->es_crosscheck_snapshot;
	rcestate->es_range_table = parentestate->es_range_table;
	rcestate->es_range_table_size = parentestate->es_range_table_size;
	rcestate->es_relations = parentestate->es_relations;
	rcestate->es_rowmarks = parentestate->es_rowmarks;
	rcestate->es_rteperminfos = parentestate->es_rteperminfos;
	rcestate->es_plannedstmt = parentestate->es_plannedstmt;
	rcestate->es_junkFilter = parentestate->es_junkFilter;
	rcestate->es_output_cid = parentestate->es_output_cid;
	rcestate->es_queryEnv = parentestate->es_queryEnv;

	/*
	 * ResultRelInfos needed by subplans are initialized from scratch when the
	 * subplans themselves are initialized.
	 */
	rcestate->es_result_relations = NULL;
	/* es_trig_target_relations must NOT be copied */
	rcestate->es_top_eflags = parentestate->es_top_eflags;
	rcestate->es_instrument = parentestate->es_instrument;
	/* es_auxmodifytables must NOT be copied */

	/*
	 * The external param list is simply shared from parent.  The internal
	 * param workspace has to be local state, but we copy the initial values
	 * from the parent, so as to have access to any param values that were
	 * already set from other parts of the parent's plan tree.
	 */
	rcestate->es_param_list_info = parentestate->es_param_list_info;
	if (parentestate->es_plannedstmt->paramExecTypes != NIL)
	{
		int			i;

		/*
		 * Force evaluation of any InitPlan outputs that could be needed by
		 * the subplan.  (With more complexity, maybe we could postpone this
		 * till the subplan actually demands them, but it doesn't seem worth
		 * the trouble; this is a corner case already, since usually the
		 * InitPlans would have been evaluated before reaching EvalPlanQual.)
		 *
		 * This will not touch output params of InitPlans that occur somewhere
		 * within the subplan tree, only those that are attached to the
		 * ModifyTable node or above it and are referenced within the subplan.
		 * That's OK though, because the planner would only attach such
		 * InitPlans to a lower-level SubqueryScan node, and EPQ execution
		 * will not descend into a SubqueryScan.
		 *
		 * The EState's per-output-tuple econtext is sufficiently short-lived
		 * for this, since it should get reset before there is any chance of
		 * doing EvalPlanQual again.
		 */
		ExecSetParamPlanMulti(planTree->extParam,
							  GetPerTupleExprContext(parentestate));

		/* now make the internal param workspace ... */
		i = list_length(parentestate->es_plannedstmt->paramExecTypes);
		rcestate->es_param_exec_vals = palloc0_array(ParamExecData, i);
		/* ... and copy down all values, whether really needed or not */
		while (--i >= 0)
		{
			/* copy value if any, but not execPlan link */
			rcestate->es_param_exec_vals[i].value =
				parentestate->es_param_exec_vals[i].value;
			rcestate->es_param_exec_vals[i].isnull =
				parentestate->es_param_exec_vals[i].isnull;
		}
	}

	/*
	 * Copy es_unpruned_relids so that pruned relations are ignored by
	 * ExecInitLockRows() and ExecInitModifyTable() when initializing the plan
	 * trees below.
	 */
	rcestate->es_unpruned_relids = parentestate->es_unpruned_relids;

	/*
	 * Also make the PartitionPruneInfo and the results of pruning available.
	 * These need to match exactly so that we initialize all the same Append
	 * and MergeAppend subplans as the parent did.
	 */
	rcestate->es_part_prune_infos = parentestate->es_part_prune_infos;
	rcestate->es_part_prune_states = parentestate->es_part_prune_states;
	rcestate->es_part_prune_results = parentestate->es_part_prune_results;

	/* We'll also borrow the es_partition_directory from the parent state */
	rcestate->es_partition_directory = parentestate->es_partition_directory;

	/*
	 * Initialize private state information for each SubPlan.  We must do this
	 * before running ExecInitNode on the main query tree, since
	 * ExecInitSubPlan expects to be able to find these entries. Some of the
	 * SubPlans might not be used in the part of the plan tree we intend to
	 * run, but since it's not easy to tell which, we just initialize them
	 * all.
	 */
	Assert(rcestate->es_subplanstates == NIL);
	foreach(l, parentestate->es_plannedstmt->subplans)
	{
		Plan	   *subplan = (Plan *) lfirst(l);
		PlanState  *subplanstate;

		subplanstate = ExecInitNode(subplan, rcestate, 0);
		rcestate->es_subplanstates = lappend(rcestate->es_subplanstates,
											 subplanstate);
	}

	/*
	 * Build an RTI indexed array of rowmarks, so that
	 * EvalPlanQualFetchRowMark() can efficiently access the to be fetched
	 * rowmark.
	 */
	epqstate->relsubs_rowmark = palloc0_array(ExecAuxRowMark *, rtsize);
	foreach(l, epqstate->arowMarks)
	{
		ExecAuxRowMark *earm = (ExecAuxRowMark *) lfirst(l);

		epqstate->relsubs_rowmark[earm->rowmark->rti - 1] = earm;
	}

	/*
	 * Initialize per-relation EPQ tuple states.  Result relations, if any,
	 * get marked as blocked; others as not-fetched.
	 */
	epqstate->relsubs_done = palloc_array(bool, rtsize);
	epqstate->relsubs_blocked = palloc0_array(bool, rtsize);

	foreach(l, epqstate->resultRelations)
	{
		int			rtindex = lfirst_int(l);

		Assert(rtindex > 0 && rtindex <= rtsize);
		epqstate->relsubs_blocked[rtindex - 1] = true;
	}

	memcpy(epqstate->relsubs_done, epqstate->relsubs_blocked,
		   rtsize * sizeof(bool));

	/*
	 * Initialize the private state information for all the nodes in the part
	 * of the plan tree we need to run.  This opens files, allocates storage
	 * and leaves us ready to start processing tuples.
	 */
	epqstate->recheckplanstate = ExecInitNode(planTree, rcestate, 0);

	MemoryContextSwitchTo(oldcontext);
}

/*
 * EvalPlanQualEnd -- shut down at termination of parent plan state node,
 * or if we are done with the current EPQ child.
 *
 * This is a cut-down version of ExecutorEnd(); basically we want to do most
 * of the normal cleanup, but *not* close result relations (which we are
 * just sharing from the outer query).  We do, however, have to close any
 * result and trigger target relations that got opened, since those are not
 * shared.  (There probably shouldn't be any of the latter, but just in
 * case...)
 */
void
EvalPlanQualEnd(EPQState *epqstate)
{
	EState	   *estate = epqstate->recheckestate;
	Index		rtsize;
	MemoryContext oldcontext;
	ListCell   *l;

	rtsize = epqstate->parentestate->es_range_table_size;

	/*
	 * We may have a tuple table, even if EPQ wasn't started, because we allow
	 * use of EvalPlanQualSlot() without calling EvalPlanQualBegin().
	 */
	if (epqstate->tuple_table != NIL)
	{
		memset(epqstate->relsubs_slot, 0,
			   rtsize * sizeof(TupleTableSlot *));
		ExecResetTupleTable(epqstate->tuple_table, true);
		epqstate->tuple_table = NIL;
	}

	/* EPQ wasn't started, nothing further to do */
	if (estate == NULL)
		return;

	oldcontext = MemoryContextSwitchTo(estate->es_query_cxt);

	ExecEndNode(epqstate->recheckplanstate);

	foreach(l, estate->es_subplanstates)
	{
		PlanState  *subplanstate = (PlanState *) lfirst(l);

		ExecEndNode(subplanstate);
	}

	/* throw away the per-estate tuple table, some node may have used it */
	ExecResetTupleTable(estate->es_tupleTable, false);

	/* Close any result and trigger target relations attached to this EState */
	ExecCloseResultRelations(estate);

	MemoryContextSwitchTo(oldcontext);

	/*
	 * NULLify the partition directory before freeing the executor state.
	 * Since EvalPlanQualStart() just borrowed the parent EState's directory,
	 * we'd better leave it up to the parent to delete it.
	 */
	estate->es_partition_directory = NULL;

	FreeExecutorState(estate);

	/* Mark EPQState idle */
	epqstate->origslot = NULL;
	epqstate->recheckestate = NULL;
	epqstate->recheckplanstate = NULL;
	epqstate->relsubs_rowmark = NULL;
	epqstate->relsubs_done = NULL;
	epqstate->relsubs_blocked = NULL;
}

/* ----------------------------------------------------------------
 *	   Runtime security: handle the caught rows, send to AM
 *
 * The tables are the Secure-ERMS ones (merged/01_schema.sql).
 * nodeModifyTable.c catches their rows (_PGS_RuntimeSecurity_CaptureRow);
 * at the end of each statement standard_ExecutorFinish() calls
 * _PGS_RuntimeSecurity_StatementEnd(), which reads the rows back with SPI
 * and:
 *
 *	INSERT INTO tenants              queues the tenant for AM
 *	INSERT INTO user_accounts        queues the user for AM (username, role
 *	                                 from employees -> roles, display name)
 *	UPDATE ... SET login_status = 1  login, if the account and its tenant
 *	                                 are ACTIVE: user_asset_map gets a row per
 *	                                 protected type the role may use
 *	                                 (role_protected_type_permissions) and
 *	                                 asset_key = the 32-byte key AM returns
 *	UPDATE ... SET login_status = 0, or an account that is not ACTIVE
 *	                                 logout: the user's asset keys are removed
 *	UPDATE tenants SET status        a DISABLED tenant: every key of its users
 *	                                 is removed
 *	role / protected-type tables changed
 *	                                 queues the whole matrix for AM
 *
 * The queue is sent when the transaction commits, so a rolled-back
 * statement or savepoint sends nothing.  The HTTP calls are in
 * am_client.cpp.
 * ----------------------------------------------------------------
 */

/*
 * asset_key in user_asset_map: a 32-byte key, base64 (44 characters: 43
 * and one '='). AM values of any other size are not stored.
 */
#define RSC_KEY_BYTES 32
#define RSC_KEY_PATTERN "^[A-Za-z0-9+/]{43}=$"

/* A row caught in ExecModifyTable, handled at the end of its statement */
typedef struct RscEvent
{
	RscEventKind kind;
	EState	   *estate;			/* statement that wrote the row */
	int			nestlevel;		/* (sub)transaction that wrote it */
	char	   *schema;			/* schema of the table written */
	int64		id;				/* tenant_id or user_id */
} RscEvent;

/* A call to AM, made when the transaction commits */
typedef struct RscSend
{
	int			nestlevel;
	const char *endpoint;		/* "tenants", "users" or "roles" */
	int64		tenant_id;		/* picks the API key; 0 = default key */
	char	   *body;
} RscSend;

/* Both lists live in TopTransactionContext */
static List *pending_events = NIL;
static List *pending_sends = NIL;
static bool callbacks_registered = false;
static bool rsc_busy = false;	/* running our own SPI queries */

static void _PGS_rsc_xact_callback(XactEvent event, void *arg);
static void _PGS_rsc_subxact_callback(SubXactEvent event, SubTransactionId mySubid,
								 SubTransactionId parentSubid, void *arg);

/*
 * Called by _PGS_RuntimeSecurity_CaptureRow() (nodeModifyTable.c) for each row of
 * the tenant, user and role-asset tables: remember it until the end of its
 * statement.  The events live in TopTransactionContext.
 */
void
_PGS_RuntimeSecurity_AddEvent(RscEventKind kind, EState *estate, Relation rel, int64 id)
{
	MemoryContext oldcxt;
	RscEvent   *ev;

	if (rsc_busy)				/* our own SPI queries */
		return;

	if (kind == RSC_MATRIX_CHANGED)
	{
		ListCell   *lc;

		/* One matrix event per statement is enough */
		foreach(lc, pending_events)
		{
			RscEvent   *e = (RscEvent *) lfirst(lc);

			if (e->kind == RSC_MATRIX_CHANGED && e->estate == estate)
				return;
		}
	}

	if (!callbacks_registered)
	{
		RegisterXactCallback(_PGS_rsc_xact_callback, NULL);
		RegisterSubXactCallback(_PGS_rsc_subxact_callback, NULL);
		callbacks_registered = true;
	}

	oldcxt = MemoryContextSwitchTo(TopTransactionContext);
	ev = palloc(sizeof(RscEvent));
	ev->kind = kind;
	ev->estate = estate;
	ev->nestlevel = GetCurrentTransactionNestLevel();
	ev->schema = get_namespace_name(RelationGetNamespace(rel));
	ev->id = id;
	pending_events = lappend(pending_events, ev);
	MemoryContextSwitchTo(oldcxt);
}

/* ---------------------------------------------------------------- SPI */

/* Run a query with $1 = id (bigint) and, if given, $2 = arg (text) */
static uint64
_PGS_rsc_exec(const char *sql, int64 id, const char *arg)
{
	Oid			types[2] = {INT8OID, TEXTOID};
	Datum		values[2];
	int			ret;

	values[0] = Int64GetDatum(id);
	if (arg != NULL)
		values[1] = CStringGetTextDatum(arg);

	ret = SPI_execute_with_args(sql, arg != NULL ? 2 : 1, types, values,
								NULL, false, 0);
	if (ret < 0)
		elog(ERROR, "runtime security: query failed (%s): %s",
			 SPI_result_code_string(ret), sql);
	return SPI_processed;
}

/* Column col (1-based) of the first result row, NULL if it is null */
static char *
_PGS_rsc_value(int col)
{
	return SPI_getvalue(SPI_tuptable->vals[0], SPI_tuptable->tupdesc, col);
}

/* Queue a call to AM for commit */
static void
_PGS_rsc_queue_send(const char *endpoint, int64 tenant_id, const char *body)
{
	MemoryContext oldcxt = MemoryContextSwitchTo(TopTransactionContext);
	RscSend    *s;

	/* The matrix is sent whole, so only its latest version is kept */
	if (strcmp(endpoint, "roles") == 0)
	{
		List	   *keep = NIL;
		ListCell   *lc;

		foreach(lc, pending_sends)
		{
			RscSend    *old = (RscSend *) lfirst(lc);

			if (strcmp(old->endpoint, "roles") != 0)
				keep = lappend(keep, old);
		}
		pending_sends = keep;
	}

	s = palloc(sizeof(RscSend));
	s->nestlevel = GetCurrentTransactionNestLevel();
	s->endpoint = endpoint;
	s->tenant_id = tenant_id;
	s->body = pstrdup(body);
	pending_sends = lappend(pending_sends, s);
	MemoryContextSwitchTo(oldcxt);
}

/* ------------------------------------------------------- login / logout */

/*
 * A protected type the user's role may use: any S/I/U/D permission in
 * role_protected_type_permissions.  The role is the employee's
 * (user_accounts -> employees -> role_id).  Format with the schema 4 times.
 */
#define RSC_USER_TYPES \
	"SELECT u.tenant_id, u.user_id, p.type_id FROM %s.user_accounts u" \
	" JOIN %s.employees e ON e.tenant_id = u.tenant_id" \
	"  AND e.employee_id = u.employee_id" \
	" JOIN %s.role_protected_type_permissions p ON p.role_id = e.role_id" \
	" JOIN %s.protected_type_catalog c ON c.type_id = p.type_id" \
	" WHERE u.user_id = $1" \
	" AND (p.can_select OR p.can_insert OR p.can_update OR p.can_delete)"

/*
 * Login (login_status 1, account and tenant ACTIVE): user_asset_map gets a
 * row per protected type of the user's role, and asset_key = the value AM
 * returns for that type.
 */
static void
_PGS_rsc_login(const char *q, int64 user_id, int64 tenant_id, const char *username)
{
	char	   *response = NULL;
	char		errbuf[256];
	int			status;
	uint64		n;
	uint64		bad;

	/* Types the role no longer grants */
	_PGS_rsc_exec(psprintf("DELETE FROM %s.user_asset_map k "
					  "WHERE k.user_id = $1 AND k.type_id NOT IN ("
					  "SELECT t.type_id FROM (" RSC_USER_TYPES ") t)",
					  q, q, q, q, q), user_id, NULL);
	/* A row per type of the role */
	_PGS_rsc_exec(psprintf("INSERT INTO %s.user_asset_map (tenant_id, user_id, type_id) "
					  RSC_USER_TYPES " ON CONFLICT (user_id, type_id) DO NOTHING",
					  q, q, q, q, q), user_id, NULL);
	/* No key from an earlier session survives */
	_PGS_rsc_exec(psprintf("UPDATE %s.user_asset_map SET asset_key = NULL "
					  "WHERE user_id = $1 AND asset_key IS NOT NULL", q),
			 user_id, NULL);

	status = _PGS_AmClient_Call("user_assets", username, tenant_id, NULL,
						   &response, errbuf, sizeof(errbuf));
	if (status == 0)
	{
		ereport(LOG,
				(errmsg("runtime security: login of user %lld: AM is not configured (am_client.conf), no asset keys stored",
						(long long) user_id)));
		_PGS_AmClient_Free(response);
		return;
	}
	if (status != 200 || response == NULL)
	{
		ereport(WARNING,
				(errmsg("runtime security: login of user %lld: could not get the asset values from AM",
						(long long) user_id),
				 status < 0 ? errdetail("%s", errbuf) :
				 errdetail("AM answered HTTP %d.", status)));
		_PGS_AmClient_Free(response);
		return;
	}

	/* PostgreSQL parses AM's JSON: data.assets[] {name, value} */
	_PGS_rsc_exec("SELECT 1 WHERE pg_input_is_valid($2, 'jsonb')", user_id, response);
	if (SPI_processed == 0)
	{
		ereport(WARNING,
				(errmsg("runtime security: login of user %lld: AM's answer is not valid JSON",
						(long long) user_id)));
		_PGS_AmClient_Free(response);
		return;
	}
	/* AM names each asset by its protected type id (A01 ...) */
	n = _PGS_rsc_exec(psprintf("UPDATE %s.user_asset_map k SET asset_key = a.value "
						  "FROM jsonb_to_recordset("
						  " CASE WHEN jsonb_typeof($2::jsonb #> '{data,assets}') = 'array'"
						  " THEN $2::jsonb #> '{data,assets}' ELSE '[]' END)"
						  " AS a(name text, value text) "
						  "WHERE k.user_id = $1 AND k.type_id = a.name"
						  " AND a.value ~ '" RSC_KEY_PATTERN "'",
						  q), user_id, response);
	/* Values AM sent that are not a 32-byte key: refused, not truncated */
	bad = _PGS_rsc_exec("SELECT 1 FROM jsonb_to_recordset("
						 " CASE WHEN jsonb_typeof($2::jsonb #> '{data,assets}') = 'array'"
						 " THEN $2::jsonb #> '{data,assets}' ELSE '[]' END)"
						 " AS a(name text, value text) "
						 "WHERE a.value IS NOT NULL"
						 " AND a.value !~ '" RSC_KEY_PATTERN "'", user_id, response);
	_PGS_AmClient_Free(response);
	if (bad > 0)
		ereport(WARNING,
				(errmsg("runtime security: login of user %lld: %llu asset values from AM are not %d-byte keys, not stored",
						(long long) user_id, (unsigned long long) bad, RSC_KEY_BYTES)));

	ereport(LOG,
			(errmsg("runtime security: login of user %lld: %llu asset keys stored",
					(long long) user_id, (unsigned long long) n)));
}

/* Logout (login_status 0, or the account is no longer ACTIVE): remove keys */
static void
_PGS_rsc_logout(const char *q, int64 user_id)
{
	uint64		n;

	n = _PGS_rsc_exec(psprintf("UPDATE %s.user_asset_map SET asset_key = NULL "
						  "WHERE user_id = $1 AND asset_key IS NOT NULL", q),
				 user_id, NULL);
	ereport(LOG,
			(errmsg("runtime security: logout of user %lld: %llu asset keys removed",
					(long long) user_id, (unsigned long long) n)));
}

/* --------------------------------------------------------------- events */

/*
 * A new tenant in the shape of AM's POST /api/admin/tenants: its slug (the
 * org code in lower case) and name.  The AM client adds the tenant's first
 * admin from am_client.conf.
 */
static void
_PGS_rsc_tenant_created(const char *q, int64 tenant_id)
{
	if (_PGS_rsc_exec(psprintf("SELECT json_build_object("
						  "'slug', lower(org_code), 'name', org_name)::text "
						  "FROM %s.tenants WHERE tenant_id = $1", q),
				 tenant_id, NULL) == 0)
		return;					/* not inserted after all (ON CONFLICT) */
	_PGS_rsc_queue_send("tenants", tenant_id, _PGS_rsc_value(1));
}

/* A tenant set to DISABLED: none of its users keeps an asset key */
static void
_PGS_rsc_tenant_status(const char *q, int64 tenant_id)
{
	uint64		n;

	if (_PGS_rsc_exec(psprintf("SELECT status FROM %s.tenants WHERE tenant_id = $1", q),
				 tenant_id, NULL) == 0 ||
		strcmp(_PGS_rsc_value(1), "ACTIVE") == 0)
		return;
	n = _PGS_rsc_exec(psprintf("UPDATE %s.user_asset_map SET asset_key = NULL "
						  "WHERE tenant_id = $1 AND asset_key IS NOT NULL", q),
				 tenant_id, NULL);
	ereport(LOG,
			(errmsg("runtime security: tenant %lld is not ACTIVE: %llu asset keys removed",
					(long long) tenant_id, (unsigned long long) n)));
}

static void
_PGS_rsc_user_created(const char *q, int64 user_id)
{
	int64		tenant_id;

	if (_PGS_rsc_exec(psprintf("SELECT json_build_object("
						  "'username', u.username, 'role', r.role_name,"
						  " 'displayName', e.first_name || ' ' || e.last_name)::text,"
						  " u.tenant_id, u.login_status "
						  "FROM %s.user_accounts u"
						  " JOIN %s.employees e ON e.tenant_id = u.tenant_id"
						  "  AND e.employee_id = u.employee_id"
						  " LEFT JOIN %s.roles r ON r.role_id = e.role_id "
						  "WHERE u.user_id = $1", q, q, q),
				 user_id, NULL) == 0)
		return;
	tenant_id = pg_strtoint64(_PGS_rsc_value(2));
	_PGS_rsc_queue_send("users", tenant_id, _PGS_rsc_value(1));

	/*
	 * AM only knows the user after commit, so a user created already logged
	 * in gets the map rows now and the keys at the next login.
	 */
	if (strcmp(_PGS_rsc_value(3), "1") == 0)
	{
		_PGS_rsc_exec(psprintf("INSERT INTO %s.user_asset_map (tenant_id, user_id, type_id) "
						  RSC_USER_TYPES " ON CONFLICT (user_id, type_id) DO NOTHING",
						  q, q, q, q, q), user_id, NULL);
		ereport(NOTICE,
				(errmsg("runtime security: user %lld was created with login_status 1; asset keys are stored at the next login",
						(long long) user_id)));
	}
}

static void
_PGS_rsc_user_status(const char *q, int64 user_id)
{
	bool		logged_in;
	bool		active;
	int64		tenant_id;
	char	   *username;

	if (_PGS_rsc_exec(psprintf("SELECT u.login_status, u.tenant_id, u.username,"
						  " (u.status = 'ACTIVE' AND t.status = 'ACTIVE')::text "
						  "FROM %s.user_accounts u"
						  " JOIN %s.tenants t ON t.tenant_id = u.tenant_id "
						  "WHERE u.user_id = $1", q, q),
				 user_id, NULL) == 0)
		return;
	logged_in = strcmp(_PGS_rsc_value(1), "1") == 0;
	tenant_id = pg_strtoint64(_PGS_rsc_value(2));
	username = _PGS_rsc_value(3);
	active = strcmp(_PGS_rsc_value(4), "true") == 0;

	if (logged_in && active)
		_PGS_rsc_login(q, user_id, tenant_id, username);
	else
	{
		if (logged_in)
			ereport(WARNING,
					(errmsg("runtime security: user %lld is logged in but the account or its tenant is not ACTIVE; no asset keys",
							(long long) user_id)));
		_PGS_rsc_logout(q, user_id);
	}
}

/*
 * The role / protected-type matrix in the shape of AM's role/asset map
 * (POST /api/admin/role-asset-map): each role name with the protected type
 * ids (A01 ...) it may use, [] for none.  The S/I/U/D permissions stay in
 * role_protected_type_permissions; AM is not sent them.
 */
static void
_PGS_rsc_matrix_changed(const char *q)
{
	_PGS_rsc_exec(psprintf("SELECT coalesce(json_object_agg(r.role_name,"
					  "  coalesce((SELECT json_agg(p.type_id ORDER BY p.type_id)"
					  "    FROM %s.role_protected_type_permissions p"
					  "    JOIN %s.protected_type_catalog c ON c.type_id = p.type_id"
					  "    WHERE p.role_id = r.role_id"
					  "    AND (p.can_select OR p.can_insert OR p.can_update OR p.can_delete)), '[]')"
					  " ORDER BY r.role_id), '{}')::text "
					  "FROM %s.roles r",
					  q, q, q), 0, NULL);
	_PGS_rsc_queue_send("roles", 0, _PGS_rsc_value(1));
}

static void
_PGS_rsc_process(List *events)
{
	ListCell   *lc;

	rsc_busy = true;
	PG_TRY();
	{
		if (SPI_connect() != SPI_OK_CONNECT)
			elog(ERROR, "runtime security: SPI_connect failed");

		foreach(lc, events)
		{
			RscEvent   *ev = (RscEvent *) lfirst(lc);
			const char *q = quote_identifier(ev->schema);

			switch (ev->kind)
			{
				case RSC_TENANT_CREATED:
					_PGS_rsc_tenant_created(q, ev->id);
					break;
				case RSC_USER_CREATED:
					_PGS_rsc_user_created(q, ev->id);
					break;
				case RSC_USER_STATUS:
					_PGS_rsc_user_status(q, ev->id);
					break;
				case RSC_MATRIX_CHANGED:
					_PGS_rsc_matrix_changed(q);
					break;
				case RSC_TENANT_STATUS:
					_PGS_rsc_tenant_status(q, ev->id);
					break;
			}
		}

		SPI_finish();
	}
	PG_FINALLY();
	{
		rsc_busy = false;
	}
	PG_END_TRY();
}

/*
 * Called by standard_ExecutorFinish(): handle the rows this statement
 * caught.
 */
static void
_PGS_RuntimeSecurity_StatementEnd(EState *estate)
{
	List	   *mine = NIL;
	List	   *rest = NIL;
	ListCell   *lc;
	MemoryContext oldcxt;

	if (pending_events == NIL || rsc_busy)
		return;

	oldcxt = MemoryContextSwitchTo(TopTransactionContext);
	foreach(lc, pending_events)
	{
		RscEvent   *ev = (RscEvent *) lfirst(lc);

		if (ev->estate == estate)
			mine = lappend(mine, ev);
		else
			rest = lappend(rest, ev);
	}
	MemoryContextSwitchTo(oldcxt);

	if (mine == NIL)
		return;
	pending_events = rest;
	_PGS_rsc_process(mine);
}

/* ------------------------------------------------------------- commit */

static void
_PGS_rsc_send_all(void)
{
	ListCell   *lc;

	foreach(lc, pending_sends)
	{
		RscSend    *s = (RscSend *) lfirst(lc);
		char	   *response = NULL;
		char		errbuf[256];
		int			status;

		status = _PGS_AmClient_Call(s->endpoint, NULL, s->tenant_id, s->body,
							   &response, errbuf, sizeof(errbuf));
		if (status == 0)
			ereport(LOG,
					(errmsg("runtime security: AM is not configured (am_client.conf); %s payload written to am_outbox.jsonl",
							s->endpoint)));
		else if (status < 0)
			ereport(WARNING,
					(errmsg("runtime security: could not send %s to AM: %s",
							s->endpoint, errbuf)));
		else if (status >= 200 && status < 300)
			ereport(LOG,
					(errmsg("runtime security: sent %s to AM (HTTP %d)",
							s->endpoint, status)));
		else
			ereport(WARNING,
					(errmsg("runtime security: AM refused %s (HTTP %d): %.300s",
							s->endpoint, status, response ? response : "")));
		_PGS_AmClient_Free(response);
	}
}

static void
_PGS_rsc_xact_callback(XactEvent event, void *arg)
{
	switch (event)
	{
		case XACT_EVENT_PRE_COMMIT:
			/* Rows whose statement did not reach ExecutorFinish */
			if (pending_events != NIL)
			{
				List	   *events = pending_events;

				pending_events = NIL;
				_PGS_rsc_process(events);
			}
			break;
		case XACT_EVENT_COMMIT:
			_PGS_rsc_send_all();
			pending_events = NIL;
			pending_sends = NIL;
			break;
		case XACT_EVENT_PREPARE:
			if (pending_sends != NIL)
				ereport(WARNING,
						(errmsg("runtime security: nothing is sent to AM for a prepared transaction")));
			pending_events = NIL;
			pending_sends = NIL;
			break;
		case XACT_EVENT_ABORT:
		case XACT_EVENT_PARALLEL_ABORT:
			pending_events = NIL;
			pending_sends = NIL;
			rsc_busy = false;
			break;
		default:
			break;
	}
}

/*
 * A rolled-back savepoint forgets what it caught; a released one hands it
 * to its parent.
 */
static void
_PGS_rsc_subxact_callback(SubXactEvent event, SubTransactionId mySubid,
					 SubTransactionId parentSubid, void *arg)
{
	int			level = GetCurrentTransactionNestLevel();
	List	   *events = NIL;
	List	   *sends = NIL;
	ListCell   *lc;
	MemoryContext oldcxt;

	if (event != SUBXACT_EVENT_ABORT_SUB && event != SUBXACT_EVENT_COMMIT_SUB)
		return;

	oldcxt = MemoryContextSwitchTo(TopTransactionContext);
	foreach(lc, pending_events)
	{
		RscEvent   *ev = (RscEvent *) lfirst(lc);

		if (ev->nestlevel < level)
			events = lappend(events, ev);
		else if (event == SUBXACT_EVENT_COMMIT_SUB)
		{
			ev->nestlevel = level - 1;
			events = lappend(events, ev);
		}
	}
	foreach(lc, pending_sends)
	{
		RscSend    *s = (RscSend *) lfirst(lc);

		if (s->nestlevel < level)
			sends = lappend(sends, s);
		else if (event == SUBXACT_EVENT_COMMIT_SUB)
		{
			s->nestlevel = level - 1;
			sends = lappend(sends, s);
		}
	}
	MemoryContextSwitchTo(oldcxt);

	pending_events = events;
	pending_sends = sends;
	if (event == SUBXACT_EVENT_ABORT_SUB)
		rsc_busy = false;
}
