/*-------------------------------------------------------------------------
 *
 * discreet_hooks.h
 *	  Discreet R1/W1 executor instrumentation hooks.
 *
 * The executor calls these at two points (see the design brief
 * Discreet_PostgreSQL_R1_W1_Design_Rationale_With_Test_Cases):
 *
 *	R1  ExecutePlan()      each result row, before it is sent to the client
 *	W1  ExecInsert/ExecUpdate/ExecDelete()  each row before it is written
 *
 * plus the logger hook _PGS_LogExecutorTableInfo().  All the code lives in
 * src/backend/executor/discreet_hooks.c; execMain.c and nodeModifyTable.c
 * only contain the calls.
 *
 * src/include/executor/discreet_hooks.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef DISCREET_HOOKS_H
#define DISCREET_HOOKS_H

#include "executor/execdesc.h"
#include "nodes/execnodes.h"
#include "executor/tuptable.h"
#include "storage/itemptr.h"
#include "utils/relcache.h"

/* Logger hook: action, table, PID and thread ID */
extern void _PGS_LogExecutorTableInfo(const char *action, Oid table_oid, const char *relname);

/* Logger hook for ExecutorRun: one line per table the plan uses */
extern void _PGS_Discreet_LogExecutorRun(QueryDesc *queryDesc);

/* R1: a result row about to be sent (TC-01..04, 07..10, 12) */
extern void _PGS_Discreet_R1_Intercept(QueryDesc *queryDesc, TupleTableSlot *slot, uint64 row_num);

/* W1: a row about to be written (TC-05, TC-06, TC-11) */
extern void _PGS_Discreet_W1_Insert(Relation rel, TupleTableSlot *slot, const char *stage);
extern void _PGS_Discreet_W1_Update(Relation rel, TupleTableSlot *slot, ItemPointer tupleid);
extern void _PGS_Discreet_W1_Delete(Relation rel, ItemPointer tupleid);

/*
 * Integer shift: user tables store integer columns +10 (W1) and the client
 * gets them back -10 (R1), so it sees what it wrote while the table and the
 * logs hold the shifted value.  SET discreet.shift_integers = off disables it.
 */
extern void _PGS_Discreet_W1_ShiftInsert(ModifyTableState *mtstate, ResultRelInfo *resultRelInfo,
									TupleTableSlot *slot);
extern void _PGS_Discreet_W1_ShiftUpdate(ResultRelInfo *resultRelInfo, EState *estate,
									TupleTableSlot *slot);
extern void _PGS_Discreet_R1_Unshift(QueryDesc *queryDesc, TupleTableSlot *slot, uint64 row_num);

/* Planner: rewrite a client query so WHERE, expressions and SET use original values */
extern void _PGS_Discreet_PlannerRewrite(Query *parse);

#endif							/* DISCREET_HOOKS_H */
