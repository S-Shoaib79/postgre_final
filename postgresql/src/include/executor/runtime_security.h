/*-------------------------------------------------------------------------
 *
 * runtime_security.h
 *	  Runtime security check: executor hooks on the Secure-ERMS tenant,
 *	  user account and role / protected-type tables.  The code lives in the two executor files:
 *
 *	nodeModifyTable.c  ExecModifyTable(): each row written is caught
 *	                   (_PGS_RuntimeSecurity_CaptureRow) and handed to execMain.c
 *	execMain.c         standard_ExecutorFinish(): the caught rows are handled
 *	                   (SPI, login / logout, JSON), and sent to AM at commit
 *
 * This header is only what the two files share.
 *
 * src/include/executor/runtime_security.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef RUNTIME_SECURITY_H
#define RUNTIME_SECURITY_H

#include "nodes/execnodes.h"
#include "utils/relcache.h"

/* What a caught row means */
typedef enum RscEventKind
{
	RSC_TENANT_CREATED,			/* INSERT INTO tenants (id = tenant_id) */
	RSC_USER_CREATED,			/* INSERT INTO user_accounts (id = user_id) */
	RSC_USER_STATUS,			/* UPDATE user_accounts SET login_status or
								 * status (login / logout / disabled) */
	RSC_MATRIX_CHANGED,			/* any write to roles, protected_type_catalog,
								 * role_protected_type_permissions */
	RSC_TENANT_STATUS,			/* UPDATE tenants SET status (disabled) */
} RscEventKind;

/*
 * execMain.c: remember a row caught by nodeModifyTable.c until the end of
 * its statement.
 */
extern void _PGS_RuntimeSecurity_AddEvent(RscEventKind kind, EState *estate,
									 Relation rel, int64 id);

#endif							/* RUNTIME_SECURITY_H */
