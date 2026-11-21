/*-------------------------------------------------------------------------
 *
 * discreet_metadata.h
 *	  Discreet metadata service: asset records for columns marked for
 *	  encryption in their comment.
 *
 * DefineRelation() (CREATE TABLE), CommentObject() (COMMENT ON) and
 * heap_drop_with_catalog() (DROP TABLE) only call _PGS_Discreet_Metadata_Track();
 * all the code lives in
 * src/backend/commands/discreet_metadata.c.
 *
 * src/include/commands/discreet_metadata.h
 *
 *-------------------------------------------------------------------------
 */
#ifndef DISCREET_METADATA_H
#define DISCREET_METADATA_H

/* Remember a table; its asset records are written to metadata.json at commit */
extern void _PGS_Discreet_Metadata_Track(Oid relid);

#endif							/* DISCREET_METADATA_H */
