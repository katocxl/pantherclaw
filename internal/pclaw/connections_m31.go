// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"flag"

	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// snowflakeFlags are a snowflake connection's settings on connection create
// (G0 M31 D962a): the account, warehouse, database and schema. The tables
// it may read are its manifest, which a person confirms on the manifest
// page; the server checks every value.
type snowflakeFlags struct {
	account, warehouse, database, schema optional
}

const snowflakeFlagUsage = " [--snowflake-account A --snowflake-warehouse W --snowflake-database DB --snowflake-schema S]"

func addSnowflakeFlags(fs *flag.FlagSet) *snowflakeFlags {
	s := &snowflakeFlags{}
	fs.Var(&s.account, "snowflake-account", "snowflake connections: the account identifier (orgname-account_name, or a locator)")
	fs.Var(&s.warehouse, "snowflake-warehouse", "snowflake connections: the warehouse every statement runs on")
	fs.Var(&s.database, "snowflake-database", "snowflake connections: the database every statement runs in")
	fs.Var(&s.schema, "snowflake-schema", "snowflake connections: the schema statements name by default")
	return s
}

// set reports whether any snowflake flag was given.
func (s *snowflakeFlags) set() bool {
	return s.account.set || s.warehouse.set || s.database.set || s.schema.set
}

// config is the flags' snowflake configuration.
func (s *snowflakeFlags) config() *pb.SnowflakeConfig {
	return &pb.SnowflakeConfig{Account: s.account.v, Warehouse: s.warehouse.v, Database: s.database.v, Schema: s.schema.v}
}
