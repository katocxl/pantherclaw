// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

package pclaw

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"google.golang.org/protobuf/proto"

	"github.com/katocxl/pantherclaw/internal/gateway/pgdispatch"
	pb "github.com/katocxl/pantherclaw/internal/gen/pantherclaw/v1"
)

// vectorstoreFlags are a vectorstore connection's settings on connection
// create and update (G0 M30 D922-D925a). The endpoint (host, port,
// database, user, sslmode, CA, internal) is set at create only: an update
// that changes it is refused (VECTORSTORE_ENDPOINT_IMMUTABLE).
type vectorstoreFlags struct {
	host, port, database, user, sslmode, caFile optional
	internal                                    *bool
	schema, table, dimensions, distance         optional
	writers                                     list
	clearWriters                                *bool
}

const vectorstoreFlagUsage = " [--db-host H --db-port N --db-name DB --db-user U --sslmode verify-full|require [--ca-file PEM] [--internal]" +
	" --vector-schema S --vector-table T --dimensions N --distance cosine|l2|inner_product [--writer AGENT_ID...]]"

func addVectorstoreFlags(fs *flag.FlagSet, update bool) *vectorstoreFlags {
	v := &vectorstoreFlags{}
	if !update {
		fs.Var(&v.host, "db-host", "vectorstore connections: the database host")
		fs.Var(&v.port, "db-port", "vectorstore connections: the database port (default 5432)")
		fs.Var(&v.database, "db-name", "vectorstore connections: the database name")
		fs.Var(&v.user, "db-user", "vectorstore connections: the database role (not a superuser)")
		fs.Var(&v.sslmode, "sslmode", "vectorstore connections: verify-full, or require with --internal and --ca-file")
		fs.Var(&v.caFile, "ca-file", "vectorstore connections: a PEM file of the CA that signs the database's certificate")
		v.internal = fs.Bool("internal", false, "vectorstore connections: the database is on an internal network")
	} else {
		v.internal = new(bool)
	}
	fs.Var(&v.schema, "vector-schema", "vectorstore connections: the table's schema")
	fs.Var(&v.table, "vector-table", "vectorstore connections: the table")
	fs.Var(&v.dimensions, "dimensions", "vectorstore connections: the embedding's dimensions (1-12288)")
	fs.Var(&v.distance, "distance", "vectorstore connections: cosine, l2 or inner_product")
	fs.Var(&v.writers, "writer", "vectorstore connections: an agent id that may write without approval (repeatable; replaces the list)")
	if update {
		v.clearWriters = fs.Bool("clear-writers", false, "vectorstore connections: no writer agents")
	} else {
		v.clearWriters = new(bool)
	}
	return v
}

// set reports whether any vectorstore flag was given.
func (v *vectorstoreFlags) set() bool {
	return v.host.set || v.port.set || v.database.set || v.user.set || v.sslmode.set || v.caFile.set || *v.internal ||
		v.schema.set || v.table.set || v.dimensions.set || v.distance.set || len(v.writers) > 0 || *v.clearWriters
}

// config applies the flags to base (the connection's current settings on
// update, nil on create).
func (v *vectorstoreFlags) config(base *pb.VectorstoreConfig) (*pb.VectorstoreConfig, error) {
	out := &pb.VectorstoreConfig{Port: 5432}
	if base != nil {
		out = proto.CloneOf(base)
	}
	var errs []error
	for _, f := range []struct {
		o   *optional
		dst *string
	}{
		{&v.host, &out.Host},
		{&v.database, &out.Database},
		{&v.user, &out.User},
		{&v.sslmode, &out.Sslmode},
		{&v.schema, &out.SchemaName},
		{&v.table, &out.TableName},
		{&v.distance, &out.Distance},
	} {
		if f.o.set {
			*f.dst = f.o.v
		}
	}
	for _, f := range []struct {
		o    *optional
		name string
		dst  *int32
	}{{&v.port, "--db-port", &out.Port}, {&v.dimensions, "--dimensions", &out.Dimensions}} {
		if f.o.set {
			n, err := strconv.ParseInt(f.o.v, 10, 32)
			if err != nil {
				errs = append(errs, errors.New(f.name+": an integer"))
			}
			*f.dst = int32(n)
		}
	}
	if v.caFile.set {
		b, err := os.ReadFile(v.caFile.v)
		if err != nil {
			errs = append(errs, fmt.Errorf("--ca-file: %w", err))
		}
		out.CaPem = string(b)
	}
	if *v.internal {
		out.Internal = true
	}
	switch {
	case *v.clearWriters && len(v.writers) > 0:
		errs = append(errs, errors.New("--clear-writers goes without --writer"))
	case *v.clearWriters:
		out.WriterAgentIds = nil
	case len(v.writers) > 0:
		out.WriterAgentIds = v.writers
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return out, nil
}

// currentVectorstore is a vectorstore connection's settings, read before an
// update changes some of them.
func currentVectorstore(ctx context.Context, c clients, id string) (*pb.VectorstoreConfig, error) {
	res, err := c.connections.GetConnection(ctx, &pb.GetConnectionRequest{Id: id})
	if err != nil {
		return nil, err
	}
	if res.GetConnection().GetKind() != pb.ConnectionKind_CONNECTION_KIND_VECTORSTORE {
		return nil, errors.New("the vectorstore flags change vectorstore connections only")
	}
	return res.GetConnection().GetVectorstore(), nil
}

func init() {
	commands["connection vectorstore ddl"] = command{usage: "connection vectorstore ddl ID", run: vectorstoreDDL}
}

// vectorstoreDDL prints the extension and table a vectorstore connection
// needs (G0 M30 D923), for the database admin to run; PantherClaw never
// runs it.
func vectorstoreDDL(ctx context.Context, a *app, args []string) error {
	if len(args) != 1 {
		return errUsage
	}
	c, err := a.clients()
	if err != nil {
		return err
	}
	vc, err := currentVectorstore(ctx, c, args[0])
	if err != nil {
		return err
	}
	ddl, err := pgdispatch.VectorDDL(pgdispatch.VectorTable{
		Schema: vc.GetSchemaName(), Name: vc.GetTableName(), Dimensions: int(vc.GetDimensions()), Distance: pgdispatch.Distance(vc.GetDistance()),
	})
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(a.stdout, ddl)
	return err
}
