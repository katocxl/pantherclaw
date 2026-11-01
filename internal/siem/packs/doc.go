// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 Joshua Kato. See LICENSE and NOTICE.

// Package packs tests the SIEM content packs in integrations/siem (G0 M27
// D509): the golden OCSF samples are what the exporter writes, and each rule
// of each pack, read from the vendor's own file by a small parser of the
// syntax the pack uses, fires on exactly the samples rules.yaml lists. It has
// no code outside its tests: nothing in the product reads the packs.
package packs
