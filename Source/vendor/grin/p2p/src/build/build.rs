// Copyright 2026 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Build hooks to spit out version info

//! GrinSight Fly copy: the upstream script calls the `built` crate to record
//! the git commit for the user agent string. That pulls libgit2 into an
//! offline build for the sake of one optional suffix, so this copy writes the
//! one constant the crate reads and nothing else.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
	let out_dir = env::var("OUT_DIR").unwrap();
	let _ = fs::write(
		Path::new(&out_dir).join("built.rs"),
		"/// No commit is recorded in this copy.\npub const GIT_COMMIT_HASH_SHORT: Option<&str> = None;\n",
	);
	println!("cargo:rerun-if-changed=src/build/build.rs");
}
