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

// Unity: no `built`/git2 (libgit2 is a large C build and breaks on some
// Windows setups); only GIT_COMMIT_HASH_SHORT is used, by the user agent.
use std::env;

fn main() {
	let out = format!("{}{}", env::var("OUT_DIR").unwrap(), "/built.rs");
	std::fs::write(
		out,
		"#[allow(dead_code)]\npub const GIT_COMMIT_HASH_SHORT: Option<&str> = None;\n",
	)
	.unwrap();
}
