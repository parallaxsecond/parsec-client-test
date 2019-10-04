<!--
  -- Copyright (c) 2019, Arm Limited, All Rights Reserved
  -- SPDX-License-Identifier: Apache-2.0
  --
  -- Licensed under the Apache License, Version 2.0 (the "License"); you may
  -- not use this file except in compliance with the License.
  -- You may obtain a copy of the License at
  --
  -- http://www.apache.org/licenses/LICENSE-2.0
  --
  -- Unless required by applicable law or agreed to in writing, software
  -- distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
  -- WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  -- See the License for the specific language governing permissions and
  -- limitations under the License.
--->
![PARSEC logo](PARSEC.png)
# PARSEC Test Client

This repository is a PARSEC Client library used for tests. Integration tests of this library are used as integration
tests for the PARSEC service.
This library is used to perform two kinds of integration tests:
* Normal tests. They can be executed when `parsec` is running by executing `cargo test --test normal`.
* Shutdown persistency tests. They test that the PARSEC service is still running correctly even if it shutdowns. They are executed with `cargo test --test persistent-before`, restarting `parsec` and then `cargo test --test persistent-after`.

# License

The software is provided under Apache-2.0. Contributions to this project are accepted under the same license.

This project uses the following third party crates:
* num (MIT and Apache-2.0)

# Contributing

Please check the [Contributing](CONTRIBUTING.md) to know more about the contribution process.

