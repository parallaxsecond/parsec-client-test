// Copyright (c) 2019, Arm Limited, All Rights Reserved
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//          http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//! # PARSEC Test Client library
//!
//! This library exposes minimal functions to communicate with the PARSEC service as a real client
//! would do. It is used to perform integration tests on the PARSEC service as a whole.
//!
//! It contains three subclients to communicate on different abstraction levels.
//!
//! ### Request Test Client Example
//!
//!```no_run
//!use parsec_interface::requests::Request;
//!use parsec_client_test::RequestTestClient;
//!
//!let mut client = RequestTestClient::new();
//!let response = client.send_request(Request::new()).unwrap();
//!```
//!
//! ### Operation Test Client Example
//!
//!```no_run
//!use parsec_client_test::OperationTestClient;
//!use parsec_interface::operations::NativeOperation;
//!use parsec_interface::operations::OpPing;
//!use parsec_interface::requests::ProviderID;
//!use parsec_interface::requests::request::RequestAuth;
//!
//!let mut client = OperationTestClient::new();
//!let operation = NativeOperation::Ping(OpPing {});
//!let result = client.send_operation(operation,
//!                                   ProviderID::CoreProvider,
//!                                   RequestAuth::from_bytes(Vec::new()))
//!                   .unwrap();
//!```
//!
//! ### Test Client Example
//!
//!```no_run
//!use parsec_client_test::TestClient;
//!use parsec_interface::operations::NativeOperation;
//!use parsec_interface::operations::OpPing;
//!use parsec_interface::requests::ProviderID;
//!use parsec_interface::requests::request::RequestAuth;
//!
//!let mut client = TestClient::new();
//!let key_name = String::from("🔑 What shall I sign? 🔑");
//!client.create_rsa_sign_key(key_name.clone()).unwrap();
//!let signature = client.sign(key_name,
//!                            String::from("Platform AbstRaction for SECurity").into_bytes())
//!                      .unwrap();
//!```
mod abstract_test_client;
mod operation_test_client;
mod request_test_client;

pub use abstract_test_client::TestClient;
pub use operation_test_client::OperationTestClient;
pub use request_test_client::RequestTestClient;
