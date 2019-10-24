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
use super::OperationTestClient;
use log::error;
use parsec_interface::operations::key_attributes::*;
use parsec_interface::operations::OpPing;
use parsec_interface::operations::ProviderInfo;
use parsec_interface::operations::{NativeOperation, NativeResult};
use parsec_interface::operations::{OpAsymSign, OpAsymVerify};
use parsec_interface::operations::{OpCreateKey, OpDestroyKey};
use parsec_interface::operations::{OpExportPublicKey, OpImportKey};
use parsec_interface::operations::{OpListOpcodes, OpListProviders};
use parsec_interface::requests::{request::RequestAuth, Opcode, ProviderID, Result};
use std::collections::{HashMap, HashSet};

/// Client structure automatically choosing a provider and high-level operation functions.
pub struct TestClient {
    op_client: OperationTestClient,
    cached_opcodes: Option<HashMap<ProviderID, HashSet<Opcode>>>,
    provider: Option<ProviderID>,
    auth: RequestAuth,
    created_keys: Option<HashSet<(String, Vec<u8>, ProviderID)>>,
}

impl TestClient {
    /// Creates a TestClient instance with no provider or authentication set.
    ///
    /// For each request, a provider able to execute the operation will be chosen.
    /// The keys creates by this client will be automatically destroyed when it is dropped unless
    /// the method `do_not_destroy_keys` is called.
    pub fn new() -> TestClient {
        TestClient {
            op_client: OperationTestClient::new(),
            cached_opcodes: None,
            provider: None,
            auth: RequestAuth::from_bytes(Vec::new()),
            created_keys: Some(HashSet::new()),
        }
    }

    /// Manually set the provider to execute the requests. If not set, one will be chosen
    /// automatically.
    pub fn set_provider(&mut self, provider: Option<ProviderID>) {
        self.provider = provider;
    }

    /// Set the authentication body for every request.
    pub fn set_auth(&mut self, auth: Vec<u8>) {
        self.auth = RequestAuth::from_bytes(auth);
    }

    /// By default the `TestClient` instance will destroy the keys it created when it is dropped,
    /// unless this function is called.
    pub fn do_not_destroy_keys(&mut self) {
        self.created_keys.take();
    }

    fn build_cache(&mut self) {
        let mut map = HashMap::new();
        let provider_result = self
            .op_client
            .send_operation(
                NativeOperation::ListProviders(OpListProviders {}),
                ProviderID::CoreProvider,
                self.auth.clone(),
            )
            .expect("List providers failed");
        if let NativeResult::ListProviders(provider_result) = provider_result {
            for provider in provider_result.providers {
                let opcode_result = self
                    .op_client
                    .send_operation(
                        NativeOperation::ListOpcodes(OpListOpcodes {}),
                        provider.id,
                        self.auth.clone(),
                    )
                    .expect("List opcodes failed");
                if let NativeResult::ListOpcodes(opcode_result) = opcode_result {
                    map.insert(provider.id, opcode_result.opcodes);
                }
            }
        }

        self.cached_opcodes = Some(map);
    }

    fn get_cached_provider(&mut self, opcode: Opcode) -> ProviderID {
        if self.cached_opcodes.is_none() {
            self.build_cache();
        }

        if let Some(cache) = &self.cached_opcodes {
            for (provider, opcodes) in cache.iter() {
                if opcodes.contains(&opcode) {
                    return *provider;
                }
            }
        }

        ProviderID::CoreProvider
    }

    fn provider(&mut self, opcode: Opcode) -> ProviderID {
        match self.provider {
            Some(provider) => provider,
            None => self.get_cached_provider(opcode),
        }
    }

    fn send_operation(&mut self, operation: NativeOperation) -> Result<NativeResult> {
        let provider = self.provider(operation.opcode());
        self.op_client
            .send_operation(operation, provider, self.auth.clone())
    }

    fn send_operation_to_provider(
        &mut self,
        operation: NativeOperation,
        provider: ProviderID,
    ) -> Result<NativeResult> {
        self.op_client
            .send_operation(operation, provider, self.auth.clone())
    }

    /// Creates a key with specific attributes.
    pub fn create_key(
        &mut self,
        key_name: String,
        key_type: KeyType,
        algorithm: Algorithm,
    ) -> Result<()> {
        let create_key = OpCreateKey {
            key_name: key_name.clone(),
            key_attributes: KeyAttributes {
                key_type,
                ecc_curve: None,
                algorithm,
                key_size: 1024,
                permit_sign: true,
                permit_verify: true,
                permit_export: true,
                permit_derive: true,
                permit_encrypt: true,
                permit_decrypt: true,
            },
        };

        self.send_operation(NativeOperation::CreateKey(create_key))?;

        let provider = self.provider(Opcode::CreateKey);
        let auth = self.auth.bytes().to_vec();

        if let Some(ref mut created_keys) = self.created_keys {
            created_keys.insert((key_name, auth, provider));
        }

        Ok(())
    }

    /// Creates a key for RSA signing.
    pub fn create_rsa_sign_key(&mut self, key_name: String) -> Result<()> {
        let result = self.create_key(
            key_name.clone(),
            KeyType::RsaKeypair,
            Algorithm::sign(SignAlgorithm::RsaPkcs1v15Sign, None),
        );

        if result.is_ok() {
            let provider = self.provider(Opcode::CreateKey);
            let auth = self.auth.bytes().to_vec();

            if let Some(ref mut created_keys) = self.created_keys {
                created_keys.insert((key_name, auth, provider));
            }
        }
        result
    }

    /// Imports and creates a key with specific attributes.
    pub fn import_key(
        &mut self,
        key_name: String,
        key_type: KeyType,
        algorithm: Algorithm,
        key_data: Vec<u8>,
    ) -> Result<()> {
        let import = OpImportKey {
            key_name: key_name.clone(),
            key_attributes: KeyAttributes {
                key_type,
                ecc_curve: None,
                algorithm,
                key_size: 0,
                permit_sign: true,
                permit_verify: true,
                permit_export: true,
                permit_derive: true,
                permit_encrypt: true,
                permit_decrypt: true,
            },
            key_data,
        };

        self.send_operation(NativeOperation::ImportKey(import))?;

        let provider = self.provider(Opcode::ImportKey);
        let auth = self.auth.bytes().to_vec();

        if let Some(ref mut created_keys) = self.created_keys {
            created_keys.insert((key_name, auth, provider));
        }

        Ok(())
    }

    /// Exports a public key.
    pub fn export_public_key(&mut self, key_name: String) -> Result<Vec<u8>> {
        let export = OpExportPublicKey { key_name };

        let result = self.send_operation(NativeOperation::ExportPublicKey(export))?;

        if let NativeResult::ExportPublicKey(result) = result {
            Ok(result.key_data)
        } else {
            panic!("Wrong type of result");
        }
    }

    /// Destroys a key.
    pub fn destroy_key(&mut self, key_name: String) -> Result<()> {
        let destroy_key = OpDestroyKey {
            key_name: key_name.clone(),
        };

        self.send_operation(NativeOperation::DestroyKey(destroy_key))?;

        let provider = self.provider(Opcode::DestroyKey);
        let auth = self.auth.bytes().to_vec();

        if let Some(ref mut created_keys) = self.created_keys {
            created_keys.remove(&(key_name, auth, provider));
        }

        Ok(())
    }

    /// Signs a short digest with a key.
    pub fn sign(&mut self, key_name: String, hash: Vec<u8>) -> Result<Vec<u8>> {
        let asym_sign = OpAsymSign {
            key_name: key_name.clone(),
            hash: hash.clone(),
        };

        let result = self.send_operation(NativeOperation::AsymSign(asym_sign))?;

        if let NativeResult::AsymSign(result) = result {
            Ok(result.signature)
        } else {
            panic!("Wrong type of result");
        }
    }

    /// Verifies a signature.
    pub fn verify(&mut self, key_name: String, hash: Vec<u8>, signature: Vec<u8>) -> Result<()> {
        let asym_verify = OpAsymVerify {
            key_name,
            hash,
            signature,
        };

        self.send_operation(NativeOperation::AsymVerify(asym_verify))?;

        Ok(())
    }

    /// Lists the provider available for the PARSEC service.
    pub fn list_providers(&mut self) -> Result<Vec<ProviderInfo>> {
        let result = self.send_operation(NativeOperation::ListProviders(OpListProviders {}))?;

        if let NativeResult::ListProviders(result) = result {
            Ok(result.providers)
        } else {
            panic!("Wrong type of result");
        }
    }

    /// Lists the opcodes available for one provider to execute.
    pub fn list_opcodes(&mut self, provider: ProviderID) -> Result<HashSet<Opcode>> {
        let result = self
            .send_operation_to_provider(NativeOperation::ListOpcodes(OpListOpcodes {}), provider)?;

        if let NativeResult::ListOpcodes(result) = result {
            Ok(result.opcodes)
        } else {
            panic!("Wrong type of result");
        }
    }

    /// Executes a ping operation on one provider.
    pub fn ping(&mut self, provider: ProviderID) -> Result<(u8, u8)> {
        let result = self.send_operation_to_provider(NativeOperation::Ping(OpPing {}), provider)?;

        if let NativeResult::Ping(result) = result {
            Ok((result.supp_version_min, result.supp_version_maj))
        } else {
            panic!("Wrong type of result");
        }
    }
}

impl Default for TestClient {
    fn default() -> Self {
        TestClient::new()
    }
}

impl Drop for TestClient {
    fn drop(&mut self) {
        if let Some(ref mut created_keys) = self.created_keys {
            for (key_name, auth, provider) in created_keys.clone().iter() {
                self.provider = Some(*provider);
                self.auth = RequestAuth::from_bytes(auth.clone());
                if self.destroy_key(key_name.clone()).is_err() {
                    error!("Failed to destroy key '{}'", key_name);
                }
            }
        }
    }
}
