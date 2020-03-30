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
use parsec_interface::operations::list_opcodes::Operation as ListOpcodes;
use parsec_interface::operations::list_providers::{Operation as ListProviders, ProviderInfo};
use parsec_interface::operations::ping::Operation as Ping;
use parsec_interface::operations::psa_algorithm::{Algorithm, AsymmetricSignature, Hash};
use parsec_interface::operations::psa_destroy_key::Operation as PsaDestroyKey;
use parsec_interface::operations::psa_export_public_key::Operation as PsaExportPublicKey;
use parsec_interface::operations::psa_generate_key::Operation as PsaGenerateKey;
use parsec_interface::operations::psa_import_key::Operation as PsaImportKey;
use parsec_interface::operations::psa_key_attributes::*;
use parsec_interface::operations::psa_key_attributes::{KeyAttributes, KeyPolicy, UsageFlags};
use parsec_interface::operations::psa_sign_hash::Operation as PsaSignHash;
use parsec_interface::operations::psa_verify_hash::Operation as PsaVerifyHash;
use parsec_interface::operations::{NativeOperation, NativeResult};
use parsec_interface::requests::{request::RequestAuth, Opcode, ProviderID, Result};
use std::collections::{HashMap, HashSet};

/// Client structure automatically choosing a provider and high-level operation functions.
#[derive(Debug)]
pub struct TestClient {
    op_client: OperationTestClient,
    cached_opcodes: Option<HashMap<ProviderID, HashSet<Opcode>>>,
    provider: Option<ProviderID>,
    auth: RequestAuth,
    created_keys: Option<HashSet<(String, Vec<u8>, ProviderID)>>,
}

impl TestClient {
    /// Creates a TestClient instance with no provider and a default authentication value of "root".
    ///
    /// For each request, a provider able to execute the operation will be chosen.
    /// The keys creates by this client will be automatically destroyed when it is dropped unless
    /// the method `do_not_destroy_keys` is called.
    pub fn new() -> TestClient {
        TestClient {
            op_client: OperationTestClient::new(),
            cached_opcodes: None,
            provider: None,
            auth: RequestAuth::from_bytes(Vec::from("root")),
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
        let _ = self.created_keys.take();
    }

    fn build_cache(&mut self) {
        let mut map = HashMap::new();
        let provider_result = self
            .op_client
            .send_operation(
                NativeOperation::ListProviders(ListProviders {}),
                ProviderID::Core,
                self.auth.clone(),
            )
            .expect("List providers failed");
        if let NativeResult::ListProviders(provider_result) = provider_result {
            for provider in provider_result.providers {
                let opcode_result = self
                    .op_client
                    .send_operation(
                        NativeOperation::ListOpcodes(ListOpcodes {}),
                        provider.id,
                        self.auth.clone(),
                    )
                    .expect("List opcodes failed");
                if let NativeResult::ListOpcodes(opcode_result) = opcode_result {
                    let _ = map.insert(provider.id, opcode_result.opcodes);
                }
            }
        }

        self.cached_opcodes = Some(map);
    }

    pub fn get_cached_provider(&mut self, opcode: Opcode) -> ProviderID {
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

        ProviderID::Core
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
    pub fn generate_key(&mut self, key_name: String, attributes: KeyAttributes) -> Result<()> {
        let generate_key = PsaGenerateKey {
            key_name: key_name.clone(),
            attributes,
        };

        let _ = self.send_operation(NativeOperation::PsaGenerateKey(generate_key))?;

        let provider = self.provider(Opcode::PsaGenerateKey);
        let auth = self.auth.bytes().to_vec();

        if let Some(ref mut created_keys) = self.created_keys {
            let _ = created_keys.insert((key_name, auth, provider));
        }

        Ok(())
    }

    /// Generate a 1024 bits RSA key pair.
    /// The key can only be used for signing/verifying with the RSA PKCS 1v15 signing algorithm with SHA-256 and exporting its public part.
    pub fn generate_rsa_sign_key(&mut self, key_name: String) -> Result<()> {
        let result = self.generate_key(
            key_name.clone(),
            KeyAttributes {
                key_type: KeyType::RsaKeyPair,
                key_bits: 1024,
                key_policy: KeyPolicy {
                    key_usage_flags: UsageFlags {
                        sign_hash: true,
                        verify_hash: true,
                        sign_message: true,
                        verify_message: true,
                        export: true,
                        encrypt: false,
                        decrypt: false,
                        cache: false,
                        copy: false,
                        derive: false,
                    },
                    key_algorithm: Algorithm::AsymmetricSignature(
                        AsymmetricSignature::RsaPkcs1v15Sign {
                            hash_alg: Hash::Sha256,
                        },
                    ),
                },
            },
        );

        if result.is_ok() {
            let provider = self.provider(Opcode::PsaGenerateKey);
            let auth = self.auth.bytes().to_vec();

            if let Some(ref mut created_keys) = self.created_keys {
                let _ = created_keys.insert((key_name, auth, provider));
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
        let import = PsaImportKey {
            key_name: key_name.clone(),
            attributes: KeyAttributes {
                key_type,
                key_policy: KeyPolicy {
                    key_usage_flags: UsageFlags {
                        sign_hash: true,
                        verify_hash: true,
                        sign_message: true,
                        verify_message: true,
                        export: true,
                        encrypt: false,
                        decrypt: false,
                        cache: false,
                        copy: false,
                        derive: false,
                    },
                    key_algorithm: algorithm,
                },
                key_bits: 1024,
            },
            data: key_data,
        };

        let _ = self.send_operation(NativeOperation::PsaImportKey(import))?;

        let provider = self.provider(Opcode::PsaImportKey);
        let auth = self.auth.bytes().to_vec();

        if let Some(ref mut created_keys) = self.created_keys {
            let _ = created_keys.insert((key_name, auth, provider));
        }

        Ok(())
    }

    /// Exports a public key.
    pub fn export_public_key(&mut self, key_name: String) -> Result<Vec<u8>> {
        let export = PsaExportPublicKey { key_name };

        let result = self.send_operation(NativeOperation::PsaExportPublicKey(export))?;

        if let NativeResult::PsaExportPublicKey(result) = result {
            Ok(result.data)
        } else {
            panic!("Wrong type of result");
        }
    }

    /// Destroys a key.
    pub fn destroy_key(&mut self, key_name: String) -> Result<()> {
        let destroy_key = PsaDestroyKey {
            key_name: key_name.clone(),
        };

        let _ = self.send_operation(NativeOperation::PsaDestroyKey(destroy_key))?;

        let provider = self.provider(Opcode::PsaDestroyKey);
        let auth = self.auth.bytes().to_vec();

        if let Some(ref mut created_keys) = self.created_keys {
            let _ = created_keys.remove(&(key_name, auth, provider));
        }

        Ok(())
    }

    /// Signs a short digest with a key.
    pub fn sign(
        &mut self,
        key_name: String,
        alg: AsymmetricSignature,
        hash: Vec<u8>,
    ) -> Result<Vec<u8>> {
        let asym_sign = PsaSignHash {
            key_name,
            alg,
            hash,
        };

        let result = self.send_operation(NativeOperation::PsaSignHash(asym_sign))?;

        if let NativeResult::PsaSignHash(result) = result {
            Ok(result.signature)
        } else {
            panic!("Wrong type of result");
        }
    }

    /// Signs a short digest with an RSA key.
    pub fn sign_with_rsa_sha256(&mut self, key_name: String, hash: Vec<u8>) -> Result<Vec<u8>> {
        self.sign(
            key_name,
            AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            },
            hash,
        )
    }

    /// Verifies a signature.
    pub fn verify(
        &mut self,
        key_name: String,
        alg: AsymmetricSignature,
        hash: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<()> {
        let asym_verify = PsaVerifyHash {
            key_name,
            alg,
            hash,
            signature,
        };

        let _ = self.send_operation(NativeOperation::PsaVerifyHash(asym_verify))?;

        Ok(())
    }

    /// Verifies a signature made with an RSA key.
    pub fn verify_with_rsa_sha256(
        &mut self,
        key_name: String,
        hash: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<()> {
        self.verify(
            key_name,
            AsymmetricSignature::RsaPkcs1v15Sign {
                hash_alg: Hash::Sha256,
            },
            hash,
            signature,
        )
    }

    /// Lists the provider available for the Parsec service.
    pub fn list_providers(&mut self) -> Result<Vec<ProviderInfo>> {
        let result = self.send_operation(NativeOperation::ListProviders(ListProviders {}))?;

        if let NativeResult::ListProviders(result) = result {
            Ok(result.providers)
        } else {
            panic!("Wrong type of result");
        }
    }

    /// Lists the opcodes available for one provider to execute.
    pub fn list_opcodes(&mut self, provider: ProviderID) -> Result<HashSet<Opcode>> {
        let result = self
            .send_operation_to_provider(NativeOperation::ListOpcodes(ListOpcodes {}), provider)?;

        if let NativeResult::ListOpcodes(result) = result {
            Ok(result.opcodes)
        } else {
            panic!("Wrong type of result");
        }
    }

    /// Executes a ping operation on one provider.
    pub fn ping(&mut self, provider: ProviderID) -> Result<(u8, u8)> {
        let result = self.send_operation_to_provider(NativeOperation::Ping(Ping {}), provider)?;

        if let NativeResult::Ping(result) = result {
            Ok((
                result.wire_protocol_version_maj,
                result.wire_protocol_version_min,
            ))
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
