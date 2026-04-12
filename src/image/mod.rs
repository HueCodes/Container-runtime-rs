//! OCI image pulling and content-addressable storage.
//!
//! Implements the Docker Registry HTTP API V2 for pulling images from
//! OCI-compliant registries, with Docker Hub as the default. Images are
//! stored locally in a content-addressable layout keyed by SHA256 digest.

use std::fmt;
use std::path::{Path, PathBuf};

use futures::StreamExt;
use sha2::{Digest, Sha256};
use tracing::{debug, info, instrument, warn};

use crate::error::{ContainerError, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_REGISTRY: &str = "registry-1.docker.io";
const AUTH_URL: &str = "https://auth.docker.io/token";
const DEFAULT_TAG: &str = "latest";

/// Media types we accept when fetching manifests.
const MANIFEST_ACCEPT: &[&str] = &[
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
];

// ---------------------------------------------------------------------------
// ImageReference
// ---------------------------------------------------------------------------

/// A parsed OCI image reference such as `alpine:latest` or
/// `ghcr.io/owner/repo@sha256:abc...`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageReference {
    /// Registry hostname (e.g. `registry-1.docker.io`).
    pub registry: String,
    /// Repository path (e.g. `library/alpine`).
    pub repository: String,
    /// Tag or digest. A digest starts with `sha256:`.
    pub reference: String,
}

impl ImageReference {
    /// Parse an image reference string.
    ///
    /// Accepted forms:
    /// - `alpine` -> `registry-1.docker.io/library/alpine:latest`
    /// - `alpine:3.19` -> `registry-1.docker.io/library/alpine:3.19`
    /// - `ubuntu:22.04` -> `registry-1.docker.io/library/ubuntu:22.04`
    /// - `library/alpine:latest`
    /// - `ghcr.io/owner/repo:tag`
    /// - `repo@sha256:abcd...`
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();
        if input.is_empty() {
            return Err(ContainerError::Image("empty image reference".into()));
        }

        // Split off @digest first (takes precedence over :tag).
        let (name_part, reference) = if let Some(idx) = input.find('@') {
            let digest = &input[idx + 1..];
            if !digest.starts_with("sha256:") {
                return Err(ContainerError::Image(format!(
                    "unsupported digest algorithm in '{}'",
                    input
                )));
            }
            (&input[..idx], digest.to_string())
        } else if let Some(colon_idx) = input.rfind(':') {
            // Only treat as tag if the part before the colon contains no '/'.
            // This avoids splitting on the port in `host:5000/repo`.
            let before = &input[..colon_idx];
            let after = &input[colon_idx + 1..];
            // If `after` contains a '/' it is part of a host:port/repo pattern.
            if after.contains('/') {
                (input, DEFAULT_TAG.to_string())
            } else {
                (before, after.to_string())
            }
        } else {
            (input, DEFAULT_TAG.to_string())
        };

        // Determine registry vs repository.
        let (registry, repository) = if let Some(slash_idx) = name_part.find('/') {
            let first = &name_part[..slash_idx];
            // Heuristic: the first component is a registry if it contains a dot
            // or a colon (port), or is "localhost".
            if first.contains('.') || first.contains(':') || first == "localhost" {
                (first.to_string(), name_part[slash_idx + 1..].to_string())
            } else {
                // Docker Hub with explicit namespace, e.g. `library/alpine`.
                (DEFAULT_REGISTRY.to_string(), name_part.to_string())
            }
        } else {
            // Bare name like `alpine` -> `library/alpine` on Docker Hub.
            (
                DEFAULT_REGISTRY.to_string(),
                format!("library/{}", name_part),
            )
        };

        if repository.is_empty() {
            return Err(ContainerError::Image(format!(
                "empty repository in '{}'",
                input
            )));
        }

        Ok(Self {
            registry,
            repository,
            reference,
        })
    }

    /// Returns `true` when the reference is a digest rather than a tag.
    pub fn is_digest(&self) -> bool {
        self.reference.starts_with("sha256:")
    }
}

impl fmt::Display for ImageReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.registry == DEFAULT_REGISTRY {
            write!(f, "{}:{}", self.repository, self.reference)
        } else {
            write!(
                f,
                "{}/{}:{}",
                self.registry, self.repository, self.reference
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Manifest types
// ---------------------------------------------------------------------------

/// A single layer (or config) descriptor inside an OCI/Docker manifest.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct Descriptor {
    /// Media type of the referenced content.
    #[serde(rename = "mediaType")]
    pub media_type: String,
    /// Content digest, e.g. `sha256:abcdef...`.
    pub digest: String,
    /// Size in bytes.
    pub size: u64,
}

/// An OCI / Docker V2 image manifest.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct ImageManifest {
    /// Schema version (always 2 for current manifests).
    #[serde(rename = "schemaVersion")]
    pub schema_version: u32,
    /// Media type of the manifest itself.
    #[serde(rename = "mediaType", default)]
    pub media_type: Option<String>,
    /// Config descriptor (contains the image JSON config).
    pub config: Descriptor,
    /// Ordered list of layer descriptors.
    pub layers: Vec<Descriptor>,
}

// ---------------------------------------------------------------------------
// Token response from Docker Hub auth
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct TokenResponse {
    token: String,
}

// ---------------------------------------------------------------------------
// RegistryClient
// ---------------------------------------------------------------------------

/// HTTP client for communicating with OCI-compliant container registries.
pub struct RegistryClient {
    client: reqwest::Client,
}

impl RegistryClient {
    /// Create a new registry client.
    pub fn new() -> Result<Self> {
        let client = reqwest::Client::builder()
            .user_agent("crate-runtime/0.1")
            .build()
            .map_err(|e| ContainerError::Http(e.to_string()))?;
        Ok(Self { client })
    }

    /// Obtain a bearer token for pulling from `repository` on `registry`.
    ///
    /// Currently implements the Docker Hub token flow. For other registries
    /// that do not require auth an empty token is returned.
    #[instrument(skip(self), fields(registry, repository))]
    pub async fn authenticate(&self, registry: &str, repository: &str) -> Result<String> {
        if registry != DEFAULT_REGISTRY && registry != "docker.io" {
            // Many registries support anonymous pulls without tokens.
            // Try an unauthenticated request first; a real implementation
            // would parse the WWW-Authenticate header on 401.
            debug!(registry, "skipping token auth for non-Docker-Hub registry");
            return Ok(String::new());
        }

        let url = format!(
            "{}?service=registry.docker.io&scope=repository:{}:pull",
            AUTH_URL, repository
        );

        debug!(url = %url, "requesting auth token");

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| ContainerError::Http(format!("token request failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(ContainerError::Http(format!(
                "auth endpoint returned {}",
                resp.status()
            )));
        }

        let body: TokenResponse = resp
            .json()
            .await
            .map_err(|e| ContainerError::Http(format!("failed to parse token response: {}", e)))?;

        debug!("obtained bearer token");
        Ok(body.token)
    }

    /// Fetch the image manifest for the given reference.
    #[instrument(skip(self, token), fields(image = %reference))]
    pub async fn fetch_manifest(
        &self,
        reference: &ImageReference,
        token: &str,
    ) -> Result<ImageManifest> {
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            reference.registry, reference.repository, reference.reference
        );

        debug!(url = %url, "fetching manifest");

        let accept = MANIFEST_ACCEPT.join(", ");
        let mut req = self.client.get(&url).header("Accept", &accept);
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ContainerError::Http(format!("manifest request failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(ContainerError::Image(format!(
                "registry returned {} for manifest of {}",
                resp.status(),
                reference
            )));
        }

        let manifest: ImageManifest = resp
            .json()
            .await
            .map_err(|e| ContainerError::Image(format!("failed to parse manifest: {}", e)))?;

        info!(
            layers = manifest.layers.len(),
            config = %manifest.config.digest,
            "fetched manifest"
        );

        Ok(manifest)
    }

    /// Download a single blob (layer or config) from the registry to `dest`.
    ///
    /// The file is written to a temporary path first, then renamed after
    /// the download completes so that partial downloads are never visible
    /// to readers.
    #[instrument(skip(self, token), fields(image = %reference, digest, dest = %dest.display()))]
    pub async fn download_layer(
        &self,
        reference: &ImageReference,
        digest: &str,
        token: &str,
        dest: &Path,
    ) -> Result<()> {
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            reference.registry, reference.repository, digest
        );

        debug!(url = %url, "downloading blob");

        let mut req = self.client.get(&url);
        if !token.is_empty() {
            req = req.bearer_auth(token);
        }

        let resp = req
            .send()
            .await
            .map_err(|e| ContainerError::Http(format!("blob download failed: {}", e)))?;

        if !resp.status().is_success() {
            return Err(ContainerError::Image(format!(
                "registry returned {} for blob {}",
                resp.status(),
                digest
            )));
        }

        // Ensure parent directory exists.
        if let Some(parent) = dest.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| ContainerError::Image(format!("mkdir failed: {}", e)))?;
        }

        let tmp_path = dest.with_extension("part");
        let mut file = tokio::fs::File::create(&tmp_path)
            .await
            .map_err(|e| ContainerError::Image(format!("create tmp file: {}", e)))?;

        let mut stream = resp.bytes_stream();
        let mut total: u64 = 0;

        use tokio::io::AsyncWriteExt;
        while let Some(chunk) = stream.next().await {
            let chunk =
                chunk.map_err(|e| ContainerError::Http(format!("stream read error: {}", e)))?;
            file.write_all(&chunk)
                .await
                .map_err(|e| ContainerError::Image(format!("write error: {}", e)))?;
            total += chunk.len() as u64;
        }

        file.flush()
            .await
            .map_err(|e| ContainerError::Image(format!("flush error: {}", e)))?;
        drop(file);

        tokio::fs::rename(&tmp_path, dest)
            .await
            .map_err(|e| ContainerError::Image(format!("rename failed: {}", e)))?;

        info!(bytes = total, "downloaded blob");
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Standalone helpers
// ---------------------------------------------------------------------------

/// Verify that the file at `path` matches `expected_digest`.
///
/// `expected_digest` must be in the form `sha256:<hex>`.
#[instrument(fields(path = %path.display(), expected_digest))]
pub fn verify_digest(path: &Path, expected_digest: &str) -> Result<()> {
    let expected_hex = expected_digest.strip_prefix("sha256:").ok_or_else(|| {
        ContainerError::Image(format!("unsupported digest format: {}", expected_digest))
    })?;

    let data = std::fs::read(path)
        .map_err(|e| ContainerError::Image(format!("read {}: {}", path.display(), e)))?;

    let mut hasher = Sha256::new();
    hasher.update(&data);
    let actual_hex = hex::encode(hasher.finalize());

    if actual_hex != expected_hex {
        return Err(ContainerError::Image(format!(
            "digest mismatch for {}: expected {} but got {}",
            path.display(),
            expected_hex,
            actual_hex,
        )));
    }

    debug!("digest verified");
    Ok(())
}

/// Extract a gzipped tar layer into `dest`.
///
/// This handles the common `application/vnd.oci.image.layer.v1.tar+gzip`
/// and `application/vnd.docker.image.rootfs.diff.tar.gzip` media types.
#[instrument(fields(layer = %layer_path.display(), dest = %dest.display()))]
pub fn extract_layer(layer_path: &Path, dest: &Path) -> Result<()> {
    let file = std::fs::File::open(layer_path)
        .map_err(|e| ContainerError::Image(format!("open layer: {}", e)))?;

    let gz = flate2::read::GzDecoder::new(file);
    let mut archive = tar::Archive::new(gz);

    std::fs::create_dir_all(dest).map_err(|e| ContainerError::Image(format!("mkdir: {}", e)))?;

    archive
        .unpack(dest)
        .map_err(|e| ContainerError::Image(format!("unpack layer: {}", e)))?;

    info!("extracted layer to {}", dest.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// ImageStore
// ---------------------------------------------------------------------------

/// Local content-addressable store for OCI image blobs.
///
/// Layout under root:
/// ```text
/// <root>/
///   blobs/sha256/<hex_digest>    -- raw blobs (layers, configs)
///   manifests/<repo>/<reference> -- cached manifests as JSON
/// ```
pub struct ImageStore {
    /// Root directory of the store.
    root: PathBuf,
    /// Registry client instance.
    client: RegistryClient,
}

impl ImageStore {
    /// Create a new store rooted at `root`.
    ///
    /// The directory is created lazily when content is first written.
    pub fn new(root: PathBuf) -> Self {
        let client = RegistryClient::new().expect("failed to create HTTP client");
        Self { root, client }
    }

    /// Return the default store path: `~/.crate/images/`.
    pub fn default_root() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("/tmp"))
            .join(".crate")
            .join("images")
    }

    /// Return the on-disk path for a blob identified by its full digest
    /// (e.g. `sha256:abcdef...`).
    pub fn get_layer_path(&self, digest: &str) -> PathBuf {
        // digest format: "sha256:hex"
        let hex = digest.strip_prefix("sha256:").unwrap_or(digest);
        self.root.join("blobs").join("sha256").join(hex)
    }

    /// Check whether a blob with the given digest already exists locally.
    pub fn layer_exists(&self, digest: &str) -> bool {
        self.get_layer_path(digest).exists()
    }

    /// Pull an image from its registry, downloading all layers into the
    /// content-addressable store. Returns the parsed manifest.
    #[instrument(skip(self), fields(image = %reference))]
    pub async fn pull_image(&self, reference: &ImageReference) -> Result<ImageManifest> {
        info!("pulling image {}", reference);

        // 1. Authenticate
        let token = self
            .client
            .authenticate(&reference.registry, &reference.repository)
            .await?;

        // 2. Fetch manifest
        let manifest = self.client.fetch_manifest(reference, &token).await?;

        // 3. Download config blob if missing
        if !self.layer_exists(&manifest.config.digest) {
            let dest = self.get_layer_path(&manifest.config.digest);
            self.client
                .download_layer(reference, &manifest.config.digest, &token, &dest)
                .await?;
            verify_digest(&dest, &manifest.config.digest)?;
        } else {
            debug!(digest = %manifest.config.digest, "config blob already cached");
        }

        // 4. Download each layer
        for (i, layer) in manifest.layers.iter().enumerate() {
            if self.layer_exists(&layer.digest) {
                debug!(layer = i, digest = %layer.digest, "layer already cached");
                continue;
            }

            let dest = self.get_layer_path(&layer.digest);
            self.client
                .download_layer(reference, &layer.digest, &token, &dest)
                .await?;
            verify_digest(&dest, &layer.digest)?;
            info!(layer = i, digest = %layer.digest, "layer downloaded and verified");
        }

        // 5. Persist manifest
        self.save_manifest(reference, &manifest)?;

        info!("pull complete");
        Ok(manifest)
    }

    /// Return the local paths for all layers of a previously pulled image.
    ///
    /// The paths are in the correct stacking order (bottom layer first).
    #[instrument(skip(self), fields(image = %reference))]
    pub fn get_image_layers(&self, reference: &ImageReference) -> Result<Vec<PathBuf>> {
        let manifest = self.load_manifest(reference)?;
        let paths: Vec<PathBuf> = manifest
            .layers
            .iter()
            .map(|l| self.get_layer_path(&l.digest))
            .collect();

        for p in &paths {
            if !p.exists() {
                return Err(ContainerError::Image(format!(
                    "missing layer blob: {}",
                    p.display()
                )));
            }
        }

        Ok(paths)
    }

    // -- internal helpers ---------------------------------------------------

    fn manifest_path(&self, reference: &ImageReference) -> PathBuf {
        self.root
            .join("manifests")
            .join(&reference.repository)
            .join(&reference.reference)
    }

    fn save_manifest(&self, reference: &ImageReference, manifest: &ImageManifest) -> Result<()> {
        let path = self.manifest_path(reference);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| ContainerError::Image(format!("mkdir: {}", e)))?;
        }
        let json = serde_json::to_string_pretty(manifest)
            .map_err(|e| ContainerError::Image(format!("serialize manifest: {}", e)))?;
        std::fs::write(&path, json)
            .map_err(|e| ContainerError::Image(format!("write manifest: {}", e)))?;
        Ok(())
    }

    fn load_manifest(&self, reference: &ImageReference) -> Result<ImageManifest> {
        let path = self.manifest_path(reference);
        let data = std::fs::read_to_string(&path).map_err(|e| {
            ContainerError::Image(format!(
                "manifest not found for {} ({}): {}",
                reference,
                path.display(),
                e
            ))
        })?;
        let manifest: ImageManifest = serde_json::from_str(&data)
            .map_err(|e| ContainerError::Image(format!("parse manifest: {}", e)))?;
        Ok(manifest)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    // -- ImageReference parsing ---------------------------------------------

    #[test]
    fn parse_bare_name() {
        let r = ImageReference::parse("alpine").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn parse_name_with_tag() {
        let r = ImageReference::parse("ubuntu:22.04").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/ubuntu");
        assert_eq!(r.reference, "22.04");
    }

    #[test]
    fn parse_namespaced_docker_hub() {
        let r = ImageReference::parse("library/alpine:latest").unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, "latest");
    }

    #[test]
    fn parse_custom_registry() {
        let r = ImageReference::parse("ghcr.io/owner/repo:v1.0").unwrap();
        assert_eq!(r.registry, "ghcr.io");
        assert_eq!(r.repository, "owner/repo");
        assert_eq!(r.reference, "v1.0");
    }

    #[test]
    fn parse_registry_with_port() {
        let r = ImageReference::parse("localhost:5000/myimage:dev").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.repository, "myimage");
        assert_eq!(r.reference, "dev");
    }

    #[test]
    fn parse_digest_reference() {
        let digest = "sha256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
        let input = format!("alpine@{}", digest);
        let r = ImageReference::parse(&input).unwrap();
        assert_eq!(r.registry, "registry-1.docker.io");
        assert_eq!(r.repository, "library/alpine");
        assert_eq!(r.reference, digest);
        assert!(r.is_digest());
    }

    #[test]
    fn parse_empty_errors() {
        assert!(ImageReference::parse("").is_err());
        assert!(ImageReference::parse("   ").is_err());
    }

    #[test]
    fn display_docker_hub() {
        let r = ImageReference::parse("alpine:3.19").unwrap();
        assert_eq!(r.to_string(), "library/alpine:3.19");
    }

    #[test]
    fn display_custom_registry() {
        let r = ImageReference::parse("ghcr.io/owner/repo:v1").unwrap();
        assert_eq!(r.to_string(), "ghcr.io/owner/repo:v1");
    }

    // -- Digest verification ------------------------------------------------

    #[test]
    fn verify_digest_valid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        std::fs::write(&path, b"hello world").unwrap();

        // sha256("hello world")
        let digest = "sha256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";
        verify_digest(&path, digest).unwrap();
    }

    #[test]
    fn verify_digest_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        std::fs::write(&path, b"hello world").unwrap();

        let bad = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert!(verify_digest(&path, bad).is_err());
    }

    #[test]
    fn verify_digest_bad_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("blob");
        std::fs::write(&path, b"data").unwrap();
        assert!(verify_digest(&path, "md5:abc").is_err());
    }

    // -- Store path construction --------------------------------------------

    #[test]
    fn store_layer_path() {
        let store = ImageStore::new(PathBuf::from("/tmp/test-store"));
        let p = store.get_layer_path("sha256:aabbcc");
        assert_eq!(p, PathBuf::from("/tmp/test-store/blobs/sha256/aabbcc"));
    }

    #[test]
    fn store_layer_exists_false() {
        let store = ImageStore::new(PathBuf::from("/tmp/nonexistent-store-xyz"));
        assert!(!store.layer_exists("sha256:no_such_digest"));
    }

    #[test]
    fn store_layer_exists_true() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().to_path_buf());
        let digest = "sha256:abc123";
        let blob_path = store.get_layer_path(digest);
        std::fs::create_dir_all(blob_path.parent().unwrap()).unwrap();
        std::fs::write(&blob_path, b"data").unwrap();
        assert!(store.layer_exists(digest));
    }

    // -- Manifest deserialization -------------------------------------------

    #[test]
    fn deserialize_manifest() {
        let json = r#"{
            "schemaVersion": 2,
            "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
            "config": {
                "mediaType": "application/vnd.docker.container.image.v1+json",
                "digest": "sha256:config111",
                "size": 1234
            },
            "layers": [
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": "sha256:layer111",
                    "size": 5000000
                },
                {
                    "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                    "digest": "sha256:layer222",
                    "size": 3000000
                }
            ]
        }"#;

        let m: ImageManifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.schema_version, 2);
        assert_eq!(
            m.media_type.as_deref(),
            Some("application/vnd.docker.distribution.manifest.v2+json")
        );
        assert_eq!(m.config.digest, "sha256:config111");
        assert_eq!(m.config.size, 1234);
        assert_eq!(m.layers.len(), 2);
        assert_eq!(m.layers[0].digest, "sha256:layer111");
        assert_eq!(m.layers[1].digest, "sha256:layer222");
        assert_eq!(m.layers[1].size, 3_000_000);
    }

    #[test]
    fn deserialize_manifest_no_media_type() {
        // OCI manifests may omit the top-level mediaType.
        let json = r#"{
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": "sha256:cfgabc",
                "size": 512
            },
            "layers": []
        }"#;

        let m: ImageManifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.media_type, None);
        assert!(m.layers.is_empty());
    }

    // -- Manifest round-trip through store ----------------------------------

    #[test]
    fn manifest_save_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = ImageStore::new(dir.path().to_path_buf());
        let reference = ImageReference::parse("alpine:3.19").unwrap();

        let manifest = ImageManifest {
            schema_version: 2,
            media_type: Some("application/vnd.docker.distribution.manifest.v2+json".into()),
            config: Descriptor {
                media_type: "application/vnd.docker.container.image.v1+json".into(),
                digest: "sha256:cfg".into(),
                size: 100,
            },
            layers: vec![Descriptor {
                media_type: "application/vnd.docker.image.rootfs.diff.tar.gzip".into(),
                digest: "sha256:layer1".into(),
                size: 999,
            }],
        };

        store.save_manifest(&reference, &manifest).unwrap();
        let loaded = store.load_manifest(&reference).unwrap();
        assert_eq!(loaded.config.digest, "sha256:cfg");
        assert_eq!(loaded.layers.len(), 1);
    }

    // -- Layer extraction ---------------------------------------------------

    #[test]
    fn extract_layer_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let tar_path = dir.path().join("layer.tar.gz");
        let extract_dir = dir.path().join("rootfs");

        // Build a small tar.gz with one file.
        {
            let file = std::fs::File::create(&tar_path).unwrap();
            let gz = flate2::write::GzEncoder::new(file, flate2::Compression::fast());
            let mut builder = tar::Builder::new(gz);

            let content = b"hello from layer";
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "greeting.txt", &content[..])
                .unwrap();
            builder.finish().unwrap();
        }

        extract_layer(&tar_path, &extract_dir).unwrap();
        let extracted = std::fs::read_to_string(extract_dir.join("greeting.txt")).unwrap();
        assert_eq!(extracted, "hello from layer");
    }
}
