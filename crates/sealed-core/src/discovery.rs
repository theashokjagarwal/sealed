//! Discovery engine for identifying AI surfaces (prompts, datasets, RAG docs, tool definitions, configs).

use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;
use crate::security::{validate_path_containment, SecurityError};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum SurfaceKind {
    SystemPrompt,
    TrainingData,
    RagKnowledge,
    AgentTool,
    SecretConfig,
    ModelArtifact,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredSurface {
    pub kind: SurfaceKind,
    pub relative_path: String,
    pub absolute_path: PathBuf,
    pub size_bytes: u64,
}

pub struct DiscoveryEngine {
    max_file_count: usize,
}

impl Default for DiscoveryEngine {
    fn default() -> Self {
        Self {
            max_file_count: 50_000,
        }
    }
}

impl DiscoveryEngine {
    pub fn new(max_file_count: usize) -> Self {
        Self { max_file_count }
    }

    pub fn scan_project(&self, root: &Path) -> Result<Vec<DiscoveredSurface>, SecurityError> {
        let canonical_root = root.canonicalize()
            .map_err(|e| SecurityError::PathTraversal(format!("Root canonicalization failed: {}", e)))?;

        let mut discovered = Vec::new();
        let mut count = 0;

        // Use deterministic sorting for file iteration
        for entry in WalkDir::new(&canonical_root)
            .sort_by_file_name()
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                !name.starts_with('.') && name != "node_modules" && name != "target" && name != ".git"
            })
        {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => return Err(SecurityError::PathTraversal(err.to_string())),
            };

            if entry.file_type().is_file() {
                count += 1;
                if count > self.max_file_count {
                    return Err(SecurityError::ParserLimitExceeded(format!(
                        "Project file count exceeded safety ceiling of {}",
                        self.max_file_count
                    )));
                }

                let path = entry.path();
                validate_path_containment(&canonical_root, path)?;

                let rel_path = path.strip_prefix(&canonical_root)
                    .unwrap_or(path)
                    .to_string_lossy()
                    .replace('\\', "/");

                let metadata = entry.metadata()
                    .map_err(|e| SecurityError::PathTraversal(e.to_string()))?;

                if let Some(kind) = Self::classify_surface(&rel_path) {
                    discovered.push(DiscoveredSurface {
                        kind,
                        relative_path: rel_path,
                        absolute_path: path.to_path_buf(),
                        size_bytes: metadata.len(),
                    });
                }
            }
        }

        Ok(discovered)
    }

    fn classify_surface(path: &str) -> Option<SurfaceKind> {
        let p_lower = path.to_lowercase();
        if p_lower.contains("prompt") || p_lower.ends_with(".prompt") {
            Some(SurfaceKind::SystemPrompt)
        } else if p_lower.contains("data") || p_lower.ends_with(".jsonl") || p_lower.ends_with(".csv") {
            Some(SurfaceKind::TrainingData)
        } else if p_lower.contains("rag") || p_lower.contains("knowledge") || (p_lower.contains("docs") && p_lower.ends_with(".md")) {
            Some(SurfaceKind::RagKnowledge)
        } else if p_lower.contains("tool") || p_lower.contains("agent") {
            Some(SurfaceKind::AgentTool)
        } else if p_lower.contains("config") || p_lower.contains("secret") || p_lower.contains(".env") || p_lower.ends_with(".yaml") || p_lower.ends_with(".yml") {
            Some(SurfaceKind::SecretConfig)
        } else if p_lower.ends_with(".onnx") || p_lower.ends_with(".gguf") || p_lower.ends_with(".safetensors") {
            Some(SurfaceKind::ModelArtifact)
        } else {
            None
        }
    }
}
