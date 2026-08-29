use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;

#[derive(Debug, Deserialize)]
pub struct Catalog {
    pub schema_version: u32,
    pub model_scope: String,
    pub model_family: String,
    pub models: BTreeMap<String, Model>,
    pub bindings: BTreeMap<String, Binding>,
}

#[derive(Debug, Deserialize)]
pub struct Model {
    pub id: String,
    pub candidate_efforts: Vec<String>,
    pub effort_support: String,
    pub source_url: String,
}

#[derive(Debug, Deserialize)]
pub struct Binding {
    pub model: String,
    pub effort: String,
    pub status: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CatalogError {
    Parse(String),
    UnsupportedSchema(u32),
    InvalidScope,
    InvalidModel(String),
    MissingModel(String),
    UnsupportedEffort { role: String, effort: String },
    StableBinding(String),
}

impl fmt::Display for CatalogError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(error) => write!(formatter, "catalog parse failed: {error}"),
            Self::UnsupportedSchema(version) => {
                write!(formatter, "unsupported catalog schema: {version}")
            }
            Self::InvalidScope => write!(formatter, "catalog must use official OpenAI models only"),
            Self::InvalidModel(model) => {
                write!(
                    formatter,
                    "catalog model is outside the supported family: {model}"
                )
            }
            Self::MissingModel(role) => {
                write!(formatter, "binding for {role} has no catalog model")
            }
            Self::UnsupportedEffort { role, effort } => {
                write!(
                    formatter,
                    "binding for {role} uses unsupported effort {effort}"
                )
            }
            Self::StableBinding(role) => {
                write!(formatter, "binding for {role} must remain a hypothesis")
            }
        }
    }
}

impl std::error::Error for CatalogError {}

impl Catalog {
    pub fn parse(source: &str) -> Result<Self, CatalogError> {
        let catalog: Self =
            toml::from_str(source).map_err(|error| CatalogError::Parse(error.to_string()))?;
        catalog.validate()?;
        Ok(catalog)
    }

    pub fn validate(&self) -> Result<(), CatalogError> {
        if self.schema_version != 1 {
            return Err(CatalogError::UnsupportedSchema(self.schema_version));
        }
        if self.model_scope != "official-openai-only" {
            return Err(CatalogError::InvalidScope);
        }
        for model in self.models.values() {
            if !(model.id == self.model_family
                || model.id.starts_with(&format!("{}-", self.model_family)))
                || !(model.source_url.starts_with("https://learn.chatgpt.com/")
                    || model
                        .source_url
                        .starts_with("https://developers.openai.com/")
                    || model.source_url.starts_with("https://platform.openai.com/"))
            {
                return Err(CatalogError::InvalidModel(model.id.clone()));
            }
        }
        for (role, binding) in &self.bindings {
            let model = self
                .models
                .get(&binding.model)
                .ok_or_else(|| CatalogError::MissingModel(role.clone()))?;
            if !model.candidate_efforts.contains(&binding.effort) {
                return Err(CatalogError::UnsupportedEffort {
                    role: role.clone(),
                    effort: binding.effort.clone(),
                });
            }
            if binding.status != "hypothesis" || model.effort_support != "hypothesis" {
                return Err(CatalogError::StableBinding(role.clone()));
            }
        }
        Ok(())
    }
}
