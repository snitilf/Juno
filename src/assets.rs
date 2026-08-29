use crate::{Catalog, CatalogError};
use serde::Serialize;
use std::collections::BTreeMap;

pub const ROUTING_START: &str = "<!-- juno:begin -->";
pub const ROUTING_END: &str = "<!-- juno:end -->";
const ROUTING_LIMIT: usize = 8 * 1024;

const ROUTING_POLICY: &str = include_str!("../templates/instructions/routing-policy.md");

const ROLE_SOURCES: [(&str, &str); 8] = [
    ("scout", include_str!("../templates/agents/scout.md")),
    ("surveyor", include_str!("../templates/agents/surveyor.md")),
    (
        "mech_executor",
        include_str!("../templates/agents/mech_executor.md"),
    ),
    ("executor", include_str!("../templates/agents/executor.md")),
    (
        "light_verifier",
        include_str!("../templates/agents/light_verifier.md"),
    ),
    ("verifier", include_str!("../templates/agents/verifier.md")),
    (
        "heavy_verifier",
        include_str!("../templates/agents/heavy_verifier.md"),
    ),
    (
        "security_executor",
        include_str!("../templates/agents/security_executor.md"),
    ),
];

#[derive(Debug, Serialize)]
struct AgentFile<'a> {
    name: &'a str,
    description: &'a str,
    model: &'a str,
    model_reasoning_effort: &'a str,
    sandbox_mode: &'a str,
    developer_instructions: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    agents: Option<AgentSettings>,
}

#[derive(Debug, Serialize)]
struct AgentSettings {
    enabled: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub struct GeneratedAssets {
    pub routing_block: String,
    pub agents: BTreeMap<String, String>,
}

pub fn generate_assets(catalog_source: &str) -> Result<GeneratedAssets, CatalogError> {
    let catalog = Catalog::parse(catalog_source)?;
    let routing_block = format!(
        "{ROUTING_START}\n{}\n{ROUTING_END}\n",
        ROUTING_POLICY.trim()
    );
    assert!(
        routing_block.len() <= ROUTING_LIMIT,
        "routing block exceeds byte limit"
    );

    let mut agents = BTreeMap::new();
    for (role, source) in ROLE_SOURCES {
        let binding = catalog
            .bindings
            .get(role)
            .ok_or_else(|| CatalogError::MissingModel(role.to_string()))?;
        let model = catalog
            .models
            .get(&binding.model)
            .ok_or_else(|| CatalogError::MissingModel(role.to_string()))?;
        let (description, instructions) = source
            .split_once("\n\n")
            .expect("role template must have a description and instructions");
        let verifier = role.contains("verifier");
        let sandbox_mode = if verifier || matches!(role, "scout" | "surveyor") {
            "read-only"
        } else {
            "workspace-write"
        };
        let file = AgentFile {
            name: role,
            description: description.trim(),
            model: &model.id,
            model_reasoning_effort: &binding.effort,
            sandbox_mode,
            developer_instructions: instructions.trim(),
            agents: verifier.then_some(AgentSettings { enabled: false }),
        };
        let encoded = toml::to_string_pretty(&file)
            .map_err(|error| CatalogError::Parse(error.to_string()))?;
        agents.insert(format!("{role}.toml"), encoded);
    }
    Ok(GeneratedAssets {
        routing_block,
        agents,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const CATALOG: &str = include_str!("../config/model-catalog.toml");

    #[test]
    fn generates_bounded_model_free_policy() {
        let assets = generate_assets(CATALOG).unwrap();
        assert!(assets.routing_block.len() <= ROUTING_LIMIT);
        assert!(!assets.routing_block.contains("gpt-"));
        assert!(assets.routing_block.starts_with(ROUTING_START));
        assert!(assets.routing_block.ends_with(&format!("{ROUTING_END}\n")));
    }

    #[test]
    fn generates_eight_valid_unique_agents() {
        let assets = generate_assets(CATALOG).unwrap();
        assert_eq!(assets.agents.len(), 8);
        for (name, source) in assets.agents {
            let value: toml::Value = toml::from_str(&source).unwrap();
            assert_eq!(
                value["name"].as_str().unwrap(),
                name.trim_end_matches(".toml")
            );
            assert!(value["description"].as_str().unwrap().len() > 20);
            assert!(value["developer_instructions"].as_str().unwrap().len() > 20);
            assert!(value["model"].as_str().unwrap().starts_with("gpt-"));
            if name.contains("verifier") {
                assert_eq!(value["agents"]["enabled"].as_bool(), Some(false));
                assert!(
                    value["developer_instructions"]
                        .as_str()
                        .unwrap()
                        .contains("Do not repair")
                );
                assert!(
                    value["developer_instructions"]
                        .as_str()
                        .unwrap()
                        .contains("Do not spawn")
                );
            }
        }
    }
}
