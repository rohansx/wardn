/// USD price per 1M tokens for a model.
///
/// **Not authoritative.** This table exists to estimate spend for budget
/// enforcement (a denial-of-wallet safety net), not to produce a billing-
/// accurate ledger — provider pricing changes over time and this needs
/// updating as it does. Unknown models fall back to `default_pricing()`,
/// which deliberately errs toward overestimating rather than undercounting,
/// since undercounting would make a budget cap silently ineffective.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ModelPricing {
    pub input_per_million: f64,
    pub output_per_million: f64,
}

pub fn lookup(provider_slug: &str, model: &str) -> ModelPricing {
    let model = model.to_ascii_lowercase();
    match provider_slug {
        "anthropic" => anthropic_pricing(&model),
        "openai" => openai_pricing(&model),
        _ => default_pricing(),
    }
}

fn anthropic_pricing(model: &str) -> ModelPricing {
    if model.contains("opus") {
        ModelPricing {
            input_per_million: 15.0,
            output_per_million: 75.0,
        }
    } else if model.contains("haiku") {
        ModelPricing {
            input_per_million: 0.80,
            output_per_million: 4.0,
        }
    } else if model.contains("sonnet") {
        ModelPricing {
            input_per_million: 3.0,
            output_per_million: 15.0,
        }
    } else {
        default_pricing()
    }
}

fn openai_pricing(model: &str) -> ModelPricing {
    if model.contains("gpt-4o-mini") {
        ModelPricing {
            input_per_million: 0.15,
            output_per_million: 0.60,
        }
    } else if model.contains("gpt-4o") {
        ModelPricing {
            input_per_million: 2.50,
            output_per_million: 10.0,
        }
    } else if model.contains("gpt-4.1-mini") {
        ModelPricing {
            input_per_million: 0.40,
            output_per_million: 1.60,
        }
    } else if model.contains("gpt-4.1") {
        ModelPricing {
            input_per_million: 2.0,
            output_per_million: 8.0,
        }
    } else if model.starts_with("o1") || model.starts_with("o3") || model.starts_with("o4") {
        ModelPricing {
            input_per_million: 15.0,
            output_per_million: 60.0,
        }
    } else {
        default_pricing()
    }
}

/// Conservative fallback for unknown providers/models.
fn default_pricing() -> ModelPricing {
    ModelPricing {
        input_per_million: 5.0,
        output_per_million: 15.0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anthropic_opus_pricing() {
        let p = lookup("anthropic", "claude-opus-4-8");
        assert_eq!(p.input_per_million, 15.0);
        assert_eq!(p.output_per_million, 75.0);
    }

    #[test]
    fn test_anthropic_sonnet_pricing() {
        let p = lookup("anthropic", "claude-sonnet-5");
        assert_eq!(p.input_per_million, 3.0);
    }

    #[test]
    fn test_anthropic_haiku_pricing() {
        let p = lookup("anthropic", "claude-haiku-4-5");
        assert_eq!(p.input_per_million, 0.80);
    }

    #[test]
    fn test_openai_gpt4o_vs_mini_are_different() {
        let full = lookup("openai", "gpt-4o");
        let mini = lookup("openai", "gpt-4o-mini");
        assert!(full.input_per_million > mini.input_per_million);
    }

    #[test]
    fn test_case_insensitive_model_match() {
        let a = lookup("anthropic", "Claude-Opus-4-8");
        let b = lookup("anthropic", "claude-opus-4-8");
        assert_eq!(a, b);
    }

    #[test]
    fn test_unknown_model_uses_conservative_default() {
        let known = lookup("anthropic", "claude-haiku-4-5");
        let unknown = lookup("anthropic", "some-brand-new-model-not-in-table");
        assert!(
            unknown.input_per_million >= known.input_per_million,
            "unknown models should not be UNDER-priced relative to the cheapest known tier"
        );
    }

    #[test]
    fn test_unknown_provider_uses_default() {
        let p = lookup("some-custom-provider", "whatever-model");
        assert_eq!(p, default_pricing());
    }
}
